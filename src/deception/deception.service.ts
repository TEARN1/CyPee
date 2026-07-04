import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../database/prisma.service';
import { AuditLogService } from '../audit/audit-log.service';

@Injectable()
export class DeceptionService {
  private readonly logger = new Logger(DeceptionService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly auditLog: AuditLogService,
  ) {}

  /**
   * Generates a new decoy honeytoken credential and saves it in the database.
   */
  async generateHoneytoken(tenantId: string, label: string, type: 'AWS' | 'DB' | 'SSH'): Promise<{ token: string; keyId?: string }> {
    let token = '';
    let keyId = '';

    if (type === 'AWS') {
      keyId = `AKIA${Math.random().toString(36).substring(2, 10).toUpperCase()}`;
      const secret = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
      token = `AWS_ACCESS_KEY_ID=${keyId}\nAWS_SECRET_ACCESS_KEY=${secret}`;
    } else if (type === 'DB') {
      const pass = Math.random().toString(36).substring(2, 12);
      token = `DATABASE_URL=postgresql://decoy_admin:${pass}@decoy-db.shield.io:5432/production`;
    } else {
      token = '-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEA0y6X...decoy...';
    }

    await this.prisma.honeytoken.create({
      data: {
        tenantId,
        type,
        value: token,
        placement: label,
        zone: '1',
        isActive: true,
      },
    });

    return { token, keyId: keyId || undefined };
  }

  /**
   * Triggers an immediate critical incident and tampered audit log when a decoy endpoint
   * or credential is touched.
   */
  async handleDeceptionHit(
    tenantId: string,
    honeytokenValue: string,
    ip: string,
    headers: Record<string, string>,
    path: string,
  ): Promise<void> {
    this.logger.error(`🚨 HONEYTOKEN TRIGGERED! Decoy accessed from IP: ${ip} at path: ${path}`);

    // Track accessed count on the decoy token
    const token = await this.prisma.honeytoken.findFirst({
      where: { tenantId, value: honeytokenValue },
    });

    if (token) {
      await this.prisma.honeytoken.update({
        where: { id: token.id },
        data: {
          accessCount: token.accessCount + 1,
          accessedAt: new Date(),
          accessIp: ip,
        },
      });
    }

    // Create Incident for the SOC dashboard
    const incident = await this.prisma.incident.create({
      data: {
        tenantId,
        type: 'HONEYTOKEN_DECEPTION_TRIGGERED',
        severity: 'CRITICAL',
        status: 'OPEN',
        evidence: JSON.stringify({
          honeytokenValue,
          ip,
          path,
          headers: this.sanitizeHeaders(headers),
          timestamp: new Date().toISOString(),
        }),
      },
    });

    // Write a system-wide tampered audit log entry
    await this.auditLog.log(tenantId, 'HONEYTOKEN_COMPROMISED', `honeytoken:${token?.id || 'decoy'}`, {
      ip,
      path,
      incidentId: incident.id,
    });
  }

  private sanitizeHeaders(headers: Record<string, string>): Record<string, string> {
    const clean: Record<string, string> = {};
    const sensitive = ['authorization', 'cookie', 'x-api-key'];
    for (const [k, v] of Object.entries(headers)) {
      if (sensitive.includes(k.toLowerCase())) {
        clean[k] = '[REDACTED]';
      } else {
        clean[k] = v;
      }
    }
    return clean;
  }
}
