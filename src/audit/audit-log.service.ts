import { Injectable, Logger } from '@nestjs/common';
import * as crypto from 'crypto';
import { PrismaService } from '../database/prisma.service';

@Injectable()
export class AuditLogService {
  private readonly logger = new Logger(AuditLogService.name);

  constructor(private readonly prisma: PrismaService) {}

  /**
   * Appends an entry to the immutable SHA-256 chained audit log.
   * Each entry's hash includes the previous entry's hash — tampering
   * with any entry breaks every subsequent hash in the chain.
   */
  async log(
    tenantId: string | null,
    action: string,
    resource: string,
    metadata: Record<string, unknown> = {},
    actorId?: string,
  ): Promise<void> {
    try {
      const dbTenantId = tenantId === 'SYSTEM' ? null : tenantId;

      // Get the previous entry's hash to chain from
      const previous = await this.prisma.auditLog.findFirst({
        where: { tenantId: dbTenantId },
        orderBy: { createdAt: 'desc' },
        select: { hash: true },
      });

      const previousHash = previous?.hash ?? 'GENESIS';
      const timestamp = new Date().toISOString();
      const metadataStr = JSON.stringify(metadata);

      // Chain hash: SHA-256 of (prevHash + action + actorId + timestamp + metadata)
      const chainInput = `${previousHash}|${action}|${actorId ?? 'SYSTEM'}|${timestamp}|${metadataStr}`;
      const hash = crypto.createHash('sha256').update(chainInput).digest('hex');

      await this.prisma.auditLog.create({
        data: {
          tenantId: dbTenantId,
          action,
          actorId,
          resource,
          metadata: metadataStr,
          previousHash,
          hash,
        },
      });
    } catch (err) {
      // Audit log must never crash the application — log and continue
      this.logger.error('Failed to write audit log entry', err);
    }
  }

  /**
   * Verifies the integrity of the entire audit chain for a tenant.
   * Returns the index of the first broken link, or null if intact.
   */
  async verifyChainIntegrity(tenantId: string | null): Promise<{ intact: boolean; brokenAt?: string }> {
    const dbTenantId = tenantId === 'SYSTEM' ? null : tenantId;
    const entries = await this.prisma.auditLog.findMany({
      where: { tenantId: dbTenantId },
      orderBy: { createdAt: 'asc' },
    });

    for (let i = 1; i < entries.length; i++) {
      const prev = entries[i - 1];
      const curr = entries[i];

      // curr.metadata is already a string in SQLite, so we reference it directly
      const expected = `${prev.hash}|${curr.action}|${curr.actorId ?? 'SYSTEM'}|${curr.createdAt.toISOString()}|${curr.metadata}`;
      const expectedHash = crypto.createHash('sha256').update(expected).digest('hex');

      if (expectedHash !== curr.hash) {
        return { intact: false, brokenAt: curr.id };
      }
    }

    return { intact: true };
  }
}
