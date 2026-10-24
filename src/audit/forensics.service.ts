import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import * as geoip from 'geoip-lite';
import { PrismaService } from '../database/prisma.service';
import { AuditLogService } from './audit-log.service';
import { MitreAttackService, MitreTechnique } from '../scans/modules/mitre-attack.service';

/**
 * Evidence-based forensic report.
 *
 * Every field here is derived from observed data (request metadata, offline
 * GeoIP, and the cryptographic audit chain) — we deliberately do NOT invent
 * threat-actor names or fabricate a country of origin. `suspectedGroups` is
 * always empty: attributing an incident to a named group requires intelligence
 * this system does not have. `historicalGroupsForTechnique` is contextual MITRE
 * ATT&CK data (groups *historically associated with the technique class*), not a
 * claim about who performed this incident.
 */
export interface ForensicReport {
  incidentId: string;
  type: string;
  severity: string;
  openedAt: string;
  chainIntact: boolean;
  confidence: 'LOW' | 'MEDIUM' | 'HIGH';
  adversary: {
    originCountry: string;
    suspectedGroups: string[];
    historicalGroupsForTechnique: string[];
    note: string;
  };
  capability: {
    mitreTechnique: string;
    techniqueIds: string[];
    description: string;
    threatLevel: string;
  };
  infrastructure: {
    sourceIp: string;
    targetPath: string;
    requestHeaderUserAgent: string;
  };
  victim: {
    tenantId: string;
    targetedZone: string;
    compromisedResources: string[];
  };
  timeline: {
    id: string;
    action: string;
    actorId: string;
    timestamp: string;
    hash: string;
    tamperVerified: boolean;
  }[];
  remediationRecommendation: string;
}

@Injectable()
export class ForensicsService {
  private readonly logger = new Logger(ForensicsService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly auditLog: AuditLogService,
    private readonly mitreService: MitreAttackService,
  ) {}

  /**
   * Generates an evidence-based forensic report for a security incident:
   * maps the incident to MITRE ATT&CK techniques, resolves a real country of
   * origin via offline GeoIP, and verifies the cryptographic integrity of the
   * audit chain. No actor attribution is fabricated.
   */
  async generateAttributionReport(incidentId: string, tenantId: string): Promise<ForensicReport> {
    const incident = await this.prisma.incident.findFirst({
      where: { id: incidentId, tenantId },
    });

    if (!incident) {
      throw new NotFoundException(`Security Incident ${incidentId} not found`);
    }

    const evidence = JSON.parse(incident.evidence || '{}');
    const sourceIp: string = evidence.ip || 'Unknown';
    const targetPath: string = evidence.path || 'Unknown';
    const headers = evidence.headers || {};
    const userAgent: string = headers['user-agent'] || 'Unknown';

    // 1. Map the incident to MITRE ATT&CK techniques (a legitimate, deterministic
    //    mapping — a honeytoken hit really is T1552 "Unsecured Credentials").
    const techniqueIds = this.mapIncidentToTechniques(incident.type);
    const mitreDetails: MitreTechnique[] = [];
    for (const id of techniqueIds) {
      const detail = this.mitreService.getTechniqueDetails(id);
      if (detail) mitreDetails.push(detail);
    }

    // Contextual only: threat groups MITRE historically associates with these
    // techniques. This is NOT an attribution of the current incident.
    const historicalGroups = [
      ...new Set(mitreDetails.flatMap((d) => d.commonThreatGroups)),
    ];

    // 2. Real, offline GeoIP resolution (same geoip-lite dataset the shield uses).
    const originCountry = this.resolveOrigin(sourceIp);

    // 3. Real cryptographic tamper verification of the audit chain.
    const chainResult = await this.auditLog.verifyChainIntegrity(tenantId);

    // 4. Fetch the audit timeline and mark each entry's tamper status honestly.
    const auditLogs = await this.prisma.auditLog.findMany({
      where: { tenantId },
      orderBy: { createdAt: 'asc' },
      take: 25,
    });
    let brokenReached = false;
    const timeline = auditLogs.map((log) => {
      if (!chainResult.intact && log.id === chainResult.brokenAt) brokenReached = true;
      return {
        id: log.id,
        action: log.action,
        actorId: log.actorId || 'SYSTEM',
        timestamp: log.createdAt.toISOString(),
        hash: log.hash,
        tamperVerified: !brokenReached,
      };
    });

    // 5. Confidence is derived from real signals, not asserted.
    const confidence = this.scoreConfidence(incident.type, chainResult.intact);

    const primaryTechnique = mitreDetails[0];

    return {
      incidentId: incident.id,
      type: incident.type,
      severity: incident.severity,
      openedAt: incident.openedAt.toISOString(),
      chainIntact: chainResult.intact,
      confidence,
      adversary: {
        originCountry,
        suspectedGroups: [], // never fabricated
        historicalGroupsForTechnique: historicalGroups,
        note: 'No actor identification is claimed. Origin is a network-level GeoIP estimate of the source IP (often a proxy/VPN/Tor exit) and does not identify a person or group.',
      },
      capability: {
        mitreTechnique: primaryTechnique ? `${primaryTechnique.id} — ${primaryTechnique.name}` : 'Unmapped',
        techniqueIds,
        description: primaryTechnique?.description || 'No MITRE technique mapped for this incident type.',
        threatLevel: incident.severity,
      },
      infrastructure: {
        sourceIp,
        targetPath,
        requestHeaderUserAgent: userAgent,
      },
      victim: {
        tenantId,
        targetedZone:
          incident.type === 'HONEYTOKEN_DECEPTION_TRIGGERED'
            ? `decoy:${evidence.honeytokenValue ? 'credential' : 'endpoint'}`
            : 'public_api_endpoint',
        compromisedResources:
          incident.type === 'HONEYTOKEN_DECEPTION_TRIGGERED'
            ? ['decoy credential (no real asset exposed)']
            : [targetPath],
      },
      timeline,
      remediationRecommendation: this.recommend(incident.type, chainResult.intact),
    };
  }

  private mapIncidentToTechniques(type: string): string[] {
    switch (type) {
      case 'HONEYTOKEN_DECEPTION_TRIGGERED':
        return ['T1552']; // Unsecured Credentials
      case 'CASCADING_ATTACK_CHAIN':
        return ['T1190', 'T1552.001']; // Exploit public app + Credentials in files
      case 'SSRF_CLOUDMETADATA_LEAK':
        return ['T1190', 'T1046']; // Exploit public app + Network service discovery
      default:
        return [];
    }
  }

  /** Offline GeoIP country of the source IP, honestly labelled for loopback. */
  private resolveOrigin(ip: string): string {
    if (ip === '::1' || ip === '127.0.0.1' || ip.startsWith('192.168.') || ip.startsWith('10.')) {
      return 'Local / private network';
    }
    const lookup = geoip.lookup(ip);
    return lookup?.country ? `${lookup.country}${lookup.city ? ` (${lookup.city})` : ''}` : 'Unknown';
  }

  /** Confidence in the *maliciousness* of the event (not in actor identity). */
  private scoreConfidence(type: string, chainIntact: boolean): 'LOW' | 'MEDIUM' | 'HIGH' {
    if (!chainIntact) return 'HIGH'; // audit tampering is itself a strong signal
    if (type === 'HONEYTOKEN_DECEPTION_TRIGGERED') return 'HIGH'; // decoys have no benign use
    if (type === 'CASCADING_ATTACK_CHAIN' || type === 'SSRF_CLOUDMETADATA_LEAK') return 'MEDIUM';
    return 'LOW';
  }

  private recommend(type: string, chainIntact: boolean): string {
    const parts: string[] = [];
    if (!chainIntact) {
      parts.push('Audit chain integrity FAILED — treat the audit log as compromised and preserve the SQLite file for offline analysis.');
    }
    if (type === 'HONEYTOKEN_DECEPTION_TRIGGERED') {
      parts.push('A decoy credential was accessed. Isolate the source IP, rotate any real secrets that share a naming pattern with the decoy, and review recent authentication events.');
    } else {
      parts.push('Review perimeter rules and restrict any exposed endpoints implicated by the source path.');
    }
    return parts.join(' ');
  }
}
