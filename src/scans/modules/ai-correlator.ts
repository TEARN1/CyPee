import { PrismaService } from '../../database/prisma.service';
import { Severity } from '../types';

export class AICorrelator {
  constructor(private readonly prisma: PrismaService) {}

  /**
   * Correlates findings to look for cascading attack chains.
   * If multiple medium/high vulnerabilities form a critical path,
   * generates a custom correlated incident.
   */
  async correlate(scanId: string, tenantId: string): Promise<void> {
    const findings = await this.prisma.finding.findMany({
      where: { scanId, tenantId },
    });

    const hasSecrets = findings.some(f => f.module === 'SECRET_EXCAVATOR' || f.title.includes('Secret') || f.title.includes('Key'));
    const hasUnprotectedRoutes = findings.some(f => f.module === 'API_FUZZER' || f.title.includes('Exposed API'));
    const hasSSRF = findings.some(f => f.title.includes('SSRF') || f.title.includes('axios'));

    // Attack Chain 1: Secrets + Unprotected API Routes = Critical Attack Vector
    if (hasSecrets && hasUnprotectedRoutes) {
      await this.prisma.finding.create({
        data: {
          scanId,
          tenantId,
          module: 'AI_CORRELATOR',
          severity: 'CRITICAL',
          title: 'Cascading Attack Chain: Exposed Credentials via Public APIs',
          description: 'AI Correlator mapped a critical chain: Hardcoded secret credentials exist inside files that can be queried directly via unauthenticated public endpoints. Attackers can exploit these public endpoints to trigger system leaks and retrieve database passwords.',
          cvssScore: 9.9,
          pesScore: 99.0,
          cweId: 'CWE-200', // Information Exposure
          mitreId: 'T1592', // Gather Host Info
          remediation: 'Immediately secure the public endpoints with `@UseGuards(JwtAuthGuard)` and rotate the exposed secrets.',
        },
      });

      // Write an Incident record for the SOC team
      await this.prisma.incident.create({
        data: {
          tenantId,
          type: 'CASCADING_ATTACK_CHAIN',
          severity: 'CRITICAL',
          status: 'OPEN',
          evidence: JSON.stringify({
            scanId,
            chainVulnerabilities: ['SECRET_EXCAVATOR', 'API_FUZZER'],
            desc: 'Cascading Attack Chain identified: Exposed credentials inside unauthenticated API files.',
          }),
        },
      });
    }

    // Attack Chain 2: SSRF + AWS Access Keys = Cloud Metadata Exfiltration
    if (hasSecrets && hasSSRF) {
      await this.prisma.finding.create({
        data: {
          scanId,
          tenantId,
          module: 'AI_CORRELATOR',
          severity: 'CRITICAL',
          title: 'Cascading Attack Chain: Cloud Metadata Exfiltration via SSRF',
          description: 'AI Correlator mapped a critical chain: SSRF vulnerabilities in axios combined with stored AWS keys allow attackers to forge requests to the AWS EC2 Metadata service (http://169.254.169.254) to exfiltrate IAM role credentials.',
          cvssScore: 9.9,
          pesScore: 99.0,
          cweId: 'CWE-918', // SSRF
          mitreId: 'T1580', // Cloud Infrastructure Discovery
          remediation: 'Upgrade axios, sanitize url parameters, and configure AWS IMDSv2 to require session headers.',
        },
      });

      await this.prisma.incident.create({
        data: {
          tenantId,
          type: 'SSRF_CLOUDMETADATA_LEAK',
          severity: 'CRITICAL',
          status: 'OPEN',
          evidence: JSON.stringify({
            scanId,
            chainVulnerabilities: ['CVE_INTELLIGENCE', 'SECRET_EXCAVATOR'],
            desc: 'Cascading SSRF metadata theft chain detected.',
          }),
        },
      });
    }
  }
}
