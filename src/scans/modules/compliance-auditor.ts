import { PrismaService } from '../../database/prisma.service';
import { Severity } from '../types';

export interface ComplianceMapping {
  standard: 'SOC2' | 'PCI' | 'ISO27001' | 'NIST' | 'GDPR';
  control: string;
  requirement: string;
}

export class ComplianceAuditor {
  constructor(private readonly prisma: PrismaService) {}

  /**
   * Evaluates findings of a scan and maps them to key global compliance standards.
   *
   * This is a heuristic pass/fail check based on finding severity counts — it is NOT
   * a cryptographic proof, audit, or certification. It must never be represented to
   * users as a SOC2/PCI/ISO27001/NIST/GDPR certificate; it is a starting point for a
   * human auditor, nothing more.
   */
  async audit(scanId: string, tenantId: string): Promise<void> {
    const findings = await this.prisma.finding.findMany({
      where: { scanId, tenantId },
    });

    const hasCritical = findings.some((f) => f.severity === 'CRITICAL');
    const hasHigh = findings.some((f) => f.severity === 'HIGH');

    const standards: ('SOC2' | 'PCI' | 'ISO27001' | 'NIST' | 'GDPR')[] = [
      'SOC2', 'PCI', 'ISO27001', 'NIST', 'GDPR'
    ];

    for (const std of standards) {
      let passed = true;
      let detailMsg = '';

      if (std === 'PCI' && (hasCritical || hasHigh)) {
        passed = false;
        detailMsg = 'Heuristic check against Requirement 6.2 (remediation of high-risk vulnerabilities) found unresolved high/critical findings.';
      } else if (std === 'SOC2' && hasCritical) {
        passed = false;
        detailMsg = 'Heuristic check against Trust Services Criteria CC7.1 found unresolved critical findings.';
      } else {
        detailMsg = `No findings above the threshold configured for this heuristic ${std} check.`;
      }

      await this.prisma.zKCertificate.create({
        data: {
          scanId,
          tenantId,
          standard: std,
          proof: JSON.stringify({
            kind: 'heuristic-compliance-mapping',
            disclaimer: 'Not a cryptographic proof, audit, or certification. Automated heuristic only.',
            status: passed ? 'PASSED' : 'FAILED',
            details: detailMsg,
            generatedAt: new Date().toISOString(),
          }),
          publicInput: JSON.stringify({
            scanId,
            findingsCount: findings.length,
            criticalCount: findings.filter(f => f.severity === 'CRITICAL').length,
            highCount: findings.filter(f => f.severity === 'HIGH').length,
            compliancePassed: passed ? '1' : '0',
          }),
        },
      });
    }
  }
}
