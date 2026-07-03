import { Injectable, Logger } from '@nestjs/common';
import { IEnrichedSastFinding, SeverityLevel } from '../compliance/interfaces/finding.interface';
import { PrismaService } from '../database/prisma.service';

@Injectable()
export class FindingsRepository {
  private readonly logger = new Logger(FindingsRepository.name);
  
  constructor(private readonly prisma: PrismaService) {}

  public async save(finding: IEnrichedSastFinding): Promise<void> {
    try {
      const defaultTenantId = 'default-dev-tenant-uuid';
      
      // Get the latest scan or create a default dev scan reference
      let latestScan = await this.prisma.scan.findFirst({
        where: { tenantId: defaultTenantId },
        orderBy: { startedAt: 'desc' },
      });

      if (!latestScan) {
        latestScan = await this.prisma.scan.create({
          data: {
            tenantId: defaultTenantId,
            state: 'COMPLETE',
          },
        });
      }

      // Check if duplicate exists
      const duplicate = await this.prisma.finding.findFirst({
        where: {
          tenantId: defaultTenantId,
          scanId: latestScan.id,
          filePath: finding.filePath,
          lineNumber: finding.lineNumber,
          title: finding.ruleId,
        },
      });

      if (!duplicate) {
        await this.prisma.finding.create({
          data: {
            scanId: latestScan.id,
            tenantId: defaultTenantId,
            module: 'MANUAL_INGESTION',
            severity: finding.severity,
            title: finding.ruleId,
            description: finding.message ?? 'Ingested vulnerability.',
            cweId: finding.ruleId,
            filePath: finding.filePath,
            lineNumber: finding.lineNumber,
            remediation: finding.remediationGuide ?? 'Fix root cause.',
            cvssScore: finding.severity === 'CRITICAL' ? 9.8 : finding.severity === 'HIGH' ? 8.2 : 5.0,
          },
        });
      }
    } catch (err) {
      this.logger.error('Failed to save finding to database:', err);
    }
  }

  public async findAll(): Promise<IEnrichedSastFinding[]> {
    try {
      const defaultTenantId = 'default-dev-tenant-uuid';
      const dbFindings = await this.prisma.finding.findMany({
        where: { tenantId: defaultTenantId },
        orderBy: { createdAt: 'desc' },
      });

      return dbFindings.map((f) => ({
        id: f.id,
        filePath: f.filePath ?? 'Unknown',
        lineNumber: f.lineNumber ?? 0,
        ruleId: f.title, // ruleId maps to title (CWE_ID / Rule)
        severity: f.severity as SeverityLevel,
        message: f.description,
        remediationGuide: f.remediation ?? undefined,
        processedAt: f.createdAt,
      }));
    } catch (err) {
      this.logger.error('Failed to query findings from database:', err);
      return [];
    }
  }

  public async clear(): Promise<void> {
    try {
      const defaultTenantId = 'default-dev-tenant-uuid';
      await this.prisma.finding.deleteMany({
        where: { tenantId: defaultTenantId },
      });
    } catch (err) {
      this.logger.error('Failed to clear findings from database:', err);
    }
  }
}
