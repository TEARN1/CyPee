import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { execFile } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { PrismaService } from '../database/prisma.service';
import { ScanEventBus } from './scan-event-bus.service';
import { AuditLogService } from '../audit/audit-log.service';
import { assertValidTransition } from './scan-state.machine';
import { ScanState, Severity } from './types';

const execFileAsync = promisify(execFile);

// Import real scanning engines
import { SecretExcavator } from './modules/secret-excavator';
import { IaCSecurity } from './modules/iac-security';
import { CVEIntelligence } from './modules/cve-intelligence';
import { SupplyChainIntegrity } from './modules/supply-chain';
import { AuthGuardAuditor } from './modules/api-fuzzer';
import { SemgrepScanner } from './modules/semgrep-scanner';
import { ComplianceAuditor } from './modules/compliance-auditor';
import { FindingCorrelator } from './modules/ai-correlator';

@Injectable()
export class ScanOrchestrator {
  private readonly logger = new Logger(ScanOrchestrator.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly eventBus: ScanEventBus,
    private readonly auditLog: AuditLogService,
  ) {}

  /**
   * Transition scan state directly inside the orchestrator.
   */
  private async transition(scanId: string, newState: ScanState, tenantId: string): Promise<void> {
    const scan = await this.prisma.scan.findFirst({ where: { id: scanId, tenantId } });
    if (!scan) throw new NotFoundException(`Scan ${scanId} not found`);

    assertValidTransition(scan.state as ScanState, newState);

    await this.prisma.scan.update({
      where: { id: scanId },
      data: {
        state: newState,
        ...(newState === 'COMPLETE' ? { completedAt: new Date() } : {}),
      },
    });

    await this.auditLog.log(tenantId, 'SCAN_STATE_CHANGED', `scan:${scanId}`, {
      from: scan.state,
      to: newState,
    });
  }

  /**
   * Runs the scanning pipeline, coordinating parallel scan modules,
   * state machine updates, and SSE events.
   */
  async run(scanId: string, tenantId: string, repositoryUrl: string): Promise<void> {
    let workspacePath: string | null = null;
    try {
      this.logger.log(`Starting scan orchestrator for scan ${scanId}`);

      // 1. Transition: AUTHORIZED -> PROVISIONING
      await this.transition(scanId, 'PROVISIONING', tenantId);
      this.eventBus.emit(scanId, {
        type: 'module_start',
        module: 'PROVISIONING',
        message: 'Cloning target repository into an isolated workspace...',
      });

      workspacePath = await this.cloneRepository(scanId, repositoryUrl);
      this.logger.log(`Scan ${scanId}: cloned ${repositoryUrl} into ${workspacePath}`);

      // 2. Transition: PROVISIONING -> SCANNING
      await this.transition(scanId, 'SCANNING', tenantId);

      // Initialize all five scanners
      const secretExcavator = new SecretExcavator();
      const iacSecurity = new IaCSecurity();
      const cveIntelligence = new CVEIntelligence();
      const supplyChain = new SupplyChainIntegrity();
      const authGuardAuditor = new AuthGuardAuditor();
      const semgrepScanner = new SemgrepScanner();
      const scanTargetPath = workspacePath;

      const modules = [
        { name: 'SECRET_EXCAVATOR', runner: () => secretExcavator.scan(scanTargetPath), progress: 20 },
        { name: 'IaC_SECURITY', runner: () => iacSecurity.scan(scanTargetPath), progress: 40 },
        { name: 'CVE_INTELLIGENCE', runner: () => cveIntelligence.scan(scanTargetPath), progress: 60 },
        { name: 'SUPPLY_CHAIN', runner: () => supplyChain.scan(scanTargetPath), progress: 80 },
        { name: 'AUTH_GUARD_AUDIT', runner: () => authGuardAuditor.scan(scanTargetPath), progress: 90 },
        { name: 'SEMGREP_SAST', runner: () => semgrepScanner.scan(scanTargetPath), progress: 100 },
      ];

      await Promise.all(
        modules.map(async (mod) => {
          this.eventBus.emit(scanId, {
            type: 'module_start',
            module: mod.name,
            message: `Starting analysis module: ${mod.name}`,
          });

          // Run actual scan findings search
          const findings = await mod.runner();

          for (const f of findings) {
            // Write finding to database
            const saved = await this.prisma.finding.create({
              data: {
                scanId,
                tenantId,
                module: mod.name,
                severity: f.severity as Severity,
                title: f.title,
                description: f.description,
                cvssScore: f.cvssScore,
                pesScore: f.pesScore,
                cweId: f.cweId,
                mitreId: f.mitreId,
                filePath: f.filePath,
                lineNumber: f.lineNumber,
                remediation: f.remediation,
              },
            });

            // Emit live SSE finding update
            this.eventBus.emit(scanId, {
              type: 'finding',
              module: mod.name,
              finding: {
                id: saved.id,
                severity: saved.severity,
                title: saved.title,
                filePath: saved.filePath || undefined,
                lineNumber: saved.lineNumber || undefined,
              },
              message: `Vulnerability identified in ${mod.name}: [${saved.severity}] ${saved.title}`,
            });
          }

          // Emit module complete event
          this.eventBus.emit(scanId, {
            type: 'module_complete',
            module: mod.name,
            progress: mod.progress,
            message: `Completed analysis module: ${mod.name}. Discovered ${findings.length} findings.`,
          });
        }),
      );

      // 3. Transition: SCANNING -> CORRELATING
      await this.transition(scanId, 'CORRELATING', tenantId);
      this.eventBus.emit(scanId, {
        type: 'module_start',
        module: 'RISK_CORRELATION',
        message: 'Running rule-based cascading risk correlator...',
      });
      const correlator = new FindingCorrelator(this.prisma);
      await correlator.correlate(scanId, tenantId);
      await this.sleep(1000);

      // 4. Transition: CORRELATING -> REPORTING
      await this.transition(scanId, 'REPORTING', tenantId);
      this.eventBus.emit(scanId, {
        type: 'module_start',
        module: 'REPORT_GENERATION',
        message: 'Generating heuristic compliance mapping reports...',
      });
      const auditor = new ComplianceAuditor(this.prisma);
      await auditor.audit(scanId, tenantId);
      await this.sleep(1000);

      // Calculate final posture score
      const findingsCount = await this.prisma.finding.count({ where: { scanId } });
      const postureScore = Math.max(100 - findingsCount * 12, 10);

      await this.prisma.scan.update({
        where: { id: scanId },
        data: { postureScore },
      });

      // 5. Transition: REPORTING -> COMPLETE
      await this.transition(scanId, 'COMPLETE', tenantId);
      this.eventBus.emit(scanId, {
        type: 'complete',
        postureScore,
        totalFindings: findingsCount,
        message: 'Vulnerability scan completed successfully.',
      });

      this.eventBus.complete(scanId);
      this.logger.log(`Scan ${scanId} execution successfully completed`);
    } catch (error) {
      this.logger.error(`Scan ${scanId} failed:`, error);
      await this.prisma.scan.update({
        where: { id: scanId },
        data: { state: 'FAILED' },
      }).catch(() => {});

      this.eventBus.emit(scanId, {
        type: 'failed',
        message: `Scan execution failed: ${error.message}`,
      });
      this.eventBus.complete(scanId);
    } finally {
      if (workspacePath) {
        await fs.promises.rm(workspacePath, { recursive: true, force: true }).catch((err) => {
          this.logger.warn(`Failed to clean up scan workspace ${workspacePath}: ${err.message}`);
        });
      }
    }
  }

  /**
   * Clones the target repository into an isolated per-scan temp directory
   * so scans operate on the customer's actual code, not this server's own
   * source tree. The directory is removed in a finally block regardless of
   * scan outcome.
   */
  private async cloneRepository(scanId: string, repositoryUrl: string): Promise<string> {
    const workspacePath = path.join(os.tmpdir(), `shield-scan-${scanId}`);
    await fs.promises.rm(workspacePath, { recursive: true, force: true }).catch(() => {});
    await fs.promises.mkdir(workspacePath, { recursive: true });

    try {
      await execFileAsync('git', ['clone', '--depth', '50', '--', repositoryUrl, workspacePath], {
        timeout: 3 * 60 * 1000,
        maxBuffer: 20 * 1024 * 1024,
      });
    } catch (error: any) {
      throw new Error(`Failed to clone repository ${repositoryUrl}: ${error.message}`);
    }

    return workspacePath;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
