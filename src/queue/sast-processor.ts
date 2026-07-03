import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Logger } from '@nestjs/common';
import { Job } from 'bullmq';
import { SAST_QUEUE_NAME, SAST_PARSE_JOB } from './queue.constants';
import { RemediationService } from '../remediation/remediation.service';
import { FindingsRepository } from '../remediation/findings.repository';
import { ISastFinding, IEnrichedSastFinding } from '../compliance/interfaces/finding.interface';

@Processor(SAST_QUEUE_NAME)
export class SastProcessor extends WorkerHost {
  private readonly logger = new Logger(SastProcessor.name);

  constructor(
    private readonly remediationService: RemediationService,
    private readonly findingsRepository: FindingsRepository,
  ) {
    super();
  }

  /**
   * Worker handler executed in the background process.
   * Processes large static analysis reports asynchronously.
   */
  async process(job: Job<any, any, string>): Promise<IEnrichedSastFinding[]> {
    this.logger.log(`Background processing started for Job ID: ${job.id}`);

    if (job.name !== SAST_PARSE_JOB) {
      this.logger.warn(`Unknown job name found in queue: ${job.name}`);
      return [];
    }

    const findings: ISastFinding[] = job.data?.findings || [];
    this.logger.log(`Processing ${findings.length} findings in background worker.`);

    const enrichedFindings: IEnrichedSastFinding[] = [];

    for (let i = 0; i < findings.length; i++) {
      const finding = findings[i];
      try {
        // Log progress every 10 findings or at the start/end
        if (i % 10 === 0 || i === findings.length - 1) {
          this.logger.log(`Enriching finding ${i + 1}/${findings.length}`);
        }

        // Sanitize file path to prevent directory traversal
        const sanitizedPath = this.sanitizePath(finding.filePath);

        // Generate remediation Markdown
        const remediationGuide = this.remediationService.generateRemediationMarkdown(
          finding.ruleId,
          finding.severity,
        );

        const enriched: IEnrichedSastFinding = {
          ...finding,
          filePath: sanitizedPath,
          remediationGuide,
          processedAt: new Date(),
        };

        // Persist vulnerability directly to SQLite database
        await this.saveFindingToDatabase(enriched);

        enrichedFindings.push(enriched);
      } catch (error) {
        this.logger.error(
          `Failed to process finding at ${finding.filePath}:${finding.lineNumber}. Error: ${error.message}`,
        );
      }
    }

    // Update job progress to 100%
    await job.updateProgress(100);

    this.logger.log(`Background processing completed for Job ID: ${job.id}. Mapped ${enrichedFindings.length} findings.`);
    return enrichedFindings;
  }

  /**
   * Sanitizes paths to prevent directory traversal / path traversal attacks.
   */
  private sanitizePath(filePath: string): string {
    const normalized = filePath.replace(/\\/g, '/');
    if (normalized.includes('..') || normalized.startsWith('/') || normalized.includes(':')) {
      throw new Error(`Directory traversal attempt or absolute path detected: "${filePath}"`);
    }
    return normalized;
  }

  /**
   * Database persistence.
   * Calls the asynchronous repository to store the finding in dev.db.
   */
  private async saveFindingToDatabase(finding: IEnrichedSastFinding): Promise<void> {
    await this.findingsRepository.save(finding);
    this.logger.debug(
      `[DATABASE SAVE] Persisted vulnerability: [${finding.severity}] ${finding.ruleId} at ${finding.filePath}:${finding.lineNumber}`,
    );
  }
}
