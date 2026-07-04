import { Injectable, Logger } from '@nestjs/common';
import { Queue } from 'bullmq';
import { ScanOrchestrator } from './scan-orchestrator.service';

const MOCK_QUEUE_CONCURRENCY = parseInt(process.env.SCAN_MOCK_CONCURRENCY || '2', 10);

@Injectable()
export class ScanQueueService {
  private readonly logger = new Logger(ScanQueueService.name);
  private queue: Queue | null = null;

  // Bounds concurrent scan execution in mock mode (no Redis/BullMQ), since each
  // scan clones a real repo and runs semgrep — unbounded parallelism here would
  // let a burst of scan requests exhaust CPU/disk/network on this process.
  private mockRunning = 0;
  private readonly mockPending: Array<() => void> = [];

  constructor(private readonly orchestrator: ScanOrchestrator) {}

  setQueue(queue: Queue) {
    this.queue = queue;
  }

  async addScanJob(scanId: string, tenantId: string, repositoryUrl: string): Promise<string> {
    const jobId = `scan-job-${scanId}`;

    if (process.env.REDIS_MOCK === 'true') {
      this.logger.log(`[MOCK QUEUE] Enqueued scan job ${jobId} (in-memory execution, concurrency=${MOCK_QUEUE_CONCURRENCY})`);
      setImmediate(() => this.runWithMockConcurrencyLimit(jobId, scanId, tenantId, repositoryUrl));
      return jobId;
    }

    if (!this.queue) {
      throw new Error('BullMQ queue is not initialized. Cannot enqueue scan job.');
    }

    await this.queue.add(
      'execute-scan',
      { scanId, tenantId, repositoryUrl },
      {
        attempts: 3,
        backoff: { type: 'exponential', delay: 5000 },
        removeOnComplete: { count: 100 },
        removeOnFail: { count: 1000 },
      },
    );

    return jobId;
  }

  private async runWithMockConcurrencyLimit(jobId: string, scanId: string, tenantId: string, repositoryUrl: string): Promise<void> {
    if (this.mockRunning >= MOCK_QUEUE_CONCURRENCY) {
      await new Promise<void>((resolve) => this.mockPending.push(resolve));
    }

    this.mockRunning++;
    try {
      this.logger.log(`[MOCK QUEUE] Starting execution of job ${jobId} (${this.mockRunning}/${MOCK_QUEUE_CONCURRENCY} running)`);
      await this.orchestrator.run(scanId, tenantId, repositoryUrl);
    } catch (err: any) {
      this.logger.error(`[MOCK QUEUE] Job ${jobId} failed: ${err.message}`);
    } finally {
      this.mockRunning--;
      const next = this.mockPending.shift();
      if (next) next();
    }
  }
}
