import { Injectable, Logger } from '@nestjs/common';
import { Queue } from 'bullmq';
import { ScanOrchestrator } from './scan-orchestrator.service';

@Injectable()
export class ScanQueueService {
  private readonly logger = new Logger(ScanQueueService.name);
  private queue: Queue | null = null;

  constructor(private readonly orchestrator: ScanOrchestrator) {}

  setQueue(queue: Queue) {
    this.queue = queue;
  }

  async addScanJob(scanId: string, tenantId: string, repositoryUrl: string): Promise<string> {
    const jobId = `scan-job-${scanId}`;

    if (process.env.REDIS_MOCK === 'true') {
      this.logger.log(`[MOCK QUEUE] Enqueued scan job ${jobId} (in-memory execution)`);
      
      // Execute asynchronously on Node macro-task queue
      setImmediate(async () => {
        try {
          this.logger.log(`[MOCK QUEUE] Starting execution of job ${jobId}`);
          await this.orchestrator.run(scanId, tenantId, repositoryUrl);
        } catch (err) {
          this.logger.error(`[MOCK QUEUE] Job ${jobId} failed: ${err.message}`);
        }
      });

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
}
