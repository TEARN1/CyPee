import { Processor, WorkerHost, OnWorkerEvent } from '@nestjs/bullmq';
import { Logger } from '@nestjs/common';
import { Job } from 'bullmq';
import { ScanOrchestrator } from './scan-orchestrator.service';
import { SCAN_QUEUE } from './types';

@Processor(SCAN_QUEUE)
export class ScanWorker extends WorkerHost {
  private readonly logger = new Logger(ScanWorker.name);

  constructor(private readonly orchestrator: ScanOrchestrator) {
    super();
  }

  async process(job: Job<any, any, string>): Promise<any> {
    this.logger.log(`Processing scan job ${job.id} for scan ${job.data.scanId}`);
    
    // Call the orchestrator to run the full scanning pipeline
    await this.orchestrator.run(
      job.data.scanId,
      job.data.tenantId,
      job.data.repositoryUrl,
    );

    return { scanId: job.data.scanId, success: true };
  }

  @OnWorkerEvent('active')
  onActive(job: Job) {
    this.logger.log(`Scan job ${job.id} has become active`);
  }

  @OnWorkerEvent('completed')
  onCompleted(job: Job, result: any) {
    this.logger.log(`Scan job ${job.id} completed. Result: ${JSON.stringify(result)}`);
  }

  @OnWorkerEvent('failed')
  onFailed(job: Job, error: Error) {
    this.logger.error(`Scan job ${job.id} failed with error: ${error.message}`, error.stack);
  }
}
