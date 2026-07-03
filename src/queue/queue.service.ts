import { Injectable, Logger } from '@nestjs/common';
import { InjectQueue } from '@nestjs/bullmq';
import { Queue } from 'bullmq';
import { SAST_QUEUE_NAME, SAST_PARSE_JOB } from './queue.constants';
import { ISastFinding } from '../compliance/interfaces/finding.interface';

@Injectable()
export class QueueService {
  private readonly logger = new Logger(QueueService.name);

  constructor(
    @InjectQueue(SAST_QUEUE_NAME) private readonly sastQueue: Queue,
  ) {}

  /**
   * Pushes a batch of static code analysis findings onto the queue for asynchronous parsing.
   * Prevents API blocking when processing large upload payloads.
   */
  async addFindingsToQueue(findings: ISastFinding[]): Promise<string> {
    this.logger.log(`Enqueuing a batch of ${findings.length} findings.`);
    
    // We can pass the array of findings as the job data
    const job = await this.sastQueue.add(SAST_PARSE_JOB, {
      findings,
    }, {
      attempts: 3,
      backoff: {
        type: 'exponential',
        delay: 5000,
      },
      removeOnComplete: true, // Keep Redis clean
      removeOnFail: false,   // Retain failures for debugging
    });

    this.logger.log(`Successfully enqueued job. Job ID: ${job.id}`);
    return job.id;
  }
}
