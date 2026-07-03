import { Module, Provider, Logger } from '@nestjs/common';
import { BullModule } from '@nestjs/bullmq';
import { ConfigModule } from '@nestjs/config';
import { QueueService } from './queue.service';
import { SastProcessor } from './sast-processor';
import { RemediationModule } from '../remediation/remediation.module';
import { SAST_QUEUE_NAME } from './queue.constants';
import * as dotenv from 'dotenv';
import * as path from 'path';

// Pre-load environment variables synchronously before NestJS class decorator evaluation
dotenv.config({ path: path.resolve(process.cwd(), '.env') });

const useMock = process.env.REDIS_MOCK === 'true';

const imports: any[] = [
  ConfigModule,
  RemediationModule,
];

const providers: Provider[] = [SastProcessor];

if (!useMock) {
  // Production Mode: Bind to real Redis and BullMQ
  imports.push(
    BullModule.registerQueue({
      name: SAST_QUEUE_NAME,
    }),
  );
  providers.push(QueueService);
} else {
  // Local Mock Mode: In-memory simulation of queue processing.
  // Completely database-less and does not require a running Redis instance.
  providers.push({
    provide: QueueService,
    useFactory: (sastProcessor: SastProcessor) => {
      const logger = new Logger('MockQueueService');
      
      return {
        async addFindingsToQueue(findings: any[]): Promise<string> {
          const jobId = `mock-job-${Math.random().toString(36).substring(2, 9)}`;
          logger.log(`[MOCK QUEUE] Received batch of ${findings.length} findings. Enqueued as job ${jobId}`);

          // Trigger background processing asynchronously on the Node.js event loop macro-task
          setImmediate(async () => {
            try {
              const mockJob = {
                id: jobId,
                name: 'parse-findings',
                data: { findings },
                updateProgress: async (progress: number) => {
                  logger.log(`[MOCK QUEUE] Job ${jobId} progress updated to ${progress}%`);
                },
              };
              await sastProcessor.process(mockJob as any);
            } catch (err) {
              logger.error(`[MOCK QUEUE] Job ${jobId} processing failed: ${err.message}`);
            }
          });

          return jobId;
        },
      };
    },
    inject: [SastProcessor],
  });
}

@Module({
  imports,
  providers,
  exports: [QueueService],
})
export class QueueModule {}
