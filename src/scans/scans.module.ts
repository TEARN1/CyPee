import { Module, OnModuleInit } from '@nestjs/common';
import { ModuleRef } from '@nestjs/core';
import { BullModule, getQueueToken } from '@nestjs/bullmq';
import { ScansController } from './scans.controller';
import { ScansService } from './scans.service';
import { ScanOrchestrator } from './scan-orchestrator.service';
import { ScanWorker } from './scan.worker';
import { ScanEventBus } from './scan-event-bus.service';
import { ScanQueueService } from './scan-queue.service';
import { MitreAttackService } from './modules/mitre-attack.service';
import { SCAN_QUEUE } from './types';

const useMock = process.env.REDIS_MOCK === 'true';

const imports: any[] = [];
const providers: any[] = [
  ScansService,
  ScanOrchestrator,
  ScanEventBus,
  ScanQueueService,
  MitreAttackService,
];

if (!useMock) {
  imports.push(
    BullModule.registerQueue({
      name: SCAN_QUEUE,
    }),
  );
  providers.push(ScanWorker);
}

@Module({
  imports,
  controllers: [ScansController],
  providers,
  exports: [ScansService, ScanEventBus, ScanQueueService, MitreAttackService],
})
export class ScansModule implements OnModuleInit {
  constructor(
    private readonly moduleRef: ModuleRef,
    private readonly queueService: ScanQueueService,
  ) {}

  onModuleInit() {
    if (process.env.REDIS_MOCK !== 'true') {
      try {
        const queue = this.moduleRef.get(getQueueToken(SCAN_QUEUE), { strict: false });
        this.queueService.setQueue(queue);
      } catch (err) {
        // Fallback if queue not registered
      }
    }
  }
}
