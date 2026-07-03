import { Module } from '@nestjs/common';
import { ComplianceController } from './compliance.controller';
import { FindingsController } from './findings.controller';
import { ComplianceService } from './compliance.service';
import { QueueModule } from '../queue/queue.module';
import { RemediationModule } from '../remediation/remediation.module';

@Module({
  imports: [QueueModule, RemediationModule],
  controllers: [ComplianceController, FindingsController],
  providers: [ComplianceService],
})
export class ComplianceModule {}
