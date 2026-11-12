import { Module } from '@nestjs/common';
import { ComplianceController } from './compliance.controller';
import { FindingsController } from './findings.controller';
import { HealthController } from './health.controller';
import { IncidentsController } from './incidents.controller';
import { SecurityLogicsController } from './security-logics.controller';
import { ComplianceService } from './compliance.service';
import { SecurityLogicsService } from './security-logics.service';
import { QueueModule } from '../queue/queue.module';
import { RemediationModule } from '../remediation/remediation.module';

@Module({
  imports: [QueueModule, RemediationModule],
  controllers: [
    ComplianceController,
    FindingsController,
    HealthController,
    IncidentsController,
    SecurityLogicsController,
  ],
  providers: [ComplianceService, SecurityLogicsService],
  exports: [SecurityLogicsService],
})
export class ComplianceModule {}
