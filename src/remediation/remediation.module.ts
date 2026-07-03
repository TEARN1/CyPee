import { Module } from '@nestjs/common';
import { RemediationService } from './remediation.service';
import { FindingsRepository } from './findings.repository';
import { AutoFixService } from './auto-fix.service';

@Module({
  providers: [RemediationService, FindingsRepository, AutoFixService],
  exports: [RemediationService, FindingsRepository, AutoFixService],
})
export class RemediationModule {}
