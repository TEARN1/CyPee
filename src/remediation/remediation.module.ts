import { Module } from '@nestjs/common';
import { RemediationService } from './remediation.service';
import { FindingsRepository } from './findings.repository';
import { AutoFixService } from './auto-fix.service';
import { AstAutoPatchService } from './ast-autopatch.service';
import { AstAutoPatchController } from './ast-autopatch.controller';

@Module({
  controllers: [AstAutoPatchController],
  providers: [RemediationService, FindingsRepository, AutoFixService, AstAutoPatchService],
  exports: [RemediationService, FindingsRepository, AutoFixService, AstAutoPatchService],
})
export class RemediationModule {}
