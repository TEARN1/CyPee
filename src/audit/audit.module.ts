import { Module, Global, forwardRef } from '@nestjs/common';
import { AuditLogService } from './audit-log.service';
import { ForensicsService } from './forensics.service';
import { ScansModule } from '../scans/scans.module';

@Global()
@Module({
  imports: [forwardRef(() => ScansModule)],
  providers: [AuditLogService, ForensicsService],
  exports: [AuditLogService, ForensicsService],
})
export class AuditModule {}
