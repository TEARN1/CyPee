import { Controller, Post, Body, HttpCode, HttpStatus, UsePipes, ValidationPipe, UseGuards } from '@nestjs/common';
import { ComplianceService } from './compliance.service';
import { UploadReportDto } from './dto/upload-report.dto';
import { Ed25519SignatureGuard } from './guards/ed25519-signature.guard';

@Controller('api/v1/compliance')
@UseGuards(Ed25519SignatureGuard)
export class ComplianceController {
  constructor(private readonly complianceService: ComplianceService) {}

  /**
   * Endpoint to upload standardized static code analysis outputs (JSON reports).
   * Validates target properties (filePath, lineNumber, ruleId, severity) using ValidationPipe.
   * Offloads parsing to worker threads/background queue.
   */
  @Post('upload')
  @HttpCode(HttpStatus.ACCEPTED)
  @UsePipes(new ValidationPipe({ 
    transform: true,          // Automatically transform payloads to DTO instances
    whitelist: true,          // Strip out non-declared fields from payload for security
    forbidNonWhitelisted: true // Reject requests containing extra properties
  }))
  async uploadSastReport(@Body() uploadReportDto: UploadReportDto) {
    return this.complianceService.handleReportUpload(uploadReportDto);
  }
}
