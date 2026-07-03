import { Controller, Get, Post, HttpCode, HttpStatus, Param, Headers, UseGuards } from '@nestjs/common';
import { FindingsRepository } from '../remediation/findings.repository';
import { AutoFixService, AutoFixResult } from '../remediation/auto-fix.service';
import { IEnrichedSastFinding } from './interfaces/finding.interface';

@Controller('api/v1/compliance/findings')
export class FindingsController {
  constructor(
    private readonly findingsRepository: FindingsRepository,
    private readonly autoFixService: AutoFixService,
  ) {}

  @Get()
  public async getFindings(): Promise<IEnrichedSastFinding[]> {
    return this.findingsRepository.findAll();
  }

  @Post('clear')
  @HttpCode(HttpStatus.OK)
  public async clearFindings(): Promise<{ status: string; message: string }> {
    await this.findingsRepository.clear();
    return { status: 'success', message: 'Database findings cleared.' };
  }

  @Post(':id/fix')
  @HttpCode(HttpStatus.OK)
  public async applyFindingFix(
    @Param('id') id: string,
    @Headers('x-tenant-id') tenantIdHeader?: string,
  ): Promise<AutoFixResult> {
    // Fallback to default-dev-tenant-uuid for local development / testing
    const tenantId = tenantIdHeader || 'default-dev-tenant-uuid';
    return this.autoFixService.applyFix(id, tenantId);
  }
}
