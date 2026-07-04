import { Controller, Get, Post, HttpCode, HttpStatus, Param, Req, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { FindingsRepository } from '../remediation/findings.repository';
import { AutoFixService, AutoFixResult } from '../remediation/auto-fix.service';
import { IEnrichedSastFinding } from './interfaces/finding.interface';

@Controller('api/v1/compliance/findings')
@UseGuards(JwtAuthGuard)
export class FindingsController {
  constructor(
    private readonly findingsRepository: FindingsRepository,
    private readonly autoFixService: AutoFixService,
  ) {}

  @Get()
  public async getFindings(@Req() req: any): Promise<IEnrichedSastFinding[]> {
    return this.findingsRepository.findAll(req.user.tenantId);
  }

  @Post('clear')
  @HttpCode(HttpStatus.OK)
  public async clearFindings(@Req() req: any): Promise<{ status: string; message: string }> {
    await this.findingsRepository.clear(req.user.tenantId);
    return { status: 'success', message: 'Database findings cleared.' };
  }

  @Post(':id/fix')
  @HttpCode(HttpStatus.OK)
  public async applyFindingFix(
    @Param('id') id: string,
    @Req() req: any,
  ): Promise<AutoFixResult> {
    return this.autoFixService.applyFix(id, req.user.tenantId);
  }
}
