import { Controller, Get, Param, Req, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { PrismaService } from '../database/prisma.service';
import { ForensicsService, ForensicReport } from '../audit/forensics.service';

@Controller('api/v1/compliance/incidents')
@UseGuards(JwtAuthGuard)
export class IncidentsController {
  constructor(
    private readonly prisma: PrismaService,
    private readonly forensicsService: ForensicsService,
  ) {}

  /**
   * Lists all security incidents logged for the tenant.
   */
  @Get()
  async getIncidents(@Req() req: any) {
    return this.prisma.incident.findMany({
      where: { tenantId: req.user.tenantId },
      orderBy: { openedAt: 'desc' },
    });
  }

  /**
   * Retrieves a full Diamond Model forensic attribution report for a specific incident.
   */
  @Get(':id/forensics')
  async getForensicReport(
    @Param('id') id: string,
    @Req() req: any,
  ): Promise<ForensicReport> {
    return this.forensicsService.generateAttributionReport(id, req.user.tenantId);
  }
}
