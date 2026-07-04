import { Controller, Get, Param, Headers, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../database/prisma.service';
import { ForensicsService, ForensicReport } from '../audit/forensics.service';

@Controller('api/v1/compliance/incidents')
export class IncidentsController {
  constructor(
    private readonly prisma: PrismaService,
    private readonly forensicsService: ForensicsService,
  ) {}

  /**
   * Lists all security incidents logged for the tenant.
   */
  @Get()
  async getIncidents(@Headers('x-tenant-id') tenantIdHeader?: string) {
    const tenantId = tenantIdHeader || 'default-dev-tenant-uuid';
    return this.prisma.incident.findMany({
      where: { tenantId },
      orderBy: { openedAt: 'desc' },
    });
  }

  /**
   * Retrieves a full Diamond Model forensic attribution report for a specific incident.
   */
  @Get(':id/forensics')
  async getForensicReport(
    @Param('id') id: string,
    @Headers('x-tenant-id') tenantIdHeader?: string,
  ): Promise<ForensicReport> {
    const tenantId = tenantIdHeader || 'default-dev-tenant-uuid';
    return this.forensicsService.generateAttributionReport(id, tenantId);
  }
}
