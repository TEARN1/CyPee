import { Controller, Post, Get, Param, Query, Sse, Body, Req } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiParam, ApiQuery } from '@nestjs/swagger';
import { ScansService } from './scans.service';
import { CreateScanDto, GetScanParamsDto } from './dto/scan.dto';
import { ScanEventBus } from './scan-event-bus.service';
import { Observable } from 'rxjs';

@ApiTags('Scans')
@Controller('api/v1/scans')
export class ScansController {
  constructor(
    private readonly scansService: ScansService,
    private readonly eventBus: ScanEventBus,
  ) {}

  @Post()
  @ApiOperation({ summary: 'Trigger a new asynchronous vulnerability scan' })
  @ApiResponse({ status: 201, description: 'Scan authorized and enqueued.' })
  async create(@Body() dto: CreateScanDto, @Req() req: any) {
    const tenantId = req.tenantId ?? 'default-dev-tenant-uuid';
    const actorId = req.userId ?? 'default-dev-user-uuid';
    return this.scansService.create(dto, tenantId, actorId);
  }

  @Get()
  @ApiOperation({ summary: 'List all scans for the current tenant' })
  @ApiQuery({ name: 'page', required: false, type: Number })
  @ApiQuery({ name: 'limit', required: false, type: Number })
  async list(
    @Query('page') page: string | undefined,
    @Query('limit') limit: string | undefined,
    @Req() req: any,
  ) {
    const tenantId = req.tenantId ?? 'default-dev-tenant-uuid';
    const p = page ? parseInt(page, 10) : 1;
    const l = limit ? parseInt(limit, 10) : 20;
    return this.scansService.listForTenant(tenantId, p, l);
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get details and state of a specific scan' })
  @ApiParam({ name: 'id', type: String, description: 'Scan UUID' })
  async findOne(@Param() params: GetScanParamsDto, @Req() req: any) {
    const tenantId = req.tenantId ?? 'default-dev-tenant-uuid';
    return this.scansService.findById(params.id, tenantId);
  }

  @Get(':id/findings')
  @ApiOperation({ summary: 'Get findings of a specific scan' })
  @ApiParam({ name: 'id', type: String, description: 'Scan UUID' })
  @ApiQuery({ name: 'severity', required: false, type: String })
  async getFindings(
    @Param() params: GetScanParamsDto,
    @Query('severity') severity: string | undefined,
    @Req() req: any,
  ) {
    const tenantId = req.tenantId ?? 'default-dev-tenant-uuid';
    return this.scansService.getFindings(params.id, tenantId, { severity });
  }

  @Sse(':id/stream')
  @ApiOperation({ summary: 'Server-Sent Events stream for live telemetry' })
  @ApiParam({ name: 'id', type: String, description: 'Scan UUID' })
  stream(@Param() params: GetScanParamsDto): Observable<MessageEvent> {
    return this.eventBus.getObservable(params.id);
  }
}
