import { Controller, Post, Get, Param, Query, Sse, Body, Req, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiParam, ApiQuery, ApiBearerAuth } from '@nestjs/swagger';
import { ScansService } from './scans.service';
import { CreateScanDto, GetScanParamsDto } from './dto/scan.dto';
import { ScanEventBus } from './scan-event-bus.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { Observable } from 'rxjs';

@ApiTags('Scans')
@ApiBearerAuth()
@Controller('api/v1/scans')
@UseGuards(JwtAuthGuard)
export class ScansController {
  constructor(
    private readonly scansService: ScansService,
    private readonly eventBus: ScanEventBus,
  ) {}

  @Post()
  @ApiOperation({ summary: 'Trigger a new asynchronous vulnerability scan' })
  @ApiResponse({ status: 201, description: 'Scan authorized and enqueued.' })
  async create(@Body() dto: CreateScanDto, @Req() req: any) {
    return this.scansService.create(dto, req.user.tenantId, req.user.id);
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
    const p = page ? parseInt(page, 10) : 1;
    const l = limit ? parseInt(limit, 10) : 20;
    return this.scansService.listForTenant(req.user.tenantId, p, l);
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get details and state of a specific scan' })
  @ApiParam({ name: 'id', type: String, description: 'Scan UUID' })
  async findOne(@Param() params: GetScanParamsDto, @Req() req: any) {
    return this.scansService.findById(params.id, req.user.tenantId);
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
    return this.scansService.getFindings(params.id, req.user.tenantId, { severity });
  }

  // Note: browser EventSource cannot set Authorization headers, so a real
  // frontend would need a short-lived signed query-param token here instead.
  // Guarded the same as the rest of this controller for now since callers in
  // this codebase (and its tests) use a raw HTTP client with a Bearer header.
  @Sse(':id/stream')
  @ApiOperation({ summary: 'Server-Sent Events stream for live telemetry' })
  @ApiParam({ name: 'id', type: String, description: 'Scan UUID' })
  stream(@Param() params: GetScanParamsDto): Observable<MessageEvent> {
    return this.eventBus.getObservable(params.id);
  }
}
