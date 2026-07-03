import { Injectable, NotFoundException, Logger } from '@nestjs/common';
import { PrismaService } from '../database/prisma.service';
import { AuditLogService } from '../audit/audit-log.service';
import { CreateScanDto } from './dto/scan.dto';
import { assertValidTransition } from './scan-state.machine';
import { Scan } from '@prisma/client';
import { ScanQueueService } from './scan-queue.service';
import { ScanState } from './types';

@Injectable()
export class ScansService {
  private readonly logger = new Logger(ScansService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly auditLog: AuditLogService,
    private readonly scanQueueService: ScanQueueService,
  ) {}

  /**
   * Creates a new scan record in AUTHORIZED state and enqueues
   * a background job. Returns immediately — the queue handles execution.
   */
  async create(dto: CreateScanDto, tenantId: string, actorId?: string): Promise<Scan> {
    // Upsert the repository reference
    const repo = await this.prisma.repository.upsert({
      where: {
        id: 'non-existent-id-forces-create',
      },
      update: {},
      create: {
        tenantId,
        name: dto.repositoryName ?? dto.repositoryUrl.split('/').pop() ?? 'Unknown',
        url: dto.repositoryUrl,
        provider: dto.provider ?? 'GITHUB',
      },
    }).catch(async () => {
      // Fallback: find or create by URL within tenant
      const existing = await this.prisma.repository.findFirst({
        where: { tenantId, url: dto.repositoryUrl },
      });
      if (existing) return existing;
      return this.prisma.repository.create({
        data: {
          tenantId,
          name: dto.repositoryName ?? dto.repositoryUrl.split('/').pop() ?? 'Unknown',
          url: dto.repositoryUrl,
          provider: dto.provider ?? 'GITHUB',
        },
      });
    });

    // Create the scan record
    const scan = await this.prisma.scan.create({
      data: {
        tenantId,
        repositoryId: repo.id,
        state: 'AUTHORIZED',
      },
    });

    // Enqueue async job — works on either BullMQ or in-memory runner
    await this.scanQueueService.addScanJob(scan.id, tenantId, dto.repositoryUrl);

    await this.auditLog.log(tenantId, 'SCAN_CREATED', `scan:${scan.id}`, {
      repositoryUrl: dto.repositoryUrl,
      scanId: scan.id,
    }, actorId);

    this.logger.log(`Scan ${scan.id} created for tenant ${tenantId} → enqueued`);
    return scan;
  }

  async findById(scanId: string, tenantId: string): Promise<Scan> {
    const scan = await this.prisma.scan.findFirst({
      where: { id: scanId, tenantId },
      include: { findings: { orderBy: { cvssScore: 'desc' } } },
    });
    if (!scan) throw new NotFoundException(`Scan ${scanId} not found`);
    return scan;
  }

  async listForTenant(tenantId: string, page = 1, limit = 20) {
    const skip = (page - 1) * limit;
    const [scans, total] = await Promise.all([
      this.prisma.scan.findMany({
        where: { tenantId },
        orderBy: { startedAt: 'desc' },
        skip,
        take: limit,
        include: {
          repository: { select: { name: true, url: true } },
        },
      }),
      this.prisma.scan.count({ where: { tenantId } }),
    ]);
    return { data: scans, total, page, limit, pages: Math.ceil(total / limit) };
  }

  /**
   * Transitions a scan to a new state — validates via state machine first.
   */
  async transition(scanId: string, newState: ScanState, tenantId: string): Promise<Scan> {
    const scan = await this.prisma.scan.findFirst({ where: { id: scanId, tenantId } });
    if (!scan) throw new NotFoundException(`Scan ${scanId} not found`);

    assertValidTransition(scan.state as ScanState, newState);

    const updated = await this.prisma.scan.update({
      where: { id: scanId },
      data: {
        state: newState,
        ...(newState === 'COMPLETE' ? { completedAt: new Date() } : {}),
      },
    });

    await this.auditLog.log(tenantId, 'SCAN_STATE_CHANGED', `scan:${scanId}`, {
      from: scan.state,
      to: newState,
    });

    return updated;
  }

  async getFindings(scanId: string, tenantId: string, filters: { severity?: string } = {}) {
    return this.prisma.finding.findMany({
      where: {
        scanId,
        tenantId,
        ...(filters.severity ? { severity: filters.severity } : {}),
      },
      orderBy: [{ cvssScore: 'desc' }, { severity: 'asc' }],
    });
  }
}
