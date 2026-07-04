import { Injectable, NotFoundException, Logger, BadRequestException, HttpException, HttpStatus } from '@nestjs/common';
import * as dns from 'dns';
import { promisify } from 'util';
import * as net from 'net';
import { PrismaService } from '../database/prisma.service';
import { AuditLogService } from '../audit/audit-log.service';
import { CreateScanDto } from './dto/scan.dto';
import { assertValidTransition } from './scan-state.machine';
import { Scan } from '@prisma/client';
import { ScanQueueService } from './scan-queue.service';
import { ScanState } from './types';

const dnsLookup = promisify(dns.lookup);

@Injectable()
export class ScansService {
  private readonly logger = new Logger(ScansService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly auditLog: AuditLogService,
    private readonly scanQueueService: ScanQueueService,
  ) {}

  /**
   * Rejects repository URLs that resolve to loopback/private/link-local
   * addresses, so a scan request can't be used as an SSRF vector to probe
   * internal network services under the guise of "cloning a repo".
   */
  private async assertPublicRepositoryUrl(repositoryUrl: string): Promise<void> {
    const hostname = new URL(repositoryUrl).hostname;
    if (hostname === 'localhost') {
      throw new BadRequestException('repositoryUrl must not point at localhost or internal network addresses.');
    }

    let address: string;
    try {
      address = (await dnsLookup(hostname)).address;
    } catch {
      throw new BadRequestException('repositoryUrl hostname could not be resolved.');
    }

    if (this.isPrivateOrLoopback(address)) {
      throw new BadRequestException('repositoryUrl must not point at localhost or internal network addresses.');
    }
  }

  private isPrivateOrLoopback(ip: string): boolean {
    if (net.isIPv6(ip)) {
      return ip === '::1' || ip.startsWith('fc') || ip.startsWith('fd') || ip.startsWith('fe80');
    }
    const octets = ip.split('.').map(Number);
    if (octets.length !== 4 || octets.some(Number.isNaN)) return true; // fail closed on unparsable input
    const [a, b] = octets;
    return (
      a === 127 || // loopback
      a === 10 || // private
      (a === 172 && b >= 16 && b <= 31) || // private
      (a === 192 && b === 168) || // private
      (a === 169 && b === 254) || // link-local / cloud metadata
      a === 0
    );
  }

  private static readonly MAX_CONCURRENT_SCANS_PER_TENANT = 2;
  private static readonly MAX_SCANS_PER_HOUR_PER_TENANT = 10;
  private static readonly TERMINAL_STATES = ['COMPLETE', 'FAILED', 'ARCHIVED'];

  /**
   * Caps how many scans a tenant can have in flight and how many they can
   * launch per hour. Each scan clones a real external repo and runs several
   * scanners (including semgrep), so unbounded scan creation is a real
   * resource-exhaustion / abuse vector, not just a theoretical one.
   */
  private async assertScanRateLimit(tenantId: string): Promise<void> {
    const [activeCount, hourlyCount] = await Promise.all([
      this.prisma.scan.count({
        where: { tenantId, state: { notIn: ScansService.TERMINAL_STATES } },
      }),
      this.prisma.scan.count({
        where: { tenantId, startedAt: { gte: new Date(Date.now() - 60 * 60 * 1000) } },
      }),
    ]);

    if (activeCount >= ScansService.MAX_CONCURRENT_SCANS_PER_TENANT) {
      throw new HttpException(
        `Too many scans in progress (max ${ScansService.MAX_CONCURRENT_SCANS_PER_TENANT} concurrent). Wait for one to finish before starting another.`,
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }
    if (hourlyCount >= ScansService.MAX_SCANS_PER_HOUR_PER_TENANT) {
      throw new HttpException(
        `Scan rate limit exceeded (max ${ScansService.MAX_SCANS_PER_HOUR_PER_TENANT} per hour).`,
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }
  }

  /**
   * Creates a new scan record in AUTHORIZED state and enqueues
   * a background job. Returns immediately — the queue handles execution.
   */
  async create(dto: CreateScanDto, tenantId: string, actorId?: string): Promise<Scan> {
    await this.assertPublicRepositoryUrl(dto.repositoryUrl);
    await this.assertScanRateLimit(tenantId);

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
