import { Controller, Get, HttpCode, HttpStatus } from '@nestjs/common';
import { PrismaService } from '../database/prisma.service';

@Controller('api/v1/health')
export class HealthController {
  constructor(private readonly prisma: PrismaService) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async checkHealth() {
    let dbStatus = 'UP';
    let dbError = undefined;
    let scansCount = 0;
    let activeHoneytokens = 0;

    // 1. Test database connection
    try {
      scansCount = await this.prisma.scan.count();
      activeHoneytokens = await this.prisma.honeytoken.count({ where: { isActive: true } });
    } catch (err) {
      dbStatus = 'DOWN';
      dbError = err.message;
    }

    // 2. Formulate diagnostics payload
    return {
      status: dbStatus === 'UP' ? 'UP' : 'DEGRADED',
      timestamp: new Date().toISOString(),
      services: {
        database: {
          status: dbStatus,
          provider: 'sqlite',
          scansCount,
          activeHoneytokens,
          ...(dbError ? { error: dbError } : {}),
        },
        queue: {
          status: 'UP',
          driver: process.env.REDIS_MOCK === 'true' ? 'in-memory-macro' : 'redis-bullmq',
        },
        shield: {
          status: 'UP',
          vectorFirewallRulesCount: 10,
        },
      },
    };
  }
}
