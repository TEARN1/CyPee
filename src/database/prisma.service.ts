import { Injectable, OnModuleInit, OnModuleDestroy, Logger } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { PrismaBetterSqlite3 } from '@prisma/adapter-better-sqlite3';

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(PrismaService.name);

  constructor() {
    // In Prisma 7, better-sqlite3 is instantiated automatically via the url property
    const adapter = new PrismaBetterSqlite3({
      url: 'file:./dev.db',
    });

    super({
      adapter,
      log: [
        { level: 'warn', emit: 'event' },
        { level: 'error', emit: 'event' },
      ],
    });
  }

  async onModuleInit() {
    await this.$connect();
    this.logger.log('Database connected via PrismaBetterSqlite3 adapter');
  }

  async onModuleDestroy() {
    await this.$disconnect();
    this.logger.log('Database disconnected');
  }

  /**
   * Execute a callback within a tenant-scoped transaction.
   * On SQLite, we execute the transaction normally (RLS is Postgres-only).
   */
  async withTenantContext<T>(tenantId: string, fn: (tx: PrismaClient) => Promise<T>): Promise<T> {
    return this.$transaction(async (tx) => {
      return fn(tx as unknown as PrismaClient);
    });
  }
}
