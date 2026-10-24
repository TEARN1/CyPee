import { Global, Module } from '@nestjs/common';
import { PrismaService } from './prisma.service';
import { DbCryptoService } from './db-crypto.service';

@Global()
@Module({
  providers: [PrismaService, DbCryptoService],
  exports: [PrismaService, DbCryptoService],
})
export class DatabaseModule {}
