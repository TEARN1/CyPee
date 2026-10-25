import { Global, Module } from '@nestjs/common';
import { PrismaService } from './prisma.service';
import { DbCryptoService } from './db-crypto.service';
import { StorageAttestorService } from './storage-attestor.service';

@Global()
@Module({
  providers: [PrismaService, DbCryptoService, StorageAttestorService],
  exports: [PrismaService, DbCryptoService, StorageAttestorService],
})
export class DatabaseModule {}
