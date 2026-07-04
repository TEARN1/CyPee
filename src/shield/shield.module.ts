import { Module, Global } from '@nestjs/common';
import { ShieldService } from './shield.service';
import { FederatedDefenseService } from './federated-defense.service';
import { SecurityHardeningService } from './security-hardening.service';
import { SecurityHardeningController } from './security-hardening.controller';

@Global()
@Module({
  controllers: [SecurityHardeningController],
  providers: [ShieldService, FederatedDefenseService, SecurityHardeningService],
  exports: [ShieldService, FederatedDefenseService, SecurityHardeningService],
})
export class ShieldModule {}
