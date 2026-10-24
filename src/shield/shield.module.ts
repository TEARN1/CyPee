import { Module, Global } from '@nestjs/common';
import { ShieldService } from './shield.service';
import { FederatedDefenseService } from './federated-defense.service';
import { SecurityHardeningService } from './security-hardening.service';
import { SecurityHardeningController } from './security-hardening.controller';
import { FederatedDefenseController } from './federated-defense.controller';
import { GatewayService } from './gateway.service';
import { GatewayController } from './gateway.controller';
import { FleetService } from './fleet.service';
import { FleetController } from './fleet.controller';

@Global()
@Module({
  controllers: [
    SecurityHardeningController,
    FederatedDefenseController,
    GatewayController,
    FleetController,
  ],
  providers: [
    ShieldService,
    FederatedDefenseService,
    SecurityHardeningService,
    GatewayService,
    FleetService,
  ],
  exports: [
    ShieldService,
    FederatedDefenseService,
    SecurityHardeningService,
    GatewayService,
    FleetService,
  ],
})
export class ShieldModule {}
