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
import { BreachResponseService } from './breach-response.service';
import { BreachResponseController } from './breach-response.controller';
import { MtlsMeshGuard } from './mtls-mesh.guard';
import { AttackerReconService } from './attacker-recon.service';
import { AttackerReconController } from './attacker-recon.controller';

@Global()
@Module({
  controllers: [
    SecurityHardeningController,
    FederatedDefenseController,
    GatewayController,
    FleetController,
    BreachResponseController,
    AttackerReconController,
  ],
  providers: [
    ShieldService,
    FederatedDefenseService,
    SecurityHardeningService,
    GatewayService,
    FleetService,
    BreachResponseService,
    MtlsMeshGuard,
    AttackerReconService,
  ],
  exports: [
    ShieldService,
    FederatedDefenseService,
    SecurityHardeningService,
    GatewayService,
    FleetService,
    BreachResponseService,
    MtlsMeshGuard,
    AttackerReconService,
  ],
})
export class ShieldModule {}
