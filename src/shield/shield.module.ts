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
import { VGruvsHostGuardianService } from './vgruvs-host.service';
import { VGruvsHostController } from './vgruvs-host.controller';
import { InfiniteLabyrinthService } from './infinite-labyrinth.service';
import { InfiniteLabyrinthController } from './infinite-labyrinth.controller';
import { PqcCryptoService } from './pqc-crypto.service';
import { PqcCryptoController } from './pqc-crypto.controller';
import { MtdEngineService } from './mtd-engine.service';
import { MtdEngineController } from './mtd-engine.controller';
import { CombatRadarService } from './combat-radar.service';
import { CombatRadarController } from './combat-radar.controller';
import { GatewayAdvancedService } from './gateway-advanced.service';
import { PqcAdvancedService } from './pqc-advanced.service';
import { FleetConsensusService } from './fleet-consensus.service';
import { FleetConsensusController } from './fleet-consensus.controller';
import { SovereignVaultService } from './sovereign-vault.service';
import { SovereignVaultController } from './sovereign-vault.controller';

@Global()
@Module({
  controllers: [
    SecurityHardeningController,
    FederatedDefenseController,
    GatewayController,
    FleetController,
    BreachResponseController,
    AttackerReconController,
    VGruvsHostController,
    InfiniteLabyrinthController,
    PqcCryptoController,
    MtdEngineController,
    CombatRadarController,
    FleetConsensusController,
    SovereignVaultController,
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
    VGruvsHostGuardianService,
    InfiniteLabyrinthService,
    PqcCryptoService,
    MtdEngineService,
    CombatRadarService,
    GatewayAdvancedService,
    PqcAdvancedService,
    FleetConsensusService,
    SovereignVaultService,
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
    VGruvsHostGuardianService,
    InfiniteLabyrinthService,
    PqcCryptoService,
    MtdEngineService,
    CombatRadarService,
    GatewayAdvancedService,
    PqcAdvancedService,
    FleetConsensusService,
    SovereignVaultService,
  ],
})
export class ShieldModule {}
