import { Controller, Get, Post, Body, HttpCode, HttpStatus, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { OwnerGuard } from '../auth/guards/owner.guard';
import { SovereignVaultService } from './sovereign-vault.service';

// Runs submitted code or changes the whole system: owners only (src/auth/guards/owner.guard.ts).
@UseGuards(JwtAuthGuard, OwnerGuard)
@Controller('api/v1/shield/vault')
export class SovereignVaultController {
  constructor(private readonly vaultService: SovereignVaultService) {}

  /**
   * Retrieves all Post-Quantum Signed Immutable WORM Snapshots.
   */
  @Get('worm-snapshots')
  @HttpCode(HttpStatus.OK)
  getWormSnapshots() {
    return {
      totalSnapshots: this.vaultService.getAllWormSnapshots().length,
      snapshots: this.vaultService.getAllWormSnapshots(),
    };
  }

  /**
   * Triggers an Autonomous Self-Healing Scrub against Silent Bit-Rot and Ransomware Anomaly.
   */
  @Post('scrub')
  @HttpCode(HttpStatus.OK)
  runSelfHealingScrub() {
    return this.vaultService.executeSelfHealingScrub();
  }

  /**
   * Inspects Byzantine Fault Tolerant (BFT) Multi-Region Quorum Status.
   */
  @Get('bft-quorum')
  @HttpCode(HttpStatus.OK)
  getBftQuorum() {
    return this.vaultService.getBftQuorumStatus();
  }

  /**
   * Executes a Black-Swan Autonomous Disaster Simulation & Instant Recovery Drill.
   */
  @Post('disaster-drill')
  @HttpCode(HttpStatus.OK)
  runDisasterDrill(
    @Body()
    body?: {
      scenario?: 'TOTAL_STORAGE_CORRUPTION' | 'HOST_WIPE' | 'RANSOMWARE_ENCRYPTION_SPIKE' | 'MULTI_REGION_PARTITION';
    },
  ) {
    return this.vaultService.runBlackSwanDisasterDrill(body?.scenario);
  }
}
