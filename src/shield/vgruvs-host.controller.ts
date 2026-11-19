import { Controller, Get, Post, Body, HttpCode, HttpStatus, UseGuards } from '@nestjs/common';
import { VGruvsHostGuardianService } from './vgruvs-host.service';
import { EnclaveAppId } from './fleet.service';
import { OperatorGuard } from '../auth/guards/operator.guard';
import { ApiKeyGuard } from '../compliance/guards/api-key.guard';

@Controller('api/v1/shield/vgruvs')
export class VGruvsHostController {
  constructor(private readonly vgruvsGuardian: VGruvsHostGuardianService) {}

  /**
   * Returns complete bi-directional security posture between CyPee, V-Gruvs Host,
   * and the 3 hosted applications (The Resident, The Gruvs, Excellency).
   */
  @Get('posture')
  @UseGuards(OperatorGuard)
  getPosture() {
    return this.vgruvsGuardian.getHostPosture();
  }

  /**
   * Rotates the shared CyPee <-> V-Gruvs Enclave Transit Secret with zero downtime.
   */
  @Post('rotate-transit-key')
  @UseGuards(OperatorGuard)
  @HttpCode(HttpStatus.OK)
  async rotateTransitKey() {
    return this.vgruvsGuardian.rotateTransitKey();
  }

  /**
   * Receives signed runtime heartbeats from the V-Gruvs host connector or app guards.
   */
  @Post('heartbeat')
  @UseGuards(ApiKeyGuard)
  @HttpCode(HttpStatus.OK)
  async heartbeat(
    @Body()
    body: {
      enclaveId: EnclaveAppId;
      memoryUsageMb?: number;
      activePids?: number;
      blockedSyscallsDelta?: number;
    },
  ) {
    return this.vgruvsGuardian.recordHeartbeat(body);
  }

  /**
   * Simulates or reports a Container Escape / Host Breakout attempt against V-Gruvs,
   * triggering eBPF/Seccomp containment, enclave airgap quarantine, and Attacker Recon Dossier capture.
   */
  @Post('simulate-escape')
  @UseGuards(OperatorGuard)
  @HttpCode(HttpStatus.OK)
  async simulateEscape(
    @Body()
    body: {
      sourceEnclave?: EnclaveAppId;
      attackerIp?: string;
      escapeVector?: string;
      targetHostResource?: string;
    },
  ) {
    return this.vgruvsGuardian.handleContainerEscapeAttempt(body || {});
  }
}
