import { Controller, Get, Post, Body, Header, HttpCode, HttpStatus, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { OwnerGuard } from '../auth/guards/owner.guard';
import { FleetConsensusService } from './fleet-consensus.service';

// Runs submitted code or changes the whole system: owners only (src/auth/guards/owner.guard.ts).
@UseGuards(JwtAuthGuard, OwnerGuard)
@Controller('api/v1')
export class FleetConsensusController {
  constructor(private readonly fleetConsensus: FleetConsensusService) {}

  /**
   * Native Prometheus Metrics Endpoint
   */
  @Get('metrics')
  @Header('Content-Type', 'text/plain; version=0.0.4; charset=utf-8')
  getPrometheusMetrics(): string {
    return this.fleetConsensus.generatePrometheusMetrics();
  }

  /**
   * Raft Consensus Cluster Inspection
   */
  @Get('shield/raft/status')
  getRaftStatus() {
    return this.fleetConsensus.getRaftStatus();
  }

  /**
   * Multi-Region Gossip Threat Mesh
   */
  @Get('shield/gossip/recent')
  getRecentGossip() {
    return this.fleetConsensus.getRecentGossip();
  }

  @Post('shield/gossip/broadcast')
  @HttpCode(HttpStatus.OK)
  broadcastGossip(@Body() body: { signature: string; region?: string }) {
    return this.fleetConsensus.broadcastGossipThreat(body.signature, body.region);
  }
}
