import { Controller, Sse, Get, Post, Body, HttpCode, HttpStatus, UseGuards } from '@nestjs/common';
import { Observable } from 'rxjs';
import { CombatRadarService, CombatTelemetryEvent } from './combat-radar.service';
import { OwnerGuard } from '../auth/guards/owner.guard';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';

// Fleet-wide controls: owners only (src/auth/guards/owner.guard.ts).
@UseGuards(JwtAuthGuard, OwnerGuard)
@Controller('api/v1/shield/combat')
export class CombatRadarController {
  constructor(private readonly combatRadarService: CombatRadarService) {}

  /**
   * Real-time Server-Sent Events stream for live radar visualization in the UI.
   */
  @Sse('stream')
  streamCombatEvents(): Observable<{ data: CombatTelemetryEvent }> {
    return this.combatRadarService.getCombatStream();
  }

  /**
   * Returns recent combat events for initial component load.
   */
  @Get('recent')
  getRecentEvents() {
    return {
      events: this.combatRadarService.getRecentCombatEvents(),
    };
  }

  /**
   * Interactive Adversary Attack Launcher: Click to launch attacks and watch defenses crush them live.
   */
  @Post('simulate-attack')
  @HttpCode(HttpStatus.OK)
  async simulateAttack(
    @Body()
    body: {
      targetEnclave: 'vgruvs' | 'the-resident' | 'the-gruvs' | 'excellency' | 'labyrinth';
      attackType: string;
    },
  ) {
    return this.combatRadarService.simulateAdversaryAttack(body);
  }
}
