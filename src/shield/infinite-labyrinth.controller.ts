import { Controller, All, Get, Req, Query, Body, Headers, UseGuards } from '@nestjs/common';
import { Request } from 'express';
import { InfiniteLabyrinthService } from './infinite-labyrinth.service';
import { OwnerGuard } from '../auth/guards/owner.guard';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';

// Fleet-wide controls: owners only (src/auth/guards/owner.guard.ts).
@UseGuards(JwtAuthGuard, OwnerGuard)
@Controller('api/v1/labyrinth')
export class InfiniteLabyrinthController {
  constructor(private readonly labyrinthService: InfiniteLabyrinthService) {}

  /**
   * Real-time surveillance telemetry of trapped attackers in the procedural maze.
   */
  @Get('telemetry')
  getTelemetry() {
    return this.labyrinthService.getLabyrinthStats();
  }

  /**
   * Procedural Honeypot Trap endpoint.
   * Catches any inbound scan/probe and feeds endless procedural synthetic tables and delays.
   */
  @All('query')
  async proceduralQuery(
    @Req() req: Request,
    @Query('q') queryParam?: string,
    @Body() body?: any,
    @Headers('user-agent') userAgent?: string,
  ) {
    const ip = (req.headers['x-forwarded-for'] as string || req.ip || req.socket.remoteAddress || '127.0.0.1').split(',')[0].trim();
    const rawPayload = JSON.stringify(body || {}) + ' ' + (queryParam || '') + ' ' + (userAgent || '');
    const query = queryParam || (body?.query) || 'SELECT * FROM master_credentials WHERE 1=1';

    return this.labyrinthService.generateProceduralResponse(ip, query, rawPayload);
  }

  /**
   * Catch-all route for any synthetic database path probed by attackers.
   */
  @All('db/*path')
  async proceduralDbCatchAll(
    @Req() req: Request,
    @Query('q') queryParam?: string,
    @Body() body?: any,
  ) {
    const ip = (req.headers['x-forwarded-for'] as string || req.ip || req.socket.remoteAddress || '127.0.0.1').split(',')[0].trim();
    const path = req.path;
    const query = queryParam || `SELECT * FROM ${path.replace('/api/v1/labyrinth/db/', '')}`;

    return this.labyrinthService.generateProceduralResponse(ip, query, JSON.stringify(body || {}));
  }
}
