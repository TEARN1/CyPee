import { Controller, Get, Post, Param, Req, Res, HttpCode, HttpStatus, NotFoundException, UseGuards } from '@nestjs/common';
import { createHash } from 'crypto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { OwnerGuard } from '../auth/guards/owner.guard';
import { Request, Response } from 'express';
import { AttackerReconService } from './attacker-recon.service';

@Controller('api/v1/shield/recon')
export class AttackerReconController {
  constructor(private readonly reconService: AttackerReconService) {}

  /**
   * Retrieves all gathered attacker intelligence dossiers.
   */
  @Get('dossiers')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  getAllDossiers() {
    return {
      totalDossiers: this.reconService.getAllDossiers().length,
      dossiers: this.reconService.getAllDossiers(),
    };
  }

  /**
   * Retrieves full forensic breakdown for a specific attacker dossier.
   */
  @Get('dossiers/:id')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  getDossierById(@Param('id') id: string) {
    const dossier = this.reconService.getDossierById(id);
    if (!dossier) {
      throw new NotFoundException(`Attacker Dossier ${id} not found.`);
    }
    return dossier;
  }

  /**
   * Active Countermeasure: Phone-Home Canary Beacon endpoint.
   * When an attacker or their tools open exfiltrated decoy documents or credentials,
   * it phones home to this URL, immediately capturing their true unproxied IP and environment!
   */
  @Get('beacon/:beaconId')
  handleBeaconPingGet(@Param('beaconId') beaconId: string, @Req() req: Request, @Res() res: Response) {
    const pingIp = req.ip || req.socket.remoteAddress || '203.0.113.195';
    const userAgent = req.headers['user-agent'] || 'Unknown Attacker Agent';

    this.reconService.recordBeaconPing(beaconId, pingIp, userAgent);

    // Return an invisible 1x1 GIF so the attacker doesn't realize they've been traced
    const transparentGif = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');
    res.setHeader('Content-Type', 'image/gif');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.send(transparentGif);
  }

  /**
   * Manual or simulated beacon trigger for testing attribution tracking.
   */
  @Post('beacon/:beaconId/trigger-sim')
  @UseGuards(JwtAuthGuard, OwnerGuard)
  @HttpCode(HttpStatus.OK)
  simulateBeaconPing(@Param('beaconId') beaconId: string, @Req() req: Request) {
    const pingIp = req.body?.ip || '198.51.100.222';
    const userAgent = req.body?.userAgent || 'Microsoft Office Excel 2021 (Attacker Workstation)';
    return this.reconService.recordBeaconPing(beaconId, pingIp, userAgent);
  }

  /**
   * Exports an evidence-grade forensic incident report for law enforcement or CERT filing.
   */
  @Get('dossiers/:id/export')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  exportDossierReport(@Param('id') id: string) {
    const dossier = this.reconService.getDossierById(id);
    if (!dossier) throw new NotFoundException(`Dossier ${id} not found.`);

    return {
      reportType: 'CYBER_ATTACK_ATTRIBUTION_DOSSIER',
      classification: 'CONFIDENTIAL // LAW ENFORCEMENT & SOC',
      generatedAt: new Date().toISOString(),
      dossier,
      // A hash of the dossier, so a copy can be compared with this one. It is
      // not a digital signature and does not prove who made the report.
      integrity: {
        hashAlgorithm: 'SHA-256',
        dossierSha256: createHash('sha256').update(JSON.stringify(dossier)).digest('hex'),
      },
    };
  }
}
