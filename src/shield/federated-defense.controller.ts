import { Controller, Get, Post, Body, HttpCode, HttpStatus, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { OwnerGuard } from '../auth/guards/owner.guard';
import { FederatedDefenseService } from './federated-defense.service';

@Controller('api/v1/shield/federated')
@UseGuards(JwtAuthGuard)
export class FederatedDefenseController {
  constructor(private readonly federatedService: FederatedDefenseService) {}

  /**
   * Endpoint to retrieve the active registry of anonymized threat IOC hashes.
   */
  @Get('feed')
  @HttpCode(HttpStatus.OK)
  async getFeed() {
    const hashes = this.federatedService.getAnonymizedFeed();
    
    // Only what is really known: the hashes on this CyPee's own list. There is
    // no wider network of nodes, so none is named and no score is invented.
    return hashes.map((hash, idx) => ({
      id: `ioc-${idx + 1}`,
      indicatorHash: hash,
      threatType: 'UNCLASSIFIED',
      firstSeen: null,
      confidenceScore: null,
      reportingNode: 'This CyPee (local list)',
    }));
  }

  /**
   * Endpoint to share a new threat indicator (hashes and registers it).
   */
  @Post('share')
  @UseGuards(OwnerGuard)
  @HttpCode(HttpStatus.CREATED)
  async shareThreat(@Body() body: { threatType: string; rawIndicator: string }) {
    const hash = await this.federatedService.shareThreatSignature(body.threatType, body.rawIndicator);
    return {
      success: true,
      hash,
      message: `Saved the ${body.threatType} indicator to this CyPee's local blocklist.`,
    };
  }
}
