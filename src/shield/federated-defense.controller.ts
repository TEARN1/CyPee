import { Controller, Get, Post, Body, HttpCode, HttpStatus } from '@nestjs/common';
import { FederatedDefenseService } from './federated-defense.service';

@Controller('api/v1/shield/federated')
export class FederatedDefenseController {
  constructor(private readonly federatedService: FederatedDefenseService) {}

  /**
   * Endpoint to retrieve the active registry of anonymized threat IOC hashes.
   */
  @Get('feed')
  @HttpCode(HttpStatus.OK)
  async getFeed() {
    const hashes = this.federatedService.getAnonymizedFeed();
    
    // Map hashes with mock metadata for rich visual presentation in the dashboard
    return hashes.map((hash, idx) => {
      const threatTypes = ['SQL_INJECTION', 'COMPROMISED_IP', 'BOT_BEHAVIOR', 'CREDENTIAL_EXFILTRATION'];
      const confidenceScores = [95, 88, 92, 99];
      const nodes = ['Node-US-East', 'Node-EU-West', 'Node-APAC-Sgp', 'Node-LATAM-Brl'];
      
      return {
        id: `ioc-${idx + 1}`,
        indicatorHash: hash,
        threatType: threatTypes[idx % threatTypes.length],
        firstSeen: new Date(Date.now() - idx * 3600000).toISOString(),
        confidenceScore: confidenceScores[idx % confidenceScores.length],
        reportingNode: nodes[idx % nodes.length],
      };
    });
  }

  /**
   * Endpoint to share a new threat indicator (hashes and registers it).
   */
  @Post('share')
  @HttpCode(HttpStatus.CREATED)
  async shareThreat(@Body() body: { threatType: string; rawIndicator: string }) {
    const hash = await this.federatedService.shareThreatSignature(body.threatType, body.rawIndicator);
    return {
      success: true,
      hash,
      message: `Successfully propagated threat signature of type ${body.threatType} to anycast network.`,
    };
  }
}
