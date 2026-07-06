import { Injectable, Logger } from '@nestjs/common';
import * as crypto from 'crypto';

export interface ThreatFeedEntry {
  indicatorHash: string; // HMAC-SHA256 salted hash of threat signature
  threatType: string;    // SQL_INJECTION | COMPROMISED_IP | BOT_BEHAVIOR
  firstSeen: string;
  confidenceScore: number;
}

@Injectable()
export class FederatedDefenseService {
  private readonly logger = new Logger(FederatedDefenseService.name);

  // Simulated federated threat sharing feed
  private federatedBlocklist = new Set<string>();

  constructor() {
    // Seed the federated blocklist with a mock anonymized IP threat hash
    const mockHackerIp = '198.51.100.42';
    const hash = this.getHashedIndicator(mockHackerIp);
    this.federatedBlocklist.add(hash);
  }

  /**
   * Helper to compute a cryptographically salted HMAC-SHA256 hash.
   * This prevents simple rainbow table de-anonymization of IPs and indicators.
   */
  private getHashedIndicator(rawIndicator: string): string {
    const salt = process.env.FEDERATED_SALT || 'default-shield-edge-mesh-salt-key';
    return crypto.createHmac('sha256', salt).update(rawIndicator).digest('hex');
  }

  /**
   * Publishes an anonymized threat signature to the federated mesh.
   */
  async shareThreatSignature(threatType: string, rawIndicator: string): Promise<string> {
    const hash = this.getHashedIndicator(rawIndicator);
    
    if (!this.federatedBlocklist.has(hash)) {
      this.federatedBlocklist.add(hash);
      this.logger.log(`[FEDERATED DEFENSE] Shared threat signature of type ${threatType} with global anycast edge. Anonymized HMAC-Hash: ${hash}`);
    }
    
    return hash;
  }

  /**
   * Checks if an incoming request parameter or IP matches a known threat shared by peers.
   */
  isThreatBlocked(rawIndicator: string): boolean {
    const hash = this.getHashedIndicator(rawIndicator);
    const blocked = this.federatedBlocklist.has(hash);
    if (blocked) {
      this.logger.warn(`[FEDERATED DEFENSE] Request blocked! Indicator matched global federated blocklist hash: ${hash}`);
    }
    return blocked;
  }

  /**
   * Returns a copy of the active anonymized blocklist hashes.
   */
  getAnonymizedFeed(): string[] {
    return Array.from(this.federatedBlocklist);
  }
}
