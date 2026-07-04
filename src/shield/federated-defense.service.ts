import { Injectable, Logger } from '@nestjs/common';
import * as crypto from 'crypto';

export interface ThreatFeedEntry {
  indicatorHash: string; // SHA-256 hash of threat signature (IP, pattern, user-agent)
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
    // representing a known malicious hacker network flag
    const mockHackerIp = '198.51.100.42';
    const hash = crypto.createHash('sha256').update(mockHackerIp).digest('hex');
    this.federatedBlocklist.add(hash);
  }

  /**
   * Publishes an anonymized threat signature to the federated mesh.
   * Hashes the identifier (e.g., source IP or query payload) to maintain GDPR/POPIA privacy,
   * allowing other instances to block the threat without learning the raw parameter value.
   */
  async shareThreatSignature(threatType: string, rawIndicator: string): Promise<string> {
    const hash = crypto.createHash('sha256').update(rawIndicator).digest('hex');
    
    if (!this.federatedBlocklist.has(hash)) {
      this.federatedBlocklist.add(hash);
      this.logger.log(`[FEDERATED DEFENSE] Shared threat signature of type ${threatType} with global anycast edge. Anonymized Hash: ${hash}`);
    }
    
    return hash;
  }

  /**
   * Checks if an incoming request parameter or IP matches a known threat shared by peers.
   */
  isThreatBlocked(rawIndicator: string): boolean {
    const hash = crypto.createHash('sha256').update(rawIndicator).digest('hex');
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
