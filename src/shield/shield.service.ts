import { Injectable, Logger } from '@nestjs/common';
import * as crypto from 'crypto';

export interface RequestTelemetry {
  ip: string;
  timestamp: number;
  path: string;
  userAgent: string;
  powNonce?: string;
  payload?: string;
}

@Injectable()
export class ShieldService {
  private readonly logger = new Logger(ShieldService.name);

  // In-memory telemetry storage for behavioral analysis
  private ipHistory = new Map<string, { timestamps: number[]; paths: string[] }>();

  // Local vector firewall cache of known attack vector signatures
  private readonly threatSignatures = [
    'SELECT * FROM users WHERE',
    'UNION SELECT username, password',
    'OR 1=1',
    '../..//../etc/passwd',
    'cat /etc/passwd',
    '<script>alert(1)</script>',
    'javascript:alert(1)',
    'BinaryFormatter',
    'ObjectInputStream',
    'eval(base64_decode',
  ];

  /**
   * Generates a PoW challenge for the client.
   * Challenge format: challenge_string|difficulty_bits
   */
  generateChallenge(): string {
    const salt = crypto.randomBytes(16).toString('hex');
    const difficulty = 4; // requires leading hex zeroes
    return `${salt}|${difficulty}`;
  }

  /**
   * Verifies the client's Proof of Work.
   * Checks if SHA-256(challenge + nonce) has 'difficulty' leading hex zeroes.
   */
  verifyPoW(challenge: string, nonce: string): boolean {
    if (!challenge || !nonce) return false;
    const [salt, difficultyStr] = challenge.split('|');
    const difficulty = parseInt(difficultyStr, 10);
    
    const hash = crypto.createHash('sha256').update(`${salt}${nonce}`).digest('hex');
    const prefix = '0'.repeat(difficulty);
    return hash.startsWith(prefix);
  }

  /**
   * Evaluates the time intervals of incoming requests for an IP.
   * Low interval entropy (predictability) indicates automated bot scripts.
   */
  detectBotBehavior(ip: string, now: number): { isBot: boolean; entropy: number } {
    let history = this.ipHistory.get(ip);
    if (!history) {
      history = { timestamps: [], paths: [] };
      this.ipHistory.set(ip, history);
    }

    history.timestamps.push(now);
    // Keep only last 10 requests for windowed analysis
    if (history.timestamps.length > 10) {
      history.timestamps.shift();
    }

    if (history.timestamps.length < 5) {
      return { isBot: false, entropy: 10 }; // not enough data yet
    }

    // Calculate time differences (intervals) between consecutive requests
    const intervals: number[] = [];
    for (let i = 1; i < history.timestamps.length; i++) {
      intervals.push(history.timestamps[i] - history.timestamps[i - 1]);
    }

    // Calculate mean interval
    const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;

    // Calculate standard deviation of intervals (jitter)
    const variance = intervals.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / intervals.length;
    const stdDev = Math.sqrt(variance);

    // Flag as bot if standard deviation is low (predictable loop spacing) 
    // OR if average interval is extremely fast (under 100ms - physically humanly impossible)
    const isBot = stdDev < 35 || mean < 100;

    return { isBot, entropy: stdDev };
  }

  /**
   * Simulates a GeoIP lookup.
   * Blocks access or raises warnings for disallowed geographic coordinates.
   */
  auditGeoIp(ip: string): { country: string; allowed: boolean } {
    // Local mock GeoIP database
    if (ip === '127.0.0.1' || ip === '::1' || ip === 'localhost') {
      return { country: 'LOCALHOST', allowed: true };
    }

    // Simple IP-to-country hashing mock
    const sum = ip.split('.').reduce((a, b) => a + parseInt(b, 10), 0);
    const countries = ['US', 'ZA', 'DE', 'KP', 'RU', 'CN', 'GB', 'FR'];
    const country = countries[sum % countries.length];

    // Restrict high-risk areas from administrative/compliance uploads
    const blockedCountries = ['KP', 'RU'];
    const allowed = !blockedCountries.includes(country);

    return { country, allowed };
  }

  /**
   * Tracks navigation sequence.
   * If client hits internal compliance endpoints directly without entering
   * registration/login steps, alerts session graph anomaly.
   */
  auditSessionGraph(ip: string, path: string): boolean {
    const history = this.ipHistory.get(ip);
    if (!history) return true;

    history.paths.push(path);
    if (history.paths.length > 15) history.paths.shift();

    // Critical flow verification:
    // If accessing scans trigger (/api/v1/scans) or compliance upload (/api/v1/compliance/upload)
    // without ever having visited login/register paths first, flag anomaly.
    const isSensitivePath = path.includes('/scans') || path.includes('/upload');
    if (isSensitivePath) {
      const hasVisitedPortal = history.paths.some(p => p.includes('/auth/login') || p.includes('/auth/register'));
      if (!hasVisitedPortal) {
        this.logger.warn(`Session Graph Anomaly detected for IP ${ip}. Direct query to sensitive API path: ${path}`);
        return false; // Out of order graph traversal
      }
    }

    return true;
  }

  /**
   * Vector Firewall implementation.
   * Converts payload strings to character-gram frequency vectors and calculates
   * Cosine Similarity against a database of known injection vectors.
   */
  vectorFirewallCheck(payload: string): { blocked: boolean; similarity: number; matchedSignature?: string } {
    if (!payload) return { blocked: false, similarity: 0 };

    for (const signature of this.threatSignatures) {
      const similarity = this.calculateCosineSimilarity(payload, signature);
      // If similarity is above 0.75, block request as SQL injection / attack signature match
      if (similarity > 0.75) {
        return { blocked: true, similarity, matchedSignature: signature };
      }
    }

    return { blocked: false, similarity: 0 };
  }

  /**
   * Computes cosine similarity of character bigram vectors.
   */
  private calculateCosineSimilarity(str1: string, str2: string): number {
    const getBigrams = (str: string) => {
      const s = str.toLowerCase();
      const bigrams = new Map<string, number>();
      for (let i = 0; i < s.length - 1; i++) {
        const bigram = s.substring(i, i + 2);
        bigrams.set(bigram, (bigrams.get(bigram) || 0) + 1);
      }
      return bigrams;
    };

    const v1 = getBigrams(str1);
    const v2 = getBigrams(str2);

    // Get union of all bigrams
    const allBigrams = new Set([...v1.keys(), ...v2.keys()]);

    let dotProduct = 0;
    let mag1 = 0;
    let mag2 = 0;

    for (const b of allBigrams) {
      const count1 = v1.get(b) || 0;
      const count2 = v2.get(b) || 0;

      dotProduct += count1 * count2;
      mag1 += count1 * count1;
      mag2 += count2 * count2;
    }

    if (mag1 === 0 || mag2 === 0) return 0;
    return dotProduct / (Math.sqrt(mag1) * Math.sqrt(mag2));
  }
}
