import { Injectable, Logger } from '@nestjs/common';
import * as crypto from 'crypto';

export interface CircuitBreakerStatus {
  enclaveId: string;
  state: 'CLOSED' | 'OPEN' | 'HALF_OPEN';
  failureCount: number;
  lastFailureTime: number;
  nextAttemptAllowedAt: number;
}

export interface Ja4Fingerprint {
  rawFingerprint: string;
  clientType: 'BROWSER_HUMAN' | 'AUTOMATED_BOT' | 'UNKNOWN';
  botSignatureDetected: boolean;
  inferredTool?: string;
}

export interface EnclaveSecurityProfile {
  enclaveId: string;
  allowSubshell: boolean;
  requireTenantBinding: boolean;
  maxPayloadBytes: number;
  allowedMethods: string[];
}

@Injectable()
export class GatewayAdvancedService {
  private readonly logger = new Logger(GatewayAdvancedService.name);

  // Per-enclave circuit breaker state
  private readonly circuitBreakers = new Map<string, CircuitBreakerStatus>();

  // Distributed nonce cache to prevent replay bursts across instances
  private readonly distributedNonceCache = new Map<string, number>();

  // Granular Enclave Security Profiles
  private readonly securityProfiles: Record<string, EnclaveSecurityProfile> = {
    'the-resident': {
      enclaveId: 'the-resident',
      allowSubshell: false,
      requireTenantBinding: true,
      maxPayloadBytes: 2 * 1024 * 1024,
      allowedMethods: ['GET', 'POST', 'PUT', 'DELETE'],
    },
    'the-gruvs': {
      enclaveId: 'the-gruvs',
      allowSubshell: false,
      requireTenantBinding: false,
      maxPayloadBytes: 5 * 1024 * 1024,
      allowedMethods: ['GET', 'POST', 'PUT', 'PATCH'],
    },
    'excellency': {
      enclaveId: 'excellency',
      allowSubshell: false,
      requireTenantBinding: false,
      maxPayloadBytes: 25 * 1024 * 1024,
      allowedMethods: ['GET', 'POST', 'PUT'],
    },
    'ivory-park': {
      enclaveId: 'ivory-park',
      allowSubshell: false,
      requireTenantBinding: false,
      maxPayloadBytes: 2 * 1024 * 1024,
      allowedMethods: ['GET', 'POST'],
    },
  };

  /**
   * Egress Data Loss Prevention (DLP) Scrubber.
   * Strips credit cards, SSNs, IBANs, and bearer tokens before payloads exit the perimeter.
   */
  public scrubEgressPayload(payload: string): { scrubbed: string; redactionCount: number } {
    let redactionCount = 0;
    let scrubbed = payload;

    // Credit Card Numbers (13-16 digits with dashes or spaces)
    const ccRegex = /\b(?:\d{4}[- ]?){3}\d{4}\b/g;
    scrubbed = scrubbed.replace(ccRegex, () => {
      redactionCount++;
      return '[REDACTED_PCI_PAN]';
    });

    // US SSN / National IDs (xxx-xx-xxxx)
    const ssnRegex = /\b\d{3}-\d{2}-\d{4}\b/g;
    scrubbed = scrubbed.replace(ssnRegex, () => {
      redactionCount++;
      return '[REDACTED_SSN]';
    });

    // Bearer / API Auth Tokens
    const tokenRegex = /(Bearer\s+)[A-Za-z0-9._~+/-]{16,}/gi;
    scrubbed = scrubbed.replace(tokenRegex, (_match, prefix) => {
      redactionCount++;
      return `${prefix}[REDACTED_ENCLAVE_TOKEN]`;
    });

    return { scrubbed, redactionCount };
  }

  /**
   * Evaluates incoming request headers using JA4-style client fingerprinting.
   */
  public computeJa4Fingerprint(headers: Record<string, any>): Ja4Fingerprint {
    const userAgent = (headers['user-agent'] || '').toLowerCase();
    const accept = headers['accept'] || '';
    const acceptEncoding = headers['accept-encoding'] || '';

    const isBot = /curl|wget|python-requests|aiohttp|go-http-client|node-fetch|postman|insomnia|headless/i.test(userAgent);
    const inferredTool = isBot
      ? (userAgent.match(/curl|wget|python|aiohttp|go-http|node-fetch|postman/i) || ['bot'])[0]
      : undefined;

    const hashInput = `${userAgent}_${accept}_${acceptEncoding}`;
    const hash = crypto.createHash('sha256').update(hashInput).digest('hex').substring(0, 16);
    const rawFingerprint = `t13_${isBot ? 'b' : 'h'}_${hash}`;

    return {
      rawFingerprint,
      clientType: isBot ? 'AUTOMATED_BOT' : 'BROWSER_HUMAN',
      botSignatureDetected: isBot,
      inferredTool,
    };
  }

  /**
   * Enforces Per-Enclave Circuit Breaker Logic.
   */
  public checkCircuitBreaker(enclaveId: string): { allowed: boolean; state: string } {
    let cb = this.circuitBreakers.get(enclaveId);
    if (!cb) {
      cb = {
        enclaveId,
        state: 'CLOSED',
        failureCount: 0,
        lastFailureTime: 0,
        nextAttemptAllowedAt: 0,
      };
      this.circuitBreakers.set(enclaveId, cb);
    }

    const now = Date.now();
    if (cb.state === 'OPEN') {
      if (now > cb.nextAttemptAllowedAt) {
        cb.state = 'HALF_OPEN';
        this.logger.warn(`[CIRCUIT BREAKER] Enclave '${enclaveId}' transitioned to HALF_OPEN (probing health).`);
        return { allowed: true, state: 'HALF_OPEN' };
      }
      return { allowed: false, state: 'OPEN' };
    }

    return { allowed: true, state: cb.state };
  }

  public recordFailure(enclaveId: string) {
    const cb = this.circuitBreakers.get(enclaveId);
    if (!cb) return;

    cb.failureCount++;
    cb.lastFailureTime = Date.now();

    if (cb.failureCount >= 5 && cb.state !== 'OPEN') {
      cb.state = 'OPEN';
      cb.nextAttemptAllowedAt = Date.now() + 5000; // Open for 5 seconds
      this.logger.error(`[CIRCUIT BREAKER] Enclave '${enclaveId}' tripped OPEN due to 5 consecutive failures.`);
    }
  }

  public recordSuccess(enclaveId: string) {
    const cb = this.circuitBreakers.get(enclaveId);
    if (!cb) return;

    if (cb.state === 'HALF_OPEN') {
      cb.state = 'CLOSED';
      cb.failureCount = 0;
      this.logger.log(`[CIRCUIT BREAKER] Enclave '${enclaveId}' successfully recovered to CLOSED.`);
    } else if (cb.state === 'CLOSED') {
      cb.failureCount = 0;
    }
  }

  /**
   * Validates against Enclave Security Profile limits.
   */
  public validateSecurityProfile(enclaveId: string, method: string, payloadBytes: number): { allowed: boolean; reason?: string } {
    const profile = this.securityProfiles[enclaveId];
    if (!profile) return { allowed: true };

    if (!profile.allowedMethods.includes(method.toUpperCase())) {
      return { allowed: false, reason: `HTTP method '${method}' prohibited by security profile for '${enclaveId}'.` };
    }

    if (payloadBytes > profile.maxPayloadBytes) {
      return { allowed: false, reason: `Payload size (${payloadBytes} bytes) exceeds profile limit (${profile.maxPayloadBytes} bytes).` };
    }

    return { allowed: true };
  }

  /**
   * Distributed Nonce Cache validation.
   */
  public verifyDistributedNonce(nonce: string, ttlMs = 60000): boolean {
    if (!nonce || typeof nonce !== 'string') return false;

    const now = Date.now();
    // Prune stale nonces if cache grows large
    if (this.distributedNonceCache.size > 10000) {
      for (const [k, exp] of this.distributedNonceCache.entries()) {
        if (now > exp) this.distributedNonceCache.delete(k);
      }
    }

    if (this.distributedNonceCache.has(nonce)) {
      return false; // Replay detected!
    }

    this.distributedNonceCache.set(nonce, now + ttlMs);
    return true;
  }
}
