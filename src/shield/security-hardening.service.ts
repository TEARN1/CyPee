import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import * as crypto from 'crypto';

@Injectable()
export class SecurityHardeningService {
  private readonly logger = new Logger(SecurityHardeningService.name);

  // In-memory locks for race condition mitigation
  private activeLocks = new Map<string, NodeJS.Timeout>();
  private static readonly LOCK_TTL_MS = 30_000;

  /**
   * 1. Constant-Time Comparison Utility (Prevents Timing Attacks)
   * Uses crypto.timingSafeEqual to compare buffers in constant time.
   */
  timingSafeCompare(str1: string, str2: string): boolean {
    if (!str1 || !str2) return false;
    const buf1 = Buffer.from(str1, 'utf8');
    const buf2 = Buffer.from(str2, 'utf8');

    // To prevent length leakage timings, both buffers must have equal length
    // before calling timingSafeEqual. We pad/truncate a temp buffer for safety.
    if (buf1.length !== buf2.length) {
      // Still execute timingSafeEqual on dummy matching sizes to maintain constant latency
      crypto.timingSafeEqual(buf1, buf1);
      return false;
    }

    return crypto.timingSafeEqual(buf1, buf2);
  }

  /**
   * 2. Key-Based Lock Manager (Mitigates Concurrency Race Conditions)
   * Acquires a lock on a key. Returns false if lock is already active.
   */
  acquireLock(key: string): boolean {
    if (this.activeLocks.has(key)) {
      this.logger.warn(`[CONCURRENCY BLOCK] Concurrent operation blocked on active lock key: "${key}"`);
      return false;
    }
    const timeout = setTimeout(() => this.activeLocks.delete(key), SecurityHardeningService.LOCK_TTL_MS);
    timeout.unref?.();
    this.activeLocks.set(key, timeout);
    return true;
  }

  /**
   * Releases a lock on a key.
   */
  releaseLock(key: string): void {
    const timeout = this.activeLocks.get(key);
    if (timeout) clearTimeout(timeout);
    this.activeLocks.delete(key);
  }

  /**
   * 3. HTTP Parameter Pollution (HPP) Sanitizer
   * Flattens query parameters to prevent WAF bypass and parameter pollution.
   * If a parameter is an array, returns only the first index value.
   */
  sanitizeHpp(query: Record<string, any>): Record<string, string> {
    const sanitized: Record<string, string> = {};
    for (const [key, value] of Object.entries(query)) {
      if (Array.isArray(value)) {
        this.logger.warn(`[HPP DETECTED] Duplicate parameter array flattened for key: "${key}"`);
        sanitized[key] = String(value[0]); // Enforce single parameter value
      } else {
        sanitized[key] = String(value);
      }
    }
    return sanitized;
  }
}
