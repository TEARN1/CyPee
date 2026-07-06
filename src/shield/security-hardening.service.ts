import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';
import Redis from 'ioredis';

@Injectable()
export class SecurityHardeningService implements OnModuleInit {
  private readonly logger = new Logger(SecurityHardeningService.name);
  private redisClient: Redis | null = null;
  private activeLocks = new Set<string>();
  private revokedTokens = new Set<string>();

  constructor(private readonly configService: ConfigService) {}

  onModuleInit() {
    const isMock = this.configService.get<string>('REDIS_MOCK', 'true') === 'true';
    if (!isMock) {
      try {
        const host = this.configService.get<string>('REDIS_HOST', 'localhost');
        const port = this.configService.get<number>('REDIS_PORT', 6379);
        this.redisClient = new Redis({
          host,
          port,
          lazyConnect: true,
        });
        
        this.redisClient.connect().catch((err) => {
          this.logger.warn(`Redis connection failed for Hardening: ${err.message}. Falling back to in-memory.`);
          this.redisClient = null;
        });
      } catch (err: any) {
        this.logger.warn(`Failed to initialize Redis client: ${err.message}. Falling back to in-memory.`);
      }
    }
  }

  /**
   * 1. Constant-Time Comparison Utility (Prevents Timing Attacks)
   */
  timingSafeCompare(str1: string, str2: string): boolean {
    if (!str1 || !str2) return false;
    const buf1 = Buffer.from(str1, 'utf8');
    const buf2 = Buffer.from(str2, 'utf8');

    if (buf1.length !== buf2.length) {
      crypto.timingSafeEqual(buf1, buf1);
      return false;
    }

    return crypto.timingSafeEqual(buf1, buf2);
  }

  /**
   * 2. Key-Based Lock Manager (Mitigates Concurrency Race Conditions)
   * Acquires a lock on a key. Supports distributed Redis locks with local fallback.
   */
  async acquireLock(key: string): Promise<boolean> {
    if (this.redisClient) {
      try {
        // Set key with 5s expiration, only if not exists (NX)
        const res = await this.redisClient.set(key, 'locked', 'EX', 5, 'NX');
        return res === 'OK';
      } catch (err: any) {
        this.logger.warn(`Redis acquireLock failed: ${err.message}. Falling back to in-memory.`);
      }
    }

    if (this.activeLocks.has(key)) {
      this.logger.warn(`[CONCURRENCY BLOCK] Concurrent operation blocked on active in-memory lock key: "${key}"`);
      return false;
    }
    this.activeLocks.add(key);
    return true;
  }

  /**
   * Releases a lock on a key.
   */
  async releaseLock(key: string): Promise<void> {
    if (this.redisClient) {
      try {
        await this.redisClient.del(key);
        return;
      } catch (err: any) {
        this.logger.warn(`Redis releaseLock failed: ${err.message}. Falling back to in-memory.`);
      }
    }
    this.activeLocks.delete(key);
  }

  /**
   * 3. HTTP Parameter Pollution (HPP) Sanitizer
   */
  sanitizeHpp(query: Record<string, any>): Record<string, string> {
    const sanitized: Record<string, string> = {};
    for (const [key, value] of Object.entries(query)) {
      if (Array.isArray(value)) {
        this.logger.warn(`[HPP DETECTED] Duplicate parameter array flattened for key: "${key}"`);
        sanitized[key] = String(value[0]);
      } else {
        sanitized[key] = String(value);
      }
    }
    return sanitized;
  }

  /**
   * 4. Token Revocation Store
   */
  async revokeToken(tokenHash: string): Promise<void> {
    if (this.redisClient) {
      try {
        await this.redisClient.sadd('revoked_tokens', tokenHash);
        return;
      } catch (err: any) {
        this.logger.warn(`Redis revokeToken failed: ${err.message}. Falling back to in-memory.`);
      }
    }
    this.revokedTokens.add(tokenHash);
  }

  /**
   * Checks if token is blacklisted.
   */
  async isTokenRevoked(tokenHash: string): Promise<boolean> {
    if (this.redisClient) {
      try {
        const member = await this.redisClient.sismember('revoked_tokens', tokenHash);
        return member === 1;
      } catch (err: any) {
        this.logger.warn(`Redis isTokenRevoked failed: ${err.message}. Falling back to in-memory.`);
      }
    }
    return this.revokedTokens.has(tokenHash);
  }
}
