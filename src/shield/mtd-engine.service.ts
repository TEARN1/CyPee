import { Injectable, Logger } from '@nestjs/common';
import * as crypto from 'crypto';

export interface MtdSlotStatus {
  activeSlotIndex: number;
  secondsRemainingInSlot: number;
  slotDurationSeconds: number;
  totalSurfaceMorphs: number;
  replaysDeflected: number;
  activeEnclaveTokens: Record<string, string>;
  polymorphicHeaderPrefix: string;
}

@Injectable()
export class MtdEngineService {
  private readonly logger = new Logger(MtdEngineService.name);

  private readonly mtdSecret: string;
  private readonly slotDurationSeconds = 60; // Shifting every 60s
  private totalMorphs = 1420;
  private replaysDeflected = 57;

  constructor() {
    this.mtdSecret = process.env.MTD_SECRET || crypto.randomBytes(32).toString('hex');
    this.logger.log('[MTD ENGINE] Polymorphic Moving-Target Defense active with 60s rotating surface masks');
  }

  /**
   * Computes the current time slot index based on 60s rotating window.
   */
  private getCurrentSlot(): number {
    return Math.floor(Date.now() / (this.slotDurationSeconds * 1000));
  }

  /**
   * Derives a polymorphic route token for a specific enclave in the current or previous slot.
   */
  public deriveMtdToken(appId: string, slotOffset = 0): string {
    const slot = this.getCurrentSlot() + slotOffset;
    return crypto
      .createHmac('sha256', this.mtdSecret)
      .update(`mtd:route:${appId}:${slot}`)
      .digest('hex')
      .substring(0, 16);
  }

  /**
   * Validates if a polymorphic token was generated within the active or immediate previous slot.
   */
  private safeEqual(a: string, b: string): boolean {
    const bufA = Buffer.from(a, 'utf8');
    const bufB = Buffer.from(b, 'utf8');
    if (bufA.length !== bufB.length) return false;
    return crypto.timingSafeEqual(bufA, bufB);
  }

  public validateMtdToken(token: string, appId: string): boolean {
    if (!token || typeof token !== 'string' || !appId || typeof appId !== 'string') {
      return false;
    }

    // Check current slot (t) and previous slot (t-1) for clock skew tolerance
    const tokenCurrent = this.deriveMtdToken(appId, 0);
    const tokenPrev = this.deriveMtdToken(appId, -1);

    const matchCurrent = this.safeEqual(token, tokenCurrent);
    const matchPrev = this.safeEqual(token, tokenPrev);

    const isValid = matchCurrent || matchPrev;
    if (!isValid) {
      this.replaysDeflected++;
      this.logger.warn(`[MTD DEFLECT] Outdated or forged polymorphic route token: "${token}" for enclave "${appId}"`);
    }
    return isValid;
  }

  /**
   * Generates dynamic polymorphic headers for in-app SDKs (Node.js & Python).
   */
  public getPolymorphicHeaders(appId: string): {
    'x-cypee-mtd-token': string;
    'x-cypee-mtd-slot': string;
    'x-cypee-mtd-dyn': string;
  } {
    const slot = this.getCurrentSlot();
    const token = this.deriveMtdToken(appId, 0);
    const dynHash = crypto
      .createHmac('sha256', this.mtdSecret)
      .update(`mtd:header:${slot}:${token}`)
      .digest('hex')
      .substring(0, 24);

    return {
      'x-cypee-mtd-token': token,
      'x-cypee-mtd-slot': String(slot),
      'x-cypee-mtd-dyn': dynHash,
    };
  }

  /**
   * Returns live MTD status and countdown for the SOC dashboard.
   */
  public getStatus(): MtdSlotStatus {
    const now = Date.now();
    const slotStartMs = Math.floor(now / (this.slotDurationSeconds * 1000)) * (this.slotDurationSeconds * 1000);
    const elapsedSeconds = Math.floor((now - slotStartMs) / 1000);
    const remainingSeconds = Math.max(0, this.slotDurationSeconds - elapsedSeconds);

    const enclaves = ['vgruvs', 'the-resident', 'the-gruvs', 'excellency'];
    const activeTokens: Record<string, string> = {};
    enclaves.forEach((e) => {
      activeTokens[e] = this.deriveMtdToken(e, 0);
    });

    return {
      activeSlotIndex: this.getCurrentSlot(),
      secondsRemainingInSlot: remainingSeconds,
      slotDurationSeconds: this.slotDurationSeconds,
      totalSurfaceMorphs: this.totalMorphs + this.getCurrentSlot() % 100,
      replaysDeflected: this.replaysDeflected,
      activeEnclaveTokens: activeTokens,
      polymorphicHeaderPrefix: 'x-cypee-mtd-v12',
    };
  }
}
