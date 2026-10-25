import { Injectable, Logger } from '@nestjs/common';
import * as crypto from 'crypto';

export interface KmsVaultMetadata {
  provider: 'LOCAL_ENCLAVE' | 'HASHICORP_VAULT' | 'AWS_KMS' | 'GCP_KMS';
  activeKeyVersion: string;
  isShredded: boolean;
  totalKeysLoaded: number;
}

@Injectable()
export class DbCryptoService {
  private readonly logger = new Logger(DbCryptoService.name);
  private readonly algorithm = 'aes-256-gcm';
  private keys: Map<string, Buffer> = new Map();
  private activeVersion = 'v1';
  private isKeyShredded = false;

  constructor() {
    this.initializeKeys();
  }

  private initializeKeys() {
    const rawKeyV1 =
      process.env.DB_ENCRYPTION_KEY ||
      process.env.ENCRYPTION_KEY ||
      process.env.JWT_SECRET ||
      'cypee-hardened-db-encryption-master-salt-2026';

    // Derive strict 32-byte (256-bit) key using SHA-256
    const keyV1 = crypto.createHash('sha256').update(rawKeyV1).digest();
    this.keys.set('v1', keyV1);

    // Support secondary rotation key if provided in environment (v2)
    if (process.env.DB_ENCRYPTION_KEY_V2) {
      const keyV2 = crypto.createHash('sha256').update(process.env.DB_ENCRYPTION_KEY_V2).digest();
      this.keys.set('v2', keyV2);
      this.activeVersion = 'v2';
      this.logger.log('KMS Vault initialized with active key version v2 (rotation ready)');
    } else {
      this.activeVersion = 'v1';
      this.logger.log('KMS Vault initialized with primary key version v1');
    }

    this.isKeyShredded = false;
  }

  /**
   * Encrypts plaintext using AES-256-GCM with a fresh 12-byte IV and 16-byte authentication tag.
   * Format: enc:<version>:<iv_hex>:<tag_hex>:<ciphertext_hex>
   */
  encrypt(plaintext: string, version = this.activeVersion): string {
    if (!plaintext) return plaintext;
    if (this.isEncrypted(plaintext)) return plaintext; // Prevent double encryption

    if (this.isKeyShredded) {
      throw new Error('[CRYPTO-SHRED ACTIVE] Master keys severed from RAM during breach lockdown. Decryption/Encryption halted.');
    }

    const key = this.keys.get(version);
    if (!key) {
      throw new Error(`Encryption failed: Key version ${version} not available in KMS Vault`);
    }

    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(this.algorithm, key, iv);

    let ciphertext = cipher.update(plaintext, 'utf8', 'hex');
    ciphertext += cipher.final('hex');
    const authTag = cipher.getAuthTag();

    return `enc:${version}:${iv.toString('hex')}:${authTag.toString('hex')}:${ciphertext}`;
  }

  /**
   * Decrypts AES-256-GCM ciphertext using the embedded key version (v1, v2, etc.).
   * If the text is unencrypted (legacy format), returns it safely as-is.
   */
  decrypt(ciphertext: string): string {
    if (!ciphertext) return ciphertext;
    if (!this.isEncrypted(ciphertext)) return ciphertext; // Legacy fallback

    if (this.isKeyShredded) {
      throw new Error('[CRYPTO-SHRED ACTIVE] Master keys severed from RAM during breach lockdown. Decryption/Encryption halted.');
    }

    try {
      const parts = ciphertext.split(':');
      if (parts.length !== 5 || parts[0] !== 'enc') {
        throw new Error('Invalid encryption payload format');
      }

      const version = parts[1];
      const iv = Buffer.from(parts[2], 'hex');
      const authTag = Buffer.from(parts[3], 'hex');
      const encryptedHex = parts[4];

      const key = this.keys.get(version);
      if (!key) {
        throw new Error(`Key version ${version} not found in KMS Key Store`);
      }

      const decipher = crypto.createDecipheriv(this.algorithm, key, iv);
      decipher.setAuthTag(authTag);

      let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
      decrypted += decipher.final('utf8');

      return decrypted;
    } catch (err: any) {
      this.logger.error(`Decryption failed or corrupted payload: ${err.message}`);
      throw new Error('Database field decryption failed: Authentication tag verification error');
    }
  }

  /**
   * Re-encrypts an existing ciphertext to the active key version for automated zero-downtime rotation.
   */
  reEncrypt(ciphertext: string, targetVersion = this.activeVersion): string {
    if (!this.isEncrypted(ciphertext)) {
      return this.encrypt(ciphertext, targetVersion);
    }
    const decrypted = this.decrypt(ciphertext);
    return this.encrypt(decrypted, targetVersion);
  }

  /**
   * Emergency Countermeasure: Zeroes out all cryptographic key buffers in RAM.
   * Once shredded, no sensitive data can be read or written until an authorized administrative restoration.
   */
  cryptoShred(): { success: boolean; message: string; timestamp: string } {
    this.logger.error('🚨 EMERGENCY CRYPTO-SHRED TRIGGERED! Overwriting in-memory cryptographic key buffers.');
    for (const [ver, buf] of this.keys.entries()) {
      buf.fill(0); // Cryptographically scrub memory buffer
    }
    this.keys.clear();
    this.isKeyShredded = true;

    return {
      success: true,
      message: 'Master encryption keys purged from memory. Database vault is cryptographically locked.',
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Restores encryption keys from an authorized master key or KMS secret.
   */
  restoreKey(masterKey: string, version = 'v1'): { success: boolean; activeVersion: string } {
    if (!masterKey || masterKey.length < 16) {
      throw new Error('Invalid master key: Minimum 16 characters required');
    }

    const keyBuf = crypto.createHash('sha256').update(masterKey).digest();
    this.keys.set(version, keyBuf);
    this.activeVersion = version;
    this.isKeyShredded = false;
    this.logger.warn(`KMS Vault keys reloaded. Master key version "${version}" active.`);

    return { success: true, activeVersion: this.activeVersion };
  }

  /**
   * Returns current KMS Vault status and metadata.
   */
  getVaultStatus(): KmsVaultMetadata {
    return {
      provider: process.env.KMS_PROVIDER ? (process.env.KMS_PROVIDER as any) : 'LOCAL_ENCLAVE',
      activeKeyVersion: this.activeVersion,
      isShredded: this.isKeyShredded,
      totalKeysLoaded: this.keys.size,
    };
  }

  /**
   * Checks if string has envelope encryption envelope marker
   */
  isEncrypted(text: string): boolean {
    return typeof text === 'string' && text.startsWith('enc:');
  }
}
