import { Injectable, Logger } from '@nestjs/common';
import * as crypto from 'crypto';

@Injectable()
export class DbCryptoService {
  private readonly logger = new Logger(DbCryptoService.name);
  private readonly algorithm = 'aes-256-gcm';
  private readonly key: Buffer;

  constructor() {
    const rawKey =
      process.env.DB_ENCRYPTION_KEY ||
      process.env.ENCRYPTION_KEY ||
      process.env.JWT_SECRET ||
      'cypee-hardened-db-encryption-master-salt-2026';

    // Derive strict 32-byte (256-bit) key using SHA-256
    this.key = crypto.createHash('sha256').update(rawKey).digest();

    if (!process.env.DB_ENCRYPTION_KEY && !process.env.ENCRYPTION_KEY) {
      this.logger.warn(
        'DB_ENCRYPTION_KEY not explicitly configured in .env. Using fallback derived key. For maximum security, define DB_ENCRYPTION_KEY in production.',
      );
    }
  }

  /**
   * Encrypts plaintext using AES-256-GCM with a fresh 12-byte IV and 16-byte authentication tag.
   * Output format: enc:v1:<iv_hex>:<tag_hex>:<ciphertext_hex>
   */
  encrypt(plaintext: string): string {
    if (!plaintext) return plaintext;
    if (this.isEncrypted(plaintext)) return plaintext; // Prevent double encryption

    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(this.algorithm, this.key, iv);

    let ciphertext = cipher.update(plaintext, 'utf8', 'hex');
    ciphertext += cipher.final('hex');
    const authTag = cipher.getAuthTag();

    return `enc:v1:${iv.toString('hex')}:${authTag.toString('hex')}:${ciphertext}`;
  }

  /**
   * Decrypts AES-256-GCM ciphertext.
   * If the text is unencrypted (legacy format), returns it safely as-is.
   */
  decrypt(ciphertext: string): string {
    if (!ciphertext) return ciphertext;
    if (!this.isEncrypted(ciphertext)) return ciphertext; // Legacy fallback

    try {
      const parts = ciphertext.split(':');
      if (parts.length !== 5 || parts[0] !== 'enc' || parts[1] !== 'v1') {
        throw new Error('Invalid encryption payload format');
      }

      const iv = Buffer.from(parts[2], 'hex');
      const authTag = Buffer.from(parts[3], 'hex');
      const encryptedHex = parts[4];

      const decipher = crypto.createDecipheriv(this.algorithm, this.key, iv);
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
   * Checks if string has envelope encryption envelope marker
   */
  isEncrypted(text: string): boolean {
    return typeof text === 'string' && text.startsWith('enc:v1:');
  }
}
