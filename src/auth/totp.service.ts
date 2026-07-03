import { Injectable } from '@nestjs/common';
import * as crypto from 'crypto';

@Injectable()
export class TotpService {
  /**
   * Generates a random base32 secret for TOTP (e.g. Google Authenticator).
   */
  generateSecret(length = 20): { secret: string; uri: string; qrMock: string } {
    const buffer = crypto.randomBytes(length);
    // Base32 encoding alphabet
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let secret = '';
    for (let i = 0; i < buffer.length; i++) {
      secret += alphabet[buffer[i] % 32];
    }

    const label = encodeURIComponent('dev@shield.io');
    const issuer = encodeURIComponent('Shield Security');
    const uri = `otpauth://totp/${issuer}:${label}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
    
    return {
      secret,
      uri,
      // Provide a mock QR code render URL using chart api
      qrMock: `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(uri)}`,
    };
  }

  /**
   * Verifies a 6-digit TOTP code against the secret.
   * Supports a window of 1 interval (30 seconds) back and forward.
   */
  verifyCode(secret: string, code: string, window = 1): boolean {
    const cleanCode = code.replace(/\s+/g, '');
    if (!/^\d{6}$/.test(cleanCode)) return false;

    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    // Decode base32 secret back to bytes
    const secretBytes: number[] = [];
    let buffer = 0;
    let bits = 0;
    for (let i = 0; i < secret.length; i++) {
      const val = alphabet.indexOf(secret[i].toUpperCase());
      if (val === -1) continue;
      buffer = (buffer << 5) | val;
      bits += 5;
      if (bits >= 8) {
        bits -= 8;
        secretBytes.push((buffer >> bits) & 0xff);
      }
    }
    const key = Buffer.from(secretBytes);

    const currentTime = Math.floor(Date.now() / 1000 / 30);

    // Check window
    for (let i = -window; i <= window; i++) {
      const time = currentTime + i;
      // Convert time block to 8-byte big-endian buffer
      const timeBuffer = Buffer.alloc(8);
      let temp = time;
      for (let j = 7; j >= 0; temp = Math.floor(temp / 256), j--) {
        timeBuffer[j] = temp & 0xff;
      }

      // HMAC-SHA1
      const hmac = crypto.createHmac('sha1', key).update(timeBuffer).digest();
      
      // Dynamic truncation
      const offset = hmac[hmac.length - 1] & 0xf;
      const codeBytes =
        ((hmac[offset] & 0x7f) << 24) |
        ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) |
        (hmac[offset + 3] & 0xff);

      const generatedCode = (codeBytes % 1_000_000).toString().padStart(6, '0');

      if (generatedCode === cleanCode) {
        return true;
      }
    }

    return false;
  }
}
