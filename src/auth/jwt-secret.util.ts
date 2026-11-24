import { ConfigService } from '@nestjs/config';

/**
 * Reads JWT_SECRET from config. Throws instead of falling back to a
 * hardcoded default, since a known default would let anyone forge tokens
 * on any deployment that forgets to set the env var.
 */
export function getRequiredJwtSecret(configService: ConfigService): string {
  const secret = configService.get<string>('JWT_SECRET');
  if (!secret) {
    throw new Error('JWT_SECRET environment variable must be set.');
  }
  // A short secret can be guessed offline from one captured token, and then
  // any token can be forged (penetration test, Nov 2026). 32+ characters.
  if (secret.length < 32 || /^(.)\1+$/.test(secret) || /replace-with|changeme|example|placeholder/i.test(secret)) {
    throw new Error('JWT_SECRET must be at least 32 random characters (openssl rand -hex 32).');
  }
  return secret;
}
