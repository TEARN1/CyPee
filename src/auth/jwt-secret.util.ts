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
  return secret;
}
