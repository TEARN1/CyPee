import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';

@Injectable()
export class ApiKeyGuard implements CanActivate {
  constructor(private readonly configService: ConfigService) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    const apiKey = request.headers['x-api-key'];

    // No default: a key printed in the repository would let anyone in. Unset, nobody passes.
    const expectedKey = this.configService.get<string>('API_KEY') ?? '';
    if (expectedKey.length < 16) {
      throw new UnauthorizedException('Access denied. The server has no API key set.');
    }

    if (!apiKey || typeof apiKey !== 'string') {
      throw new UnauthorizedException('Access denied. Invalid or missing X-API-KEY header.');
    }

    const actualBuf = Buffer.from(apiKey, 'utf8');
    const expectedBuf = Buffer.from(expectedKey, 'utf8');

    if (actualBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(actualBuf, expectedBuf)) {
      throw new UnauthorizedException('Access denied. Invalid or missing X-API-KEY header.');
    }

    return true;
  }
}
