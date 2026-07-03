import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class ApiKeyGuard implements CanActivate {
  constructor(private readonly configService: ConfigService) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    const apiKey = request.headers['x-api-key'];

    // Retrieve the authorized API key from configs. Default to a test key for development convenience.
    const expectedKey = this.configService.get<string>('API_KEY', 'sast-engine-dev-token-98765');

    if (!apiKey || apiKey !== expectedKey) {
      throw new UnauthorizedException('Access denied. Invalid or missing X-API-KEY header.');
    }

    return true;
  }
}
