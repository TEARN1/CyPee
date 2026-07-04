import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { JwtPayload } from '../interfaces/jwt-payload.interface';
import { PrismaService } from '../../database/prisma.service';
import { getRequiredJwtSecret } from '../jwt-secret.util';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private readonly configService: ConfigService,
    private readonly prisma: PrismaService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: getRequiredJwtSecret(configService),
    });
  }

  /**
   * Validates the payload and makes sure the session hasn't been terminated.
   */
  async validate(payload: JwtPayload) {
    // Verify session is still active in database
    const session = await this.prisma.userSession.findUnique({
      where: { id: payload.sessionId },
    });

    if (!session) {
      throw new UnauthorizedException('Session has expired or been terminated');
    }

    // Return request context user object
    return {
      id: payload.sub,
      email: payload.email,
      tenantId: payload.tenantId,
      role: payload.role,
      mfaVerified: payload.mfaVerified,
      sessionId: payload.sessionId,
    };
  }
}
