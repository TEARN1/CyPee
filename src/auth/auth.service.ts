import { Injectable, UnauthorizedException, BadRequestException, ConflictException, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../database/prisma.service';
import { AuditLogService } from '../audit/audit-log.service';
import { TotpService } from './totp.service';
import { LoginDto, RegisterDto } from './dto/login.dto';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { JwtPayload } from './interfaces/jwt-payload.interface';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly auditLog: AuditLogService,
    private readonly totpService: TotpService,
  ) {}

  /**
   * Verifies user email/password, checks if MFA is active, and either
   * requests MFA validation or creates the authenticated session.
   */
  async login(dto: LoginDto, ipAddress?: string, deviceInfo?: string) {
    const user = await this.prisma.user.findFirst({
      where: { email: dto.email },
      include: { tenant: true },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid email or password');
    }

    const isMatch = await bcrypt.compare(dto.password, user.passwordHash);
    if (!isMatch) {
      throw new UnauthorizedException('Invalid email or password');
    }

    // Check if MFA is enabled
    if (user.mfaEnabled) {
      if (!dto.mfaCode) {
        // MFA required flag
        return {
          mfaRequired: true,
          userId: user.id,
          message: 'MFA verification code required.',
        };
      }

      const verified = this.totpService.verifyCode(user.totpSecret || '', dto.mfaCode);
      if (!verified) {
        throw new UnauthorizedException('Invalid MFA verification code');
      }
    }

    // Successful login - generate token
    const session = await this.createSession(user.id, ipAddress, deviceInfo);
    const payload: JwtPayload = {
      sub: user.id,
      email: user.email,
      tenantId: user.tenantId,
      role: user.role,
      mfaVerified: user.mfaEnabled,
      sessionId: session.id,
    };

    const token = this.jwtService.sign(payload);

    await this.auditLog.log(user.tenantId, 'USER_LOGIN', `user:${user.id}`, {
      email: user.email,
      mfaVerified: user.mfaEnabled,
      sessionId: session.id,
    }, user.id);

    return {
      token,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        tenantId: user.tenantId,
        mfaEnabled: user.mfaEnabled,
      },
    };
  }

  /**
   * Handles tenant and admin user creation under isolated contexts.
   */
  async register(dto: RegisterDto) {
    const existing = await this.prisma.user.findFirst({
      where: { email: dto.email },
    });

    if (existing) {
      throw new ConflictException('Email address is already registered');
    }

    const passwordHash = await bcrypt.hash(dto.password, 10);

    // Create Tenant and Admin User inside transaction
    const result = await this.prisma.$transaction(async (tx) => {
      const tenant = await tx.tenant.create({
        data: {
          name: dto.tenantName,
          plan: 'FREE',
        },
      });

      const user = await tx.user.create({
        data: {
          tenantId: tenant.id,
          email: dto.email,
          passwordHash,
          role: 'ADMIN',
        },
      });

      return { tenant, user };
    });

    await this.auditLog.log(result.tenant.id, 'TENANT_REGISTERED', `tenant:${result.tenant.id}`, {
      adminEmail: result.user.email,
    }, result.user.id);

    return {
      message: 'Registration successful',
      userId: result.user.id,
      tenantId: result.tenant.id,
    };
  }

  /**
   * Generates a new TOTP key for MFA setup.
   */
  async enableMfaSetup(userId: string, tenantId: string) {
    const user = await this.prisma.user.findFirst({
      where: { id: userId, tenantId },
    });

    if (!user) throw new BadRequestException('User not found');
    if (user.mfaEnabled) throw new BadRequestException('MFA is already active');

    const setup = this.totpService.generateSecret();

    // Temporarily save secret
    await this.prisma.user.update({
      where: { id: userId },
      data: { totpSecret: setup.secret },
    });

    return {
      secret: setup.secret,
      qrMock: setup.qrMock,
      uri: setup.uri,
    };
  }

  /**
   * Verifies registration/enablement code and turns on MFA.
   */
  async confirmMfa(userId: string, tenantId: string, code: string) {
    const user = await this.prisma.user.findFirst({
      where: { id: userId, tenantId },
    });

    if (!user || !user.totpSecret) {
      throw new BadRequestException('MFA setup is not initialized');
    }

    const verified = this.totpService.verifyCode(user.totpSecret, code);
    if (!verified) {
      throw new BadRequestException('Invalid MFA verification code');
    }

    await this.prisma.user.update({
      where: { id: userId },
      data: { mfaEnabled: true },
    });

    await this.auditLog.log(tenantId, 'MFA_ENABLED', `user:${userId}`, {}, userId);

    return { success: true, message: 'MFA successfully activated' };
  }

  /**
   * Logs out the user by terminating the active session record.
   */
  async logout(sessionId: string, tenantId: string) {
    await this.prisma.userSession.deleteMany({
      where: { id: sessionId },
    });
    this.logger.log(`Session terminated: ${sessionId}`);
  }

  private async createSession(userId: string, ipAddress?: string, deviceInfo?: string) {
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7); // 7-day session duration

    const tokenHash = crypto.createHash('sha256').update(crypto.randomBytes(32)).digest('hex');

    return this.prisma.userSession.create({
      data: {
        userId,
        tokenHash,
        ipAddress,
        deviceInfo,
        expiresAt,
      },
    });
  }
}
