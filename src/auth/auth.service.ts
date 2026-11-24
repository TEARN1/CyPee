import { HttpException, HttpStatus, Injectable, UnauthorizedException, BadRequestException, ConflictException, ForbiddenException, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../database/prisma.service';
import { DbCryptoService } from '../database/db-crypto.service';
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
    private readonly dbCrypto: DbCryptoService,
    private readonly jwtService: JwtService,
    private readonly auditLog: AuditLogService,
    private readonly totpService: TotpService,
  ) {}

  /**
   * Verifies user email/password, checks if MFA is active, and either
   * requests MFA validation or creates the authenticated session.
   */
  // Wrong passwords or codes per account: after MAX_FAILURES in the window,
  // sign-in for that account waits until the window passes.
  private static readonly MAX_FAILURES = 5;
  private static readonly WINDOW_MS = 15 * 60 * 1000;
  private readonly failures = new Map<string, number[]>();
  // Compared against when the account does not exist, so both take as long.
  private static readonly DUMMY_HASH = bcrypt.hashSync('not-a-real-password', 10);

  private recentFailures(key: string): number[] {
    const since = Date.now() - AuthService.WINDOW_MS;
    const list = (this.failures.get(key) ?? []).filter((t) => t > since);
    if (list.length) this.failures.set(key, list);
    else this.failures.delete(key);
    return list;
  }

  private fail(key: string, message: string): never {
    if (this.failures.size > 10_000) this.failures.clear();
    this.failures.set(key, [...this.recentFailures(key), Date.now()]);
    throw new UnauthorizedException(message);
  }

  async login(dto: LoginDto, ipAddress?: string, deviceInfo?: string) {
    const key = dto.email.trim().toLowerCase();
    if (this.recentFailures(key).length >= AuthService.MAX_FAILURES) {
      throw new HttpException('Too many failed sign-ins for this account. Try again in 15 minutes.', HttpStatus.TOO_MANY_REQUESTS);
    }

    const user = await this.prisma.user.findFirst({
      where: { email: dto.email },
      include: { tenant: true },
    });

    const isMatch = await bcrypt.compare(dto.password, user?.passwordHash ?? AuthService.DUMMY_HASH);
    if (!user || !isMatch) {
      this.fail(key, 'Invalid email or password');
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

      const secret = user.totpSecret ? this.dbCrypto.decrypt(user.totpSecret) : '';
      const verified = this.totpService.verifyCode(secret, dto.mfaCode);
      if (!verified) {
        this.fail(key, 'Invalid MFA verification code');
      }
    }

    this.failures.delete(key);

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
    // Every registration creates a tenant admin, so after the first account
    // registration is closed unless CYPEE_ALLOW_REGISTRATION=true.
    if (process.env.CYPEE_ALLOW_REGISTRATION !== 'true' && (await this.prisma.user.count()) > 0) {
      throw new ForbiddenException('Registration is closed. Ask an owner of this CyPee to add you.');
    }

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

    // Save secret with AES-256-GCM envelope encryption at rest
    const encryptedSecret = this.dbCrypto.encrypt(setup.secret);
    await this.prisma.user.update({
      where: { id: userId },
      data: { totpSecret: encryptedSecret },
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

    const decryptedSecret = this.dbCrypto.decrypt(user.totpSecret);
    const verified = this.totpService.verifyCode(decryptedSecret, code);
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
   * Logs out the user by terminating the active session record scoped to the tenant.
   */
  async logout(sessionId: string, tenantId: string) {
    await this.prisma.userSession.deleteMany({
      where: {
        id: sessionId,
        user: { tenantId },
      },
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
