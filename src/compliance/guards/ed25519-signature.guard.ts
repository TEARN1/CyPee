import { CanActivate, ExecutionContext, Injectable, UnauthorizedException, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';

@Injectable()
export class Ed25519SignatureGuard implements CanActivate {
  private readonly logger = new Logger(Ed25519SignatureGuard.name);
  private readonly clientPublicKey: crypto.KeyObject;

  constructor(private readonly configService: ConfigService) {
    const rawPublicKeyPem = this.configService.get<string>('CLIENT_ED25519_PUBLIC_KEY');
    
    if (!rawPublicKeyPem) {
      this.logger.warn('CLIENT_ED25519_PUBLIC_KEY is undefined. Falling back to an ephemeral public key for testing.');
      // Generate a temporary key pair to prevent startup crashes
      const { publicKey } = crypto.generateKeyPairSync('ed25519');
      this.clientPublicKey = publicKey;
    } else {
      try {
        this.clientPublicKey = crypto.createPublicKey({
          key: rawPublicKeyPem,
          format: 'pem',
          type: 'spki',
        });
      } catch (error) {
        this.logger.error(`Failed to load Ed25519 public key: ${error.message}`);
        throw error;
      }
    }
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const signatureBase64 = request.headers['x-sast-signature'];
    const timestamp = request.headers['x-sast-timestamp'];

    if (!signatureBase64 || !timestamp) {
      throw new UnauthorizedException('Authentication Failed: x-sast-signature or x-sast-timestamp header is missing.');
    }

    // Prevent Replay Attacks (Reject requests older than 120 seconds)
    const timeDifference = Math.abs(Date.now() - parseInt(timestamp, 10));
    if (timeDifference > 120000) {
      throw new UnauthorizedException('Authentication Failed: Timestamp replay boundary exceeded.');
    }

    // Use raw request body buffer if available, otherwise fallback
    const rawBody = request.rawBody || Buffer.from('', 'utf8');
    
    // Construct Signature Verification Input: timestamp + '.' + rawBody
    const verificationData = Buffer.concat([
      Buffer.from(timestamp + '.', 'utf8'),
      rawBody
    ]);
    const signatureBuffer = Buffer.from(signatureBase64, 'base64');

    try {
      const isVerified = crypto.verify(
        null, // Algorithm is inferred from key structure (Ed25519)
        verificationData,
        this.clientPublicKey,
        signatureBuffer
      );

      if (!isVerified) {
        throw new UnauthorizedException('Authentication Failed: Invalid cryptographic payload signature.');
      }
    } catch (error) {
      this.logger.error(`Cryptographic verification exception: ${error.message}`);
      throw new UnauthorizedException('Authentication Failed: Signature verification error.');
    }

    return true;
  }
}
