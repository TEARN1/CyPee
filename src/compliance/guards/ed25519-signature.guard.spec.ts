import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { Ed25519SignatureGuard } from './ed25519-signature.guard';
import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import * as crypto from 'crypto';

describe('Ed25519SignatureGuard', () => {
  let guard: Ed25519SignatureGuard;
  let privateKey: crypto.KeyObject;
  let publicKeyPem: string;

  beforeAll(() => {
    // Generate static key pair for testing
    const keys = crypto.generateKeyPairSync('ed25519');
    privateKey = keys.privateKey;
    publicKeyPem = keys.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  });

  beforeEach(async () => {
    const mockConfigService = {
      get: jest.fn().mockImplementation((key: string) => {
        if (key === 'CLIENT_ED25519_PUBLIC_KEY') {
          return publicKeyPem;
        }
        return null;
      }),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        Ed25519SignatureGuard,
        { provide: ConfigService, useValue: mockConfigService },
      ],
    }).compile();

    guard = module.get<Ed25519SignatureGuard>(Ed25519SignatureGuard);
  });

  it('should be defined', () => {
    expect(guard).toBeDefined();
  });

  function createMockExecutionContext(headers: Record<string, string>, body: any): ExecutionContext {
    const req = {
      headers,
      body,
      rawBody: Buffer.from(JSON.stringify(body), 'utf8'),
    };
    return {
      switchToHttp: () => ({
        getRequest: () => req,
      }),
    } as any;
  }

  describe('canActivate', () => {
    it('should allow activation when a valid Ed25519 signature is provided', async () => {
      const body = { findings: [] };
      const timestamp = Date.now().toString();
      const bodyStr = JSON.stringify(body);
      const signData = Buffer.from(timestamp + '.' + bodyStr, 'utf8');

      // Generate signature
      const signatureBuffer = crypto.sign(null, signData, privateKey);
      const signatureBase64 = signatureBuffer.toString('base64');

      const context = createMockExecutionContext(
        {
          'x-sast-signature': signatureBase64,
          'x-sast-timestamp': timestamp,
        },
        body
      );

      const result = await guard.canActivate(context);
      expect(result).toBe(true);
    });

    it('should throw UnauthorizedException if headers are missing', async () => {
      const context = createMockExecutionContext({}, { findings: [] });
      
      await expect(guard.canActivate(context)).rejects.toThrow(
        new UnauthorizedException('Authentication Failed: x-sast-signature or x-sast-timestamp header is missing.')
      );
    });

    it('should throw UnauthorizedException if timestamp replay boundary is exceeded', async () => {
      const body = { findings: [] };
      const oldTimestamp = (Date.now() - 200000).toString(); // > 120 seconds old
      
      const context = createMockExecutionContext(
        {
          'x-sast-signature': 'somesignature',
          'x-sast-timestamp': oldTimestamp,
        },
        body
      );

      await expect(guard.canActivate(context)).rejects.toThrow(
        new UnauthorizedException('Authentication Failed: Timestamp replay boundary exceeded.')
      );
    });

    it('should throw UnauthorizedException if signature is invalid', async () => {
      const body = { findings: [] };
      const timestamp = Date.now().toString();
      
      const context = createMockExecutionContext(
        {
          'x-sast-signature': Buffer.from('invalid-sig').toString('base64'),
          'x-sast-timestamp': timestamp,
        },
        body
      );

      await expect(guard.canActivate(context)).rejects.toThrow(
        new UnauthorizedException('Authentication Failed: Signature verification error.')
      );
    });
  });
});
