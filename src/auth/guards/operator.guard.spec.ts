import { UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { isOperator } from './operator.guard';
import { ApiKeyGuard } from '../../compliance/guards/api-key.guard';

describe('isOperator', () => {
  const admin = { email: 'Owner@Example.com', role: 'ADMIN' };

  it('lets in only a listed ADMIN', () => {
    expect(isOperator(admin, 'owner@example.com, other@example.com')).toBe(true);
    expect(isOperator({ ...admin, role: 'ENGINEER' }, 'owner@example.com')).toBe(false);
    expect(isOperator({ email: 'tenant-admin@example.com', role: 'ADMIN' }, 'owner@example.com')).toBe(false);
  });

  it('lets nobody in when no operator is listed', () => {
    expect(isOperator(admin, undefined)).toBe(false);
    expect(isOperator(admin, '  ,  ')).toBe(false);
    expect(isOperator(undefined, 'owner@example.com')).toBe(false);
  });
});

describe('ApiKeyGuard', () => {
  const context = (key?: string) =>
    ({ switchToHttp: () => ({ getRequest: () => ({ headers: key ? { 'x-api-key': key } : {} }) }) }) as any;
  const guard = (configured?: string) => new ApiKeyGuard(new ConfigService(configured === undefined ? {} : { API_KEY: configured }));

  it('refuses everyone when the server has no key, including the old published default', () => {
    expect(() => guard().canActivate(context('sast-engine-dev-token-98765'))).toThrow(UnauthorizedException);
    expect(() => guard('short').canActivate(context('short'))).toThrow(UnauthorizedException);
  });

  it('accepts only the configured key', () => {
    const key = 'a-long-random-api-key-0123456789';
    expect(guard(key).canActivate(context(key))).toBe(true);
    expect(() => guard(key).canActivate(context('wrong-key-0123456789abcdef'))).toThrow(UnauthorizedException);
    expect(() => guard(key).canActivate(context())).toThrow(UnauthorizedException);
  });
});
