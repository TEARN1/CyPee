import { ForbiddenException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { OwnerGuard, isOwner } from './owner.guard';

const contextFor = (user: unknown) =>
  ({ switchToHttp: () => ({ getRequest: () => ({ user }) }) }) as any;

describe('OwnerGuard', () => {
  it('lets a listed owner through, whatever the case and spacing', () => {
    expect(isOwner('Owner@Example.com', ' other@example.com , owner@example.com')).toBe(true);
  });

  it('turns away tenant admins who are not owners, and everyone when no owner is set', () => {
    expect(isOwner('admin@tenant.com', 'owner@example.com')).toBe(false);
    expect(isOwner('owner@example.com', undefined)).toBe(false);
    expect(isOwner(undefined, 'owner@example.com')).toBe(false);
  });

  it('throws Forbidden for a signed-in non-owner', () => {
    const guard = new OwnerGuard({ get: () => 'owner@example.com' } as unknown as ConfigService);
    expect(() => guard.canActivate(contextFor({ email: 'admin@tenant.com', role: 'ADMIN' }))).toThrow(ForbiddenException);
    expect(guard.canActivate(contextFor({ email: 'owner@example.com' }))).toBe(true);
  });
});
