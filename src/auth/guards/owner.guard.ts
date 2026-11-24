import { CanActivate, ExecutionContext, ForbiddenException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

/**
 * System-wide actions (shredding the keys, quarantining an app, adding a proxy
 * target, a database backup) belong to the people who run this CyPee, not to
 * every tenant admin: anyone allowed to register becomes the admin of their own
 * tenant. Owners are the emails in CYPEE_OWNER_EMAILS (comma-separated); with
 * none set, nobody can run these actions. Use after JwtAuthGuard.
 */
@Injectable()
export class OwnerGuard implements CanActivate {
  constructor(private readonly config: ConfigService) {}

  canActivate(context: ExecutionContext): boolean {
    const user = context.switchToHttp().getRequest().user as { email?: string } | undefined;
    if (!isOwner(user?.email, this.config.get<string>('CYPEE_OWNER_EMAILS'))) {
      throw new ForbiddenException('Only the owners of this CyPee can do this.');
    }
    return true;
  }
}

export function isOwner(email: string | undefined, ownerList: string | undefined): boolean {
  if (!email) return false;
  const owners = (ownerList ?? '')
    .split(',')
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean);
  return owners.includes(email.trim().toLowerCase());
}
