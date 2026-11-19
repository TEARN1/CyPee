import { ExecutionContext, ForbiddenException, Injectable } from '@nestjs/common';
import { JwtAuthGuard } from './jwt-auth.guard';

/**
 * For fleet-wide controls (key shredding and restore, quarantine, key
 * rotation, attacker dossiers, backups). Anyone can register a tenant and
 * become its ADMIN, so a login alone is not enough: the caller must be an
 * ADMIN whose email is listed in CYPEE_OPERATOR_EMAILS (comma-separated).
 * With that list unset, nobody passes.
 */
@Injectable()
export class OperatorGuard extends JwtAuthGuard {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    if (!(await super.canActivate(context))) return false;
    const user = context.switchToHttp().getRequest().user as { email?: string; role?: string } | undefined;
    if (!isOperator(user, process.env.CYPEE_OPERATOR_EMAILS)) {
      throw new ForbiddenException('Operator access only');
    }
    return true;
  }
}

export function isOperator(user: { email?: string; role?: string } | undefined, operatorEmails: string | undefined): boolean {
  const allowed = (operatorEmails ?? '')
    .split(',')
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean);
  if (allowed.length === 0 || !user || user.role !== 'ADMIN' || typeof user.email !== 'string') return false;
  return allowed.includes(user.email.trim().toLowerCase());
}
