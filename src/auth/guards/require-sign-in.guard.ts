import { ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtAuthGuard } from './jwt-auth.guard';
import { IS_PUBLIC } from '../public.decorator';

/**
 * Global: every route needs a signed-in user unless it is marked @Public().
 * New routes are safe by default, instead of open until someone remembers a
 * guard (main added three open controllers in one week).
 */
@Injectable()
export class RequireSignInGuard extends JwtAuthGuard {
  constructor(private readonly reflector: Reflector) {
    super();
  }

  canActivate(context: ExecutionContext) {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC, [context.getHandler(), context.getClass()]);
    if (isPublic) return true;
    return super.canActivate(context);
  }
}
