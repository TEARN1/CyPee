import { SetMetadata } from '@nestjs/common';

/** Marks a route that needs no sign-in. Every other route does (RequireSignInGuard). */
export const IS_PUBLIC = 'cypee:isPublic';
export const Public = () => SetMetadata(IS_PUBLIC, true);
