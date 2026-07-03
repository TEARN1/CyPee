export interface JwtPayload {
  sub: string;       // User ID
  email: string;
  tenantId: string;
  role: string;
  mfaVerified: boolean;
  sessionId: string;
}
