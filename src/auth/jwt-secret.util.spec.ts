import { getRequiredJwtSecret } from './jwt-secret.util';

const config = (value?: string) => ({ get: () => value }) as never;

// Pentest: a weak signing secret lets anyone crack it from one token and forge any user's.
describe('JWT_SECRET', () => {
  it.each([undefined, '', 'secret', 'changeme', 'replace-with-64-byte-cryptographic-jwt-secret'.slice(0, 31), 'replace-with-64-byte-cryptographic-jwt-secret', // the .env.example placeholder
     'a'.repeat(64)])('refuses %p', (value) => {
    expect(() => getRequiredJwtSecret(config(value))).toThrow();
  });
  it('accepts a long random secret', () => {
    expect(getRequiredJwtSecret(config('9f4c2a7d0e1b3c5a8d6f2e4b7a9c1d3e5f7a2b4c6d8e0f1a'))).toHaveLength(48);
  });
});
