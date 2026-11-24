import { DbCryptoService } from './db-crypto.service';

// Pentest: with no key set, the database key used to fall back to a phrase in
// this public repository, so anyone with the database file could decrypt it.
describe('database encryption key', () => {
  const env = { ...process.env };
  afterEach(() => {
    process.env = { ...env };
  });

  it('refuses to start with no key, or a short or placeholder one', () => {
    for (const k of ['DB_ENCRYPTION_KEY', 'ENCRYPTION_KEY', 'JWT_SECRET']) delete process.env[k];
    expect(() => new DbCryptoService()).toThrow(/32 random characters/);
    process.env.DB_ENCRYPTION_KEY = 'short';
    expect(() => new DbCryptoService()).toThrow();
    process.env.DB_ENCRYPTION_KEY = 'replace-with-high-entropy-master-key-v1';
    expect(() => new DbCryptoService()).toThrow();
  });

  it('round-trips with a real key, and another key cannot read it', () => {
    process.env.DB_ENCRYPTION_KEY = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718';
    const one = new DbCryptoService();
    const sealed = one.encrypt('totp-secret');
    expect(sealed).not.toContain('totp-secret');
    expect(one.decrypt(sealed)).toBe('totp-secret');
    process.env.DB_ENCRYPTION_KEY = 'f0e1d2c3b4a5968778695a4b3c2d1e0ff0e1d2c3b4a59687';
    expect(() => new DbCryptoService().decrypt(sealed)).toThrow();
  });
});
