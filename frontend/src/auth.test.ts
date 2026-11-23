// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

describe('the dashboard fetch wrapper', () => {
  let seen: { url: string; auth: string | null }[];
  let status: number;

  beforeEach(async () => {
    vi.resetModules();
    sessionStorage.clear();
    seen = [];
    status = 200;
    window.fetch = vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      seen.push({ url, auth: new Headers(init.headers).get('Authorization') });
      return new Response('{}', { status });
    }) as typeof fetch;
    const auth = await import('./auth');
    auth.installAuthFetch();
    auth.setToken('tok-123');
  });

  afterEach(() => sessionStorage.clear());

  it('adds the token to our own /api/ calls', async () => {
    await fetch('/api/v1/shield/fleet/posture');
    await fetch(`${window.location.origin}/api/v1/health`);
    expect(seen.map((s) => s.auth)).toEqual(['Bearer tok-123', 'Bearer tok-123']);
  });

  it('never sends the token to another site or a non-API path', async () => {
    await fetch('https://evil.example/api/v1/steal');
    await fetch('/index.html');
    expect(seen.map((s) => s.auth)).toEqual([null, null]);
  });

  it('keeps an Authorization header the caller set', async () => {
    await fetch('/api/v1/x', { headers: { Authorization: 'Bearer other' } });
    expect(seen[0].auth).toBe('Bearer other');
  });

  it('says so when the server refuses (401 sign in, 403 owners only)', async () => {
    const events: number[] = [];
    window.addEventListener('cypee:denied', (e) => events.push((e as CustomEvent<number>).detail));
    status = 401;
    await fetch('/api/v1/shield/fleet/posture');
    status = 403;
    await fetch('/api/v1/shield/breach/status');
    status = 401;
    await fetch('/api/v1/auth/login'); // a wrong password is the form's to show, not a banner
    status = 500;
    await fetch('/api/v1/health');
    expect(events).toEqual([401, 403]);
  });

  it('sends nothing once signed out', async () => {
    const auth = await import('./auth');
    auth.setToken(null);
    await fetch('/api/v1/health');
    expect(seen[0].auth).toBeNull();
  });
});
