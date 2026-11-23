// HTTP tests: boot the real app (same setup as main.ts) on a throwaway
// database and check, over real requests, who can reach every route.
//
// Run with: npm run test:http
import { execSync } from 'child_process';
import { createHash } from 'crypto';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { INestApplication, RequestMethod } from '@nestjs/common';
import { DiscoveryService, MetadataScanner, Reflector } from '@nestjs/core';
import { GUARDS_METADATA, METHOD_METADATA, PATH_METADATA } from '@nestjs/common/constants';
import { Test } from '@nestjs/testing';
import * as jwt from 'jsonwebtoken';
import * as request from 'supertest';

const dir = mkdtempSync(join(tmpdir(), 'cypee-http-'));
const SECRET = 'http-test-secret-'.padEnd(64, 'x');
const OWNER = 'owner@example.test';
const API_KEY = 'http-test-api-key-0123456789';

Object.assign(process.env, {
  DATABASE_URL: `file:${join(dir, 'test.db')}`,
  JWT_SECRET: SECRET,
  CYPEE_OWNER_EMAILS: OWNER,
  API_KEY,
  CYPEE_ALLOW_REGISTRATION: 'true',
  CYPEE_ALLOW_CODE_RUN: 'false',
  CYPEE_DEMO: 'false',
  NODE_ENV: 'test',
});

interface Route {
  method: string;
  path: string;
  isPublic: boolean;
  guards: string[];
  name: string;
}

const METHODS: Record<number, string> = {
  [RequestMethod.GET]: 'get',
  [RequestMethod.POST]: 'post',
  [RequestMethod.PUT]: 'put',
  [RequestMethod.PATCH]: 'patch',
  [RequestMethod.DELETE]: 'delete',
  [RequestMethod.ALL]: 'get',
};

/** Every route the app serves, read from Nest's own metadata, with its guards. */
function listRoutes(app: INestApplication): Route[] {
  const discovery = app.get(DiscoveryService);
  const scanner = app.get(MetadataScanner);
  const reflector = app.get(Reflector);
  const routes: Route[] = [];
  for (const wrapper of discovery.getControllers()) {
    const { instance, metatype } = wrapper;
    if (!instance || !metatype) continue;
    const base = ([] as string[]).concat(Reflect.getMetadata(PATH_METADATA, metatype) ?? '')[0];
    const classGuards: unknown[] = Reflect.getMetadata(GUARDS_METADATA, metatype) ?? [];
    const proto = Object.getPrototypeOf(instance);
    for (const key of scanner.getAllMethodNames(proto)) {
      const handler = proto[key];
      const sub = Reflect.getMetadata(PATH_METADATA, handler);
      const m = Reflect.getMetadata(METHOD_METADATA, handler);
      if (sub === undefined || m === undefined) continue;
      const guards = [...classGuards, ...(Reflect.getMetadata(GUARDS_METADATA, handler) ?? [])].map(
        (g: any) => g?.name ?? String(g),
      );
      const isPublic = Boolean(reflector.getAllAndOverride('cypee:isPublic', [handler, metatype]));
      const raw = `/${base}/${([] as string[]).concat(sub)[0]}`.replace(/\/+/g, '/').replace(/\/$/, '') || '/';
      // Fill route parameters with harmless values so the request reaches the guard.
      const path = raw.replace(/\*path/g, 'x').replace(/\{\*path\}/g, 'x').replace(/:[A-Za-z]+/g, 'test-id');
      routes.push({ method: METHODS[m] ?? 'get', path, isPublic, guards, name: `${metatype.name}.${key}` });
    }
  }
  return routes;
}

function token(payload: object, opts: jwt.SignOptions = { expiresIn: '1h' }, secret = SECRET): string {
  return jwt.sign(payload, secret, opts);
}


/** Solves the shield's proof-of-work challenge, as the dashboard does. */
function solve(challenge: string): string {
  const [salt, d] = challenge.split('|');
  const prefix = '0'.repeat(parseInt(d, 10));
  for (let n = 0; ; n++) {
    if (createHash('sha256').update(salt + n).digest('hex').startsWith(prefix)) return String(n);
  }
}

interface CallOpts {
  token?: string;
  body?: unknown;
  headers?: Record<string, string>;
  raw?: string;
}

/** One request, answering a proof-of-work challenge once if the shield asks, like the real client. */
async function call(app: INestApplication, method: string, path: string, opts: CallOpts = {}): Promise<request.Response> {
  const go = (extra: Record<string, string> = {}) => {
    let req = (request(app.getHttpServer()) as any)[method](path).timeout({ response: 15_000 });
    const headers = { ...(opts.headers ?? {}), ...extra };
    if (opts.token) headers.Authorization = `Bearer ${opts.token}`;
    for (const [k, v] of Object.entries(headers)) req = req.set(k, v);
    if (opts.raw !== undefined) return req.set('Content-Type', 'application/json').send(opts.raw);
    return method === 'get' || method === 'delete' ? req : req.send((opts.body ?? {}) as object);
  };
  // A live stream (server-sent events) never ends: the headers are the answer.
  const settle = (p: Promise<request.Response>) =>
    p.catch((e: any) => (e?.timeout ? ({ status: 200, headers: {}, body: {}, text: '' } as unknown as request.Response) : Promise.reject(e)));
  const first = await settle(go());
  const challenge = first.headers['x-shield-challenge'];
  if (first.status !== 400 || !challenge) return first;
  return settle(go({ 'x-shield-pow-challenge': challenge, 'x-shield-pow-nonce': solve(challenge) }));
}

describe('HTTP access (real app, real requests)', () => {
  let app: INestApplication;
  let routes: Route[];
  let ownerToken: string;
  let memberToken: string;

  beforeAll(async () => {
    // The schema as SQL (no database touched), applied to a fresh file.
    const sql = execSync('npx prisma migrate diff --from-empty --to-schema prisma/schema.prisma --script', {
      cwd: join(__dirname, '..', '..'),
      env: process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    }).toString();
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const Database = require('better-sqlite3');
    const db = new Database(join(dir, 'test.db'));
    db.exec(sql);
    db.close();
    const { AppModule } = await import('../app.module');
    const { configureApp } = await import('../app.setup');
    const moduleRef = await Test.createTestingModule({ imports: [AppModule], providers: [DiscoveryService, MetadataScanner] }).compile();
    app = moduleRef.createNestApplication({ bodyParser: false, logger: false });
    configureApp(app);
    await app.init();
    routes = listRoutes(app);

    // The first account: the owner. Then a second, ordinary account.
    const reg = (email: string) =>
      call(app, 'post', '/api/v1/auth/register', { body: { email, password: 'Correct-Horse-9', tenantName: `${email} tenant` } });
    const login = async (email: string) => {
      const res = await call(app, 'post', '/api/v1/auth/login', { body: { email, password: 'Correct-Horse-9' } });
      return res.body.token ?? res.body.accessToken ?? res.body.access_token;
    };
    const r1 = await reg(OWNER);
    const r2 = await reg('member@example.test');
    if (r1.status >= 300 || r2.status >= 300) throw new Error(`register: ${r1.status} ${JSON.stringify(r1.body)} / ${r2.status} ${JSON.stringify(r2.body)}`);
    ownerToken = await login(OWNER);
    memberToken = await login('member@example.test');
  }, 120_000);

  afterAll(async () => {
    await app?.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('finds the routes', () => {
    expect(routes.length).toBeGreaterThan(40);
    expect(ownerToken).toEqual(expect.any(String));
    expect(memberToken).toEqual(expect.any(String));
  });

  it('refuses every protected route without a sign-in (401)', async () => {
    const wrong: string[] = [];
    for (const r of routes.filter((x) => !x.isPublic)) {
      const res = await call(app, r.method, r.path);
      if (res.status !== 401) wrong.push(`${r.method.toUpperCase()} ${r.path} (${r.name}) -> ${res.status}`);
    }
    expect(wrong).toEqual([]);
  }, 120_000);

  it('refuses forged, expired and unsigned tokens (401)', async () => {
    const target = routes.find((r) => !r.isPublic && r.method === 'get')!;
    const bad = [
      token({ sub: 'x', email: OWNER }, { expiresIn: '1h' }, 'not-the-secret-'.padEnd(64, 'y')),
      token({ sub: 'x', email: OWNER }, { expiresIn: -10 }),
      `${Buffer.from('{"alg":"none","typ":"JWT"}').toString('base64url')}.${Buffer.from(JSON.stringify({ sub: 'x', email: OWNER })).toString('base64url')}.`,
      'garbage',
    ];
    for (const t of bad) {
      const res = await call(app, 'get', target.path, { token: t });
      expect(res.status).toBe(401);
    }
  });

  it('keeps owner-only routes from ordinary accounts (403)', async () => {
    const ownerRoutes = routes.filter((r) => r.guards.includes('OwnerGuard'));
    expect(ownerRoutes.length).toBeGreaterThan(5);
    const wrong: string[] = [];
    for (const r of ownerRoutes) {
      const res = await call(app, r.method, r.path, { token: memberToken });
      if (res.status !== 403) wrong.push(`${r.method.toUpperCase()} ${r.path} (${r.name}) -> ${res.status}`);
    }
    expect(wrong).toEqual([]);
  }, 120_000);

  it('lets the owner through to read-only owner routes', async () => {
    const reads = routes.filter((r) => r.guards.includes('OwnerGuard') && r.method === 'get' && !r.path.endsWith('/stream'));
    for (const r of reads) {
      const res = await call(app, 'get', r.path, { token: ownerToken });
      expect([401, 403]).not.toContain(res.status);
    }
  }, 120_000);

  it('refuses API-key routes without the right key', async () => {
    const keyed = routes.filter((r) => r.guards.includes('ApiKeyGuard'));
    expect(keyed.length).toBeGreaterThan(0);
    for (const r of keyed) {
      const none = await call(app, r.method, r.path);
      const wrongKey = await call(app, r.method, r.path, { headers: { 'x-api-key': 'wrong-key-0123456789' } });
      expect([401, 403]).toContain(none.status);
      expect([401, 403]).toContain(wrongKey.status);
    }
  });

  it('closes registration after the first account unless it is switched on', async () => {
    process.env.CYPEE_ALLOW_REGISTRATION = 'false';
    try {
      const res = await call(app, 'post', '/api/v1/auth/register', { body: { email: 'late@example.test', password: 'Correct-Horse-9', tenantName: 'Late' } });
      expect(res.status).toBeGreaterThanOrEqual(400);
      expect(res.status).toBeLessThan(500);
    } finally {
      process.env.CYPEE_ALLOW_REGISTRATION = 'true';
    }
  });

  it('rejects a wrong password without saying whether the account exists', async () => {
    const a = await call(app, 'post', '/api/v1/auth/login', { body: { email: OWNER, password: 'Wrong-Pass-1' } });
    const b = await call(app, 'post', '/api/v1/auth/login', { body: { email: 'nobody@example.test', password: 'Wrong-Pass-1' } });
    expect(a.status).toBe(401);
    expect(b.status).toBe(401);
    expect(a.body.message).toBe(b.body.message);
  });

  it('locks an account after five wrong passwords (429), without locking others', async () => {
    const victim = 'locked@example.test';
    for (let i = 0; i < 5; i++) {
      const res = await call(app, 'post', '/api/v1/auth/login', { body: { email: victim, password: `Wrong-${i}-pass` } });
      expect(res.status).toBe(401);
    }
    const sixth = await call(app, 'post', '/api/v1/auth/login', { body: { email: victim, password: 'Wrong-6-pass' } });
    expect(sixth.status).toBe(429);
    const other = await call(app, 'post', '/api/v1/auth/login', { body: { email: 'member@example.test', password: 'Correct-Horse-9' } });
    expect(other.status).toBeLessThan(300);
  });

  it("keeps one account's scans from another account", async () => {
    const { PrismaService } = await import('../database/prisma.service');
    const prisma = app.get(PrismaService);
    const ownerTenant = (jwt.decode(ownerToken) as { tenantId: string }).tenantId;
    const scan = await prisma.scan.create({ data: { tenantId: ownerTenant } });

    const asOwner = await call(app, 'get', `/api/v1/scans/${scan.id}`, { token: ownerToken });
    expect(asOwner.status).toBe(200);
    const asMember = await call(app, 'get', `/api/v1/scans/${scan.id}`, { token: memberToken });
    expect([403, 404]).toContain(asMember.status);
    const memberFindings = await call(app, 'get', `/api/v1/scans/${scan.id}/findings`, { token: memberToken });
    // Findings answer an empty list, never the other account's rows.
    if (memberFindings.status === 200) expect(memberFindings.body).toEqual([]);
    else expect([403, 404]).toContain(memberFindings.status);
    const memberList = await call(app, 'get', '/api/v1/scans', { token: memberToken });
    expect(JSON.stringify(memberList.body)).not.toContain(scan.id);
  });

  it('rejects unknown fields and oversized bodies', async () => {
    const extra = await call(app, 'post', '/api/v1/auth/login', { body: { email: OWNER, password: 'x', isAdmin: true } });
    expect(extra.status).toBe(400);
    const big = await call(app, 'post', '/api/v1/auth/login', { raw: JSON.stringify({ email: OWNER, password: 'x'.repeat(1_100_000) }) });
    expect(big.status).toBe(413);
  });

  it('never echoes a token, a password hash or a secret back', async () => {
    const me = routes.filter((r) => !r.isPublic && r.method === 'get' && !r.path.includes('test-id') && !r.path.endsWith('/stream'));
    for (const r of me) {
      const res = await call(app, 'get', r.path, { token: ownerToken });
      const text = JSON.stringify(res.body ?? '') + (res.text ?? '');
      expect(text).not.toContain(SECRET);
      expect(text).not.toContain(API_KEY);
      expect(text).not.toMatch(/\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}/); // a real bcrypt hash (the labyrinth decoys are short fakes)
    }
  }, 120_000);

  it('sends security headers', async () => {
    const res = await call(app, 'get', '/api/v1/health');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-powered-by']).toBeUndefined();
  });
});
