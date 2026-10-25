import { Injectable, Logger, NotFoundException, ForbiddenException, BadGatewayException, HttpStatus } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Request, Response } from 'express';
import * as crypto from 'crypto';
import { ShieldService } from './shield.service';
import { FederatedDefenseService } from './federated-defense.service';
import { AuditLogService } from '../audit/audit-log.service';
import { BreachResponseService } from './breach-response.service';
import { AttackerReconService } from './attacker-recon.service';
import { FleetService } from './fleet.service';

export interface UpstreamApp {
  id: string;
  name: string;
  targetUrl: string;
  healthy: boolean;
  rateLimitPerMin: number;
  lastChecked?: string;
}

@Injectable()
export class GatewayService {
  private readonly logger = new Logger(GatewayService.name);

  // Registered application fleet including V-Gruvs core ecosystem
  private readonly apps = new Map<string, UpstreamApp>();

  // In-memory sliding window rate-limiter: Map<`${appId}:${ip}`, number[]>
  private readonly rateLimitBuckets = new Map<string, number[]>();

  // Shared secret for cryptographic transit stamping (VG_AUTH_TOKEN)
  private readonly enclaveSecret: string;

  constructor(
    private readonly configService: ConfigService,
    private readonly shieldService: ShieldService,
    private readonly federatedDefense: FederatedDefenseService,
    private readonly auditLog: AuditLogService,
    private readonly breachResponse: BreachResponseService,
    private readonly reconService: AttackerReconService,
    private readonly fleetService: FleetService,
  ) {
    this.enclaveSecret = this.configService.get<string>('JWT_SECRET', 'shield-super-secret-jwt-key-change-in-production-2025');

    // Register Default Upstreams: V-Gruvs host platform and the 3 core applications
    const vgruvsUrl = this.configService.get<string>('VGRUVS_URL', 'http://127.0.0.1:4000');
    const residentUrl = this.configService.get<string>('APP1_URL', 'http://127.0.0.1:4001');
    const gruvsUrl = this.configService.get<string>('APP2_URL', 'http://127.0.0.1:4002');
    const excellencyUrl = this.configService.get<string>('APP3_URL', 'http://127.0.0.1:4003');

    this.registerApp('vgruvs', vgruvsUrl, 'V-Gruvs (Host Infrastructure)', 300);
    this.registerApp('the-resident', residentUrl, 'The Resident (Identity & Portal)', 120);
    this.registerApp('the-gruvs', gruvsUrl, 'The Gruvs (Core Operations)', 180);
    this.registerApp('excellency', excellencyUrl, 'Excellency (Financials & Sheets)', 60);

    // Maintain legacy aliases for backwards compatibility
    this.registerApp('app1', residentUrl, 'The Resident (Alias: app1)', 120);
    this.registerApp('app2', gruvsUrl, 'The Gruvs (Alias: app2)', 180);
    this.registerApp('app3', excellencyUrl, 'Excellency (Alias: app3)', 60);
  }

  registerApp(id: string, targetUrl: string, name?: string, rateLimitPerMin = 120): UpstreamApp {
    let parsed: URL;
    try {
      parsed = new URL(targetUrl);
    } catch {
      throw new ForbiddenException(`Invalid targetUrl "${targetUrl}" for enclave registration.`);
    }

    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new ForbiddenException(`Disallowed protocol "${parsed.protocol}" for enclave upstream.`);
    }

    // Block SSRF registration against cloud metadata endpoints
    if (parsed.hostname === '169.254.169.254' || parsed.hostname === 'metadata.google.internal') {
      throw new ForbiddenException('Cloud metadata endpoints cannot be registered as gateway upstreams.');
    }

    const cleanUrl = targetUrl.replace(/\/+$/, '');
    const app: UpstreamApp = {
      id,
      name: name || `Application ${id}`,
      targetUrl: cleanUrl,
      healthy: true,
      rateLimitPerMin,
      lastChecked: new Date().toISOString(),
    };
    this.apps.set(id, app);
    this.logger.log(`[GATEWAY ENCLAVE] Registered upstream route for "${id}" -> ${cleanUrl} (RateLimit: ${rateLimitPerMin} req/min)`);
    return app;
  }

  getApp(id: string): UpstreamApp {
    const app = this.apps.get(id);
    if (!app) {
      throw new NotFoundException(`Application "${id}" is not enrolled in the CyPee Security Enclave.`);
    }
    return app;
  }

  async listApps(): Promise<UpstreamApp[]> {
    const list = Array.from(this.apps.values());
    await Promise.all(
      list.map(async (app) => {
        try {
          const controller = new AbortController();
          const timeout = setTimeout(() => controller.abort(), 1000);
          const res = await fetch(`${app.targetUrl}/health`, { signal: controller.signal }).catch(() => null);
          clearTimeout(timeout);
          app.healthy = res ? res.ok : false;
        } catch {
          app.healthy = false;
        }
        app.lastChecked = new Date().toISOString();
      }),
    );
    return list;
  }

  /**
   * Generates a cryptographically signed VG_AUTH_TOKEN proving the request
   * traversed the CyPee Security Gateway without tampering.
   */
  generateTransitToken(appId: string, ip: string, method: string, timestamp: number, nonce: string): string {
    const payload = `${appId}|${ip}|${method}|${timestamp}|${nonce}`;
    return crypto.createHmac('sha256', this.enclaveSecret).update(payload).digest('hex');
  }

  /**
   * Deep payload normalization: recursive URL & Hex decoding to unmask obfuscation.
   */
  private normalizePayload(raw: string): string {
    let current = raw;
    for (let depth = 0; depth < 3; depth++) {
      try {
        const decoded = decodeURIComponent(current.replace(/\+/g, ' '));
        if (decoded === current) break;
        current = decoded;
      } catch {
        break;
      }
    }
    // Strip null bytes and comment tricks
    return current.replace(/\0/g, '').replace(/\/\*.*?\*\//g, ' ');
  }

  /**
   * Multi-Vector Deep Packet Inspection covering OWASP Top 10 injection vectors.
   */
  private inspectDeepPayload(normalized: string): { blocked: boolean; threatCategory?: string; vector?: string } {
    const lower = normalized.toLowerCase();

    // 1. SQL Injection (Union, Tautologies, Time-based blind, comments)
    const sqlPatterns = [
      /\b(union\s+(all\s+)?select)\b/i,
      /\b(select\s+.+?\s+from)\b/i,
      /\b(insert\s+into\s+.+?\s+values)\b/i,
      /\b(or\s+1\s*=\s*1|or\s+'1'\s*=\s*'1')\b/i,
      /\b(sleep\s*\(|pg_sleep\s*\(|waitfor\s+delay)\b/i,
      /(;\s*drop\s+table|;\s*delete\s+from)/i,
    ];
    for (const p of sqlPatterns) {
      if (p.test(lower)) return { blocked: true, threatCategory: 'SQL_INJECTION', vector: p.source };
    }

    // 2. Cross-Site Scripting (XSS)
    const xssPatterns = [
      /<script\b[^>]*>([\s\S]*?)<\/script>/i,
      /\bjavascript\s*:/i,
      /\b(onload|onerror|onclick|onmouseover)\s*=/i,
      /<iframe\b|<object\b|<embed\b/i,
      /\beval\s*\(|document\.cookie/i,
    ];
    for (const p of xssPatterns) {
      if (p.test(lower)) return { blocked: true, threatCategory: 'XSS_ATTACK', vector: p.source };
    }

    // 3. Remote Code Execution (RCE) / Command Injection
    const rcePatterns = [
      /[;&|`]\s*(cat\s+\/etc\/passwd|whoami|id|uname\s+-a|powershell|cmd\.exe)/i,
      /\$\(\s*(whoami|cat|ls|pwd)\s*\)/i,
      /\b(nc\s+-e|\/bin\/bash|\/bin\/sh)\b/i,
    ];
    for (const p of rcePatterns) {
      if (p.test(lower)) return { blocked: true, threatCategory: 'COMMAND_INJECTION_RCE', vector: p.source };
    }

    // 4. Path Traversal & LFI
    const traversalPatterns = [
      /(\.\.[\/\\]){2,}/,
      /\/etc\/(passwd|shadow|hosts)/i,
      /\bwin\.ini|system32\\config/i,
    ];
    for (const p of traversalPatterns) {
      if (p.test(lower)) return { blocked: true, threatCategory: 'PATH_TRAVERSAL_LFI', vector: p.source };
    }

    // 5. SSRF (Server-Side Request Forgery against cloud metadata)
    const ssrfPatterns = [
      /169\.254\.169\.254/,
      /metadata\.google\.internal/,
      /127\.0\.0\.1:\d{4,5}/,
    ];
    for (const p of ssrfPatterns) {
      if (p.test(lower)) return { blocked: true, threatCategory: 'SSRF_METADATA_PROBE', vector: p.source };
    }

    return { blocked: false };
  }

  /**
   * Enforces Per-App Sliding Window Rate Limiting.
   */
  private checkRateLimit(appId: string, ip: string, limitPerMin: number): boolean {
    const key = `${appId}:${ip}`;
    const now = Date.now();
    const windowStart = now - 60000;

    let timestamps = this.rateLimitBuckets.get(key) || [];
    timestamps = timestamps.filter(t => t > windowStart);
    timestamps.push(now);
    this.rateLimitBuckets.set(key, timestamps);

    return timestamps.length <= limitPerMin;
  }

  /**
   * Enterprise Zero-Trust Proxy execution.
   */
  async proxyRequest(appId: string, subPath: string, req: Request, res: Response): Promise<void> {
    const start = performance.now();
    const app = this.getApp(appId);
    const ip = req.ip || req.socket.remoteAddress || '127.0.0.1';

    // Tier 0: Enclave Airgap Quarantine, Edge Firewall Blacklist & Tarpit Deflection
    if (this.fleetService.isQuarantined(appId)) {
      this.logger.warn(`[ENCLAVE AIRGAP] Blocked inbound traffic to quarantined enclave "${appId}" from IP: ${ip}`);
      throw new ForbiddenException(`Enclave "${app.name}" is currently under FULL_AIRGAP quarantine lockdown.`);
    }

    if (this.breachResponse.isBlacklisted(ip)) {
      this.logger.warn(`[FIREWALL DROP] Inbound traffic dropped for blacklisted IP: ${ip}`);
      throw new ForbiddenException('Access denied by CyPee Edge Threat Defense firewall');
    }

    if (this.breachResponse.isTarpitted(ip)) {
      this.logger.warn(`[TARPIT ENGAGED] Throttling suspicious client socket for IP: ${ip}`);
      await new Promise((r) => setTimeout(r, 2000)); // Artificial Slowloris friction
    }

    // Tier 1: Threat Mesh Instant Quarantine Check
    if (this.federatedDefense.isThreatBlocked(ip)) {
      this.logger.warn(`[ENCLAVE QUARANTINE] IP ${ip} is banned in the Federated Mesh. Dropped before reaching "${appId}".`);
      await this.auditLog.log('SYSTEM', 'GATEWAY_MESH_QUARANTINE_BLOCKED', `gateway:${appId}`, { ip, subPath });
      throw new ForbiddenException('Access denied. Client is quarantined across the multi-app defense mesh.');
    }

    // Tier 2: Per-App Rate Limiting
    if (!this.checkRateLimit(appId, ip, app.rateLimitPerMin)) {
      this.logger.warn(`[RATE LIMIT EXCEEDED] IP ${ip} exceeded ${app.rateLimitPerMin} req/min on "${appId}".`);
      res.setHeader('Retry-After', '60');
      res.status(HttpStatus.TOO_MANY_REQUESTS).json({
        statusCode: 429,
        error: 'Too Many Requests',
        message: `Rate limit of ${app.rateLimitPerMin} requests/minute exceeded for ${app.name}.`,
      });
      return;
    }

    // Tier 3: GeoIP Boundary Enforcement
    const geo = this.shieldService.auditGeoIp(ip);
    if (!geo.allowed) {
      this.logger.warn(`[GEOIP ENCLAVE BLOCKED] Restricted origin ${geo.country} for IP ${ip}.`);
      throw new ForbiddenException(`Origin location [${geo.country}] is restricted from accessing this service.`);
    }

    // Tier 4: Multi-Vector Deep Packet Inspection & Normalization
    const rawBody = req.body && Object.keys(req.body).length > 0 ? JSON.stringify(req.body) : '';
    const rawQuery = req.query && Object.keys(req.query).length > 0 ? JSON.stringify(req.query) : '';
    const combined = `${rawBody} ${rawQuery}`.trim();

    if (combined) {
      const normalized = this.normalizePayload(combined);

      // Deep Heuristic Inspection
      const deepCheck = this.inspectDeepPayload(normalized);
      if (deepCheck.blocked) {
        this.logger.warn(
          `[ZERO-TRUST INTERCEPT] Detected ${deepCheck.threatCategory} targeting "${appId}". Vector: "${deepCheck.vector}". IP: ${ip}`,
        );

        // Immediate synchronized quarantine across all apps (V-Gruvs + App1 + App2 + App3)
        await this.federatedDefense.shareThreatSignature(deepCheck.threatCategory!, ip);

        // Active Countermeasure Response (Tarpit, Enclave Airgap, Forensic Freeze)
        await this.breachResponse.handleBreachEvent({
          source: 'GATEWAY_DPI',
          enclaveAppId: (appId as any) || 'vgruvs',
          attackerIp: ip,
          targetResource: `${appId}:${subPath}`,
          payloadSnippet: deepCheck.vector,
        }).catch((err) => this.logger.error(`Breach handling error: ${err.message}`));

        // Reverse Cyber Reconnaissance: Build Forensic Intelligence Dossier & Arm Canary Beacons
        await this.reconService.captureAttackerTelemetry(
          ip,
          (appId as any) || 'vgruvs',
          subPath,
          req.method,
          req.headers as any,
          req.query || {},
          deepCheck.vector || normalized,
          deepCheck.threatCategory || 'EXPLOIT_INTERCEPTED',
        ).catch((err) => this.logger.error(`Recon capture error: ${err.message}`));

        await this.auditLog.log('SYSTEM', 'GATEWAY_ATTACK_INTERCEPTED', `gateway:${appId}`, {
          ip,
          subPath,
          category: deepCheck.threatCategory,
          vector: deepCheck.vector,
          quarantinedAcrossAllApps: true,
        });

        throw new ForbiddenException(`Security violation detected: [${deepCheck.threatCategory}]. Quarantined across all apps.`);
      }

      // Cosine Bigram Vector Firewall
      const firewall = this.shieldService.vectorFirewallCheck(normalized);
      if (firewall.blocked) {
        this.logger.warn(`[VECTOR FIREWALL BLOCKED] Cosine similarity ${firewall.similarity.toFixed(2)} on "${appId}".`);
        await this.federatedDefense.shareThreatSignature('VECTOR_FIREWALL_MATCH', ip);
        throw new ForbiddenException('Request blocked by Vector Firewall similarity model.');
      }
    }

    // Tier 5: Cryptographic Enclave Transit Proof (VG_AUTH_TOKEN)
    const timestamp = Date.now();
    const nonce = crypto.randomUUID();
    const transitToken = this.generateTransitToken(appId, ip, req.method, timestamp, nonce);

    const normalizedSubPath = subPath ? (subPath.startsWith('/') ? subPath : `/${subPath}`) : '';
    const queryString = req.url.includes('?') ? req.url.substring(req.url.indexOf('?')) : '';
    const targetUrl = `${app.targetUrl}${normalizedSubPath}${queryString}`;

    const forwardHeaders: Record<string, string> = {};
    for (const [key, value] of Object.entries(req.headers)) {
      if (typeof value === 'string' && !['host', 'connection', 'content-length'].includes(key.toLowerCase())) {
        forwardHeaders[key] = value;
      }
    }

    // Cryptographic proof headers stamped by CyPee for V-Gruvs and target apps
    forwardHeaders['x-forwarded-for'] = ip;
    forwardHeaders['x-cypee-enclave'] = 'VERIFIED_SECURE';
    forwardHeaders['x-cypee-app'] = appId;
    forwardHeaders['x-vg-auth'] = transitToken;
    forwardHeaders['x-vg-timestamp'] = String(timestamp);
    forwardHeaders['x-vg-nonce'] = nonce;
    forwardHeaders['vg_auth_token'] = transitToken;

    try {
      const fetchOptions: RequestInit = {
        method: req.method,
        headers: forwardHeaders,
      };

      if (!['GET', 'HEAD'].includes(req.method.toUpperCase()) && req.body) {
        fetchOptions.body = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
        if (!forwardHeaders['content-type']) {
          forwardHeaders['content-type'] = 'application/json';
        }
      }

      const upstreamResponse = await fetch(targetUrl, fetchOptions);
      const durationMs = (performance.now() - start).toFixed(1);

      res.status(upstreamResponse.status);
      upstreamResponse.headers.forEach((val, key) => {
        if (!['content-encoding', 'transfer-encoding'].includes(key.toLowerCase())) {
          res.setHeader(key, val);
        }
      });

      res.setHeader('x-cypee-shield-version', 'CyPee-Enclave-v11-ZeroTrust');
      res.setHeader('x-cypee-proxy-time', `${durationMs}ms`);

      const responseBody = await upstreamResponse.arrayBuffer();
      res.send(Buffer.from(responseBody));
    } catch (err: any) {
      this.logger.error(`[UPSTREAM ERROR] Application "${appId}" unreachable at ${targetUrl}: ${err.message}`);
      throw new BadGatewayException(
        `CyPee Security Enclave cannot reach "${app.name}" (${app.targetUrl}). Error: ${err.message}`,
      );
    }
  }
}
