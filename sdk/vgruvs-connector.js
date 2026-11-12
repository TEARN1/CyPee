/**
 * V-Gruvs Sovereign Host & Enclave Security Connector (v12 Zero-Trust)
 *
 * Provides bi-directional cryptographic transit verification (VG_AUTH_TOKEN v1 & v2 with Body-SHA256),
 * container escape / host breakout prevention, federated threat mesh HMAC synchronization,
 * and automatic runtime telemetry heartbeats to the CyPee Security Enclave.
 *
 * Usage in V-Gruvs (Express / Node.js):
 *   const { createVGruvsSecurityGuard } = require('./sdk/vgruvs-connector');
 *   app.use(createVGruvsSecurityGuard({
 *     enclaveSecret: process.env.JWT_SECRET,
 *     cypeeUrl: 'http://127.0.0.1:3000',
 *     appId: 'vgruvs'
 *   }));
 */

const crypto = require('crypto');

function createVGruvsSecurityGuard(options = {}) {
  const secret =
    options.enclaveSecret ||
    process.env.ENCLAVE_SECRET ||
    process.env.JWT_SECRET ||
    'shield-super-secret-jwt-key-change-in-production-2025';
  const federatedSalt =
    options.federatedSalt ||
    process.env.FEDERATED_SALT ||
    'default-shield-edge-mesh-salt-key';
  const cypeeUrl = (options.cypeeUrl || process.env.CYPEE_URL || 'http://127.0.0.1:3000').replace(/\/+$/, '');
  const appId = options.appId || 'vgruvs';
  const maxClockSkewMs = options.maxClockSkewMs || 60000; // 60s replay window

  const seenNonces = new Map(); // nonce -> timestamp
  let blockedThreatHashes = new Set();
  let blockedSyscallsDelta = 0;

  // 1. Evict expired nonces every 60s without wiping recent nonces
  const nonceTimer = setInterval(() => {
    const cutoff = Date.now() - maxClockSkewMs * 2;
    for (const [n, ts] of seenNonces.entries()) {
      if (ts < cutoff) seenNonces.delete(n);
    }
  }, 60000);
  if (nonceTimer.unref) nonceTimer.unref();

  // 2. Sync Federated Threat Mesh & Send Host Telemetry Heartbeat every 15s
  async function syncAndHeartbeat() {
    try {
      const feedRes = await fetch(`${cypeeUrl}/api/v1/shield/federated/feed`);
      if (feedRes.ok) {
        const feed = await feedRes.json();
        blockedThreatHashes = new Set(feed.map((item) => (typeof item === 'string' ? item : item.indicatorHash)));
      }
    } catch {
      // Fail-safe offline continuation
    }

    try {
      const memMb = Math.round(process.memoryUsage().rss / (1024 * 1024));
      await fetch(`${cypeeUrl}/api/v1/shield/vgruvs/heartbeat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          enclaveId: appId,
          memoryUsageMb: memMb,
          blockedSyscallsDelta,
        }),
      });
      blockedSyscallsDelta = 0;
    } catch {
      // Fail-safe offline continuation
    }
  }

  syncAndHeartbeat();
  const syncTimer = setInterval(syncAndHeartbeat, 15000);
  if (syncTimer.unref) syncTimer.unref();

  function hashIndicator(rawIp) {
    return crypto.createHmac('sha256', federatedSalt).update(String(rawIp)).digest('hex');
  }

  function safeCompareHex(a, b) {
    if (!a || !b || typeof a !== 'string' || typeof b !== 'string') return false;
    const bufA = Buffer.from(a, 'utf8');
    const bufB = Buffer.from(b, 'utf8');
    return bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB);
  }

  return function vgruvsSecurityMiddleware(req, res, next) {
    const vgAuthToken = req.headers['x-vg-auth'] || req.headers['vg_auth_token'];
    const vgAuthV2 = req.headers['x-vg-auth-v2'];
    const vgKeyVersion = req.headers['x-vg-key-version'] || 'vg-key-v1';
    const vgPath = req.headers['x-vg-path'] || req.path || '/';
    const vgBodySha256 = req.headers['x-vg-body-sha256'];
    const timestampStr = req.headers['x-vg-timestamp'];
    const nonce = req.headers['x-vg-nonce'];
    const clientIp = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1').split(',')[0].trim();

    // Tier 0: Check Federated Threat Mesh (using salted HMAC-SHA256 indicator match)
    const ipHash = hashIndicator(clientIp);
    if (blockedThreatHashes.has(ipHash) || blockedThreatHashes.has(clientIp)) {
      res.setHeader('X-VGruvs-Blocked', 'Federated-Mesh-Quarantine');
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Client IP is quarantined across the V-Gruvs & CyPee Federated Defense Mesh.',
        code: 'MESH_QUARANTINE_ACTIVE',
      });
    }

    // Tier 1: V-Gruvs Host Container Escape & Control-Plane Breakout Guard
    const serializedBody =
      req.body && Object.keys(req.body).length > 0
        ? typeof req.body === 'string'
          ? req.body
          : JSON.stringify(req.body)
        : '';
    const inspectionTarget = `${req.originalUrl || req.url || ''} ${serializedBody}`.toLowerCase();

    const escapeSignatures = [
      '/var/run/docker.sock',
      '/proc/self/environ',
      '/proc/1/environ',
      'release_agent',
      'nsenter',
      'kexec_load',
      '169.254.169.254',
    ];
    const matchedEscape = escapeSignatures.find((sig) => inspectionTarget.includes(sig));
    if (matchedEscape) {
      blockedSyscallsDelta += 1;
      fetch(`${cypeeUrl}/api/v1/shield/vgruvs/simulate-escape`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sourceEnclave: appId,
          attackerIp: clientIp,
          escapeVector: `HOST_ESCAPE_SIGNATURE:${matchedEscape.toUpperCase()}`,
          targetHostResource: matchedEscape,
        }),
      }).catch(() => {});

      return res.status(403).json({
        error: 'Forbidden',
        message: 'V-Gruvs Host Guardian blocked container breakout / hypervisor probe.',
        code: 'VGRUVS_HOST_BREAKOUT_BLOCKED',
      });
    }

    // Tier 2: Mandatory Enclave Transit Token Check (Reject direct bypass traffic)
    if ((!vgAuthToken && !vgAuthV2) || !timestampStr || !nonce) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Direct access denied. All requests to V-Gruvs must route through the CyPee Security Enclave with a valid VG_AUTH_TOKEN.',
        code: 'MISSING_ENCLAVE_TRANSIT_TOKEN',
      });
    }

    // Tier 3: Replay Attack & Timestamp Freshness Check
    const timestamp = Number(timestampStr);
    const now = Date.now();
    if (!Number.isFinite(timestamp) || Math.abs(now - timestamp) > maxClockSkewMs) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Transit token has expired or clock skew is too large. Possible replay attack.',
        code: 'EXPIRED_TRANSIT_TOKEN',
      });
    }

    if (seenNonces.has(nonce)) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Cryptographic nonce has already been used. Replay attack blocked.',
        code: 'REPLAYED_NONCE_DETECTED',
      });
    }
    seenNonces.set(nonce, now);

    // Tier 4: Verify Payload Body SHA-256 Integrity (prevents on-host bridge tampering)
    if (vgBodySha256 && serializedBody) {
      const actualBodySha256 = crypto.createHash('sha256').update(serializedBody).digest('hex');
      if (!safeCompareHex(vgBodySha256, actualBodySha256)) {
        return res.status(403).json({
          error: 'Forbidden',
          message: 'Payload body SHA-256 mismatch. Request body was modified in transit.',
          code: 'TRANSIT_BODY_TAMPERED',
        });
      }
    }

    // Tier 5: Constant-Time Cryptographic Signature Attestation (v2 preferred, v1 fallback)
    let verified = false;
    if (vgAuthV2 && vgBodySha256) {
      const canonicalV2 = `v2|${vgKeyVersion}|${appId}|${clientIp}|${req.method.toUpperCase()}|${vgPath}|${vgBodySha256}|${timestamp}|${nonce}`;
      const expectedV2 = crypto.createHmac('sha256', secret).update(canonicalV2).digest('hex');
      verified = safeCompareHex(vgAuthV2, expectedV2);
    }

    if (!verified && vgAuthToken) {
      const expectedPayloadV1 = `${appId}|${clientIp}|${req.method}|${timestamp}|${nonce}`;
      const expectedSigV1 = crypto.createHmac('sha256', secret).update(expectedPayloadV1).digest('hex');
      verified = safeCompareHex(vgAuthToken, expectedSigV1);
    }

    if (!verified) {
      fetch(`${cypeeUrl}/api/v1/shield/federated/share`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          threatType: 'VGRUVS_FORGED_TRANSIT_TOKEN',
          rawIndicator: clientIp,
        }),
      }).catch(() => {});

      return res.status(403).json({
        error: 'Forbidden',
        message: 'Cryptographic attestation failed. VG_AUTH_TOKEN is invalid or forged.',
        code: 'TAMPERED_TRANSIT_PROOF',
      });
    }

    // Attach verified enclave metadata to request
    req.enclave = {
      verified: true,
      clientIp,
      appId,
      keyVersion: vgKeyVersion,
      timestamp,
      enclaveVersion: 'v12-Sovereign-ZeroTrust',
    };

    res.setHeader('X-VGruvs-Protected-By', 'CyPee-Enclave-Mesh-v12');
    next();
  };
}

module.exports = { createVGruvsSecurityGuard };
