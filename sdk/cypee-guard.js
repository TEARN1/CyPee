/**
 * CyPee In-App Shield SDK (Node.js / Express / Next.js) — v12 Sovereign Edition
 *
 * Drop-in runtime protection for:
 *   - the-resident (Identity & Resident Portal)
 *   - the-gruvs (Core Operations & Workflow Engine)
 *   - excellency (Financials & Spreadsheets Engine)
 *   - vgruvs (Host Platform)
 *
 * Usage in Express:
 *   const { createCyPeeGuard } = require('./cypee-guard');
 *   app.use(createCyPeeGuard({ cypeeUrl: 'http://127.0.0.1:3000', appId: 'the-resident' }));
 */

const crypto = require('crypto');

function createCyPeeGuard(options = {}) {
  const cypeeUrl = (options.cypeeUrl || process.env.CYPEE_URL || 'http://127.0.0.1:3000').replace(/\/+$/, '');
  const appId = options.appId || process.env.CYPEE_APP_ID || 'the-resident';
  const federatedSalt = options.federatedSalt || process.env.FEDERATED_SALT || 'default-shield-edge-mesh-salt-key';
  const syncIntervalMs = options.syncIntervalMs || 15000;

  let cachedThreatHashes = new Set();

  function hashIndicator(rawIp) {
    return crypto.createHmac('sha256', federatedSalt).update(String(rawIp)).digest('hex');
  }

  // Background polling of CyPee Federated Threat Mesh
  async function syncMesh() {
    try {
      const res = await fetch(`${cypeeUrl}/api/v1/shield/federated/feed`);
      if (res.ok) {
        const feed = await res.json();
        const hashes = new Set(feed.map((item) => item.indicatorHash || item));
        cachedThreatHashes = hashes;
      }
    } catch {
      // CyPee offline fallback: continue operating safely without crashing the host app
    }
  }

  syncMesh();
  const timer = setInterval(syncMesh, syncIntervalMs);
  if (timer.unref) timer.unref();

  return async function cypeeMiddleware(req, res, next) {
    const ip = (req.headers['x-forwarded-for'] || req.ip || req.socket.remoteAddress || '127.0.0.1').split(',')[0].trim();
    const ipHash = hashIndicator(ip);

    // 1. Check if incoming client IP (or its salted HMAC-SHA256 hash) is quarantined in the mesh
    if (cachedThreatHashes.has(ipHash) || cachedThreatHashes.has(ip)) {
      res.setHeader('X-CyPee-Blocked', 'true');
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Client is quarantined by CyPee Cross-Application Threat Mesh.',
        appId,
      });
    }

    // 2. Local Deep Inspection (Universal + App-Specific Signatures for The Resident, The Gruvs, and Excellency)
    const bodyStr = req.body ? JSON.stringify(req.body) : '';
    const queryStr = req.query ? JSON.stringify(req.query) : '';
    const payload = `${req.originalUrl || req.url || ''} ${bodyStr} ${queryStr}`.toLowerCase();

    let detectedVector = null;

    if (
      payload.includes('union select') ||
      payload.includes('or 1=1') ||
      payload.includes('<script>alert(') ||
      payload.includes('/etc/passwd') ||
      payload.includes('/var/run/docker.sock')
    ) {
      detectedVector = 'UNIVERSAL_INJECTION_OR_ESCAPE';
    } else if (appId === 'excellency' && (/[=+\-@]\s*(cmd|powershell|msexe)\s*\|/.test(payload) || payload.includes('<!entity'))) {
      detectedVector = 'EXCELLENCY_DDE_FORMULA_OR_XXE';
    } else if (appId === 'the-gruvs' && (payload.includes('$(') || payload.includes('; cat ') || payload.includes('| sh'))) {
      detectedVector = 'THE_GRUVS_COMMAND_INJECTION';
    } else if (appId === 'the-resident' && (payload.includes('"alg":"none"') || payload.includes('../'))) {
      detectedVector = 'THE_RESIDENT_AUTH_BYPASS_PROBE';
    }

    if (detectedVector) {
      // Immediately add to local cache & broadcast to central CyPee Threat Mesh
      cachedThreatHashes.add(ipHash);
      fetch(`${cypeeUrl}/api/v1/shield/federated/share`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          threatType: detectedVector,
          rawIndicator: ip,
        }),
      }).catch(() => {});

      res.setHeader('X-CyPee-Blocked', 'true');
      return res.status(403).json({
        error: 'Forbidden',
        message: `Attack vector [${detectedVector}] detected and quarantined by CyPee In-App Shield.`,
        appId,
      });
    }

    res.setHeader('X-CyPee-Protected', `In-App-Guard-v12 (${appId})`);
    next();
  };
}

module.exports = { createCyPeeGuard };
