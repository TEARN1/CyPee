/**
 * CyPee In-App Shield SDK (Node.js / Express / Next.js)
 * 
 * Drop this file directly into any of your target applications to provide instant
 * in-process defense connected to the CyPee Threat Mesh.
 * 
 * Usage in Express:
 *   const { createCyPeeGuard } = require('./cypee-guard');
 *   app.use(createCyPeeGuard({ cypeeUrl: 'http://localhost:3000', appId: 'app1' }));
 */

function createCyPeeGuard(options = {}) {
  const cypeeUrl = (options.cypeeUrl || process.env.CYPEE_URL || 'http://127.0.0.1:3000').replace(/\/+$/, '');
  const appId = options.appId || process.env.CYPEE_APP_ID || 'app_default';
  const syncIntervalMs = options.syncIntervalMs || 15000; // sync threat mesh every 15s

  let cachedThreatHashes = new Set();

  // Background polling of CyPee Federated Threat Mesh
  async function syncMesh() {
    try {
      const res = await fetch(`${cypeeUrl}/api/v1/shield/federated/feed`);
      if (res.ok) {
        const feed = await res.json();
        const hashes = new Set(feed.map(item => item.indicatorHash || item));
        cachedThreatHashes = hashes;
      }
    } catch (e) {
      // CyPee offline fallback: continue operating safely without crashing the host app
    }
  }

  // Initial sync & interval setup
  syncMesh();
  const timer = setInterval(syncMesh, syncIntervalMs);
  if (timer.unref) timer.unref();

  return async function cypeeMiddleware(req, res, next) {
    const ip = req.ip || req.socket.remoteAddress || '127.0.0.1';

    // 1. Check if incoming client IP is currently quarantined in the mesh
    // (Notice: uses crypto HMAC or fast query check if indicator matches)
    if (cachedThreatHashes.has(ip)) {
      res.setHeader('X-CyPee-Blocked', 'true');
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Client is quarantined by CyPee Cross-Application Threat Mesh.',
        appId,
      });
    }

    // 2. Local fast injection signature inspection
    const bodyStr = req.body ? JSON.stringify(req.body) : '';
    const queryStr = req.query ? JSON.stringify(req.query) : '';
    const payload = `${bodyStr} ${queryStr}`.toLowerCase();

    const isMalicious = 
      payload.includes('union select') ||
      payload.includes('or 1=1') ||
      payload.includes('<script>alert(') ||
      payload.includes('/etc/passwd');

    if (isMalicious) {
      // Report attack to central CyPee mesh asynchronously to trigger instant quarantine across all other apps
      fetch(`${cypeeUrl}/api/v1/shield/federated/share`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          threatType: 'IN_APP_INJECTION_DETECTED',
          rawIndicator: ip,
        }),
      }).catch(() => {});

      res.setHeader('X-CyPee-Blocked', 'true');
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Attack vector detected and quarantined by CyPee In-App Shield.',
        appId,
      });
    }

    // Inject CyPee assurance header
    res.setHeader('X-CyPee-Protected', 'In-App-Guard-Active');
    next();
  };
}

module.exports = { createCyPeeGuard };
