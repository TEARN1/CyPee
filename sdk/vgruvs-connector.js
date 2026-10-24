/**
 * V-Gruvs Enterprise Security Connector for CyPee Enclave
 * 
 * Provides cryptographic transit verification (VG_AUTH_TOKEN), anti-tampering,
 * replay attack prevention, and synchronized threat reporting for V-Gruvs.
 * 
 * Usage in Express / Node.js:
 *   const { createVGruvsSecurityGuard } = require('./sdk/vgruvs-connector');
 *   app.use(createVGruvsSecurityGuard({
 *     enclaveSecret: process.env.ENCLAVE_SECRET || 'shield-super-secret-jwt-key-change-in-production-2025',
 *     cypeeUrl: 'http://localhost:3050',
 *     appId: 'vgruvs'
 *   }));
 */

const crypto = require('crypto');

function createVGruvsSecurityGuard(options = {}) {
  const secret = options.enclaveSecret || process.env.ENCLAVE_SECRET || 'shield-super-secret-jwt-key-change-in-production-2025';
  const cypeeUrl = (options.cypeeUrl || process.env.CYPEE_URL || 'http://127.0.0.1:3050').replace(/\/+$/, '');
  const appId = options.appId || 'vgruvs';
  const maxClockSkewMs = options.maxClockSkewMs || 60000; // 60s max timestamp variance

  const seenNonces = new Set();

  // Periodically flush old nonces to prevent memory leak
  setInterval(() => seenNonces.clear(), 120000).unref();

  return function vgruvsSecurityMiddleware(req, res, next) {
    const vgAuthToken = req.headers['x-vg-auth'] || req.headers['vg_auth_token'];
    const timestampStr = req.headers['x-vg-timestamp'];
    const nonce = req.headers['x-vg-nonce'];
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';

    // 1. Mandatory Enclave Token Check: Reject direct bypass traffic!
    if (!vgAuthToken || !timestampStr || !nonce) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Direct access denied. All requests to V-Gruvs must route through the CyPee Security Enclave with a valid VG_AUTH_TOKEN.',
        code: 'MISSING_ENCLAVE_TRANSIT_TOKEN',
      });
    }

    // 2. Replay Attack & Timestamp Freshness Check
    const timestamp = parseInt(timestampStr, 10);
    const now = Date.now();
    if (isNaN(timestamp) || Math.abs(now - timestamp) > maxClockSkewMs) {
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
    seenNonces.add(nonce);

    // 3. Constant-Time Cryptographic Signature Attestation
    const expectedPayload = `${appId}|${clientIp}|${req.method}|${timestamp}|${nonce}`;
    const expectedSig = crypto.createHmac('sha256', secret).update(expectedPayload).digest('hex');

    const bufA = Buffer.from(vgAuthToken, 'utf8');
    const bufB = Buffer.from(expectedSig, 'utf8');

    const isMatch = bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB);
    if (!isMatch) {
      // Report forged/tampered token back to CyPee Threat Mesh immediately
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
      timestamp,
      enclaveVersion: 'v11-ZeroTrust',
    };

    res.setHeader('X-VGruvs-Protected-By', 'CyPee-Enclave-Mesh');
    next();
  };
}

module.exports = { createVGruvsSecurityGuard };
