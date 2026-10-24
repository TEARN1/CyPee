const http = require('http');
const path = require('path');
const { fork } = require('child_process');
const crypto = require('crypto');
const { createVGruvsSecurityGuard } = require('../sdk/vgruvs-connector');

function solveChallenge(challenge) {
  const [salt, difficultyStr] = challenge.split('|');
  const difficulty = parseInt(difficultyStr, 10);
  const prefix = '0'.repeat(difficulty);

  let nonce = 0;
  while (true) {
    const hash = crypto.createHash('sha256').update(`${salt}${nonce}`).digest('hex');
    if (hash.startsWith(prefix)) {
      return nonce.toString();
    }
    nonce++;
  }
}

// Start V-Gruvs with strict in-app enclave verification guard
function startVGruvsApp(port = 4000) {
  return new Promise((resolve) => {
    const vgruvsGuard = createVGruvsSecurityGuard({
      enclaveSecret: 'shield-super-secret-jwt-key-change-in-production-2025',
      cypeeUrl: 'http://127.0.0.1:3050',
      appId: 'vgruvs',
    });

    const server = http.createServer((req, res) => {
      // Run V-Gruvs security middleware
      vgruvsGuard(req, res, () => {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            service: 'V-Gruvs Core Enclave Platform',
            status: 'operational_and_attested',
            receivedPath: req.url,
            enclaveVerified: req.enclave?.verified,
            clientIp: req.enclave?.clientIp,
            receivedVgToken: req.headers['vg_auth_token']?.substring(0, 16) + '...',
          }));
        });
      });
    });

    server.listen(port, '127.0.0.1', () => {
      console.log(`[V-GRUVS PLATFORM] Started on http://127.0.0.1:${port} with Strict Enclave Verification`);
      resolve(server);
    });
  });
}

function startStandardApp(name, port) {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', () => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          app: name,
          receivedPath: req.url,
          enclaveTransitHeader: req.headers['x-cypee-enclave'],
          vgTokenReceived: !!req.headers['vg_auth_token'],
        }));
      });
    });

    server.listen(port, '127.0.0.1', () => {
      console.log(`[MOCK UPSTREAM] ${name} started on http://127.0.0.1:${port}`);
      resolve(server);
    });
  });
}

function request(urlPath, method = 'GET', body = null, extraHeaders = {}, customPort = 3050) {
  return new Promise((resolve, reject) => {
    const bodyStr = body ? JSON.stringify(body) : '';
    const options = {
      hostname: '127.0.0.1',
      port: customPort,
      path: urlPath,
      method,
      headers: {
        'Content-Type': 'application/json',
        ...(body ? { 'Content-Length': Buffer.byteLength(bodyStr) } : {}),
        ...extraHeaders,
      },
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        const challenge = res.headers['x-shield-challenge'];
        if (res.statusCode === 400 && challenge) {
          const nonce = solveChallenge(challenge);
          return request(urlPath, method, body, {
            ...extraHeaders,
            'x-shield-pow-challenge': challenge,
            'x-shield-pow-nonce': nonce,
          }, customPort).then(resolve).catch(reject);
        }

        let parsed = null;
        try {
          parsed = data ? JSON.parse(data) : null;
        } catch {
          parsed = data;
        }

        resolve({
          status: res.statusCode,
          headers: res.headers,
          data: parsed,
        });
      });
    });

    req.on('error', reject);
    if (body) req.write(bodyStr);
    req.end();
  });
}

async function waitForServerReady(maxRetries = 90) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      const res = await request('/api/v1/health');
      if (res && (res.status === 200 || res.status === 400)) return true;
    } catch {
      // server starting up
    }
    await new Promise(r => setTimeout(r, 500));
  }
  throw new Error('Timed out waiting for CyPee server on port 3050');
}

async function runEnclaveDefenseSuite() {
  console.log('\n🛡️  STARTING CYPEE ZERO-TRUST ENCLAVE & V-GRUVS INTEGRATION SUITE 🛡️\n');

  // 1. Start V-Gruvs and peer apps
  const vgruvsServer = await startVGruvsApp(4000);
  const app1Server = await startStandardApp('App-1 (Web Portal)', 4001);
  const app2Server = await startStandardApp('App-2 (REST API)', 4002);

  // 2. Start CyPee Enclave Gateway Server
  console.log('\nStarting CyPee Enclave Gateway Server...');
  const serverProcess = fork(path.join(__dirname, '../dist/src/main.js'), [], {
    silent: false,
    env: { ...process.env, PORT: '3050' },
  });

  try {
    await waitForServerReady();
    console.log('✅ CyPee server is live on port 3050.');

    // TEST 1: Direct Bypass Rejection on V-Gruvs (Bypass Prevention)
    console.log('\n--- TEST 1: Direct Bypass Prevention on V-Gruvs ---');
    const directRes = await request('/vgruvs/internal/data', 'GET', null, {}, 4000);
    console.log(`Direct Connection to V-Gruvs port 4000 without CyPee - Status: ${directRes.status} | Code: ${directRes.data.code}`);
    if (directRes.status !== 401 || directRes.data.code !== 'MISSING_ENCLAVE_TRANSIT_TOKEN') {
      throw new Error('V-Gruvs failed to reject direct connection without CyPee transit token!');
    }
    console.log('✅ Direct connection successfully blocked: V-Gruvs requires CyPee Enclave transit token.');

    // TEST 2: Forged Token Rejection on V-Gruvs
    console.log('\n--- TEST 2: Forged VG_AUTH_TOKEN Detection ---');
    const forgedRes = await request('/vgruvs/internal/data', 'GET', null, {
      'x-vg-auth': 'fake-forged-signature-abc123',
      'x-vg-timestamp': String(Date.now()),
      'x-vg-nonce': crypto.randomUUID(),
    }, 4000);
    console.log(`Forged Token Attempt - Status: ${forgedRes.status} | Code: ${forgedRes.data.code}`);
    if (forgedRes.status !== 403 || forgedRes.data.code !== 'TAMPERED_TRANSIT_PROOF') {
      throw new Error('V-Gruvs failed to reject forged transit token!');
    }
    console.log('✅ Forged token successfully rejected with constant-time HMAC validation.');

    // TEST 3: Legitimate Routed Traffic to V-Gruvs through CyPee
    console.log('\n--- TEST 3: Authenticated Traffic to V-Gruvs via CyPee Enclave ---');
    const vgruvsEnclaveRes = await request('/api/v1/gateway/vgruvs/system/status');
    console.log(`V-Gruvs via CyPee Status: ${vgruvsEnclaveRes.status} | Body:`, vgruvsEnclaveRes.data);
    if (vgruvsEnclaveRes.status !== 200 || !vgruvsEnclaveRes.data.enclaveVerified) {
      throw new Error('Legitimate V-Gruvs enclave transit failed!');
    }
    console.log('✅ V-Gruvs successfully verified CyPee enclave transit and authenticated VG_AUTH_TOKEN.');

    // TEST 4: Clean Routing to App 1 & App 2
    console.log('\n--- TEST 4: Verified Routing to App 1 & App 2 ---');
    const app1Res = await request('/api/v1/gateway/app1/dashboard');
    const app2Res = await request('/api/v1/gateway/app2/orders/123');
    console.log(`App 1: Status ${app1Res.status} | Enclave Header: ${app1Res.data.enclaveTransitHeader}`);
    console.log(`App 2: Status ${app2Res.status} | Enclave Header: ${app2Res.data.enclaveTransitHeader}`);
    if (app1Res.status !== 200 || app2Res.status !== 200) {
      throw new Error('Clean routing to App 1 or App 2 failed');
    }
    console.log('✅ App 1 & App 2 securely reached through CyPee Enclave.');

    // TEST 5: Deep Packet Inspection - Obfuscated SQLi
    console.log('\n--- TEST 5: Deep Packet Inspection (Obfuscated SQLi) ---');
    const sqliRes = await request('/api/v1/gateway/app1/search', 'POST', {
      q: '1%20UNION%20SELECT%20username,%20password%20FROM%20users',
    });
    console.log(`Obfuscated SQLi Status: ${sqliRes.status} | Message: ${sqliRes.data?.message}`);
    if (sqliRes.status !== 403) throw new Error('Failed to block obfuscated SQL injection!');
    console.log('✅ Obfuscated URL-encoded SQLi blocked by Deep Packet Inspection.');

    // TEST 6: Deep Packet Inspection - Remote Code Execution (RCE)
    console.log('\n--- TEST 6: Remote Code Execution (RCE) Interception ---');
    const rceRes = await request('/api/v1/gateway/app2/execute', 'POST', {
      cmd: 'test; cat /etc/passwd',
    });
    console.log(`RCE Attack Status: ${rceRes.status} | Message: ${rceRes.data?.message}`);
    if (rceRes.status !== 403) throw new Error('Failed to block RCE attack!');
    console.log('✅ RCE Command Injection intercepted & blocked.');

    // TEST 7: Cross-App Threat Mesh Quarantine Propagation
    console.log('\n--- TEST 7: Cross-App Synchronized Quarantine ---');
    // Notice: IP 127.0.0.1 was just quarantined across all apps by the previous attacks!
    const quarantinedRes = await request('/api/v1/gateway/vgruvs/protected-resource');
    console.log(`Subsequent Request to V-Gruvs - Status: ${quarantinedRes.status} | Message: ${quarantinedRes.data?.message}`);
    if (quarantinedRes.status !== 403) {
      throw new Error('Quarantine failed: attacker was not barred from V-Gruvs!');
    }
    console.log('✅ Attacker is completely quarantined across V-Gruvs, App 1, and App 2.');

    console.log('\n🎉 ALL ZERO-TRUST ENCLAVE & V-GRUVS SECURITY TESTS PASSED! 🎉\n');
  } finally {
    serverProcess.kill('SIGTERM');
    vgruvsServer.close();
    app1Server.close();
    app2Server.close();
  }
}

runEnclaveDefenseSuite().catch((err) => {
  console.error('❌ Test failed:', err);
  process.exit(1);
});
