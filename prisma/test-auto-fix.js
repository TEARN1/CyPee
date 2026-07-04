const http = require('http');

function solveChallenge(challenge) {
  const crypto = require('crypto');
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

function request(path, method, body, headers = {}) {
  return new Promise((resolve) => {
    const bodyStr = body ? JSON.stringify(body) : '';
    const options = {
      hostname: 'localhost',
      port: 3000,
      path,
      method,
      headers: {
        'Content-Type': 'application/json',
        ...(body ? { 'Content-Length': Buffer.byteLength(bodyStr) } : {}),
        ...headers,
      },
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
      res.on('end', () => {
        const challenge = res.headers['x-shield-challenge'];
        if (res.statusCode === 400 && challenge) {
          const nonce = solveChallenge(challenge);
          const retriedHeaders = {
            ...headers,
            'x-shield-pow-challenge': challenge,
            'x-shield-pow-nonce': nonce
          };
          resolve(request(path, method, body, retriedHeaders));
          return;
        }

        try {
          resolve({ status: res.statusCode, body: JSON.parse(data), headers: res.headers });
        } catch {
          resolve({ status: res.statusCode, body: data, headers: res.headers });
        }
      });
    });

    req.on('error', (e) => {
      resolve({ status: 500, error: e.message });
    });
    if (body) req.write(bodyStr);
    req.end();
  });
}

async function run() {
  console.log('\n🔧 STARTING AUTO-REMEDIATION AUTO-FIX ENGINE TESTS 🔧');

  const email = `auto-fix-test-${Date.now()}@testcorp.com`;
  const password = 'AutoFixTest2025!';
  const regRes = await request('/api/v1/auth/register', 'POST', { email, password, tenantName: 'Auto Fix Test Corp' });
  if (regRes.status !== 201) throw new Error('Setup registration failed');
  const loginRes = await request('/api/v1/auth/login', 'POST', { email, password });
  if (loginRes.status !== 200 || !loginRes.body.token) throw new Error('Setup login failed');
  const token = loginRes.body.token;
  const auth = { 'Authorization': `Bearer ${token}` };

  // 1. Fetch current findings list
  console.log('\n1. Fetching active findings list from database...');
  const listRes = await request('/api/v1/compliance/findings', 'GET', null, auth);
  console.log('Status Code:', listRes.status);

  if (listRes.status !== 200 || !Array.isArray(listRes.body)) {
    throw new Error('Failed to retrieve active findings list');
  }

  if (listRes.body.length === 0) {
    console.log('⚠️ Findings database is empty. Triggering a quick mock scan to populate...');

    // Trigger a scan and poll until findings show up (a real clone + semgrep
    // scan of an external repo takes longer than a fixed short sleep allows)
    const scanRes = await request('/api/v1/scans', 'POST', {
      repositoryUrl: 'https://github.com/OWASP/WebGoat',
      repositoryName: 'WebGoat-Test',
    }, auth);

    const deadline = Date.now() + 5 * 60 * 1000;
    let listRes2 = { body: [] };
    while (Date.now() < deadline) {
      await new Promise(r => setTimeout(r, 5000));
      listRes2 = await request('/api/v1/compliance/findings', 'GET', null, auth);
      if (Array.isArray(listRes2.body) && listRes2.body.length > 0) break;
    }
    listRes.body = listRes2.body;
    listRes.status = listRes2.status;
  }

  console.log('First finding returned:', JSON.stringify(listRes.body[0], null, 2));

  // Prefer a finding that matches one of auto-fix's known deterministic patterns
  // (exposed docker-compose db port); if none exists in this scan's results,
  // fall back to any patchable-looking finding and verify the HONEST "no
  // automated fix available" response instead — both are valid outcomes to test.
  const deterministicMatch = listRes.body.find(f =>
    f.filePath && f.lineNumber && f.filePath.includes('docker-compose'),
  );
  const targetFinding = deterministicMatch || listRes.body.find(f => f.filePath && f.lineNumber);
  if (!targetFinding) {
    throw new Error('No findings containing file paths and line numbers found in database! Run a scan first.');
  }

  const findingId = targetFinding.id || targetFinding.findingId;
  const title = targetFinding.title || targetFinding.ruleId;

  console.log(`\nSelected Target Finding for patch test:`);
  console.log(`- ID: ${findingId}`);
  console.log(`- Title: ${title}`);
  console.log(`- File Path: ${targetFinding.filePath}`);
  console.log(`- Line Number: ${targetFinding.lineNumber}`);
  console.log(`- Expecting a deterministic patch: ${!!deterministicMatch}`);

  if (!findingId) {
    throw new Error('Selected target finding ID is undefined!');
  }

  // 2. Request auto-remediation fix
  console.log('\n2. Sending POST auto-fix request to backend...');
  const fixRes = await request(`/api/v1/compliance/findings/${findingId}/fix`, 'POST', null, auth);
  console.log('Status Code:', fixRes.status);
  console.log('Response Body:', fixRes.body);

  if (fixRes.status !== 200) {
    throw new Error('Remediation request returned non-200 code!');
  }

  if (deterministicMatch) {
    if (!fixRes.body.success || fixRes.body.method !== 'deterministic') {
      throw new Error(`Expected a deterministic patch to succeed, got: ${JSON.stringify(fixRes.body)}`);
    }

    console.log('\n3. Validating returned Git payload details...');
    console.log(`- Generated Branch: ${fixRes.body.branchName}`);
    console.log(`- Git Diff Output:\n${fixRes.body.diff}`);

    if (!fixRes.body.branchName.startsWith('shield/remediate-')) {
      throw new Error('Remediation branch naming format incorrect!');
    }
    if (!fixRes.body.diff) {
      throw new Error('Auto-fix did not return a valid Git diff!');
    }
    console.log('✅ Deterministic git diff contains edits.');
  } else {
    // No ANTHROPIC_API_KEY configured in this test environment, so a finding
    // with no deterministic match must honestly report failure, not fake a fix.
    if (fixRes.body.success !== false || fixRes.body.method !== 'none') {
      throw new Error(`Expected an honest "no automated fix" response, got: ${JSON.stringify(fixRes.body)}`);
    }
    if (!fixRes.body.message.includes('No automated fix pattern available')) {
      throw new Error(`Unexpected message for the no-fix-available case: ${fixRes.body.message}`);
    }
    console.log('✅ Correctly reported no automated fix available (no deterministic match, AI suggestions disabled).');
  }

  console.log('\n🎉 ALL AUTO-REMEDIATION FIX TESTS PASSED SUCCESSFULLY! 🎉');
  process.exit(0);
}

run().catch((err) => {
  console.error('\n❌ Test execution failed:', err.message);
  process.exit(1);
});
