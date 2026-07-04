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

  // 1. Fetch current findings list
  console.log('\n1. Fetching active findings list from database...');
  const listRes = await request('/api/v1/compliance/findings', 'GET', null);
  console.log('Status Code:', listRes.status);
  
  if (listRes.status !== 200 || !Array.isArray(listRes.body)) {
    throw new Error('Failed to retrieve active findings list');
  }

  if (listRes.body.length === 0) {
    console.log('⚠️ Findings database is empty. Triggering a quick mock scan to populate...');
    
    // Trigger mock scan
    const scanRes = await request('/api/v1/scans', 'POST', {
      repositoryUrl: 'https://github.com/OWASP/WebGoat',
      repositoryName: 'WebGoat-Test',
    });
    
    // Wait for the scan modules to complete db inserts
    await new Promise(r => setTimeout(r, 6000));
    
    // Re-fetch findings list
    const listRes2 = await request('/api/v1/compliance/findings', 'GET', null);
    listRes.body = listRes2.body;
    listRes.status = listRes2.status;
  }

  console.log('First finding returned:', JSON.stringify(listRes.body[0], null, 2));

  // Find a patchable finding (e.g. exposed port or security header or API endpoint)
  const patchable = listRes.body.find(f => f.filePath && f.lineNumber && f.filePath.includes('docker-compose'));
  if (!patchable) {
    console.warn('⚠️ No patchable docker-compose finding found. Let\'s check for other patchable files.');
  }

  const targetFinding = patchable || listRes.body.find(f => f.filePath && f.lineNumber);
  if (!targetFinding) {
    throw new Error('No patchable findings containing file paths and line numbers found in database! Run a scan first.');
  }

  // Map keys if the controller response mapping differs from database model
  const findingId = targetFinding.id || targetFinding.findingId;
  const title = targetFinding.title || targetFinding.ruleId;

  console.log(`\nSelected Target Finding for patch test:`);
  console.log(`- ID: ${findingId}`);
  console.log(`- Title: ${title}`);
  console.log(`- File Path: ${targetFinding.filePath}`);
  console.log(`- Line Number: ${targetFinding.lineNumber}`);

  if (!findingId) {
    throw new Error('Selected target finding ID is undefined!');
  }

  // 2. Request auto-remediation fix
  console.log('\n2. Sending POST auto-fix request to backend...');
  const fixRes = await request(`/api/v1/compliance/findings/${findingId}/fix`, 'POST', null);
  console.log('Status Code:', fixRes.status);
  console.log('Response Body:', fixRes.body);

  if (fixRes.status !== 200) {
    throw new Error('Remediation request returned non-200 code!');
  }

  if (!fixRes.body.success) {
    throw new Error(`Remediation patch failed: ${fixRes.body.message}`);
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

  console.log('✅ Git Diff contains edits.');

  console.log('\n🎉 ALL AUTO-REMEDIATION FIX TESTS PASSED SUCCESSFULLY! 🎉');
  process.exit(0);
}

run().catch((err) => {
  console.error('\n❌ Test execution failed:', err.message);
  process.exit(1);
});
