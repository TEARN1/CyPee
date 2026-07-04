const http = require('http');

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

// Simple client-side PoW solver
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

async function run() {
  console.log('\n🛡️ STARTING AI DEFENSIVE SHIELD INTEGRATION TESTS 🛡️');

  // Test 1: Vector Firewall Injection Blocking
  console.log('\n1. Testing Vector Firewall (sending SQL injection payload)...');
  const injectionPayload = {
    query: "SELECT * FROM users WHERE username = 'admin' UNION SELECT password FROM users OR 1=1",
  };
  const res1 = await request('/api/v1/compliance/findings', 'GET', injectionPayload);
  console.log('Status Code:', res1.status);
  console.log('Response Body:', res1.body);
  if (res1.status !== 403) throw new Error('Vector Firewall failed to intercept SQL injection query!');
  console.log('✅ Vector Firewall successfully blocked SQL injection.');

  // Test 2: Standard safe request payload
  console.log('\n2. Testing safe payload representation...');
  const safePayload = {
    username: 'safe-user',
    action: 'query-status',
  };
  const res2 = await request('/api/v1/auth/login', 'POST', safePayload);
  console.log('Status Code:', res2.status); // should return 200 (auth code requirements) or similar, but NOT 403
  if (res2.status === 403) throw new Error('Vector Firewall blocked safe payload mistakenly!');
  console.log('✅ Safe payload parsed successfully without firewall interference.');

  // Test 3: Automated Bot spacing / Jitter test (triggering bot detection)
  console.log('\n3. Triggering automated bot detector (sending multiple rapid queries)...');
  let challengeHeader = null;
  // Use 15 iterations to flush out any previous slow requests from the sliding history window (size 10)
  for (let i = 0; i < 15; i++) {
    const res = await request('/api/v1/compliance/findings', 'GET', null);
    if (res.headers['x-shield-challenge']) {
      challengeHeader = res.headers['x-shield-challenge'];
    }
    // minimal sleep to simulate script fuzzer execution speed
    await new Promise(r => setTimeout(r, 5));
  }
  console.log(`Bot trigger completed. Challenge returned: ${challengeHeader}`);
  if (!challengeHeader) throw new Error('Bot detector failed to generate PoW challenge!');

  // Test 4: Solving challenge and bypassing block
  console.log('\n4. Solving PoW challenge and validating bypass...');
  const nonce = solveChallenge(challengeHeader);
  console.log(`Solved challenge nonce: ${nonce}`);
  const powBypassRes = await request('/api/v1/compliance/findings', 'GET', null, {
    'x-shield-pow-challenge': challengeHeader,
    'x-shield-pow-nonce': nonce,
  });
  console.log('Status Code:', powBypassRes.status);
  if (powBypassRes.status === 400) throw new Error('PoW challenge verification failed on server!');
  console.log('✅ Proof of Work verification successfully completed.');

  console.log('\n🎉 ALL AI SHIELD DEFENSIVE TESTS PASSED SUCCESSFULLY! 🎉');
  process.exit(0);
}

run().catch((err) => {
  console.error('\n❌ Test execution failed:', err.message);
  process.exit(1);
});
