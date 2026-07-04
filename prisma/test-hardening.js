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

function request(path, method, body, token = null, headers = {}) {
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
        ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
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
          resolve(request(path, method, body, token, retriedHeaders));
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
  console.log('\n🔒 STARTING SECURITY HARDENING & CONCURRENCY CONTROL TESTS 🔒');

  // Setup: register + login to obtain an authenticated user/token for guarded endpoints
  const email = `hardening-test-${Date.now()}@testcorp.com`;
  const password = 'HardeningTest2025!';
  const regRes = await request('/api/v1/auth/register', 'POST', {
    email,
    password,
    tenantName: 'Hardening Test Corp',
  });
  if (regRes.status !== 201) throw new Error('Setup registration failed');

  const loginRes = await request('/api/v1/auth/login', 'POST', { email, password });
  if (loginRes.status !== 200 || !loginRes.body.token) throw new Error('Setup login failed');
  const token = loginRes.body.token;
  const userId = loginRes.body.user.id;

  // Test 1: Constant-Time Comparison
  console.log('\n1. Verifying Timing-Safe String Comparison...');
  const compRes1 = await request('/api/v1/shield/hardening/compare', 'POST', {
    secret1: 'SuperSecretToken2025!',
    secret2: 'SuperSecretToken2025!'
  }, token);
  console.log('Matching secrets test status:', compRes1.status, 'Match:', compRes1.body.match);

  const compRes2 = await request('/api/v1/shield/hardening/compare', 'POST', {
    secret1: 'SuperSecretToken2025!',
    secret2: 'AttackerGuessingToken!'
  }, token);
  console.log('Mismatching secrets test status:', compRes2.status, 'Match:', compRes2.body.match);

  if (compRes1.body.match !== true || compRes2.body.match !== false) {
    throw new Error('Timing safe compare utility returned incorrect result!');
  }
  console.log('✅ Timing-safe compare utility verified successfully.');

  // Test 2: Concurrency Race Condition Block
  console.log('\n2. Testing Race Condition prevention (sending overlapping concurrent transactions)...');

  // Pre-solve a PoW challenge and attach it to both requests up front. Without this,
  // the bot-behavior detector's reactive challenge-then-retry cycle (triggered after
  // several rapid requests from this test script) adds nondeterministic delay to
  // whichever request gets challenged, which would desynchronize the two "concurrent"
  // requests and mask the race condition this test is meant to exercise.
  const precheck = await request('/api/v1/shield/hardening/transaction', 'POST', { userId, amount: 1 }, token);
  const challenge = precheck.headers?.['x-shield-challenge'];
  const powHeaders = challenge
    ? { 'x-shield-pow-challenge': challenge, 'x-shield-pow-nonce': solveChallenge(challenge) }
    : {};

  // Fire two transaction queries simultaneously (no ordering assumed, since JWT auth
  // adds nondeterministic async latency before either reaches the lock manager)
  console.log('Dispatching Transaction Request 1 and 2 concurrently...');
  const [tx1, tx2] = await Promise.all([
    request('/api/v1/shield/hardening/transaction', 'POST', { userId, amount: 250 }, token, powHeaders),
    request('/api/v1/shield/hardening/transaction', 'POST', { userId, amount: 250 }, token, powHeaders)
  ]);

  console.log('Request 1 Result - Status:', tx1.status, 'Body:', tx1.body);
  console.log('Request 2 Result - Status:', tx2.status, 'Body:', tx2.body);

  const results = [tx1, tx2];
  const succeeded = results.filter(r => r.status === 200);
  const blocked = results.filter(r => r.status === 400 && r.body.message?.includes('Concurrent request active'));

  if (succeeded.length === 1 && blocked.length === 1) {
    console.log('✅ Concurrency Lock Manager successfully blocked the race condition transfer!');
  } else {
    throw new Error('Race condition control failed! Both requests processed or returned unexpected errors.');
  }

  // Test 3: HTTP Parameter Pollution
  console.log('\n3. Testing HTTP Parameter Pollution (HPP) flattening...');
  const hppRes = await request('/api/v1/shield/hardening/query?apiKey=secret_key_1&apiKey=secret_key_2', 'GET', null, token);
  console.log('HPP Status:', hppRes.status, 'Sanitized Parameters:', hppRes.body.sanitized);

  if (hppRes.body.sanitized.apiKey !== 'secret_key_1') {
    throw new Error('HTTP Parameter Pollution sanitizer failed to flatten query inputs!');
  }
  console.log('✅ HTTP Parameter Pollution validation verified successfully.');

  console.log('\n🎉 ALL SECURITY HARDENING TESTS PASSED SUCCESSFULLY! 🎉');
  process.exit(0);
}

run().catch((err) => {
  console.error('\n❌ Test execution failed:', err.message);
  process.exit(1);
});
