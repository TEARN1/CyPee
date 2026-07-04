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
  console.log('\n🏥 STARTING HEALTH DIAGNOSTICS & SYSTEM STATUS TESTS 🏥');

  // Test: Query health check endpoint
  console.log('\n1. Querying system health endpoint...');
  const healthRes = await request('/api/v1/health', 'GET', null);
  console.log('Status Code:', healthRes.status);
  console.log('Response Body:', JSON.stringify(healthRes.body, null, 2));

  if (healthRes.status !== 200 || healthRes.body.status !== 'UP') {
    throw new Error('System health check returned degraded status!');
  }

  console.log('\n2. Validating service checks...');
  console.log(`- Database Service: ${healthRes.body.services.database.status}`);
  console.log(`- Queue Service: ${healthRes.body.services.queue.status}`);
  console.log(`- Shield Service: ${healthRes.body.services.shield.status}`);

  if (healthRes.body.services.database.status !== 'UP') {
    throw new Error('Prisma database adapter check failed!');
  }

  console.log('\n🎉 ALL HEALTH DIAGNOSTICS TESTS PASSED SUCCESSFULLY! 🎉');
  process.exit(0);
}

run().catch((err) => {
  console.error('\n❌ Test execution failed:', err.message);
  process.exit(1);
});
