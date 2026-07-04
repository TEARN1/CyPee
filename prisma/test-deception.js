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

async function verifyDatabaseEntries() {
  const { PrismaClient } = require('@prisma/client');
  const { PrismaBetterSqlite3 } = require('@prisma/adapter-better-sqlite3');
  
  const adapter = new PrismaBetterSqlite3({ url: 'file:./dev.db' });
  const prisma = new PrismaClient({ adapter });

  try {
    const incidents = await prisma.incident.findMany({
      where: { type: 'HONEYTOKEN_DECEPTION_TRIGGERED' },
      orderBy: { openedAt: 'desc' },
      take: 2,
    });

    const audits = await prisma.auditLog.findMany({
      where: { action: 'HONEYTOKEN_COMPROMISED' },
      orderBy: { createdAt: 'desc' },
      take: 2,
    });

    return { incidents, audits };
  } finally {
    await prisma.$disconnect();
  }
}

async function run() {
  console.log('\n🍯 STARTING HONEYTOKEN DECEPTION FABRIC TESTS 🍯');

  const email = `deception-test-${Date.now()}@testcorp.com`;
  const password = 'DeceptionTest2025!';
  const regRes = await request('/api/v1/auth/register', 'POST', { email, password, tenantName: 'Deception Test Corp' });
  if (regRes.status !== 201) throw new Error('Setup registration failed');
  const loginRes = await request('/api/v1/auth/login', 'POST', { email, password });
  if (loginRes.status !== 200 || !loginRes.body.token) throw new Error('Setup login failed');
  const auth = { 'Authorization': `Bearer ${loginRes.body.token}` };

  // Test 1: Generate a decoy Honeytoken (requires auth — creating tokens is an admin action)
  console.log('\n1. Creating a decoy honeytoken (AWS Access Key ID)...');
  const tokenRes = await request('/api/v1/deception/honeytoken', 'POST', {
    label: 'decoy-developers-env',
    type: 'AWS',
  }, auth);
  console.log('Status Code:', tokenRes.status);
  console.log('Response Body:', tokenRes.body);
  if (tokenRes.status !== 201 || !tokenRes.body.token) throw new Error('Honeytoken generation failed!');

  // Test 2: Query decoy DB backup route (Trap 1)
  console.log('\n2. Querying decoy database backup endpoint (Trap 1)...');
  const decoyDbRes = await request('/api/v1/admin/db-backup', 'GET', null);
  console.log('Status Code:', decoyDbRes.status);
  console.log('Response Body:', decoyDbRes.body);
  if (decoyDbRes.status !== 200 || decoyDbRes.body.code !== 'DB_CONNECTION_TIMEOUT') {
    throw new Error('Database backup decoy trap returned unexpected response!');
  }

  // Test 3: Query decoy AWS credentials route (Trap 2)
  console.log('\n3. Querying decoy AWS credentials configuration endpoint (Trap 2)...');
  const decoyAwsRes = await request('/api/v1/config/aws-credentials', 'GET', null);
  console.log('Status Code:', decoyAwsRes.status);
  console.log('Response Body:', decoyAwsRes.body);
  if (decoyAwsRes.status !== 200 || !decoyAwsRes.body.aws_access_key_id) {
    throw new Error('AWS credentials decoy trap returned unexpected response!');
  }

  // Allow some time for database writes
  await new Promise(r => setTimeout(r, 1000));

  // Test 4: Verify Database side-effects (incidents and audits)
  console.log('\n4. Verifying database security incidents & audit chains...');
  const dbVerify = await verifyDatabaseEntries();
  console.log(`Discovered Incidents count: ${dbVerify.incidents.length}`);
  console.log(`Discovered Audits count: ${dbVerify.audits.length}`);

  if (dbVerify.incidents.length === 0) {
    throw new Error('No Incident tickets were created for the decoy access!');
  }
  if (dbVerify.audits.length === 0) {
    throw new Error('No immutable Audit Logs were appended for the compromised honeytoken!');
  }

  console.log('\nIncident evidence parsed:', JSON.parse(dbVerify.incidents[0].evidence));
  console.log('Audit metadata parsed:', JSON.parse(dbVerify.audits[0].metadata));

  console.log('\n🎉 ALL DECEPTION HONEYTOKEN TESTS PASSED SUCCESSFULLY! 🎉');
  process.exit(0);
}

run().catch((err) => {
  console.error('\n❌ Test execution failed:', err.message);
  process.exit(1);
});
