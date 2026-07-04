const http = require('http');

const email = `test-user-${Math.random().toString(36).substring(2, 7)}@testcorp.com`;
const password = 'TestSecurePassword2025!';
const tenantName = 'Test Corp Inc';

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

function request(path, method, body, token = null, extraHeaders = {}) {
  return new Promise((resolve, reject) => {
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
        ...extraHeaders,
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
          // Solve PoW challenge on the fly and retry
          const nonce = solveChallenge(challenge);
          const retriedHeaders = {
            ...extraHeaders,
            'x-shield-pow-challenge': challenge,
            'x-shield-pow-nonce': nonce
          };
          resolve(request(path, method, body, token, retriedHeaders));
          return;
        }

        try {
          const parsed = data ? JSON.parse(data) : {};
          resolve({ status: res.statusCode, body: parsed });
        } catch {
          resolve({ status: res.statusCode, body: data });
        }
      });
    });

    req.on('error', (e) => reject(e));
    if (body) req.write(bodyStr);
    req.end();
  });
}

// Custom simple TOTP generator for local validation
function generateTOTP(secret) {
  const crypto = require('crypto');
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  
  // Decode base32 secret to bytes
  const secretBytes = [];
  let buffer = 0;
  let bits = 0;
  for (let i = 0; i < secret.length; i++) {
    const val = alphabet.indexOf(secret[i].toUpperCase());
    if (val === -1) continue;
    buffer = (buffer << 5) | val;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      secretBytes.push((buffer >> bits) & 0xff);
    }
  }
  const key = Buffer.from(secretBytes);

  const time = Math.floor(Date.now() / 1000 / 30);
  const timeBuffer = Buffer.alloc(8);
  let temp = time;
  for (let j = 7; j >= 0; temp = Math.floor(temp / 256), j--) {
    timeBuffer[j] = temp & 0xff;
  }

  const hmac = crypto.createHmac('sha1', key).update(timeBuffer).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const codeBytes =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  return (codeBytes % 1_000_000).toString().padStart(6, '0');
}

async function run() {
  console.log(`\n1. Registering new tenant admin user: ${email}...`);
  const regRes = await request('/api/v1/auth/register', 'POST', {
    email,
    password,
    tenantName,
  });
  console.log('Status:', regRes.status, 'Body:', regRes.body);
  if (regRes.status !== 201) throw new Error('Registration failed');

  console.log('\n2. Logging in (without MFA enabled yet)...');
  const loginRes1 = await request('/api/v1/auth/login', 'POST', {
    email,
    password,
  });
  console.log('Status:', loginRes1.status, 'Token returned:', !!loginRes1.body.token);
  if (loginRes1.status !== 200 || !loginRes1.body.token) throw new Error('Initial login failed');
  const token = loginRes1.body.token;

  console.log('\n3. Requesting MFA enrollment secret...');
  const mfaSetup = await request('/api/v1/auth/mfa/setup', 'POST', null, token);
  console.log('Status:', mfaSetup.status, 'Secret:', mfaSetup.body.secret);
  if (mfaSetup.status !== 200 || !mfaSetup.body.secret) throw new Error('MFA setup request failed');
  const mfaSecret = mfaSetup.body.secret;

  console.log('\n4. Confirming and activating MFA...');
  const code = generateTOTP(mfaSecret);
  console.log(`Generated current TOTP code: ${code}`);
  const confirmRes = await request('/api/v1/auth/mfa/confirm', 'POST', { code }, token);
  console.log('Status:', confirmRes.status, 'Body:', confirmRes.body);
  if (confirmRes.status !== 200) throw new Error('MFA activation failed');

  console.log('\n5. Logging out of current session...');
  const logoutRes = await request('/api/v1/auth/logout', 'POST', null, token);
  console.log('Status:', logoutRes.status, 'Body:', logoutRes.body);

  console.log('\n6. Logging in again WITHOUT MFA code (should prompt for code)...');
  const loginRes2 = await request('/api/v1/auth/login', 'POST', {
    email,
    password,
  });
  console.log('Status:', loginRes2.status, 'Body:', loginRes2.body);
  if (loginRes2.status !== 200 || !loginRes2.body.mfaRequired) throw new Error('Login should require MFA');

  console.log('\n7. Logging in with WRONG MFA code (should fail)...');
  const loginRes3 = await request('/api/v1/auth/login', 'POST', {
    email,
    password,
    mfaCode: '000000',
  });
  console.log('Status:', loginRes3.status, 'Body:', loginRes3.body);
  if (loginRes3.status !== 401) throw new Error('Login should have been rejected');

  console.log('\n8. Logging in with CORRECT MFA code (should succeed)...');
  const newCode = generateTOTP(mfaSecret);
  console.log(`Generated new TOTP code: ${newCode}`);
  const loginRes4 = await request('/api/v1/auth/login', 'POST', {
    email,
    password,
    mfaCode: newCode,
  });
  console.log('Status:', loginRes4.status, 'Token returned:', !!loginRes4.body.token);
  if (loginRes4.status !== 200 || !loginRes4.body.token) throw new Error('MFA login failed');

  console.log('\n🎉 ALL PHASE 2 AUTHENTICATION TESTS PASSED SUCCESSFULLY! 🎉');
  process.exit(0);
}

run().catch((err) => {
  console.error('\n❌ Test execution failed:', err.message);
  process.exit(1);
});
