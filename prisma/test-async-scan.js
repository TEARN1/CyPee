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

function request(path, method, body, extraHeaders = {}) {
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
          const nonce = solveChallenge(challenge);
          const retriedHeaders = {
            ...extraHeaders,
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

function listenToSse(scanId, powChallenge = null, powNonce = null) {
  console.log(`\nConnecting to SSE Telemetry stream for scan: ${scanId}...`);
  const sseOptions = {
    hostname: 'localhost',
    port: 3000,
    path: `/api/v1/scans/${scanId}/stream`,
    method: 'GET',
    headers: {
      ...(powChallenge ? { 'x-shield-pow-challenge': powChallenge } : {}),
      ...(powNonce ? { 'x-shield-pow-nonce': powNonce } : {}),
    }
  };

  const sseReq = http.request(sseOptions, (res) => {
    console.log(`SSE Connection Status: ${res.statusCode} ${res.statusMessage}`);
    
    const challenge = res.headers['x-shield-challenge'];
    if (res.statusCode === 400 && challenge) {
      console.log('SSE connection requested PoW. Solving...');
      const nonce = solveChallenge(challenge);
      listenToSse(scanId, challenge, nonce);
      return;
    }

    res.on('data', (chunk) => {
      const lines = chunk.toString().split('\n');
      lines.forEach((line) => {
        if (line.startsWith('data:')) {
          try {
            const event = JSON.parse(line.substring(5).trim());
            console.log(`[SSE EVENT] ${event.type.toUpperCase()}:`, event.message || event.finding || event);
            if (event.type === 'complete' || event.type === 'failed') {
              console.log('\nSSE stream finished. Exiting.');
              process.exit(0);
            }
          } catch (e) {
            console.log('Raw SSE Line:', line);
          }
        }
      });
    });
  });

  sseReq.on('error', (e) => {
    console.error(`SSE stream connection failed: ${e.message}`);
  });

  sseReq.end();
}

async function run() {
  console.log('Sending async scan request...');
  const payload = {
    repositoryUrl: 'https://github.com/OWASP/WebGoat',
    repositoryName: 'WebGoat-Test',
  };

  const res = await request('/api/v1/scans', 'POST', payload);
  console.log(`Response Status: ${res.status}`);
  console.log('Scan Created:', JSON.stringify(res.body, null, 2));

  if (res.status === 201 && res.body.id) {
    listenToSse(res.body.id);
  } else {
    console.error('Scan creation failed!');
    process.exit(1);
  }
}

run();
