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
  console.log('\n💎 STARTING DIAMOND MODEL FORENSIC ATTRIBUTION TESTS 💎');

  // 1. Trigger a Honeytoken access trap to log a fresh incident
  console.log('\n1. Accessing Honeytoken decoy database backup trap...');
  const triggerRes = await request('/api/v1/admin/db-backup', 'GET', null, {
    'x-tenant-id': 'default-dev-tenant-uuid',
    'user-agent': 'Mozilla/5.0 Threat-Hunting-Verification-Script',
  });
  console.log('Trigger status:', triggerRes.status);

  // 2. Fetch incidents list
  console.log('\n2. Retrieving logged security incidents list...');
  const listRes = await request('/api/v1/compliance/incidents', 'GET', null, {
    'x-tenant-id': 'default-dev-tenant-uuid',
  });
  console.log('Incident list size:', listRes.body.length);
  if (listRes.status !== 200 || listRes.body.length === 0) {
    throw new Error('Failed to retrieve logged incidents!');
  }

  const latestIncident = listRes.body[0];
  console.log(`Latest Incident ID: ${latestIncident.id} | Type: ${latestIncident.type}`);

  // 3. Request forensics report
  console.log('\n3. Requesting Diamond Model Forensic Attribution Report...');
  const reportRes = await request(`/api/v1/compliance/incidents/${latestIncident.id}/forensics`, 'GET', null, {
    'x-tenant-id': 'default-dev-tenant-uuid',
  });
  console.log('Status Code:', reportRes.status);
  console.log('Attribution Report:', JSON.stringify(reportRes.body, null, 2));

  if (reportRes.status !== 200) {
    throw new Error('Forensic attribution request failed!');
  }

  console.log('\n4. Validating Diamond Model quadrants...');
  const att = reportRes.body.attribution;
  console.log(`- Suspected Adversaries: ${att.adversary.suspectedGroups.join(', ')}`);
  console.log(`- Target Capability (MITRE): ${att.capability.techniquesUsed.join(', ')}`);
  console.log(`- Attacker IP / User Agent: ${att.infrastructure.sourceIp} | ${att.infrastructure.userAgent}`);
  console.log(`- Victim Tenant Impact: ${att.victim.tenantId} (Posture Score Impact: -${att.victim.postureImpactScore})`);

  if (!att.adversary.suspectedGroups || att.adversary.suspectedGroups.length === 0) {
    throw new Error('Diamond Model adversary quadrant missing suspected threat groups!');
  }

  console.log('\n🎉 ALL FORENSIC DIAMOND MODEL ATTRIBUTION TESTS PASSED SUCCESSFULLY! 🎉');
  process.exit(0);
}

run().catch((err) => {
  console.error('\n❌ Test execution failed:', err.message);
  process.exit(1);
});
