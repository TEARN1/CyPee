const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const http = require('http');

// Pre-configured Ed25519 Private Key PEM matching the backend PEM
const PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPcujgM1F7YBz8bjNa1++Ne338cY03xOFam0wP0+wPY0
-----END PRIVATE KEY-----`;

// Regex detection rules
const RULES = [
  {
    ruleId: 'SQL_INJECTION',
    severity: 'CRITICAL',
    regex: /(select|insert|update|delete)\b.*?\${.*?\}/i,
    message: 'Potential unparameterized SQL query string concatenation detected.',
  },
  {
    ruleId: 'HARDCODED_SECRETS',
    severity: 'HIGH',
    regex: /(const|let|var)\s+\w*(secret|key|password|token)\w*\s*=\s*['"`][a-zA-Z0-9_\-+=]{16,}['"`]/i,
    message: 'Potential plaintext cryptographic secret key assigned inline.',
  },
  {
    ruleId: 'MISSING_SECURITY_HEADERS',
    severity: 'MEDIUM',
    regex: /NestFactory\.create\(AppModule\)(?![\s\S]*?helmet)/i,
    message: 'Application bootstrapped without Helmet middleware security headers.',
  },
];

// Helper to recursively walk a directory
function walkDir(dir, fileList = []) {
  const files = fs.readdirSync(dir);
  for (const file of files) {
    const filePath = path.join(dir, file);
    const stat = fs.statSync(filePath);
    if (stat.isDirectory()) {
      if (!['node_modules', 'dist', '.git', 'frontend'].includes(file)) {
        walkDir(filePath, fileList);
      }
    } else {
      if (/\.(ts|js|cs|java|json|xml|html)$/.test(file)) {
        fileList.push(filePath);
      }
    }
  }
  return fileList;
}

// Client-side Proof of Work solver
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

// Upload helper with automatic PoW challenge bypass
function uploadPayload(bodyStr, signatureBase64, timestamp, powHeaders = {}) {
  return new Promise((resolve) => {
    const options = {
      hostname: 'localhost',
      port: 3000,
      path: '/api/v1/compliance/upload',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-sast-signature': signatureBase64,
        'x-sast-timestamp': timestamp,
        'Content-Length': Buffer.byteLength(bodyStr),
        ...powHeaders,
      },
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        const challenge = res.headers['x-shield-challenge'];
        
        if (res.statusCode === 400 && challenge) {
          console.log('\n🛡️  AI Defensive Shield triggered: Solving Proof of Work Challenge...');
          const nonce = solveChallenge(challenge);
          console.log(`Solved challenge (nonce: ${nonce}). Retrying upload...`);
          
          resolve(
            uploadPayload(bodyStr, signatureBase64, timestamp, {
              'x-shield-pow-challenge': challenge,
              'x-shield-pow-nonce': nonce,
            })
          );
          return;
        }

        try {
          resolve({ status: res.statusCode, body: JSON.parse(data) });
        } catch {
          resolve({ status: res.statusCode, body: data });
        }
      });
    });

    req.on('error', (e) => {
      resolve({ status: 500, error: e.message });
    });

    req.write(bodyStr);
    req.end();
  });
}

// Main scanning function
async function run() {
  const scanTarget = process.argv[2] || './src';
  console.log(`🛡️ Initializing Local SAST Scan on: "${scanTarget}"...`);

  if (!fs.existsSync(scanTarget)) {
    console.error(`ERROR: Scan target path "${scanTarget}" does not exist.`);
    process.exit(1);
  }

  const filesToScan = fs.statSync(scanTarget).isDirectory() 
    ? walkDir(scanTarget) 
    : [scanTarget];

  console.log(`Analyzing ${filesToScan.length} files...`);

  const findings = [];

  for (const filePath of filesToScan) {
    const content = fs.readFileSync(filePath, 'utf8');
    const lines = content.split('\n');

    // Run rules against content line-by-line
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const rule of RULES) {
        if (rule.regex.test(line)) {
          // Normalize path format for cross-platform consistency
          const normalizedPath = path.relative(process.cwd(), filePath).replace(/\\/g, '/');
          
          findings.push({
            filePath: normalizedPath,
            lineNumber: i + 1,
            ruleId: rule.ruleId,
            severity: rule.severity,
            message: rule.message,
          });
        }
      }
    }
  }

  console.log(`Scan complete. Found ${findings.length} security flags.`);

  if (findings.length === 0) {
    console.log('✅ No vulnerabilities detected.');
    return;
  }

  // Cryptographic Ingestion Upload
  console.log('\n🔐 Preparing secure cryptographic ingestion payload...');
  const payload = { findings };
  const bodyStr = JSON.stringify(payload);
  const timestamp = Date.now().toString();

  console.log('Signing payload using private key...');
  const privateKey = crypto.createPrivateKey(PRIVATE_KEY_PEM);
  const signData = Buffer.from(timestamp + '.' + bodyStr, 'utf8');
  const signatureBase64 = crypto.sign(null, signData, privateKey).toString('base64');

  console.log(`Signature (Base64): ${signatureBase64.substring(0, 30)}...`);

  console.log('Dispatching request to ingestion portal...');
  const res = await uploadPayload(bodyStr, signatureBase64, timestamp);

  console.log(`\nResponse Status: ${res.status}`);
  console.log('Response Body:');
  console.log(JSON.stringify(res.body, null, 2));

  // 201 Created or 202 Accepted represent successful ingestion
  if (res.status === 201 || res.status === 202) {
    console.log('\n🚀 SAST findings successfully ingested by backend ledger.');
    process.exit(0);
  } else {
    console.error('\n❌ Ingestion rejected by compliance server.');
    process.exit(1);
  }
}

run();
