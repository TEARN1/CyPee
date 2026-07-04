const crypto = require('crypto');
const http = require('http');

// Static, pre-configured Ed25519 Key Pair for out-of-the-box local testing
const PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPcujgM1F7YBz8bjNa1++Ne338cY03xOFam0wP0+wPY0
-----END PRIVATE KEY-----`;

const PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAQQFS0Qa3bcZaax+xkOxNs9uJQM+RYeykLKL43FdyYlY=
-----END PUBLIC KEY-----`;

console.log('Loading pre-configured Ed25519 key pair...');
const privateKey = crypto.createPrivateKey(PRIVATE_KEY_PEM);

// Prepare Sample SAST Findings Payload
const payload = {
  findings: [
    {
      filePath: "src/users/users.service.ts",
      lineNumber: 42,
      ruleId: "SQL_INJECTION",
      severity: "CRITICAL",
      message: "Raw query string concatenation detected."
    },
    {
      filePath: "src/auth/auth.module.ts",
      lineNumber: 15,
      ruleId: "HARDCODED_SECRETS",
      severity: "HIGH",
      message: "Plaintext signature secret key assigned inline."
    }
  ]
};

const bodyStr = JSON.stringify(payload);
const timestamp = Date.now().toString();

// Sign Payload (Data = timestamp + '.' + bodyStr)
console.log('Signing payload using private key...');
const signData = Buffer.from(timestamp + '.' + bodyStr, 'utf8');
const signatureBuffer = crypto.sign(null, signData, privateKey);
const signatureBase64 = signatureBuffer.toString('base64');

console.log(`Timestamp: ${timestamp}`);
console.log(`Signature (Base64): ${signatureBase64}\n`);

// Send HTTP request
const options = {
  hostname: 'localhost',
  port: 3000,
  path: '/api/v1/compliance/upload',
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'x-sast-signature': signatureBase64,
    'x-sast-timestamp': timestamp,
    'Content-Length': Buffer.byteLength(bodyStr)
  }
};

const req = http.request(options, (res) => {
  let data = '';
  res.on('data', (chunk) => {
    data += chunk;
  });
  res.on('end', () => {
    console.log(`\nResponse Status: ${res.statusCode} ${res.statusMessage}`);
    console.log('Response Body:');
    try {
      console.log(JSON.stringify(JSON.parse(data), null, 2));
    } catch {
      console.log(data);
    }
  });
});

req.on('error', (e) => {
  console.error(`Request failed: ${e.message}`);
});

req.write(bodyStr);
req.end();
