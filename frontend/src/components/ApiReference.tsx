import React, { useState } from 'react';
import { Terminal, Copy, Check, Code, KeyRound, ShieldAlert } from 'lucide-react';

export const ApiReference: React.FC = () => {
  const [copiedKey, setCopiedKey] = useState(false);
  const [copiedCode, setCopiedCode] = useState<string | null>(null);

  // States for dynamic key generation
  const [genPublicKey, setGenPublicKey] = useState<string | null>(null);
  const [genPrivateKey, setGenPrivateKey] = useState<string | null>(null);
  const [generating, setGenerating] = useState(false);
  const [copiedGenPublic, setCopiedGenPublic] = useState(false);
  const [copiedGenPrivate, setCopiedGenPrivate] = useState(false);

  const publicKeyPem = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAQQFS0Qa3bcZaax+xkOxNs9uJQM+RYeykLKL43FdyYlY=
-----END PUBLIC KEY-----`;

  const codeSnippets = {
    curl: `curl -X POST http://localhost:3000/api/v1/compliance/upload \\
  -H "Content-Type: application/json" \\
  -H "x-sast-signature: <BASE64_SIGNATURE>" \\
  -H "x-sast-timestamp: <TIMESTAMP>" \\
  -d '{
    "findings": [
      {
        "filePath": "src/users/users.service.ts",
        "lineNumber": 42,
        "ruleId": "SQL_INJECTION",
        "severity": "CRITICAL",
        "message": "Raw query string concatenation detected."
      }
    ]
  }'`,
    node: `const crypto = require('crypto');
const http = require('http');

const PRIVATE_KEY_PEM = \`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPcujgM1F7YBz8bjNa1++Ne338cY03xOFam0wP0+wPY0
-----END PRIVATE KEY-----\`;

const payload = {
  findings: [{
    filePath: "src/users/users.service.ts",
    lineNumber: 42,
    ruleId: "SQL_INJECTION",
    severity: "CRITICAL",
    message: "Raw query string concatenation detected."
  }]
};

const bodyStr = JSON.stringify(payload);
const timestamp = Date.now().toString();
const privateKey = crypto.createPrivateKey(PRIVATE_KEY_PEM);
const signature = crypto.sign(null, Buffer.from(timestamp + '.' + bodyStr), privateKey).toString('base64');

const req = http.request({
  hostname: 'localhost',
  port: 3000,
  path: '/api/v1/compliance/upload',
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'x-sast-signature': signature,
    'x-sast-timestamp': timestamp,
    'Content-Length': Buffer.byteLength(bodyStr)
  }
}, (res) => {
  res.on('data', d => process.stdout.write(d));
});
req.write(bodyStr);
req.end();`,
    python: `import time
import json
import requests
from cryptography.hazmat.primitives.asymmetric import ed25519

# Private key bytes (32-byte seed)
private_key_bytes = bytes.fromhex("f72e8e033517b601cfc6e335ad7ef8d7b7ddc718d37c4e15a9b4c0fd3ec0f634")
private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)

payload = {
    "findings": [{
        "filePath": "src/users/users.service.ts",
        "lineNumber": 42,
        "ruleId": "SQL_INJECTION",
        "severity": "CRITICAL",
        "message": "Raw query string concatenation detected."
    }]
}

body_str = json.dumps(payload, separators=(',', ':'))
timestamp = str(int(time.time() * 1000))
sign_data = (timestamp + "." + body_str).encode('utf-8')
signature = private_key.sign(sign_data).hex()

headers = {
    "Content-Type": "application/json",
    "x-sast-signature": signature,
    "x-sast-timestamp": timestamp
}

# Submit signed request
response = requests.post("http://localhost:3000/api/v1/compliance/upload", data=body_str, headers=headers)
print(response.status_code, response.json())`
  };

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    if (id === 'public_key') {
      setCopiedKey(true);
      setTimeout(() => setCopiedKey(false), 2000);
    } else if (id === 'gen_public') {
      setCopiedGenPublic(true);
      setTimeout(() => setCopiedGenPublic(false), 2000);
    } else if (id === 'gen_private') {
      setCopiedGenPrivate(true);
      setTimeout(() => setCopiedGenPrivate(false), 2000);
    } else {
      setCopiedCode(id);
      setTimeout(() => setCopiedCode(null), 2000);
    }
  };

  // Dynamic Key Generator
  const generateKeys = async () => {
    setGenerating(true);
    try {
      const keyPair = await window.crypto.subtle.generateKey(
        {
          name: "Ed25519",
        },
        true,
        ["sign", "verify"]
      );

      // Export Public Key
      const exportedPublic = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
      const publicBase64 = arrayBufferToBase64(exportedPublic);
      const publicPemString = `-----BEGIN PUBLIC KEY-----\n${formatBase64(publicBase64)}\n-----END PUBLIC KEY-----`;
      setGenPublicKey(publicPemString);

      // Export Private Key
      const exportedPrivate = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
      const privateBase64 = arrayBufferToBase64(exportedPrivate);
      const privatePemString = `-----BEGIN PRIVATE KEY-----\n${formatBase64(privateBase64)}\n-----END PRIVATE KEY-----`;
      setGenPrivateKey(privatePemString);
    } catch (e: any) {
      console.error("Key generation failed:", e.message);
    } finally {
      setGenerating(false);
    }
  };

  // Convert ArrayBuffer to Base64
  const arrayBufferToBase64 = (buffer: ArrayBuffer): string => {
    let binary = "";
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  };

  // Format base64 to 64 character lines
  const formatBase64 = (str: string): string => {
    return str.match(/.{1,64}/g)?.join("\n") || str;
  };

  return (
    <div className="flex flex-col gap-6 overflow-y-auto pr-1 h-full max-w-4xl mx-auto">
      {/* Introduction */}
      <div className="border-b border-slate-800 pb-4">
        <h3 className="text-lg font-bold text-slate-200">Developer API Reference Portal</h3>
        <p className="text-xs text-slate-400 mt-1">
          Secure, tokenless cryptographic ingestion endpoints. Integrates seamlessly with CI/CD hooks and custom scanners.
        </p>
      </div>

      {/* Public Key Display */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 flex flex-col gap-3">
        <div className="flex justify-between items-center">
          <span className="text-xs font-bold text-indigo-400 uppercase tracking-widest flex items-center gap-1.5">
            <KeyRound size={14} /> Active Verification Public Key (Ed25519)
          </span>
          <button
            onClick={() => handleCopy(publicKeyPem, 'public_key')}
            className={`flex items-center gap-1 px-2.5 py-1 rounded text-[10px] font-semibold border transition-all ${
              copiedKey
                ? 'bg-emerald-500/20 border-emerald-500/30 text-emerald-400'
                : 'bg-slate-950 border-slate-800 hover:border-slate-700 text-slate-300'
            }`}
          >
            {copiedKey ? <Check size={12} /> : <Copy size={12} />}
            {copiedKey ? 'Copied PEM!' : 'Copy Key'}
          </button>
        </div>
        <pre className="bg-slate-950/80 p-3 rounded-lg border border-slate-900 font-mono text-[10px] text-slate-400 overflow-x-auto">
          {publicKeyPem}
        </pre>
      </div>

      {/* Interactive Key Generator */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 flex flex-col gap-4">
        <div className="flex justify-between items-center border-b border-slate-800/40 pb-3">
          <span className="text-xs font-bold text-purple-400 uppercase tracking-widest flex items-center gap-1.5">
            <KeyRound size={14} /> Interactive Key Pair Generator (Ed25519)
          </span>
          <button
            onClick={generateKeys}
            disabled={generating}
            className="px-4 py-1.5 bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white rounded-lg text-xs font-bold transition-all shadow-md shadow-purple-900/25"
          >
            {generating ? 'Generating...' : 'Generate New Key Pair'}
          </button>
        </div>
        
        {genPublicKey && genPrivateKey ? (
          <div className="flex flex-col gap-4">
            <div className="flex flex-col gap-1.5">
              <div className="flex justify-between items-center text-xs text-slate-400 font-semibold">
                <span>Generated Public Key (SPKI PEM)</span>
                <button
                  onClick={() => handleCopy(genPublicKey, 'gen_public')}
                  className="text-purple-400 hover:text-purple-300 flex items-center gap-1"
                >
                  {copiedGenPublic ? <Check size={12} /> : <Copy size={12} />} Copy
                </button>
              </div>
              <pre className="bg-slate-950 p-3 rounded-lg border border-slate-900 font-mono text-[9px] text-slate-400 overflow-x-auto max-h-[120px]">
                {genPublicKey}
              </pre>
            </div>

            <div className="flex flex-col gap-1.5">
              <div className="flex justify-between items-center text-xs text-slate-400 font-semibold">
                <span>Generated Private Key (PKCS8 PEM)</span>
                <button
                  onClick={() => handleCopy(genPrivateKey, 'gen_private')}
                  className="text-purple-400 hover:text-purple-300 flex items-center gap-1"
                >
                  {copiedGenPrivate ? <Check size={12} /> : <Copy size={12} />} Copy
                </button>
              </div>
              <pre className="bg-slate-950 p-3 rounded-lg border border-slate-900 font-mono text-[9px] text-slate-400 overflow-x-auto max-h-[120px]">
                {genPrivateKey}
              </pre>
            </div>
          </div>
        ) : (
          <p className="text-xs text-slate-500 italic">
            Need unique keys for scanning? Click generate to spawn custom Ed25519 key-pairs dynamically inside your browser enclaves.
          </p>
        )}
      </div>

      {/* Endpoint Details */}
      <div className="flex flex-col gap-4">
        <div className="flex items-center gap-3">
          <span className="bg-indigo-600/20 text-indigo-400 border border-indigo-500/30 px-3 py-1 rounded-lg text-xs font-bold font-mono">
            POST
          </span>
          <span className="font-mono text-sm text-slate-200">/api/v1/compliance/upload</span>
        </div>

        <div className="bg-sky-500/5 border border-sky-500/20 rounded-xl p-4 flex flex-col gap-1.5 text-xs">
          <div className="font-bold text-sky-400 uppercase tracking-widest flex items-center gap-1.5">
            <ShieldAlert size={14} /> Header Authentication Specs
          </div>
          <div className="flex flex-col gap-2 mt-2">
            <div className="flex justify-between border-b border-slate-800/40 pb-2">
              <span className="font-mono text-slate-300 font-bold">x-sast-signature</span>
              <span className="text-slate-400">Base64 string representing the private key signature of <code className="bg-slate-900 px-1 py-0.5 rounded text-slate-200">timestamp + '.' + rawBody</code>.</span>
            </div>
            <div className="flex justify-between pb-1">
              <span className="font-mono text-slate-300 font-bold">x-sast-timestamp</span>
              <span className="text-slate-400">Millisecond epoch timestamp. Request is rejected if age &gt; 120 seconds.</span>
            </div>
          </div>
        </div>
      </div>

      {/* Code Snippets */}
      <div className="flex flex-col gap-4">
        <span className="text-xs font-bold text-slate-400 uppercase tracking-widest flex items-center gap-1.5">
          <Code size={14} /> Cryptographic Ingestion Snippets
        </span>

        {Object.entries(codeSnippets).map(([lang, code]) => (
          <div key={lang} className="flex flex-col border border-slate-800 rounded-xl overflow-hidden">
            <div className="flex justify-between items-center px-4 py-2 bg-slate-900/60 border-b border-slate-800 text-xs font-bold text-slate-400 uppercase tracking-wider">
              <span className="flex items-center gap-1.5">
                <Terminal size={12} /> {lang} implementation
              </span>
              <button
                onClick={() => handleCopy(code, lang)}
                className={`flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold border transition-all ${
                  copiedCode === lang
                    ? 'bg-emerald-500/20 border-emerald-500/30 text-emerald-400'
                    : 'bg-slate-950 border-slate-850 hover:border-slate-750 text-slate-400'
                }`}
              >
                {copiedCode === lang ? <Check size={10} /> : <Copy size={10} />}
                {copiedCode === lang ? 'Copied!' : 'Copy Code'}
              </button>
            </div>
            <pre className="bg-slate-950 p-4 font-mono text-[10px] text-slate-300 overflow-x-auto max-h-[300px]">
              <code>{code}</code>
            </pre>
          </div>
        ))}
      </div>
    </div>
  );
};
