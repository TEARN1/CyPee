/**
 * Signs scan payloads with Ed25519 (Web Crypto). The private key is never part
 * of the page: the person pastes their own key once, and it is kept in this
 * tab's memory only. A key built into the bundle would let anyone sign.
 */
let sessionKeyBase64: string | null = null;

function signingKeyBase64(): string {
  if (!sessionKeyBase64) {
    const pasted = window.prompt('Paste your Ed25519 private key (PKCS8 PEM or base64). It stays in this tab only.') ?? '';
    const body = pasted.replace(/-----(BEGIN|END) PRIVATE KEY-----/g, '').replace(/\s+/g, '');
    if (!body) throw new Error('No signing key: uploads need your Ed25519 private key.');
    sessionKeyBase64 = body;
  }
  return sessionKeyBase64;
}

export async function signPayload(timestamp: string, bodyStr: string): Promise<string> {
  const privateKeyBase64 = signingKeyBase64();
  
  // Convert base64 to ArrayBuffer
  const binaryString = window.atob(privateKeyBase64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }

  // Import PKCS8 private key
  const privateKey = await window.crypto.subtle.importKey(
    "pkcs8",
    bytes.buffer,
    {
      name: "Ed25519",
    },
    false,
    ["sign"]
  );

  // Data to sign: timestamp + '.' + bodyStr
  const dataStr = timestamp + "." + bodyStr;
  const encoder = new TextEncoder();
  const dataBytes = encoder.encode(dataStr);

  // Sign data
  const signatureBuffer = await window.crypto.subtle.sign(
    {
      name: "Ed25519",
    },
    privateKey,
    dataBytes
  );

  // Convert signature to Base64
  const signatureBytes = new Uint8Array(signatureBuffer);
  let binarySignature = "";
  for (let i = 0; i < signatureBytes.byteLength; i++) {
    binarySignature += String.fromCharCode(signatureBytes[i]);
  }
  
  return window.btoa(binarySignature);
}
