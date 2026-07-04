/**
 * Browser-side cryptographic utility to sign scan payloads using Ed25519
 * via standard Web Crypto API.
 */
export async function signPayload(timestamp: string, bodyStr: string): Promise<string> {
  // Pre-configured PKCS8 private key base64 matching the PEM inside test-ingestion.js
  const privateKeyBase64 = "MC4CAQAwBQYDK2VwBCIEIPcujgM1F7YBz8bjNa1++Ne338cY03xOFam0wP0+wPY0";
  
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
