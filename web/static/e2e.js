// End-to-end encryption for k-fileshare.
//
// The browser encrypts before upload and decrypts after download using the
// SAME container format the Go side uses, so ciphertext is interchangeable:
// 64 KiB plaintext chunks, each sealed with AES-256-GCM under a 12-byte
// nonce = 4 zero bytes || big-endian uint64 chunk index.
//
// Key handling never involves the server:
//   no password : 32 random bytes live only in the URL fragment;
//                 fileKey = HKDF-SHA256(secret, "", "…-e2e-url-v1")
//   password    : master  = PBKDF2-SHA256(password, salt, 600k)
//                 fileKey = HKDF(master, salt, "…-e2e-enc-v1")   (never sent)
//                 auth    = HKDF(master, salt, "…-e2e-auth-v1")  (sent once)
//                 the server stores only SHA-256(auth) to gate the ciphertext.
(function () {
  'use strict';

  const CHUNK = 65536;
  const TAG = 16;
  const PBKDF2_ITER = 600000;
  const INFO_URL = 'k-fileshare-e2e-url-v1';
  const INFO_ENC = 'k-fileshare-e2e-enc-v1';
  const INFO_AUTH = 'k-fileshare-e2e-auth-v1';

  const subtle = (window.crypto && window.crypto.subtle) || null;
  const te = new TextEncoder();

  function b64uEncode(bytes) {
    let s = '';
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function b64uDecode(str) {
    const b64 = str.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function randomBytes(n) {
    const b = new Uint8Array(n);
    crypto.getRandomValues(b);
    return b;
  }

  function chunkNonce(idx) {
    const n = new Uint8Array(12);
    const dv = new DataView(n.buffer);
    dv.setUint32(4, Math.floor(idx / 4294967296));
    dv.setUint32(8, idx >>> 0);
    return n;
  }

  async function hkdf32(material, salt, info) {
    const key = await subtle.importKey('raw', material, 'HKDF', false, ['deriveBits']);
    const bits = await subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: salt, info: te.encode(info) }, key, 256);
    return new Uint8Array(bits);
  }

  async function importAes(raw) {
    return subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
  }

  async function deriveUrlKey(secret) {
    return importAes(await hkdf32(secret, new Uint8Array(0), INFO_URL));
  }

  // Returns { key, auth } — the encryption key never leaves the browser.
  async function derivePasswordKeys(password, salt, onStatus) {
    if (onStatus) onStatus();
    const base = await subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = await subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt: salt, iterations: PBKDF2_ITER }, base, 256);
    const master = new Uint8Array(bits);
    const [encKey, auth] = await Promise.all([
      hkdf32(master, salt, INFO_ENC),
      hkdf32(master, salt, INFO_AUTH),
    ]);
    return { key: await importAes(encKey), auth: auth };
  }

  // encryptFile turns a File/Blob into a ciphertext Blob in chunk format.
  async function encryptFile(file, aesKey, onProgress) {
    const total = file.size;
    const chunks = Math.ceil(total / CHUNK);
    const parts = [];
    for (let i = 0; i < chunks; i++) {
      const slice = file.slice(i * CHUNK, Math.min((i + 1) * CHUNK, total));
      const buf = await slice.arrayBuffer();
      const ct = await subtle.encrypt({ name: 'AES-GCM', iv: chunkNonce(i) }, aesKey, buf);
      parts.push(new Uint8Array(ct));
      if (onProgress) onProgress((i + 1) / chunks);
    }
    return new Blob(parts, { type: 'application/octet-stream' });
  }

  // decryptBuffer reverses encryptFile. Any tampering fails GCM verification
  // and rejects, so a corrupted or substituted blob can never be shown.
  async function decryptBuffer(cipherBuf, aesKey, type, onProgress) {
    const ct = new Uint8Array(cipherBuf);
    const chunks = Math.ceil(ct.length / (CHUNK + TAG));
    const parts = [];
    for (let i = 0; i < chunks; i++) {
      const start = i * (CHUNK + TAG);
      const end = Math.min(start + CHUNK + TAG, ct.length);
      const plain = await subtle.decrypt(
        { name: 'AES-GCM', iv: chunkNonce(i) }, aesKey, ct.subarray(start, end));
      parts.push(new Uint8Array(plain));
      if (onProgress) onProgress((i + 1) / chunks);
    }
    return new Blob(parts, { type: type || 'application/octet-stream' });
  }

  window.KFS_E2E = {
    available: !!subtle && !!(window.crypto && crypto.getRandomValues),
    b64uEncode: b64uEncode,
    b64uDecode: b64uDecode,
    randomBytes: randomBytes,
    importAes: importAes,
    deriveUrlKey: deriveUrlKey,
    derivePasswordKeys: derivePasswordKeys,
    encryptFile: encryptFile,
    decryptBuffer: decryptBuffer,
    SALT_LEN: 16,
    KEY_LEN: 32,
  };
})();
