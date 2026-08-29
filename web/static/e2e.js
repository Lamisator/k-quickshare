// End-to-end encryption for Pyxis.
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
  const INFO_URL = 'pyxis-e2e-url-v1';
  const INFO_ENC = 'pyxis-e2e-enc-v1';
  const INFO_AUTH = 'pyxis-e2e-auth-v1';
  const INFO_BATCH = 'pyxis-e2e-batch-v1';
  const WRAP_NONCE = 12;

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

  // --- batch keys ----------------------------------------------------------
  //
  // A batch link carries ONE secret, but every member file is encrypted under
  // its own random key, sealed under the batch key and stored server-side as an
  // opaque blob. Two reasons to wrap rather than derive per-file keys from the
  // secret: the browser encrypts before the server has assigned a file id, so
  // there is nothing stable to derive from; and a member can later be removed
  // or added without renumbering anything.
  //
  // INFO_BATCH keeps a batch secret and a single-file secret in separate key
  // spaces even if the same 32 bytes were ever reused.
  async function deriveBatchKey(secret) {
    return importAes(await hkdf32(secret, new Uint8Array(0), INFO_BATCH));
  }

  async function wrapFileKey(batchKey, rawFileKey) {
    const nonce = randomBytes(WRAP_NONCE);
    const sealed = await subtle.encrypt({ name: 'AES-GCM', iv: nonce }, batchKey, rawFileKey);
    const out = new Uint8Array(WRAP_NONCE + sealed.byteLength);
    out.set(nonce, 0);
    out.set(new Uint8Array(sealed), WRAP_NONCE);
    return out;
  }

  // Throws if the batch key is wrong — GCM verification fails, so a bad secret
  // or password can never yield a usable file key.
  async function unwrapFileKey(batchKey, wrapped) {
    if (!wrapped || wrapped.length <= WRAP_NONCE) throw new Error('malformed wrapped key');
    const raw = await subtle.decrypt(
      { name: 'AES-GCM', iv: wrapped.subarray(0, WRAP_NONCE) }, batchKey,
      wrapped.subarray(WRAP_NONCE));
    return importAes(new Uint8Array(raw));
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

  // aborted reports whether a cancellation token has been tripped. The token is
  // anything with an `aborted` property, so a real AbortSignal works too.
  function aborted(signal) {
    return !!(signal && signal.aborted);
  }

  function abortError() {
    const err = new Error('aborted');
    err.name = 'AbortError';
    return err;
  }

  // encryptFile turns a File/Blob into a ciphertext Blob in chunk format.
  //
  // The optional cancellation token is checked between chunks: an aborted
  // encryption throws AbortError and the partial ciphertext is dropped with
  // the rest of the frame, so nothing half-encrypted can reach the network.
  // Cancelling cannot interrupt a chunk already inside subtle.encrypt, but a
  // 64 KiB chunk returns fast enough that the delay is imperceptible.
  async function encryptFile(file, aesKey, onProgress, signal) {
    const total = file.size;
    const chunks = Math.ceil(total / CHUNK);
    const parts = [];
    for (let i = 0; i < chunks; i++) {
      if (aborted(signal)) throw abortError();
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

  window.PYXIS_E2E = {
    available: !!subtle && !!(window.crypto && crypto.getRandomValues),
    b64uEncode: b64uEncode,
    b64uDecode: b64uDecode,
    randomBytes: randomBytes,
    importAes: importAes,
    deriveUrlKey: deriveUrlKey,
    derivePasswordKeys: derivePasswordKeys,
    deriveBatchKey: deriveBatchKey,
    wrapFileKey: wrapFileKey,
    unwrapFileKey: unwrapFileKey,
    encryptFile: encryptFile,
    decryptBuffer: decryptBuffer,
    SALT_LEN: 16,
    KEY_LEN: 32,
  };
})();
