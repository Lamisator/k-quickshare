// End-to-end encryption for Pyxis.
//
// The browser encrypts before upload and decrypts after download using the
// SAME container format the Go side documents, so ciphertext is interchangeable:
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
//
// ---------------------------------------------------------------------------
// CONTAINER VERSIONS
// ---------------------------------------------------------------------------
//
// Version 1 sealed nothing but the chunks. Each chunk authenticated itself and
// said nothing about the file it belonged to: no plaintext length, no chunk
// count, no name, no type. Three things followed from that, none of them
// obvious from "every chunk is authenticated":
//
//   * whole trailing chunks could be removed and the rest still verified, so
//     a file could be silently truncated at a 64 KiB boundary;
//   * a blob replaced with ZERO bytes decrypted to zero chunks — an empty file
//     that never failed a check, because there was nothing left to check;
//   * the name, size and MIME type shown to the recipient came from the
//     server's database columns, which nothing bound to the ciphertext.
//
// Version 2 keeps the chunk stream byte-identical in layout and adds a
// MANIFEST: a small JSON document naming the protocol version, a random
// client-generated file id, the owning batch, the plaintext size, the chunk
// count and geometry, the file name and the MIME type. The manifest bytes are
// passed to AES-GCM as additional authenticated data for EVERY chunk, so the
// whole file is bound to its own metadata. Truncation now fails (the count is
// authenticated), an empty blob fails (version 2 always emits at least one
// chunk, whose only content is the tag over the manifest), substitution fails,
// and a renamed file fails.
//
// The manifest is authenticated as BYTES. Whatever the sender produced is what
// must come back — the server stores it verbatim and this file compares the
// document it parses against the bytes it received, never a re-serialisation.
//
// Version 1 files are still read. They cannot be upgraded in place (that would
// need the key), so they keep decrypting through decryptLegacy until they
// expire, and the reduced guarantee is stated on the page rather than papered
// over.
(function () {
  'use strict';

  const CHUNK = 65536;
  const TAG = 16;
  const PBKDF2_ITER = 600000;
  const WRAP_NONCE = 12;
  const ROSTER_NONCE = 12;

  // Container version this build writes. Everything at or below it can be read.
  const VERSION = 2;

  // KDF labels, indexed by container version.
  //
  // A table rather than five constants because the labels ARE part of the
  // protocol: changing one changes every derived key, and the last time they
  // moved (the k-fileshare → pyxis rename) every live share became
  // undecryptable with no way to tell that from a wrong password. Adding a
  // version here keeps the old row, so old links keep opening while new ones
  // use the new labels.
  const LABELS = {
    1: {
      url: 'pyxis-e2e-url-v1',
      enc: 'pyxis-e2e-enc-v1',
      auth: 'pyxis-e2e-auth-v1',
      batch: 'pyxis-e2e-batch-v1',
      roster: 'pyxis-e2e-roster-v1',
    },
  };
  // Version 2 changed the framing, not the key schedule: the same secret must
  // still derive the same keys, or v1 shares would stop opening.
  LABELS[2] = LABELS[1];

  const ROSTER_AAD_PREFIX = 'pyxis-roster-v2|';

  const subtle = (window.crypto && window.crypto.subtle) || null;
  const te = new TextEncoder();
  const td = new TextDecoder();

  function labels(version) {
    return LABELS[version] || LABELS[VERSION];
  }

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

  async function sha256b64u(bytes) {
    const d = await subtle.digest('SHA-256', bytes);
    return b64uEncode(new Uint8Array(d));
  }

  async function deriveUrlKey(secret, version) {
    return importAes(await hkdf32(secret, new Uint8Array(0), labels(version).url));
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
  // The roster key is a SEPARATE HKDF branch off the same secret. Sealing the
  // member list under the key that also wraps file keys would put two different
  // kinds of message in one key space; a dedicated branch keeps them apart, so
  // a wrapped key can never be opened as a roster or the reverse.
  async function deriveBatchKeys(secret, version) {
    const l = labels(version);
    const empty = new Uint8Array(0);
    const [wrap, roster] = await Promise.all([
      hkdf32(secret, empty, l.batch),
      hkdf32(secret, empty, l.roster),
    ]);
    return { key: await importAes(wrap), roster: await importAes(roster) };
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

  // Returns { key, auth, roster } — only `auth` ever leaves the browser.
  async function derivePasswordKeys(password, salt, version) {
    const l = labels(version);
    const base = await subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = await subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt: salt, iterations: PBKDF2_ITER }, base, 256);
    const master = new Uint8Array(bits);
    const [encKey, auth, rosterKey] = await Promise.all([
      hkdf32(master, salt, l.enc),
      hkdf32(master, salt, l.auth),
      hkdf32(master, salt, l.roster),
    ]);
    return { key: await importAes(encKey), auth: auth, roster: await importAes(rosterKey) };
  }

  // --- manifests -----------------------------------------------------------

  function chunkCount(size) {
    // At least one chunk, always: the empty file's single tag is what
    // authenticates its manifest. Without it, "no bytes" would be a valid
    // decryption of a blob an attacker emptied.
    return Math.max(1, Math.ceil(size / CHUNK));
  }

  function newFileId() {
    return b64uEncode(randomBytes(32));
  }

  // buildManifest returns the exact bytes that will be authenticated. Key order
  // is fixed and the result is never rebuilt from the parsed object: these bytes
  // are the AAD, and any re-serialisation that differs by a single byte — a
  // space, a reordered key, a different number format — makes the file
  // permanently undecryptable.
  function buildManifest(fields) {
    return te.encode(JSON.stringify({
      v: VERSION,
      id: fields.id,
      batch: fields.batch || '',
      size: fields.size,
      chunks: chunkCount(fields.size),
      chunk: CHUNK,
      name: fields.name,
      type: fields.type || 'application/octet-stream',
    }));
  }

  function parseManifest(bytes) {
    const m = JSON.parse(td.decode(bytes));
    if (m.v !== VERSION) throw new Error('unsupported manifest version ' + m.v);
    if (typeof m.size !== 'number' || m.size < 0) throw new Error('manifest size is invalid');
    if (m.chunk !== CHUNK) throw new Error('unsupported chunk size ' + m.chunk);
    if (m.chunks !== chunkCount(m.size)) throw new Error('manifest chunk count is inconsistent');
    return m;
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

  // encryptFile turns a File/Blob into a ciphertext Blob in chunk format, with
  // `manifest` bound into every chunk as additional authenticated data.
  //
  // The optional cancellation token is checked between chunks: an aborted
  // encryption throws AbortError and the partial ciphertext is dropped with
  // the rest of the frame, so nothing half-encrypted can reach the network.
  // Cancelling cannot interrupt a chunk already inside subtle.encrypt, but a
  // 64 KiB chunk returns fast enough that the delay is imperceptible.
  async function encryptFile(file, aesKey, manifest, onProgress, signal) {
    if (!manifest || !manifest.length) throw new Error('a manifest is required');
    const total = file.size;
    const chunks = chunkCount(total);
    const parts = [];
    for (let i = 0; i < chunks; i++) {
      if (aborted(signal)) throw abortError();
      const slice = file.slice(i * CHUNK, Math.min((i + 1) * CHUNK, total));
      const buf = await slice.arrayBuffer();
      const ct = await subtle.encrypt(
        { name: 'AES-GCM', iv: chunkNonce(i), additionalData: manifest }, aesKey, buf);
      parts.push(new Uint8Array(ct));
      if (onProgress) onProgress((i + 1) / chunks);
    }
    return new Blob(parts, { type: 'application/octet-stream' });
  }

  // decryptFile reverses encryptFile and returns { blob, manifest }.
  //
  // Every property the caller might display — name, type, size — comes from the
  // manifest, which the decryption itself authenticated. Nothing here trusts the
  // server's copy of any of it.
  async function decryptFile(cipherBuf, aesKey, manifestBytes, onProgress) {
    const m = parseManifest(manifestBytes);
    const ct = new Uint8Array(cipherBuf);

    // The length is fixed by the authenticated chunk count, so a truncated or
    // padded body is rejected before a single tag is checked.
    const want = m.size + m.chunks * TAG;
    if (ct.length !== want) {
      throw new Error('ciphertext is ' + ct.length + ' bytes, the manifest requires ' + want);
    }

    const parts = [];
    let plain = 0;
    for (let i = 0; i < m.chunks; i++) {
      const start = i * (CHUNK + TAG);
      const end = Math.min(start + CHUNK + TAG, ct.length);
      const out = await subtle.decrypt(
        { name: 'AES-GCM', iv: chunkNonce(i), additionalData: manifestBytes },
        aesKey, ct.subarray(start, end));
      parts.push(new Uint8Array(out));
      plain += out.byteLength;
      if (onProgress) onProgress((i + 1) / m.chunks);
    }
    // Belt and braces: the chunk geometry already forces this, and a mismatch
    // here would mean the format assumptions themselves had drifted.
    if (plain !== m.size) {
      throw new Error('decrypted ' + plain + ' bytes, the manifest declares ' + m.size);
    }
    return { blob: new Blob(parts, { type: m.type || 'application/octet-stream' }), manifest: m };
  }

  // decryptLegacy reads a version 1 container: no manifest, no AAD, and no
  // authenticated length — so the chunk count is inferred from whatever arrived.
  // Kept so shares created before version 2 keep opening; never used for new
  // files. Callers show the weaker guarantee rather than implying this is the
  // same thing as decryptFile.
  async function decryptLegacy(cipherBuf, aesKey, type, onProgress) {
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

  // --- batch roster --------------------------------------------------------
  //
  // The roster is the authenticated MEMBER LIST of a batch. Per-file manifests
  // protect each file's own bytes and metadata, but say nothing about which
  // files the link resolves to — without a roster the server picks that, and can
  // drop or add a member with every remaining file still verifying perfectly.
  //
  // Sealed under the roster branch of the batch secret, with the batch id as
  // AAD so a roster cannot be replayed onto a different batch.

  function rosterAAD(batchId) {
    return te.encode(ROSTER_AAD_PREFIX + batchId);
  }

  async function sealRoster(rosterKey, batchId, roster) {
    const nonce = randomBytes(ROSTER_NONCE);
    const body = te.encode(JSON.stringify(roster));
    const sealed = await subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: rosterAAD(batchId) }, rosterKey, body);
    const out = new Uint8Array(ROSTER_NONCE + sealed.byteLength);
    out.set(nonce, 0);
    out.set(new Uint8Array(sealed), ROSTER_NONCE);
    return out;
  }

  async function openRoster(rosterKey, batchId, sealed) {
    if (!sealed || sealed.length <= ROSTER_NONCE) throw new Error('malformed roster');
    const body = await subtle.decrypt(
      { name: 'AES-GCM', iv: sealed.subarray(0, ROSTER_NONCE), additionalData: rosterAAD(batchId) },
      rosterKey, sealed.subarray(ROSTER_NONCE));
    const r = JSON.parse(td.decode(new Uint8Array(body)));
    if (r.v !== VERSION) throw new Error('unsupported roster version ' + r.v);
    if (r.batch !== batchId) throw new Error('roster names a different batch');
    if (!Array.isArray(r.files)) throw new Error('roster has no file list');
    return r;
  }

  window.PYXIS_E2E = {
    available: !!subtle && !!(window.crypto && crypto.getRandomValues),
    VERSION: VERSION,
    b64uEncode: b64uEncode,
    b64uDecode: b64uDecode,
    randomBytes: randomBytes,
    sha256b64u: sha256b64u,
    importAes: importAes,
    deriveUrlKey: deriveUrlKey,
    derivePasswordKeys: derivePasswordKeys,
    deriveBatchKeys: deriveBatchKeys,
    wrapFileKey: wrapFileKey,
    unwrapFileKey: unwrapFileKey,
    newFileId: newFileId,
    buildManifest: buildManifest,
    parseManifest: parseManifest,
    encryptFile: encryptFile,
    decryptFile: decryptFile,
    decryptLegacy: decryptLegacy,
    sealRoster: sealRoster,
    openRoster: openRoster,
    SALT_LEN: 16,
    KEY_LEN: 32,
  };
})();
