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
// Version 3 embeds that manifest IN the stored object:
//
//     "PYX3" || uint16be manifestLength || manifest || chunk 0 || chunk 1 ...
//
// Version 2 got the integrity right but left the blob mute: the manifest lived
// only in a database column beside it, so the bytes on disk carried no magic,
// no version and no self-description. Anything that read them without the
// database — a backup, a copy, a future format migration, a person trying to
// work out what a file is — had no way to tell what it was holding or how to
// interpret it. That is not a break, it is a format that cannot explain itself.
//
// The header needs no separate MAC. Alter the length and a different slice is
// read as the manifest, so the AAD changes and every chunk fails; alter the
// manifest and the same happens; alter the magic and it is refused outright.
// The database column survives as a convenience for listings that must not
// fetch whole blobs, and the reader checks it against the embedded copy.
//
// Versions 1 and 2 are still read. They cannot be upgraded in place — that
// would need the key — so they keep decrypting through the routine that wrote
// them, and version 1's reduced guarantee is stated on the page rather than
// papered over.
(function () {
  'use strict';

  const CHUNK = 65536;
  const TAG = 16;
  const PBKDF2_ITER = 600000;
  const WRAP_NONCE = 12;
  const ROSTER_NONCE = 12;

  // Container version this build writes. Everything at or below it can be read.
  const VERSION = 5;

  // Version 3 and 4 share a header: 4-byte magic then a big-endian uint16
  // manifest length. uint16 is deliberate — a manifest is a short JSON object
  // and the server caps it at 4 KiB, so a 64 KiB ceiling is already far more
  // than the format can legitimately carry.
  //
  // Version 4 keeps that framing and changes what the manifest may say: the
  // file NAME is no longer in it. A manifest is stored in the clear — it is the
  // AAD, so it cannot be encrypted — which meant every name the server held was
  // readable, in the manifest column and in the object's own header, whatever
  // the files column said. In version 4 the name travels sealed, on its own key
  // branch, in a blob of its own (sealName below), so a listing can show names
  // without fetching a byte of ciphertext and the server can read none of them.
  const MAGIC3 = [0x50, 0x59, 0x58, 0x33]; // "PYX3"
  const MAGIC4 = [0x50, 0x59, 0x58, 0x34]; // "PYX4"
  const MAGIC5 = [0x50, 0x59, 0x58, 0x35]; // "PYX5"
  const HEADER_FIXED = 6;

  // Version 5 finishes what 4 started. Version 4 took the name out of the
  // manifest and left the MIME type in it, which meant the server still knew
  // that an account had uploaded eleven JPEGs of 7.5 MB each — a shape, if not
  // a story. In version 5 the manifest carries nothing about the CONTENT at
  // all: version, id, batch, size and chunk geometry, every one of which the
  // server can already derive from the ciphertext it is holding.
  //
  // The type moves into the sealed name blob, which is padded from version 2 of
  // that blob onwards, so its length says nothing about the length of the name
  // it holds. What remains visible to the server is what being the server
  // shows it anyway: the size, the time, the account and the batch.
  const NAME_PAD = 512;

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
      // Only version 4 seals names, but the label lives on the shared row: no
      // older share ever derived this branch, so nothing can collide with it.
      name: 'pyxis-e2e-name-v1',
    },
  };
  // Versions 2, 3 and 4 changed the framing and what the manifest carries, not
  // the key schedule: the same secret must still derive the same keys, or older
  // shares would stop opening.
  LABELS[2] = LABELS[1];
  LABELS[3] = LABELS[1];
  LABELS[4] = LABELS[1];
  LABELS[5] = LABELS[1];

  // Drop labels, indexed by DROP_VERSION.
  //
  // Same discipline as LABELS above and for the same reason: every one of these
  // strings is load-bearing protocol. A drop's whole key schedule hangs off one
  // 32-byte secret, so changing a label here silently changes every key derived
  // from it — and the failure mode is a drop that stops opening with no way to
  // tell that from a corrupted link. New labels get a new version; the old row
  // stays so live drops keep working.
  const DROP_LABELS = {
    1: {
      kem: 'pyxis-drop-kem-v1',     // owner secret -> X-Wing seed
      share: 'pyxis-drop-share-v1', // owner secret -> the public link's secret
      pk: 'pyxis-drop-pk-v1',       // share secret -> key sealing the public key
      up: 'pyxis-drop-up-v1',       // share secret -> upload token
      sub: 'pyxis-drop-sub-v1',     // KEM shared secret -> a submission's root
      note: 'pyxis-drop-note-v1',   // submission root -> key sealing the sender note
    },
  };

  // Drop protocol version this build writes, recorded on the drop row.
  const DROP_VERSION = 1;

  const DROP_PK_AAD_PREFIX = 'pyxis-drop-pk-v1|';
  const NOTE_AAD_PREFIX = 'pyxis-note-v1|';

  const ROSTER_AAD_PREFIX = 'pyxis-roster-v2|';
  const NAME_AAD_PREFIX = 'pyxis-name-v1|';
  const NAME_NONCE = 12;

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

  // The name branch of a single-file URL secret. Batch shares get theirs from
  // deriveBatchKeys; this is the same branch for a share that is its own file.
  async function deriveNameKey(secret, version) {
    return importAes(await hkdf32(secret, new Uint8Array(0), labels(version).name));
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
    const [wrap, roster, name] = await Promise.all([
      hkdf32(secret, empty, l.batch),
      hkdf32(secret, empty, l.roster),
      hkdf32(secret, empty, l.name),
    ]);
    return {
      key: await importAes(wrap),
      roster: await importAes(roster),
      name: await importAes(name),
    };
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

  // Returns { key, auth, roster, name } — only `auth` ever leaves the browser.
  async function derivePasswordKeys(password, salt, version) {
    const l = labels(version);
    const base = await subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = await subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt: salt, iterations: PBKDF2_ITER }, base, 256);
    const master = new Uint8Array(bits);
    const [encKey, auth, rosterKey, nameKey] = await Promise.all([
      hkdf32(master, salt, l.enc),
      hkdf32(master, salt, l.auth),
      hkdf32(master, salt, l.roster),
      hkdf32(master, salt, l.name),
    ]);
    return {
      key: await importAes(encKey),
      auth: auth,
      roster: await importAes(rosterKey),
      name: await importAes(nameKey),
    };
  }

  // --- drop keys -----------------------------------------------------------
  //
  // Every other share in Pyxis is symmetric: whoever encrypted it can decrypt
  // it, and the link carries the key both ways. A DROP inverts that. A stranger
  // holding the public link must be able to seal files that only the owner can
  // open, and must not be able to open anything — including what they just
  // sent. That is a key encapsulation problem, so it needs an asymmetric
  // primitive: X-Wing (ML-KEM-768 + X25519), in mlkem.js.
  //
  // What the KEM does NOT do is replace the schedule below it. Encapsulation
  // produces a 32-byte shared secret, which is exactly the shape of the secret
  // a batch link already carries — so from that point on a submission IS a
  // batch, byte for byte: the same three HKDF branches, the same wrapped file
  // keys, the same sealed names, the same roster. The new cryptography is one
  // step at the front, and nothing downstream of it had to change.
  //
  //   K  — 32 random bytes, the owner's secret, only ever in the private
  //   │    link's #fragment
  //   ├── HKDF(K, "", kem)   -> X-Wing seed -> (decapsulation key, public key)
  //   └── HKDF(K, "", share) -> S, the public link's #fragment
  //                             ├── HKDF(S, "", pk) -> seals the public key
  //                             └── HKDF(S, "", up) -> the upload token
  //
  // S is one-way from K, so the public link tells its holder nothing about the
  // private one; and K regenerates S, so an owner who loses the link they gave
  // out can always produce it again from the one they kept.

  function dropLabels(version) {
    return DROP_LABELS[version] || DROP_LABELS[DROP_VERSION];
  }

  function dropKem() {
    const kem = window.PYXIS_KEM;
    // Fail closed and say which half is missing: a drop page without the KEM
    // must never quietly fall back to something the server could open.
    if (!kem || typeof kem.encapsulate !== 'function') {
      throw new Error('post-quantum KEM unavailable');
    }
    return kem;
  }

  // The owner's side. Returns everything derivable from the private link, which
  // is everything: the public key to publish, the share secret to hand out, and
  // the KEM seed that opens submissions.
  async function deriveDropOwnerKeys(secret, version) {
    const kem = dropKem();
    const l = dropLabels(version);
    const empty = new Uint8Array(0);
    const [kemSeed, shareSecret] = await Promise.all([
      hkdf32(secret, empty, l.kem),
      hkdf32(secret, empty, l.share),
    ]);
    const pair = kem.keygen(kemSeed);
    return {
      kemSeed: kemSeed,
      shareSecret: shareSecret,
      publicKey: pair.publicKey,
    };
  }

  // The public link's side. `token` is the only value here that ever leaves a
  // browser: the server keeps SHA-256(token) and compares, exactly as it does
  // for a password share's auth branch, so a stolen database yields no way to
  // write into the drop.
  async function deriveDropShareKeys(shareSecret, version) {
    const l = dropLabels(version);
    const empty = new Uint8Array(0);
    const [pkKey, token] = await Promise.all([
      hkdf32(shareSecret, empty, l.pk),
      hkdf32(shareSecret, empty, l.up),
    ]);
    return { pk: await importAes(pkKey), token: token };
  }

  function dropPkAAD(publicId) {
    return te.encode(DROP_PK_AAD_PREFIX + publicId);
  }

  // The public key is sealed rather than published. It costs one AES-GCM
  // operation and buys two things: the public link's fragment stays 43
  // characters (a 1216-byte key in a URL would not survive being copied, let
  // alone photographed as a QR code), and a server that swaps in a public key
  // of its own is caught — it cannot forge a blob under a key derived from S,
  // which it has never seen. The public id is the AAD, so a sealed key cannot
  // be moved from one drop to another either.
  async function sealDropPublicKey(pkKey, publicId, publicKey) {
    const nonce = randomBytes(WRAP_NONCE);
    const sealed = await subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: dropPkAAD(publicId) }, pkKey, publicKey);
    const out = new Uint8Array(WRAP_NONCE + sealed.byteLength);
    out.set(nonce, 0);
    out.set(new Uint8Array(sealed), WRAP_NONCE);
    return out;
  }

  async function openDropPublicKey(pkKey, publicId, sealed) {
    if (!sealed || sealed.length <= WRAP_NONCE) throw new Error('malformed drop key');
    const raw = await subtle.decrypt(
      { name: 'AES-GCM', iv: sealed.subarray(0, WRAP_NONCE), additionalData: dropPkAAD(publicId) },
      pkKey, sealed.subarray(WRAP_NONCE));
    const pk = new Uint8Array(raw);
    if (pk.length !== dropKem().PUBLIC_KEY_LEN) throw new Error('drop key has the wrong length');
    return pk;
  }

  function dropEncapsulate(publicKey) {
    const { cipherText, sharedSecret } = dropKem().encapsulate(publicKey);
    return { ct: cipherText, ss: sharedSecret };
  }

  function dropDecapsulate(kemSeed, ct) {
    return dropKem().decapsulate(ct, kemSeed);
  }

  // One submission's keys, from the KEM shared secret.
  //
  // The ciphertext is bound in as the HKDF salt. X-Wing already claims
  // MAL-BIND-K-CT and MAL-BIND-K-PK — raw ML-KEM does not — so this is belt and
  // braces rather than load-bearing, but it costs nothing and it keeps drop
  // keys in a different space from URL-fragment shares even though both end in
  // the same three branches.
  async function deriveSubmissionKeys(ss, ct, version) {
    const digest = new Uint8Array(await subtle.digest('SHA-256', ct));
    const root = await hkdf32(ss, digest, dropLabels(version).sub);
    const keys = await deriveBatchKeys(root, VERSION);
    const noteKey = await hkdf32(root, new Uint8Array(0), dropLabels(version).note);
    return {
      key: keys.key,
      roster: keys.roster,
      name: keys.name,
      note: await importAes(noteKey),
    };
  }

  // --- the sender's note ---------------------------------------------------
  //
  // A drop's whole point is that the owner does not know who will use it, so a
  // submission carries an optional "from" and a message. It is sealed like a
  // file name — same padding, so its length says nothing about its contents,
  // and the batch id as AAD so it cannot be moved onto another submission.
  //
  // It proves nothing about who sent it. Anyone with the link can write
  // anything here, and the inbox must present it as what it is: a label the
  // sender chose, not an identity the application verified.

  function noteAAD(batchId) {
    return te.encode(NOTE_AAD_PREFIX + batchId);
  }

  async function sealNote(noteKey, batchId, fields) {
    const json = te.encode(JSON.stringify({
      v: 1,
      from: (fields.from || '').slice(0, 200),
      message: (fields.message || '').slice(0, 1000),
    }));
    if (2 + json.length > 4096) throw new Error('note is too long to seal');
    const body = padNameBody(json);
    const nonce = randomBytes(NAME_NONCE);
    const sealed = await subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: noteAAD(batchId) }, noteKey, body);
    const out = new Uint8Array(NAME_NONCE + sealed.byteLength);
    out.set(nonce, 0);
    out.set(new Uint8Array(sealed), NAME_NONCE);
    return out;
  }

  async function openNote(noteKey, batchId, sealed) {
    if (!sealed || sealed.length <= NAME_NONCE) throw new Error('malformed note');
    const body = await subtle.decrypt(
      { name: 'AES-GCM', iv: sealed.subarray(0, NAME_NONCE), additionalData: noteAAD(batchId) },
      noteKey, sealed.subarray(NAME_NONCE));
    const n = JSON.parse(td.decode(unpadNameBody(new Uint8Array(body))));
    if (n.v !== 1) throw new Error('unsupported note version ' + n.v);
    return { from: n.from || '', message: n.message || '' };
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
  // These bytes are stored and served in the clear — they are the AAD, they
  // cannot be encrypted — so anything in here is something the server knows.
  // Since version 5 that is nothing it could not already work out from the
  // ciphertext: no name (version 4 removed it), no type (version 5 removed
  // it), only the geometry needed to read the object. Name and type are sealed
  // separately; what binds them to this file is the manifest id, which is the
  // sealed blob's AAD.
  function buildManifest(fields) {
    return te.encode(JSON.stringify({
      v: VERSION,
      id: fields.id,
      batch: fields.batch || '',
      size: fields.size,
      chunks: chunkCount(fields.size),
      chunk: CHUNK,
    }));
  }

  // Accepts a manifest from any version that has one (2 and 3). The manifest's
  // own `v` is the container version it was written for.
  function parseManifest(bytes) {
    const m = JSON.parse(td.decode(bytes));
    // Bounded by VERSION rather than a list of numbers: a hardcoded list is a
    // thing to forget on the next bump, and forgetting it makes every new share
    // unreadable by the client that wrote it.
    if (m.v < 2 || m.v > VERSION) throw new Error('unsupported manifest version ' + m.v);
    if (typeof m.size !== 'number' || m.size < 0) throw new Error('manifest size is invalid');
    if (m.chunk !== CHUNK) throw new Error('unsupported chunk size ' + m.chunk);
    if (m.chunks !== chunkCount(m.size)) throw new Error('manifest chunk count is inconsistent');
    return m;
  }

  function bytesEqual(a, b) {
    if (!a || !b || a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  }

  function magicFor(version) {
    if (version >= 5) return MAGIC5;
    return version >= 4 ? MAGIC4 : MAGIC3;
  }

  // readHeader pulls the embedded manifest out of a version 3 or 4 object. Both
  // magics are accepted because the framing is the same; which one is present
  // says whether the manifest may still carry a name.
  function readHeader(ct) {
    if (ct.length < HEADER_FIXED) throw new Error('object is too short to be a container');
    const magic = ct[3] === MAGIC5[3] ? MAGIC5 : (ct[3] === MAGIC4[3] ? MAGIC4 : MAGIC3);
    for (let i = 0; i < magic.length; i++) {
      if (ct[i] !== magic[i]) throw new Error('not a Pyxis container');
    }
    const len = (ct[4] << 8) | ct[5];
    if (len === 0 || ct.length < HEADER_FIXED + len) throw new Error('container header is truncated');
    return { manifest: ct.subarray(HEADER_FIXED, HEADER_FIXED + len), body: HEADER_FIXED + len };
  }

  function writeHeader(manifest, version) {
    if (manifest.length > 0xffff) throw new Error('manifest is too large for the header');
    const head = new Uint8Array(HEADER_FIXED + manifest.length);
    head.set(magicFor(version || VERSION), 0);
    head[4] = (manifest.length >> 8) & 0xff;
    head[5] = manifest.length & 0xff;
    head.set(manifest, HEADER_FIXED);
    return head;
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

  const sleep = (ms) => new Promise((res) => setTimeout(res, ms));

  // readBlobViaReader is the FileReader spelling of blob.arrayBuffer(). It
  // exists because the two take different paths through WebKit, and a read
  // that fails one way sometimes succeeds the other.
  function readBlobViaReader(blob) {
    return new Promise((resolve, reject) => {
      const fr = new FileReader();
      fr.onload = () => resolve(fr.result);
      fr.onerror = () => reject(fr.error || new Error('the file could not be read'));
      fr.readAsArrayBuffer(blob);
    });
  }

  // fileGoneError marks a read the browser will not serve, as opposed to
  // anything about the cryptography. The caller shows its own message for it —
  // the browser's ("The object cannot be found here") names no file and
  // suggests nothing to do about it.
  function fileGoneError(cause) {
    const err = new Error((cause && cause.message) || 'the file could not be read');
    err.name = 'FileUnreadableError';
    err.code = 'file-unreadable';
    return err;
  }

  // readSlice reads one chunk of the file, and works around what iPhones and
  // iPads do to a file that lives in iCloud.
  //
  // A File handed over by the picker is a reference, not a copy. On iOS the
  // bytes behind it may still be in iCloud and are materialised on demand, and
  // that materialisation can fail or time out — the read then rejects with
  // NotFoundError ("The object cannot be found here") or NotReadableError,
  // typically for the fourth or fifth file of a large selection, minutes after
  // it was picked, because uploads run one at a time and the queue waits.
  //
  // Both are worth another go, so the chunk is re-read several times, each
  // pass through both read paths, before it is declared unreadable.
  async function readSlice(file, start, end, signal) {
    const want = end - start;
    let last;
    // A short read is a failed read: a browser that loses the backing file
    // mid-read has been known to resolve with a truncated buffer rather than
    // reject, and a chunk short of its length would seal happily and decrypt
    // to the wrong bytes.
    const sized = (buf) => {
      if (buf.byteLength === want) return buf;
      throw new Error('read ' + buf.byteLength + ' of ' + want + ' bytes');
    };
    for (let attempt = 0; attempt < 4; attempt++) {
      if (aborted(signal)) throw abortError();
      // Both readers are tried on every attempt rather than alternating: a
      // browser missing FileReader, or one where it fails for its own
      // reasons, would otherwise spend half the attempts on it.
      try {
        const slice = file.slice(start, end);
        if (!slice.arrayBuffer) throw new Error('this browser cannot read a file slice');
        return sized(await slice.arrayBuffer());
      } catch (err) {
        if (err && err.name === 'AbortError') throw err;
        last = err; // the direct read's error is the one worth reporting
      }
      try {
        return sized(await readBlobViaReader(file.slice(start, end)));
      } catch (err) {
        if (err && err.name === 'AbortError') throw err;
      }
      // Re-slicing from the File on the next pass is deliberate: a stale Blob
      // reference is part of what goes wrong, and the pause gives iCloud a
      // moment to finish fetching the bytes. No pause after the last one —
      // there is nothing left to wait for.
      if (attempt < 3) await sleep(250 * (attempt + 1));
    }
    throw fileGoneError(last);
  }

  // Ciphertext is handed to the blob store this often rather than kept in the
  // JS heap to the end. A 2 GiB file held as 32768 Uint8Arrays and then copied
  // into a Blob needs twice the file in memory at the moment of the copy,
  // which is where an iPad quietly kills the tab — and a killed tab is
  // indistinguishable, from the outside, from the upload being cut off. Blobs
  // are backed by storage the browser can spill to disk, so flushing keeps the
  // heap flat and costs one extra reference per 4 MiB.
  const FLUSH_BYTES = 4 << 20;

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
    // The header goes in front, so the stored object says what it is. It is
    // covered by the chunks' AAD rather than a MAC of its own: change the
    // length or the manifest and every chunk stops verifying.
    const flushed = [];
    let parts = [writeHeader(manifest, VERSION)];
    let pending = 0;
    for (let i = 0; i < chunks; i++) {
      if (aborted(signal)) throw abortError();
      const start = i * CHUNK;
      const buf = await readSlice(file, start, Math.min(start + CHUNK, total), signal);
      const ct = await subtle.encrypt(
        { name: 'AES-GCM', iv: chunkNonce(i), additionalData: manifest }, aesKey, buf);
      parts.push(new Uint8Array(ct));
      pending += ct.byteLength;
      if (pending >= FLUSH_BYTES) {
        flushed.push(new Blob(parts));
        parts = [];
        pending = 0;
      }
      if (onProgress) onProgress((i + 1) / chunks);
    }
    if (parts.length) flushed.push(new Blob(parts));
    // Concatenating blobs copies no bytes: the pieces are already stored.
    return new Blob(flushed, { type: 'application/octet-stream' });
  }

  // decryptChunks is the shared body of versions 2 and 3: the manifest is
  // already known, `offset` is where the chunk stream starts.
  async function decryptChunks(ct, offset, aesKey, manifestBytes, onProgress, type) {
    const m = parseManifest(manifestBytes);

    // The length is fixed by the authenticated chunk count, so a truncated or
    // padded body is rejected before a single tag is checked.
    const want = offset + m.size + m.chunks * TAG;
    if (ct.length !== want) {
      throw new Error('ciphertext is ' + ct.length + ' bytes, the manifest requires ' + want);
    }

    const parts = [];
    let plain = 0;
    for (let i = 0; i < m.chunks; i++) {
      const start = offset + i * (CHUNK + TAG);
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
    // A version 5 manifest states no type — that is the point of it — so the
    // caller passes the one it opened out of the sealed name blob. Older
    // manifests still carry theirs and keep using it.
    return {
      blob: new Blob(parts, { type: m.type || type || 'application/octet-stream' }),
      manifest: m,
    };
  }

  // decryptFile reverses encryptFile and returns { blob, manifest }.
  //
  // The manifest comes out of the object itself. `expected`, when given, is the
  // server's separate copy — the one that drove the listing the caller has
  // already rendered — and it must match the embedded bytes exactly. Only the
  // embedded copy is ever used as AAD, so a server that sends a different one
  // is caught rather than obeyed.
  async function decryptFile(cipherBuf, aesKey, expected, onProgress, type) {
    const ct = new Uint8Array(cipherBuf);
    const head = readHeader(ct);
    if (expected && expected.length && !bytesEqual(expected, head.manifest)) {
      throw new Error('the stored metadata does not match the file');
    }
    return decryptChunks(ct, head.body, aesKey, head.manifest, onProgress, type);
  }

  // decryptV2 reads a version 2 object: the same chunk stream, but with the
  // manifest supplied out of band because the object carries no header.
  async function decryptV2(cipherBuf, aesKey, manifestBytes, onProgress) {
    if (!manifestBytes || !manifestBytes.length) throw new Error('a manifest is required');
    return decryptChunks(new Uint8Array(cipherBuf), 0, aesKey, manifestBytes, onProgress);
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

  // openFile is the one entry point callers should use: it picks the reader for
  // the version the object was written with and always returns
  // { blob, manifest }, with manifest null for version 1, which has none.
  //
  // Version confusion fails closed in both directions and does not need a
  // separate check: the chunks of a version 2 or 3 file are sealed against
  // their manifest, so reading one as version 1 (no AAD) fails, and reading a
  // version 1 file as either of the others fails too.
  async function openFile(version, cipherBuf, aesKey, manifestBytes, type, onProgress) {
    const v = Number(version) || 1;
    if (v >= 3) return decryptFile(cipherBuf, aesKey, manifestBytes, onProgress, type);
    if (v === 2) return decryptV2(cipherBuf, aesKey, manifestBytes, onProgress);
    return { blob: await decryptLegacy(cipherBuf, aesKey, type, onProgress), manifest: null };
  }

  // --- sealed names --------------------------------------------------------
  //
  // A name is sealed on its own, in its own blob, under its own HKDF branch of
  // the share secret — not folded into the file's ciphertext. That is the whole
  // point: a listing can show every name in a batch after one cheap request,
  // without pulling a single chunk of any file, without spending a download
  // slot, and without the server ever holding a name it can read.
  //
  // The manifest id is the AAD, so a sealed name belongs to exactly one file:
  // the server cannot move a name onto another object, and cannot swap two
  // names within a batch. The id is generated in the browser, so it is not the
  // server's to choose either.
  function nameAAD(fileId) {
    return te.encode(NAME_AAD_PREFIX + fileId);
  }

  // The plaintext is padded before sealing, because AES-GCM ciphertext is the
  // length of its input: without padding, a 540-byte blob and a 560-byte blob
  // would tell the server how long the file's name is. Blob version 2 is
  //
  //     uint16be jsonLength || json || zero padding, to a multiple of NAME_PAD
  //
  // so every ordinary name produces exactly the same number of bytes. Version 1
  // (container version 4, unpadded raw JSON) is still read: those shares exist.
  // The two are told apart by their first byte — a version 1 blob starts with
  // '{', a version 2 blob with the high byte of a length under 4 KiB.
  function padNameBody(json) {
    const total = Math.ceil((2 + json.length) / NAME_PAD) * NAME_PAD;
    const out = new Uint8Array(total);
    out[0] = (json.length >> 8) & 0xff;
    out[1] = json.length & 0xff;
    out.set(json, 2);
    return out;
  }

  function unpadNameBody(body) {
    if (body[0] === 0x7b) return body;                    // version 1: bare JSON
    const len = (body[0] << 8) | body[1];
    if (len === 0 || 2 + len > body.length) throw new Error('sealed name is malformed');
    return body.subarray(2, 2 + len);
  }

  async function sealName(nameKey, fileId, fields) {
    const json = te.encode(JSON.stringify({
      v: 2,
      name: fields.name,
      type: fields.type || 'application/octet-stream',
    }));
    if (2 + json.length > 4096) throw new Error('file name is too long to seal');
    const body = padNameBody(json);
    const nonce = randomBytes(NAME_NONCE);
    const sealed = await subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: nameAAD(fileId) }, nameKey, body);
    const out = new Uint8Array(NAME_NONCE + sealed.byteLength);
    out.set(nonce, 0);
    out.set(new Uint8Array(sealed), NAME_NONCE);
    return out;
  }

  // Throws if the blob was sealed for another file or under another secret —
  // GCM verifies both before a single character of the name is returned.
  async function openName(nameKey, fileId, sealed) {
    if (!sealed || sealed.length <= NAME_NONCE) throw new Error('malformed sealed name');
    const body = await subtle.decrypt(
      { name: 'AES-GCM', iv: sealed.subarray(0, NAME_NONCE), additionalData: nameAAD(fileId) },
      nameKey, sealed.subarray(NAME_NONCE));
    const n = JSON.parse(td.decode(unpadNameBody(new Uint8Array(body))));
    if (n.v !== 1 && n.v !== 2) throw new Error('unsupported sealed name version ' + n.v);
    // (The blob has its own small version, not the container's: 1 unpadded,
    // 2 padded. Both are read; only 2 is written.)
    if (typeof n.name !== 'string' || !n.name) throw new Error('sealed name is empty');
    return n;
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
    // Accept every roster version that has ever been sealed. The roster format
    // has not changed since 2 — only the file container has — and refusing an
    // older one would make a batch uploaded before the change report its own
    // member list as unverifiable. Names have always been sealed in here, which
    // is why version 4 could take them out of the manifest without touching
    // this format at all.
    if (r.v < 2 || r.v > VERSION) throw new Error('unsupported roster version ' + r.v);
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
    deriveNameKey: deriveNameKey,
    derivePasswordKeys: derivePasswordKeys,
    deriveBatchKeys: deriveBatchKeys,
    wrapFileKey: wrapFileKey,
    unwrapFileKey: unwrapFileKey,
    newFileId: newFileId,
    buildManifest: buildManifest,
    parseManifest: parseManifest,
    encryptFile: encryptFile,
    openFile: openFile,
    decryptFile: decryptFile,
    decryptV2: decryptV2,
    decryptLegacy: decryptLegacy,
    readHeader: readHeader,
    HEADER_FIXED: HEADER_FIXED,
    sealRoster: sealRoster,
    openRoster: openRoster,
    sealName: sealName,
    openName: openName,
    DROP_VERSION: DROP_VERSION,
    kemAvailable: function () {
      return !!(window.PYXIS_KEM && typeof window.PYXIS_KEM.encapsulate === 'function');
    },
    deriveDropOwnerKeys: deriveDropOwnerKeys,
    deriveDropShareKeys: deriveDropShareKeys,
    sealDropPublicKey: sealDropPublicKey,
    openDropPublicKey: openDropPublicKey,
    dropEncapsulate: dropEncapsulate,
    dropDecapsulate: dropDecapsulate,
    deriveSubmissionKeys: deriveSubmissionKeys,
    sealNote: sealNote,
    openNote: openNote,
    SALT_LEN: 16,
    KEY_LEN: 32,
  };
})();
