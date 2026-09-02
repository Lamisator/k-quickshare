# Pyxis

**Secure sharing, ephemerally.**

*Pyxis* (Latin, from Greek *pyxís*): a small lidded box — the kind used to carry
something valuable a short distance, then opened once and set aside. It is also
a faint southern constellation, the Mariner's Compass.

Self-hosted file sharing where **the server cannot read what it stores**.

Files are encrypted in the browser before upload. The server receives ciphertext,
stores ciphertext, and serves ciphertext back; the key never leaves the uploader's
tab except inside the share link's URL fragment, which browsers do not transmit.
Losing the link (or the password) means losing the file — for everyone, administrators
included.

Go + PostgreSQL + vanilla JavaScript. No build step, no framework, no runtime
dependencies beyond the two containers.

### Cryptography at a glance

| | |
|---|---|
| **Payload** | AES-256-GCM over 64 KiB chunks, each sealed against the file's manifest as AAD |
| **Key derivation** | HKDF-SHA256 from a 256-bit link secret, or PBKDF2-SHA256 (600 000 iterations) from a password |
| **Where keys exist** | The uploader's tab, and any tab holding the link. Never the server, in any form, at any moment |
| **File names and types** | Sealed in a blob of their own, padded to a fixed size, under their own key branch |
| **Batch integrity** | Each member's key wrapped under the batch key; the member list itself sealed as a roster |
| **What the server stores** | Ciphertext, a sealed name blob, an opaque wrapped key, and a manifest that describes only geometry |
| **What the server can decrypt** | Nothing. There is no code path, no key, and no fallback |

The whole scheme is in one file — [`web/static/e2e.js`](web/static/e2e.js), some
640 lines of WebCrypto with no dependencies — and Go mirrors its format decisions in
[`crypto.go`](crypto.go) so both ends can be tested against byte-exact vectors.
[**Cryptography**](#cryptography) has the diagrams.

---

## Contents

- [Features](#features)
- [Cryptography](#cryptography)
- [Batch shares](#batch-shares)
- [Running it](#running-it)
- [Configuration](#configuration)
- [Routes](#routes)
- [Development](#development)
- [Testing](#testing)
- [Operational notes](#operational-notes)
- [Known limits](#known-limits)

---

## Features

**Sharing**
- Two-step upload: the link's terms are settled first, and only then does the
  dropzone open — nothing can be shared under settings nobody chose.
- Drag-and-drop upload with per-file progress, transfer rate, cancel and retry.
- **Paste from the clipboard** — Ctrl+V anywhere on the upload page, or the
  button under the dropzone. A screenshot arrives as `pasted-<timestamp>.png`
  rather than the `image.png` every browser hands over, so two pastes stay
  apart; a file copied in a file manager keeps its own name.
- Every file uploaded in one visit is collected under **one share link**.
- **File names and types are encrypted too**, sealed apart from the file so a
  recipient sees a listing without downloading anything and the server sees
  nothing about the content — not a name, not a type, not even a name's length.
- **My files** folds each of those batches into a collapsible group — the share's
  terms are stated once on the header, its members indented beneath it, and the
  whole group selects, expands or collapses in one click.
- Recipients download files individually or all at once as a ZIP built in their browser.
- Inline preview for images, video, audio, PDF and text.
- Expiry by preset or an arbitrary date; download limits; optional share password.
- QR code for any link, generated client-side.

**Access**
- Local accounts (Argon2id, database-backed sessions) and OIDC single sign-on,
  which coexist — enabling SSO does not disable password login.
- Admin and super-admin roles; user management and OIDC settings in the UI.
- **My files** is your own uploads, for everyone including admins. The
  instance-wide listing is a separate, admin-only page.

**Operations**
- Storage quotas admins set in the UI: an instance-wide default per user, plus
  per-user overrides. Instance ceiling and free-disk floor on top. Everyone
  sees their own usage as a bar in the page shell; the volume's free space is
  shown to admins only.
- A sweeper retires expired and used-up links every minute: the blob is deleted
  at once, the metadata row is kept for 30 days as "expired", then purged.
- Full English and German localisation, dark and light themes.
- Language is detected from the browser's `Accept-Language` header, honouring
  q-values rather than header order, and falls back to English for anything
  unsupported. An explicit choice via the switcher is remembered in a cookie
  and always wins.

---

## Cryptography

**The server holds no key for any file, in any mode, at any moment.** There is
exactly one encryption scheme, it runs entirely in the browser, and everything
below follows from that single constraint.

### The trust boundary

Everything that identifies a file — its bytes, its name, its type — is sealed on
the left of this line. Only the right-hand side is ever written to disk.

```
             BROWSER  (holds every key)         │         SERVER  (holds none)
                                                │
   ┌────────────────────────────────────┐       │   ┌──────────────────────────────┐
   │ the file's plaintext bytes         │       │   │ files                        │
   │ its name          "invoice.pdf"    │       │   │   size_bytes    197 842      │
   │ its type          application/pdf  │       │   │   uploaded_at   2026-08-31   │
   │                                    │       │   │   uploaded_by   marius       │
   │ share secret — 32 bytes, generated │       │   │   original_name NULL         │
   │ here, living only in the link's    │       │   │   content_type  NULL         │
   │ #fragment                          │       │   │   enc_name      540 bytes    │
   │   ├── file key                     │       │   │   wrapped_key    60 bytes    │
   │   ├── roster key                   │       │   │   manifest      {v,id,size…} │
   │   └── name key                     │       │   │                              │
   └──────────────────┬─────────────────┘       │   │ on disk                      │
                      │                         │   │   PYX5 ‖ manifest ‖ chunks…  │
                      │   ciphertext only       │   └──────────────────────────────┘
                      └─────────────────────────┼──▶
                                                │
   The #fragment is never sent. Browsers do not │   Everything here is either
   put it in the request line, so the secret    │   ciphertext, opaque, or a fact
   cannot reach the server even by accident.    │   about the transaction itself.
```

The right-hand column is not an aspiration. Dump the database and grep it for a
file name, a MIME type, or any plaintext byte of a file: there is nothing to
find. What remains — size, time, account, which files share a link — is listed
under [what the server can still see](#what-the-server-can-still-see).

### The key schedule

Every key in the system descends from one of two roots, and each purpose gets
its own HKDF branch. Separate branches mean a key that seals a name can never
open a file, and the one value the server is given cannot be walked backwards
into any of the others.

```
  URL-key share  (key_mode 3)                  Password share  (key_mode 4)
  ───────────────────────────                  ────────────────────────────
  32 random bytes, generated in the tab        the password, never transmitted
  and written into the link's #fragment                     │
              │                                 PBKDF2-SHA256, 600 000 iters,
              │                                 16-byte random salt (stored)
              │                                             ▼
              │                                  master secret, 256 bits
              ▼                                             ▼
   HKDF-SHA256, salt = ""                        HKDF-SHA256, salt = that salt
              │                                             │
   info ──────┤                                  info ──────┤
              │                                             │
   ├─ pyxis-e2e-url-v1     → file key            ├─ pyxis-e2e-enc-v1    → file / batch key
   ├─ pyxis-e2e-batch-v1   → batch key           ├─ pyxis-e2e-auth-v1   → auth token  ──┐
   ├─ pyxis-e2e-roster-v1  → roster key          ├─ pyxis-e2e-roster-v1 → roster key    │
   └─ pyxis-e2e-name-v1    → name key            └─ pyxis-e2e-name-v1   → name key      │
                                                                                        │
   nothing here ever leaves the tab               one branch leaves the tab, once ──────┘
                                                  the server keeps SHA-256(token)
                                                  and compares; it cannot invert it
                                                  and it cannot derive `enc` from it
```

The info strings are part of the protocol, not decoration: they are versioned in
a table in `e2e.js` because changing one changes every key derived from it. The
last time they moved — the `k-fileshare` → `pyxis` rename — every live share
became undecryptable, and the failure was indistinguishable from a wrong
password. That table exists so it cannot happen twice.

| `key_mode` | Name | Where the key comes from |
|---|---|---|
| `3` | E2E URL | `HKDF(fragment secret, "", "pyxis-e2e-url-v1")` |
| `4` | E2E password | `PBKDF2-SHA256(password, salt, 600k)` → HKDF split |

### The file container

Files are encrypted with WebCrypto before anything is sent: **chunked
AES-256-GCM**, 64 KiB of plaintext per chunk. Chunking keeps memory bounded on a
phone and makes the ciphertext seekable, so a preview does not have to hold a
gigabyte in RAM to show the first page.

```
  container version 5, as stored on disk and as served
  ┌────────┬──────────┬────────────────┬────────────────┬────────────────┬─────
  │ "PYX5" │ uint16be │   manifest     │ chunk 0        │ chunk 1        │  …
  │ 4 B    │ length   │   JSON, plain  │ ≤64 KiB + 16 B │ ≤64 KiB + 16 B │
  └────────┴──────────┴───────┬────────┴───────▲────────┴───────▲────────┴─────
                              │                │                │
                              └─── AAD ────────┴────────────────┘
                              every chunk is sealed against these exact bytes

  chunk nonce, 12 bytes — a counter, never a random value
  ┌─────────────┬──────────────────────────────────┐
  │ 00 00 00 00 │ big-endian uint64 chunk index    │
  └─────────────┴──────────────────────────────────┘
  The key is single-use and random, so a counter cannot repeat under it —
  which is the one thing GCM must never do.
```

The manifest is the load-bearing part. It is plaintext, deliberately: it is the
AAD, and AAD is not encrypted. So the rule that governs the whole format is
**nothing that describes the content may go in it** — and what is in it, the
server could work out from the ciphertext's length anyway.

```json
{"v":5,"id":"<32 random bytes, base64url>","batch":"<uuid or empty>",
 "size":197842,"chunks":4,"chunk":65536}
```

Binding those bytes into every chunk is what turns "each chunk is authenticated"
into "the file is authenticated":

| Attack on stored data | What stops it |
|---|---|
| Drop trailing chunks | `chunks` is authenticated; the count no longer matches |
| Replace the blob with zero bytes | An empty file still has one chunk, whose only content is a tag over the manifest |
| Swap one file's blob for another's | `id` is authenticated and unique per file |
| Move a file into another share | `batch` is authenticated |
| Edit the header's length field | A different slice is read as AAD, so every chunk fails |
| Serve a different manifest than the embedded one | The reader compares them and refuses |
| Rename the file | The name is not here at all — see below |

### Sealed names and types

A name is sealed on its own, in a blob of its own, under its own HKDF branch. It
is deliberately *not* folded into the file's ciphertext: a recipient's listing
shows every name in a batch after one short decryption each, without fetching a
byte of any file and without spending a download slot. The MIME type travels
with it, so the icon and the preview decision are made by the browser rather
than by a server that would have to be told what the file is.

```
  files.enc_name — 540 bytes for every ordinary name, by construction
  ┌────────────┬──────────────────────────────────────────────┬──────────┐
  │ nonce 12 B │ AES-GCM(name key, padded body)               │ tag 16 B │
  └────────────┴───────────────────────┬──────────────────────┴──────────┘
                                       │  what is inside it:
                                       ▼
  padded body — 512 B, or the next multiple for a very long name
  ┌────────────┬─────────────────────────────────┬────────────────────────┐
  │ uint16be   │ {"v":2,"name":"…","type":"…"}   │ 00 00 00 … zero padding│
  │ jsonLength │                                 │                        │
  └────────────┴─────────────────────────────────┴────────────────────────┘

  AAD = "pyxis-name-v1|" ‖ the manifest's file id
```

Two properties, both necessary:

- **The AAD binds the blob to one file.** The id is generated in the browser, so
  the server cannot choose it, cannot move a name onto another object, and
  cannot swap two names inside a batch.
- **The padding hides the name's length.** AES-GCM output is exactly as long as
  its input. Unpadded, a 540-byte blob and a 560-byte blob would tell anyone
  holding the database how long each file's name is — a small leak, but a real
  one, and the sort that composes with others. Padded to a 512-byte multiple,
  every ordinary name is indistinguishable from every other. The server rejects
  a blob whose length is not one the padding can produce.

### How a batch is keyed

One link, one secret, many files — but not one key. Each member is encrypted
under its **own** random key, which is then wrapped under the batch key and
stored as an opaque blob.

```
                    batch secret  (the link's #fragment)
                                 │
        ┌────────────────────────┼────────────────────────┐
        ▼                        ▼                        ▼
    batch key               roster key                name key
        │                        │                        │
        │                        │                        ├─▶ enc_name of file A
        │                        │                        └─▶ enc_name of file B
        │                        │
        │                        └─▶ batches.roster — the sealed member list:
        │                            id, name, size, type and manifest digest
        │                            of every file, plus a sequence number
        │
        ├─▶ wraps file A's random key ─▶ files.wrapped_key   (12 B nonce + 32 B + 16 B tag)
        └─▶ wraps file B's random key ─▶ files.wrapped_key
                     │
                     └─▶ each file's own key seals only its own chunks
```

Wrapping rather than deriving per-file keys buys two things: the browser
encrypts before the server has assigned any id, so there is nothing stable to
derive from; and a member can be added or removed without renumbering anything.

### Upload, end to end

```
  browser                                                      server
     │                                                          │
     │  POST /batches   expiry, download limit, auth_salt?      │
     │ ────────────────────────────────────────────────────────▶│  batch row created
     │ ◀────────────────────────────────────────────────────────│  batch id
     │                                                          │
     │  ① derive batch, roster and name keys from the secret    │
     │  ② random 256-bit file key, wrapped under the batch key  │
     │  ③ build the manifest — no name, no type                 │
     │  ④ seal name + type into the padded blob                 │
     │  ⑤ encrypt chunk by chunk, manifest as AAD               │
     │                                                          │
     │  POST /upload   ciphertext ‖ wrapped_key                 │
     │                 ‖ manifest ‖ enc_name                    │
     │ ────────────────────────────────────────────────────────▶│  the embedded header must
     │                                                          │  match the manifest sent
     │                                                          │  with it; bytes stored
     │                                                          │  verbatim, never re-encoded
     │                                                          │
     │  ⑥ re-seal the roster, POST /batches/{id}/roster         │
     │ ────────────────────────────────────────────────────────▶│  seq must not go backwards
     │                                                          │
     ▼                                                          ▼
  holds the only copy of the link,                             holds ciphertext, and
  #fragment included                                           metadata it cannot read
```

### When the browser loses the file, or the connection

Two failures dominate uploads from an iPhone or iPad, and neither is a
cryptographic one.

**The file goes away mid-encryption.** A `File` from the picker is a reference,
not a copy. On iOS the bytes may still be in iCloud and are fetched on demand,
and that fetch can fail — the read then rejects with `NotFoundError` ("The
object cannot be found here") or `NotReadableError`. It shows up on the fourth
or fifth file of a large selection, minutes after picking, because uploads run
one at a time and each file is read only when its turn comes. `readSlice` in
`e2e.js` re-reads the chunk four times, through both `Blob.arrayBuffer()` and
`FileReader` on each pass, re-slicing from the `File` every time and pausing in
between; a read that resolves *short* counts as a failure too, so a truncated
chunk can never be sealed as if it were whole. Only then does the row give up,
and it says what actually happened — that the browser lost access to the file,
and that opening it once in the Files app downloads it to the device — rather
than reporting the browser's words under "Encryption failed".

**The connection drops.** Backgrounding the tab, a Wi-Fi handover, or a proxy
that gives up on a body it is still reading (502/503/504) all end the same way.
The upload retries itself twice, spaced out, and does **not** encrypt again: the
ciphertext is already in hand, and re-reading the `File` is precisely the step
that fails. Only after that does the row show the failure and a Retry button.

Encryption also hands its ciphertext to the blob store every 4 MiB instead of
holding the whole file in the JS heap and copying it at the end. That copy
needed twice the file in memory at one moment, which is where a tablet quietly
kills the tab — and a killed tab looks, from the outside, exactly like the
connection being cut.

### Download, end to end

```
  recipient                                                    server
     │  GET /b/{id}      the #fragment stays in the browser     │
     │ ────────────────────────────────────────────────────────▶│
     │ ◀────────────────────────────────────────────────────────│  page ‖ sealed roster ‖ rows
     │                                                          │
     │  ① derive the same three keys from the fragment          │
     │  ② open every enc_name → names, types, icons             │  ← no ciphertext
     │  ③ open the roster, check the listing against it         │     fetched, and no
     │                                                          │     download counted
     │  ④ GET /b/{id}/f/{fid}/raw    (per file, on demand)      │
     │ ────────────────────────────────────────────────────────▶│  one download counted
     │ ◀────────────────────────────────────────────────────────│  ciphertext
     │  ⑤ unwrap the file key under the batch key               │
     │  ⑥ check the embedded header against the manifest        │
     │  ⑦ decrypt chunks, manifest as AAD                       │
     ▼                                                          │
  plaintext, in the tab, never anywhere else                    │
```

Steps ② and ③ are the reason names are sealed separately from the files they
belong to: a recipient sees the complete, verified listing before deciding to
spend a single download.

### Password shares: what the server is told

For a password share the password itself is never transmitted. The `auth` branch
produces a token; the server stores `SHA-256(token)` and compares. Knowing that
verifier yields neither the token nor — because the branches are independent —
the `enc` key, so a stolen database is useless for decryption.

Unlocking is rate-limited per IP and share, and the counters live in Postgres
rather than process memory, so they survive a restart and are shared across
replicas.

### What the server can still see

Everything about the *content* is sealed. What is left is what being the server
shows you anyway, and no amount of encryption at rest removes it:

| The server never learns | The server always knows |
|---|---|
| The file's bytes | Its exact size in bytes |
| Its name | When it was uploaded |
| Its MIME type | Which account uploaded it |
| Even the *length* of its name | Which files share one link |
| Whether two uploads are the same file — each gets its own random key, so no two ciphertexts match | The expiry and download limit it is enforcing, and how many downloads are spent |

Those right-hand facts are properties of the transaction rather than of the
file: a server that could not see them could not enforce an expiry, count a
download, or bill a quota. A 7.8 MB object with no name and no type is still
visibly a photograph-sized thing, and this design does not pretend otherwise.
Hiding size would mean padding the ciphertext — storing and transferring bytes
nobody wants — and that trade is not made here.

What sealing costs the owner: **My files** cannot read its own names or types
either, having no link and so no key. The uploading browser remembers both
locally for its own lists; every other page shows a generic icon, the size, the
date and a placeholder. See [Known limits](#known-limits).

Uploads that are not end-to-end encrypted are **rejected** (HTTP 400). There is
no server-side encryption path to fall back to, and no code left that could
decrypt a stored file.

### The container is versioned — and the version is the point

`files.e2e_version` and `batches.e2e_version` record which container a share
was written with. This exists so a future change to the framing or to a KDF
label cannot silently strand live shares again: old rows keep their version and
keep decrypting through the routine that produced them. `web/static/e2e.js`
holds the labels in a table indexed by version for exactly that reason.

Five versions exist, and each one took something away from the server:

| | Framing on disk | Manifest carries | The server can read |
|---|---|---|---|
| **1** | bare chunks | *(no manifest)* | name, type |
| **2** | bare chunks | size, geometry, **name**, **type** | name, type |
| **3** | `PYX3 ‖ len ‖ manifest ‖ chunks…` | size, geometry, **name**, **type** | name, type |
| **4** | `PYX4 ‖ len ‖ manifest ‖ chunks…` | size, geometry, **type** | type |
| **5** | `PYX5 ‖ len ‖ manifest ‖ chunks…` | size, geometry | **nothing about the content** |

```
   what the manifest carried, version by version
   ┌───────────────────────────────────────────────────────────┐
 2 │ size · chunks · chunk · id · batch │ name │ type          │  ← both in the clear
   ├───────────────────────────────────────────────────────────┤
 3 │ size · chunks · chunk · id · batch │ name │ type          │  ← now inside the object too
   ├───────────────────────────────────────────────────────────┤
 4 │ size · chunks · chunk · id · batch │      │ type          │  name ──▶ sealed blob
   ├───────────────────────────────────────────────────────────┤
 5 │ size · chunks · chunk · id · batch │      │               │  type ──▶ sealed blob
   └───────────────────────────────────────────────────────────┘
     everything left is derivable from the ciphertext's own length
```

Only version 5 may be **written**. Everything earlier is still **read**, for as
long as those shares live — but accepting one more version 4 upload would mean
one more file the server can describe, so a browser holding a cached `e2e.js`
is told to reload rather than indulged.

**Version 1** sealed the chunks and nothing else. Each chunk authenticated
itself and said nothing about the file it belonged to — no plaintext length, no
chunk count, no name, no type. "Every chunk is authenticated" sounds complete,
and is not:

- whole trailing chunks could be dropped and everything left still verified, so
  a file could be truncated at a 64 KiB boundary without a single GCM failure;
- a blob replaced with **zero bytes** decrypted to zero chunks — a valid empty
  file, because there was nothing left to check;
- the name, size and type shown to the recipient came from database columns
  that nothing tied to the ciphertext.

**Version 2** keeps the chunk layout byte for byte and adds a **manifest**:

```json
{"v":2,"id":"<32 random bytes, base64url>","batch":"<uuid or empty>",
 "size":197842,"chunks":4,"chunk":65536,"name":"report.pdf","type":"application/pdf"}
```

Those bytes are passed to AES-GCM as **additional authenticated data for every
chunk**. Truncation now fails (the count is authenticated), an empty blob fails
(there is always at least one chunk, whose only content is the tag over the
manifest), substitution fails, and moving a file into a different batch fails.
Renaming failed too, while the name was still in there — from version 4 that job
belongs to the sealed name blob, whose AAD is this manifest's id. On a
pre-version-4 share the landing page shows the server's copy of the name until
decryption succeeds, then replaces it with the manifest's and says so if the two
disagree.

**Version 3** puts that manifest *inside* the stored object:

```
"PYX3" || uint16be manifestLength || manifest || chunk 0 || chunk 1 …
```

Version 2 got the integrity right but left the blob mute: the manifest lived
only in a database column beside it, so the bytes on disk carried no magic, no
version and no self-description. Anything reading them without the database — a
backup, a copy, a future format migration, a person working out what a file is —
had no way to tell what it was holding. That is not a break; it is a format that
cannot explain itself.

The header needs no MAC of its own. Alter the length and a different slice is
read as the manifest, so the AAD changes and every chunk fails; alter the
manifest and the same happens; alter the magic and it is refused outright. The
database column survives as a convenience for listings that must not fetch whole
blobs, and the reader checks it against the embedded copy — a server that sends
a different one is caught, not obeyed. On upload the server checks the same
thing in reverse, so the row and the file can never describe different things.

**Version 4** keeps that framing — `"PYX4"` and the same header — and takes the
**name out of the manifest**:

```
{"v":4,"id":"<32 random bytes, base64url>","batch":"<uuid or empty>",
 "size":197842,"chunks":4,"chunk":65536,"type":"application/pdf"}
```

The manifest is stored and served in the clear; it has to be, since it is the
AAD. So every name in one was a name the server could read — in the `manifest`
column, and in the object's own header — whatever the `original_name` column
said. From version 4 the name is sealed separately (see
[Sealed names and types](#sealed-names-and-types)), `original_name` stays NULL,
and what still binds the
name to this exact file is the manifest id, which is the sealed blob's AAD.

**Version 5** does the same to the type, leaving a manifest that describes only
what the ciphertext's own length already gives away:

```
{"v":5,"id":"<32 random bytes, base64url>","batch":"<uuid or empty>",
 "size":197842,"chunks":4,"chunk":65536}
```

Both the name and the type now live in the sealed blob, and `content_type` joins
`original_name` at NULL. The icon and the preview decision move to the browser
with them, since the server no longer has the input either one needs.

Version confusion fails closed in both directions and needs no separate check:
the chunks of a version 2 or later file are sealed against their manifest, so
reading one as version 1 fails, and reading a version 1 file as any of the
others fails too.

The manifest is authenticated **as bytes**. The server stores exactly what the
browser produced and returns it verbatim; re-serialising it — even into
equivalent JSON — would make the file permanently undecryptable. The server
still parses it, but only to *reject* one that contradicts the upload it
arrived with (wrong size, wrong chunk count, a batch it does not belong to, or a
version that disagrees with the request).

### The batch roster

Per-file manifests protect each file. They say nothing about *which* files a
link resolves to — that is the server's answer, and on its own it is
unverifiable: a member can be withheld, or one from elsewhere spliced in, and
every remaining file still decrypts perfectly.

So the uploader seals a **roster** — the member list, with each entry's id,
name, size, type and manifest digest — under the `roster` HKDF branch of the
batch secret, with the batch id as AAD so it cannot be replayed onto another
batch. It is re-sealed after every file, carrying a sequence number the server
will not let go backwards, so the link is verifiable while an upload session is
still running.

```
  batches.roster
  ┌────────────┬──────────────────────────────────────────────┬──────────┐
  │ nonce 12 B │ AES-GCM(roster key, the member list as JSON)  │ tag 16 B │
  └────────────┴──────────────────────┬───────────────────────┴──────────┘
                                      │
        ┌─────────────────────────────┘
        ▼
  {"v":5,"batch":"<uuid>","seq":3,"files":[
     {"id":…, "name":"invoice.pdf", "size":197842,
      "type":"application/pdf", "manifest":"<sha256 of its manifest>"},
     …                                        ▲
  ]}                                          │
                                    ties each entry to one exact file
  AAD = "pyxis-roster-v2|" ‖ the batch id  →  and the list to one exact batch

           what the server is asked                what the roster says
           ┌──────────────────────┐                ┌──────────────────────┐
           │ A  B  C              │  ── compare ─▶ │ A  B  C              │  ✓ agrees
           │ A  B                 │                │ A  B  C              │  ✗ C is missing
           │ A  B  C  X           │                │ A  B  C              │  ✗ X unvouched
           │ C  A  B              │                │ A  B  C              │  ✗ reordered
           └──────────────────────┘                └──────────────────────┘
```

The download page checks the listing it was served against the roster and
**reports** what it finds rather than repairing it:

- a member the roster does not vouch for is badged *unverified* and left out of
  "Download all" — it stays individually downloadable, because its own bytes are
  still authenticated;
- a member the roster names and the server did not offer is listed as missing;
- a listing whose **order** differs from the sealed one is reported and put back
  into the sender's order. Order is part of what was sealed: it decides the
  sequence of entries in a "Download all" archive and the order a recipient
  reads them in, and matching only the *set* of members would leave the server
  free to rearrange them.

Both have innocent explanations (the owner deleted a file; a member was uploaded
seconds ago and its roster update has not landed) and neither can be told apart
from tampering in the browser, so both are stated plainly.

### The application KEK

`FILE_ENCRYPTION_KEY` still exists, but it no longer touches uploaded files. It
protects short secrets in the `settings` table — principally the OIDC client
secret. **Losing it does not lose any file**, because the server could not read
those files with it anyway.

### Fail-closed

If WebCrypto is unavailable — which is precisely the case on a plain-HTTP
origin — the upload is **refused**. It does not fall back to sending the
plaintext file and password to the server. The download side fails closed the
same way.

### The threat model, stated plainly

```
   ┌────────────────────────────────────────────────────────────────────┐
   │ DEFENDED                                                           │
   │                                                                    │
   │  stolen disk · leaked backup · a copied database · an operator     │
   │  reading the filesystem · a subpoena of stored data                │
   │      → ciphertext, sealed names, opaque wrapped keys. Nothing to    │
   │        read, and no key on the machine that could change that.     │
   │                                                                    │
   │  a server that edits what it stores — rewriting a blob, dropping   │
   │  a member, swapping a name, reordering a listing                   │
   │      → the manifest and the roster make it fail, or say so.        │
   ├────────────────────────────────────────────────────────────────────┤
   │ NOT DEFENDED                                                       │
   │                                                                    │
   │  an actively hostile server, because it ships the JavaScript       │
   │  that does the crypto: a modified e2e.js could exfiltrate keys     │
   │  or skip the checks entirely.                                      │
   │      → inherent to browser-delivered E2E. More client-side crypto  │
   │        cannot fix it; only reproducible delivery could.            │
   │                                                                    │
   │  anyone who obtains the link. For a URL-key share the link IS      │
   │  the key.                                                          │
   │      → treat it as the secret it is.                               │
   └────────────────────────────────────────────────────────────────────┘
```

The first block is the ordinary case — a self-hosted box, its backups, and
whoever can reach them — and it is where this design does real work. The second
is the honest boundary of browser-delivered end-to-end encryption, and no scheme
shipped this way can move it.

## Batch shares

Every file uploaded during one visit lands under a single link, `/b/{id}#{secret}`.

The batch is created lazily with the first file, so the share options in the form
still apply, and is frozen afterwards. Expiry, password and download limit live on
the batch row, so editing them later would silently redefine a link that may already
have been sent to someone. **Start a new link** begins a fresh batch.

### Keys

The batch link carries one secret, and every member has a random key of its own
wrapped under it — drawn out in [How a batch is keyed](#how-a-batch-is-keyed).

```
batch key   = HKDF(fragment secret, "", "pyxis-e2e-batch-v1")
              (or the PBKDF2/HKDF enc branch, for a password batch)
wrapped_key = 12-byte nonce || AES-GCM(batch key, file key)   — 60 bytes
```

### The ZIP is built in the browser

The server holds ciphertext and no keys, so it *cannot* zip a batch. `web/static/zip.js`
is a small ZIP writer that decrypts members one at a time and assembles the archive
locally. It is STORE-only — batch payloads are usually already-compressed media, and
DEFLATE would double peak memory for very little gain — and has no ZIP64 support, so
it refuses past 4 GiB rather than emitting an archive that unpacks to garbage.

### Enforcement

A batch member is reachable **only** through its batch. `/files/{id}/raw` returns
404 for anything with a `batch_id`, and `/files/{id}` redirects to the batch —
otherwise a member's UUID would serve its bytes with the batch's password, expiry
and limit all bypassed.

In **My files** the members of a batch are listed under one group header rather
than as separate rows: they share a link, an expiry and a download counter, so
repeating those on every row would state the same terms five times over — and,
worse, imply five links. The header carries them, along with the copy/QR/open
buttons; the rows below it keep only what is theirs, their name, size and their
own delete button. A batch that only ever held one file stays a plain row, since
there is nothing to fold. Groups start expanded and can be folded individually or
all at once; a filter query reaches into folded groups and opens the ones that
match, and the folds you chose come back when the query is cleared.

Two consequences worth knowing:

- **The download limit counts file downloads, not link opens.** A "download all"
  over five members spends five slots, because five blobs leave the server. That is
  the only thing enforceable when the ZIP is assembled client-side. The UI says so.
- **A password batch withholds its entire listing until unlock** — no names, no
  sizes, not even the file count. A bare link leaks nothing.

---

## Running it

### Guided installer

`install.py` is a console wizard (curses, Python 3.8+, standard library only)
that takes a bare host to a running instance. It checks for a usable Docker and
helps install one, asks whether the site sits behind Traefik, another reverse
proxy or nothing at all, collects the domain, an optional custom port and the
first administrator, generates the secrets, writes a `.env` and a
`docker-compose.yml` matched to those answers, and then builds, starts and
health-checks the stack.

```bash
sudo ./install.py
```

Root matters: the install directory, the blob directory's ownership (uid 10001)
and the Docker socket all need it. Nothing is written or executed before the
review screen — every earlier step only collects answers.

| Flag | Effect |
|---|---|
| `--dry-run` | ask everything, then print the files instead of writing them |
| `--install-dir DIR` | somewhere other than `/srv/docker/pyxis` |
| `--answers FILE` | pre-fill the wizard from a previous run |
| `--non-interactive --answers FILE` | replay a saved answer file without the wizard |

It writes `.env` (0600), `docker-compose.yml`, `INSTALL-NOTES.md`,
`installer-answers.json` (0600) and `data/{files,postgres}` into the install
directory, keeping a timestamped backup of anything it replaces. For the
reverse-proxy layout it also writes a ready nginx, Caddy or Apache site file —
with the body-size limit and the streaming settings large uploads need — but it
never edits your proxy's configuration itself. Optionally it installs Traefik,
and a nightly `pg_dump` cron entry.

### Docker Compose (recommended)

```bash
cp .env.example .env
openssl rand -hex 32          # put the result in FILE_ENCRYPTION_KEY
$EDITOR .env                  # set POSTGRES_PASSWORD and ADMIN_PASSWORD too
docker compose up -d --build
```

The app listens on `${APP_PORT:-8080}`. `deploy/docker-compose.yml` is the
production variant: no published port, Traefik labels for TLS termination, an
external `proxy` network and absolute host paths under `/srv/docker/pyxis/`.
Its build context is `..` — a relative build path in Compose resolves against
the *compose file's* directory, not your shell's, so it has to point back at the
repository root where the Dockerfile is. It also requires `FILE_ENCRYPTION_KEY`
and `TRUSTED_PROXY_CIDRS` rather than defaulting them to empty: both are silent
when wrong, and this stack always sits behind a proxy.

Data lives in two bind mounts:

```
data/files/      encrypted blobs
data/postgres/   database
```

The container runs as uid 10001 with all capabilities dropped, so `data/files`
must be owned by 10001 on the host.

### Without Docker

Needs Go 1.27 and a reachable PostgreSQL 16:

```bash
export DATABASE_URL="postgres://pyxis:secret@localhost:5432/pyxis?sslmode=disable"
export FILE_ENCRYPTION_KEY="$(openssl rand -hex 32)"
export FILES_DIR="$PWD/data/files"
export COOKIE_SECURE=false      # only when serving over plain HTTP locally
export ADMIN_USERNAME=admin ADMIN_PASSWORD=changeme
mkdir -p "$FILES_DIR"
go run .
```

Schema migrations run automatically at startup. See
[Upgrading](#upgrading) for what that actually does and how to roll back.

### First login

On first start, if no user named `ADMIN_USERNAME` exists, one is created and
promoted to super-admin. If the user already exists, **the password is not reset** —
so a stale `ADMIN_PASSWORD` in `.env` will not match the live account.

---

## Configuration

Every setting is an environment variable. Only `DATABASE_URL` and
`FILE_ENCRYPTION_KEY` are required.

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | — | **Required.** PostgreSQL DSN. |
| `FILE_ENCRYPTION_KEY` | — | **Required.** 32-byte hex KEK protecting settings secrets (not files). |
| `FILE_ENCRYPTION_KEY_FILE` | — | Read the KEK from a file instead (Docker secrets). |
| `ALLOW_UNENCRYPTED_SECRETS` | `false` | Start without a KEK; settings secrets stored in plaintext. Development only. |
| `FILES_DIR` | `/data/files` | Blob storage directory. |
| `LISTEN_ADDR` | `:8080` | Bind address. |
| `COOKIE_SECURE` | `true` | Set `false` only for local plain-HTTP work. |
| `MAX_UPLOAD_BYTES` | `536870912` | *Initial* per-file ceiling (512 MiB). Admin-editable afterwards. |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | — | First-run super-admin bootstrap. |
| `OIDC_ISSUER` | — | Enables SSO. Also configurable in `/admin/settings`. |
| `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | — | OIDC client credentials. |
| `OIDC_REDIRECT_URL` | — | Must match the provider byte for byte. |
| `OIDC_ALLOWED_DOMAIN` | — | Restrict SSO to one email/identity domain. |
| `TRUSTED_PROXY_CIDRS` | — | Only these sources' `X-Forwarded-For` is believed. |
| `QUOTA_USER_BYTES` | `21474836480` | *Initial* default per user (20 GiB). `0` = unlimited. |
| `QUOTA_USER_FILES` | `1000` | *Initial* default active files per user. |
| `QUOTA_TOTAL_BYTES` | `0` | Instance-wide ceiling. `0` = unlimited. |
| `DISK_MIN_FREE_BYTES` | `1073741824` | Refuse uploads below this free space. |

`TRUSTED_PROXY_CIDRS` matters in **both** directions, which is why it has no
safe default:

- Set too widely, a forged `X-Forwarded-For` lets an attacker evade the limiter
  by inventing a new client address per attempt.
- Left empty behind a reverse proxy, every visitor keys to the proxy's address:
  the login and share-password limits then apply to the whole instance at once,
  so one person guessing a share password locks out everybody.

Leave it empty only when clients reach the app directly. The app logs its
choice at startup and warns once if a forwarding header arrives from a peer it
does not trust — that combination is the signature of the second mistake.
`deploy/docker-compose.yml` refuses to start without it.

Rate limiting is 10 failures per 10 minutes per (source, account) and per
(source, share), plus 30 failed logins per 10 minutes from any one source
across all usernames — that last one bounds how much password hashing a single
address can make the server do. Counters live in the `auth_failures` table as
well as in process memory, so they survive a restart and are shared by every
replica; a database error opens only the shared half, leaving the local counter
in force.

---

## Routes

**Public (no session)**

| Route | Purpose |
|---|---|
| `GET /b/{id}` | Batch landing page |
| `GET /b/{id}/manifest` | Member list + wrapped keys (JSON) |
| `POST /b/{id}/unlock` | Submit the derived auth token for a password batch |
| `GET /b/{id}/f/{fileID}/raw` | One member's ciphertext; counts one download |
| `GET /files/{id}` | Single-file landing page |
| `GET /files/{id}/raw` | Ciphertext for a single-file share; counts one download |
| `GET /healthz` | Health check |

**Authenticated**

| Route | Purpose |
|---|---|
| `GET /` | Upload page |
| `POST /batches` | Open a batch, returns its id |
| `POST /batches/{id}/roster` | Store the sealed member list (owner only, monotonic `seq`) |
| `POST /upload` | Upload one file, optionally into a batch |
| `GET /usage` | The storage bars, re-rendered as an HTML fragment (see below) |
| `GET /history` | Your own uploads — an admin's own, too |
| `GET /admin/files` | Every account's uploads. Admin only |
| `POST /delete/{id}` | Delete a file |
| `POST /delete` | Delete the files named by repeated `id` fields (the list's multi-select) |
| `GET /account`, `POST /account/password` | Self-service account |
| `/admin/users`, `/admin/settings` | Admin only |
| `POST /admin/settings/upload` | Instance-wide per-file upload limit. Admin only |
| `POST /admin/users/{id}/quota` | One user's storage allowance and upload limit. Admin only |

`GET /healthz` also reports the schema version, and fails with 503 when the
database is on a different one than the binary expects — a half-finished upgrade
should take an instance out of the load balancer, not serve from it.

`GET /usage` is the one route that answers with markup rather than a page or
JSON: it renders the shell's `storagebars` template on its own. The upload page
swaps it into the shell after a file lands, so "Your storage" and "Disk usage"
move as files arrive instead of waiting for a navigation that, on the upload
page, never comes. Answering with the same template the page uses is the point —
the quota arithmetic, `humanSize`, the warning thresholds and the admin-only
rule stay where they already are, and the refreshed bars are byte for byte what
a reload would have drawn.

There is no API for uploading plaintext. A client must encrypt in the browser
container format and POST the ciphertext with `e2e=1`, `e2e_version=5`, a
`manifest` that names neither the file nor its type, and a padded sealed
`enc_name`. Anything else is rejected, earlier container versions included: they
still *read*, for as long as their shares live, but accepting one more of them
as a write would mean one more file the server can describe.
`web/static/e2e.js` is the reference implementation, and `chunkformat_test.go`
mirrors it in Go.

---

## Development

No build step for the frontend. `web/` is embedded into the binary with `go:embed`;
templates and static assets are plain files.

```
main.go              wiring, routes, middleware, env
handlers.go          upload, single-file shares, history
handlers_batch.go    batch creation, landing, manifest, gated raw access
handlers_users.go    admin user management
handlers_settings.go OIDC settings
auth.go              sessions, password auth, guards
oidc.go              OIDC login
crypto.go            container geometry, settings-secret encryption
storage.go           quotas, reservations, finalisation
sweeper.go           expiry, archiving, purging
db.go                schema and migrations
i18n.go              EN/DE catalogue
theme.go             theme cookie
web/templates/       html/template pages
web/static/          app.js, e2e.js, zip.js, qrlib.js, style.css
.github/workflows/   CI: vet, gofmt, race tests against PostgreSQL,
                     govulncheck, container build, secret scan
```

**Narrow screens.** The breakpoints are 900px (the shell goes narrow: the
sidebar collapses, and the users table becomes one card per account), 680px and
560px. The users table is the one place where the layout changes shape rather
than reflowing: seven columns and a row of buttons cannot be squeezed, and
scrolled sideways the buttons are what falls off the screen. Each `<td>` there
carries its column name in `data-label`, which the card layout renders above
the value — a cell that loses the attribute shows a bare value under no heading,
and only on a phone, so `TestUserRowsCarryTheirColumnNames` checks for them.

Two rules the codebase enforces and that are easy to break:

1. **No inline `<script>` or `style=` in templates.** The CSP forbids both. i18n
   strings reach JavaScript through a `<meta data-json>` attribute, not an inline
   script block.
2. **Never pass a `*int` or `*time.Time` to a template formatting verb.** It
   prints the pointer address. Dereference into a plain field first — this has
   bitten twice.

---

## Testing

```bash
go test ./...

# The tests that matter most are the ones written in SQL. Give them a database:
export TEST_DATABASE_URL="postgres://pyxis:pyxis@localhost:5432/pyxis_test?sslmode=disable"
go test -race ./...
```

Everything below runs in CI on every push and pull request
(`.github/workflows/ci.yml`), together with `go vet`, a `gofmt` check,
`govulncheck ./...`, a container build, a `docker compose config` check of both
compose files, and a secret scan. `govulncheck` also runs weekly, because
advisories land without anyone pushing.

- `chunkformat_test.go` — a Go reference implementation of the container
  format, both versions. Nothing in the shipped binary encrypts or decrypts a
  file, so this lives in test scope purely as an oracle.
- `crypto_test.go` — the container round-trip including seekable reads, plus
  password hashing (Argon2id, and that a bcrypt hash is now rejected outright),
  session-token hashing, the step-up window and the HSTS gate.
- `e2e_interop_test.go` — **byte-exact vectors** proving Go and browser
  WebCrypto produce identical ciphertext, for version 1 and version 3, plus the
  negative cases the manifest exists for: truncation, an emptied blob, a renamed
  or retyped or resized manifest, a file moved to another batch, a corrupted
  header magic or length, and a stored metadata column that disagrees with the
  embedded copy. Also pins the container geometry of all three versions.
  Regenerate these if the chunk size, nonce layout, header, AAD handling or any
  HKDF info string ever changes — load `web/static/e2e.js` in Node
  (`globalThis.window = globalThis`) and re-run the fixtures.
- `migrations_db_test.go` — needs `TEST_DATABASE_URL`. Migrations are recorded
  and idempotent, sessions are stored hashed, usernames are case-unique *in the
  database*, OIDC identities are scoped to their issuer (including the one-time
  adoption of pre-issuer rows), and the rate limiter counts across replicas.
- `quota_db_test.go` — needs `TEST_DATABASE_URL`. The quota rules decided in SQL.
- `templates_test.go` — renders every template in both languages, checks
  translation completeness, verifies `e2e.js` is actually loaded (a missing script
  tag once broke every upload while all other tests passed), and that no
  `jsStrings` key silently falls back to its own name.

The browser modules in `web/static/` load cleanly in Node
(`globalThis.window = globalThis`, then evaluate the file), which is how the
interop vectors are produced — client and server are tested against each other
rather than against assumptions.

---

## Operational notes

**Renamed from k-fileshare.** The rename was deliberately total and includes the
cryptographic namespace, so it is a **breaking change**, not cosmetic:

- HKDF info strings moved from `k-fileshare-e2e-*` to `pyxis-e2e-*`. Every key is
  derived differently, so **share links created before the rename can no longer
  be decrypted**. The ciphertext is intact and the failure is clean — GCM
  authentication fails and the page reports a decryption error — but the files
  are gone for practical purposes. `e2e_interop_test.go` carries regenerated
  vectors.
- Cookies moved from `fileshare_*` to `pyxis_*`, and the unlock cookie prefixes
  from `fsu_`/`fsb_` to `pxu_`/`pxb_`. Everyone is signed out once, and any
  in-flight share unlocks must be redone.
- Containers, the database, its role and the deploy directory are all `pyxis`.

### Upgrading

Schema changes are **numbered and recorded**, in `db.go`, applied one
transaction each under an advisory lock so two containers starting at once
cannot race. `schema_migrations` says where a database stands, and `/healthz`
refuses while the binary and the database disagree.

Migration 1 is the historical baseline — the single idempotent script this
replaced. It contains `DROP COLUMN IF EXISTS` statements from the removal of
the server-side key modes; they are a no-op on any database that has already
been through them, and they are the reason the old "migrations are additive"
claim was wrong. Anything added from here is append-only: a migration that has
shipped is immutable, and correcting one means adding another.

**Before upgrading:**

```bash
docker compose exec -T db pg_dump -U pyxis pyxis | gzip > pre-upgrade.sql.gz
```

**Rolling back** means restoring that dump: the previous binary does not know
the new columns, and there are no down-migrations. Nothing is lost by doing so
except whatever was uploaded since — the blobs in `data/files` are untouched by
any migration.

Two migrations do more than add columns, and are worth knowing about:

- **2 (`hash_session_tokens`)** rewrites `sessions.id` in place to
  `SHA-256(token)`. Nobody is signed out; the cookies people already hold keep
  working, because they hash to what is now stored.
- **4 (`username_case_insensitive_unique`)** fails, with the offending names in
  the message, if usernames that differ only in case already exist. Rename them
  by hand and start the container again.

**Backups.** Back up `data/postgres` and `data/files`. Neither contains
anything the server can decrypt, so a backup leaks no file contents — but it is
also unrecoverable without the share links, which live only with recipients.
`FILE_ENCRYPTION_KEY` matters only for the OIDC client secret in `settings`.

**Lifecycle.** A link that expires or exhausts its downloads is archived
immediately: the blob is deleted, the metadata row survives 30 days listed as
"expired", then is purged. Archived rows do not count against quotas. Batches
follow the same two stages; purging a batch cascades its member rows.

**Quotas** resolve in three layers. The allowance applied to an upload is the
override on the user's row when set, otherwise the instance default from
`/admin/settings`; `QUOTA_USER_BYTES` / `QUOTA_USER_FILES` are only the fallback
used until an admin saves that default for the first time, after which the
database wins and the environment variables stop mattering.

Two nulls are load-bearing. `users.quota_bytes IS NULL` means "inherit the
default"; a stored `0` means "unlimited for this user", which is how you lift
one person above a restrictive default without editing the default. Admins are
exempt from the default — as they always have been — but an override set on an
admin does apply, because an admin who types a limit into another admin's row
means it.

**The per-file upload limit** resolves the same way — the override on the
user's row when set, otherwise the instance default from `/admin/settings`,
with `MAX_UPLOAD_BYTES` as the fallback until that default is first saved — but
it differs from a quota in two deliberate ways.

It is never zero: a quota of `0` means "unlimited", while an upload ceiling of
`0` would refuse every file, so the forms reject it and a stored `0` falls back
to the default rather than becoming limitless. And admins are **not** exempt.
A quota bounds what an account accumulates over time; this bounds one request —
the browser encrypts the whole file before sending, the server holds it while it
arrives, and the reservation is booked from this number before a byte is
written. An admin who needs to send something larger raises the instance limit
or gives themselves an override; both are two clicks away, and both leave a
trace in the log, which "the rule quietly did not apply to me" does not.

The limit reaches the browser as well: the upload page carries the signed-in
user's own ceiling, so a file over it is refused before it is encrypted rather
than after minutes of work and a full upload.

Raising it above what the reverse proxy in front of the app allows does not
work — the proxy answers first, and the app never sees the request. Check the
proxy's own body-size and read-timeout settings when you raise this limit
substantially.

The page shell shows each user a bar for their own quota, drawn only when
something actually caps them, so an exempt admin sees none. The disk-usage bar
beside it is admin-only: free space on the volume is instance capacity a member
cannot act on, and it says more about the host than they need. That summary
query runs on every render for a signed-in user, which is what
`files_uploaded_by_idx` is for.

Enforcement uses an advisory-locked `upload_reservations` table — reserve,
stream, finalise — so concurrent uploads cannot race past the limit, and the
override is read inside that transaction, so a quota change takes effect on the
next upload rather than at the user's next sign-in. Abandoned reservations
expire after 15 minutes.

**Accounts and sessions.**

- Local passwords are hashed with **Argon2id** (19 MiB, t=2, p=1 — OWASP's
  first recommended configuration; the heavier m=64MiB/p=4 variant would let
  the public login form allocate that much per attempt). Minimum length is 12.
  Argon2id is the only scheme: earlier versions wrote bcrypt and kept a
  verifier so accounts could be upgraded on their next sign-in, and once every
  stored hash had been migrated that verifier was removed. Restoring a dump
  taken before the migration therefore leaves those accounts unable to log in —
  an admin has to reset their passwords.
- The session cookie is a bearer token, and only its **SHA-256** is stored. A
  leaked `sessions` row proves a session exists; it cannot be replayed as one.
  A plain hash is right here — the token is 32 bytes of CSPRNG output, so there
  is no low-entropy guess to slow down.
- Sessions are revoked on password and privilege changes.
- An **SSO-only account must re-authenticate with the provider** before it can
  set a first local password. That password would outlive the provider's
  control of the account, so a stolen session cookie must not be enough to
  create one. The flow asks for `prompt=login` and `max_age=0` and checks
  `auth_time`; the resulting step-up is good for 10 minutes and is spent by the
  change it authorises. Changing an *existing* password is unaffected — it is
  gated on that password instead.
- OIDC accounts are keyed on **(issuer, subject)**, never the subject alone.
  OpenID Connect only guarantees uniqueness for the pair. Repointing the
  instance at a different provider therefore does not hand existing accounts to
  whoever holds the same subject there; they become unreachable instead, and the
  settings page logs how many are affected. Accounts created before the issuer
  was recorded are adopted, once, by the configured issuer.

**HTTP.** HSTS (one year, `includeSubDomains`, no `preload`) is sent by the
application whenever `COOKIE_SECURE` is on — it belongs with the code that
assumes HTTPS, not only in a proxy config that can be replaced. The server sets
an explicit `ReadHeaderTimeout`, `IdleTimeout` and `MaxHeaderBytes`, and
shuts down gracefully on SIGINT/SIGTERM with 30 seconds for in-flight
transfers. There is deliberately **no `WriteTimeout`**: Go measures it from the
request headers, so it would cap the total duration of a large upload or
download rather than bounding idleness.

---

## Known limits

- **A lost link is a lost file.** There is no recovery path, no administrator
  override, no reset. This is the point of the design, but it does mean support
  requests have exactly one answer.
- **Batch options are fixed** once the first file lands. Changing expiry or
  password means starting a new link.
- **ZIP is STORE-only and capped at 4 GiB.** No compression, no ZIP64. Large
  batches must be downloaded file by file.
- **Zipping a batch is memory-bound in the browser.** Members are decrypted one
  at a time and handed to the Blob constructor by reference so the browser can
  spill to disk, but a very large batch on a phone may still struggle.
- **No "delete batch" action.** Deletion is per-file; removing a member leaves
  the rest of the batch intact.
- **Batch members have no standalone page**, so they get no per-file preview URL —
  previews happen inside the batch page after client-side decryption.
- **No plaintext upload path at all.** Scripted clients must implement the
  browser container format; there is no server-side encryption to fall back on.
  This is deliberate, but it makes `curl` uploads considerably more work.
- **A file that never comes down from iCloud cannot be uploaded.** The retries
  above cover a slow or flaky fetch, not a device that will not produce the
  bytes at all. The only fix is on the device: open the file once so it is
  stored locally, then add it again.
- **A browser without WebCrypto cannot use this app**, for upload or download.
  In practice that means it requires HTTPS.
- **Version 1 shares keep the version 1 guarantee.** They cannot be upgraded in
  place — that would need the key — so until they expire their length and name
  stay unauthenticated. The landing page says so rather than implying otherwise.
- **Shares created before container version 5 keep server-readable metadata** —
  a name before version 4, a MIME type before version 5. Their manifests carry
  it, and a manifest is the AAD of every chunk — rewriting one destroys the file
  — so it cannot be sealed after the fact. It leaves with the share, at its
  expiry plus the 30-day retirement.
- **A file list cannot show a sealed name.** The name is encrypted under the key
  in the share link, and no page that isn't the link has that key. The browser
  that uploaded a file keeps the name in `localStorage` for its own lists, which
  is per-device and disappears with site data; anywhere else the row shows the
  icon, size, date and "Encrypted file name". Filtering matches only what the
  page can actually read.
- **Size, timing and shape are not hidden, and cannot be.** The server records
  the exact byte size, when the upload happened, which account did it, which
  files share a link, and the expiry and download limit it enforces. A 7.8 MB
  file with no name and no type is still visibly a photograph-sized thing.
  Padding the ciphertext itself would fix the size; it would also mean storing
  and transferring bytes nobody wants, and it is not done.
- **Icons are generic wherever the type cannot be read.** From container version
  5 the server is not told the MIME type, so it cannot pick an icon or decide
  whether to offer a preview; the browser does both, once it has opened the
  sealed blob. A recipient with the link sees the right icon and the preview. A
  file list shows the generic one unless that browser uploaded the file.
- **Version 2 objects are not self-describing.** Their integrity is identical to
  version 3's, but the manifest lives only in the database, so the blob alone
  cannot be interpreted. Version 2 was current for one day and no share was ever
  created with it in production; the reader stays for the sake of anyone who
  did.
- **The roster can be rolled back to an earlier version of itself** by a server
  that keeps an old sealed copy. `seq` only stops replays through the API. The
  effect is bounded: an older roster is a shorter list, so it can make a genuine
  member look unverified, but it cannot make an injected one look verified.
- **A batch member deleted by its owner shows as missing** on the download page
  until a new file is uploaded to that batch and the roster is re-sealed. That
  is the honest reading — the browser cannot distinguish a deletion from a
  withheld file.
