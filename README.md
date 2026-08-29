# k-fileshare

Self-hosted file sharing where **the server cannot read what it stores**.

Files are encrypted in the browser before upload. The server receives ciphertext,
stores ciphertext, and serves ciphertext back; the key never leaves the uploader's
tab except inside the share link's URL fragment, which browsers do not transmit.
Losing the link (or the password) means losing the file — for everyone, administrators
included.

Go + PostgreSQL + vanilla JavaScript. No build step, no framework, no runtime
dependencies beyond the two containers.

---

## Contents

- [Features](#features)
- [How the encryption works](#how-the-encryption-works)
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
- Drag-and-drop upload with per-file progress, transfer rate, cancel and retry.
- Every file uploaded in one visit is collected under **one share link**.
- Recipients download files individually or all at once as a ZIP built in their browser.
- Inline preview for images, video, audio, PDF and text.
- Expiry by preset or an arbitrary date; download limits; optional share password.
- QR code for any link, generated client-side.

**Access**
- Local accounts (bcrypt, database-backed sessions) and OIDC single sign-on,
  which coexist — enabling SSO does not disable password login.
- Admin and super-admin roles; user management and OIDC settings in the UI.

**Operations**
- Per-user and instance-wide storage quotas, plus a free-disk floor.
- A sweeper retires expired and used-up links every minute: the blob is deleted
  at once, the metadata row is kept for 30 days as "expired", then purged.
- Full English and German localisation, dark and light themes.
- Language is detected from the browser's `Accept-Language` header, honouring
  q-values rather than header order, and falls back to English for anything
  unsupported. An explicit choice via the switcher is remembered in a cookie
  and always wins.

---

## How the encryption works

**The server holds no key for any file, in any mode.** There is exactly one
encryption scheme, and it runs entirely in the browser.

Files are encrypted with WebCrypto before anything is sent. Payload format is
**chunked AES-256-GCM**: 64 KiB plaintext chunks, each sealed under a 12-byte
nonce of `4 zero bytes || big-endian uint64 chunk index`. Chunking keeps memory
bounded and makes the ciphertext seekable.

| `key_mode` | Name | Where the key comes from |
|---|---|---|
| `3` | E2E URL | `HKDF(fragment secret, "", "k-fileshare-e2e-url-v1")` |
| `4` | E2E password | `PBKDF2-SHA256(password, salt, 600k)` → HKDF split |

For a **password** share the password itself is never transmitted. PBKDF2
produces a master secret, which HKDF splits down two branches:

- `enc` — the file key. Stays in the browser.
- `auth` — a token sent once. The server stores only `SHA-256(auth)` in
  `auth_verifier` and uses it to gate access to the ciphertext.

Knowing the auth branch cannot yield the encryption branch, so the stored
verifier is useless for decryption even to someone holding the database.

Uploads that are not end-to-end encrypted are **rejected** (HTTP 400). There is
no server-side encryption path to fall back to, and no code left that could
decrypt a stored file.

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

### What this does and does not protect against

It defends against **passive** compromise: a stolen disk, leaked backups, an
operator reading the filesystem, a subpoena of stored data. The bytes on disk
are unreadable without a key that only ever existed in a browser.

It does **not** defend against an actively hostile server, because the server
ships the JavaScript that performs the crypto. A compromised deployment could
serve a modified `e2e.js` that exfiltrates keys. That is inherent to
browser-delivered end-to-end encryption and cannot be fixed with more
client-side crypto.

One practical consequence: for a URL-key share, **the link is the key**. Anyone
who obtains it has the file.

## Batch shares

Every file uploaded during one visit lands under a single link, `/b/{id}#{secret}`.

The batch is created lazily with the first file, so the share options in the form
still apply, and is frozen afterwards. Expiry, password and download limit live on
the batch row, so editing them later would silently redefine a link that may already
have been sent to someone. **Start a new link** begins a fresh batch.

### Keys

The batch link carries one secret. Each member file is encrypted under its **own
random key**, sealed under the batch key and stored as an opaque `wrapped_key`:

```
batch key   = HKDF(fragment secret, "", "k-fileshare-e2e-batch-v1")
              (or the PBKDF2/HKDF enc branch, for a password batch)
wrapped_key = 12-byte nonce || AES-GCM(batch key, file key)   — 60 bytes
```

Wrapping rather than deriving per-file keys buys two things: the browser encrypts
before the server has assigned a file id, so there is nothing stable to derive
from; and members can be added or removed without renumbering anything.

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

Two consequences worth knowing:

- **The download limit counts file downloads, not link opens.** A "download all"
  over five members spends five slots, because five blobs leave the server. That is
  the only thing enforceable when the ZIP is assembled client-side. The UI says so.
- **A password batch withholds its entire listing until unlock** — no names, no
  sizes, not even the file count. A bare link leaks nothing.

---

## Running it

### Docker Compose (recommended)

```bash
cp .env.example .env
openssl rand -hex 32          # put the result in FILE_ENCRYPTION_KEY
$EDITOR .env                  # set POSTGRES_PASSWORD and ADMIN_PASSWORD too
docker compose up -d --build
```

The app listens on `${APP_PORT:-8080}`. `deploy/docker-compose.yml` is the
production variant: no published port, Traefik labels for TLS termination, an
external `proxy` network and absolute host paths under `/srv/docker/fileshare/`.

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
export DATABASE_URL="postgres://fileshare:secret@localhost:5432/fileshare?sslmode=disable"
export FILE_ENCRYPTION_KEY="$(openssl rand -hex 32)"
export FILES_DIR="$PWD/data/files"
export COOKIE_SECURE=false      # only when serving over plain HTTP locally
export ADMIN_USERNAME=admin ADMIN_PASSWORD=changeme
mkdir -p "$FILES_DIR"
go run .
```

Schema migrations run automatically at startup and are additive
(`CREATE TABLE IF NOT EXISTS` / `ADD COLUMN IF NOT EXISTS`), so upgrading is just
deploying the new binary.

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
| `MAX_UPLOAD_BYTES` | `536870912` | Per-file ceiling (512 MiB). |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | — | First-run super-admin bootstrap. |
| `OIDC_ISSUER` | — | Enables SSO. Also configurable in `/admin/settings`. |
| `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | — | OIDC client credentials. |
| `OIDC_REDIRECT_URL` | — | Must match the provider byte for byte. |
| `OIDC_ALLOWED_DOMAIN` | — | Restrict SSO to one email/identity domain. |
| `TRUSTED_PROXY_CIDRS` | — | Only these sources' `X-Forwarded-For` is believed. |
| `QUOTA_USER_BYTES` | `21474836480` | Per non-admin user (20 GiB). `0` = unlimited. |
| `QUOTA_USER_FILES` | `1000` | Active files per non-admin user. |
| `QUOTA_TOTAL_BYTES` | `0` | Instance-wide ceiling. `0` = unlimited. |
| `DISK_MIN_FREE_BYTES` | `1073741824` | Refuse uploads below this free space. |

`TRUSTED_PROXY_CIDRS` matters: rate limiting keys on client IP, and without it a
forged `X-Forwarded-For` would let an attacker evade the limiter. Leave it empty
when clients connect directly.

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
| `POST /upload` | Upload one file, optionally into a batch |
| `GET /history` | Your uploads (admins see all) |
| `POST /delete/{id}` | Delete a file |
| `GET /account`, `POST /account/password` | Self-service account |
| `/admin/users`, `/admin/settings` | Admin only |

There is no API for uploading plaintext. A client must encrypt in the browser
container format and POST the ciphertext with `e2e=1`; anything else is
rejected. `web/static/e2e.js` is the reference implementation, and
`chunkformat_test.go` mirrors it in Go.

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
```

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
```

- `chunkformat_test.go` — a Go reference implementation of the container
  format. Nothing in the shipped binary encrypts or decrypts a file, so this
  lives in test scope purely as an oracle.
- `crypto_test.go` — the container round-trip, including seekable reads.
- `e2e_interop_test.go` — **byte-exact vectors** proving Go and browser WebCrypto
  produce identical ciphertext. Regenerate these if the chunk size, nonce layout
  or any HKDF info string ever changes.
- `templates_test.go` — renders every template in both languages, checks
  translation completeness, verifies `e2e.js` is actually loaded (a missing script
  tag once broke every upload while all other tests passed), and that no
  `jsStrings` key silently falls back to its own name.

For integration work against a real database, point the app at a local PostgreSQL
and drive it over HTTP — the browser modules in `web/static/` load cleanly in Node
(`globalThis.window = globalThis`, then evaluate the file), so client and server
can be tested against each other rather than against assumptions.

---

## Operational notes

**Backups.** Back up `data/postgres` and `data/files`. Neither contains
anything the server can decrypt, so a backup leaks no file contents — but it is
also unrecoverable without the share links, which live only with recipients.
`FILE_ENCRYPTION_KEY` matters only for the OIDC client secret in `settings`.

**Lifecycle.** A link that expires or exhausts its downloads is archived
immediately: the blob is deleted, the metadata row survives 30 days listed as
"expired", then is purged. Archived rows do not count against quotas. Batches
follow the same two stages; purging a batch cascades its member rows.

**Quotas** use an advisory-locked `upload_reservations` table — reserve, stream,
finalise — so concurrent uploads cannot race past the limit. Abandoned
reservations expire after 15 minutes.

**Rate limiting** is 10 failures per 10 minutes on login and on share passwords.

**Sessions** are revoked on password and privilege changes.

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
- **A browser without WebCrypto cannot use this app**, for upload or download.
  In practice that means it requires HTTPS.
