package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Schema changes are NUMBERED and RECORDED, not re-derived from a single
// idempotent script. The previous arrangement executed one blob of
// CREATE/ALTER ... IF NOT EXISTS on every boot, which was described as
// "additive" while actually containing DROP COLUMN statements — so the
// documented upgrade story and the code disagreed, and there was no way to tell
// which version of the schema a database was on.
//
// Rules for anything added below:
//
//   - Append only. A migration that has shipped is immutable; correcting one
//     means adding another. The recorded version is what tells an operator (and
//     the upgrade test) where a database stands.
//   - Every migration runs in its own transaction and is recorded in the same
//     transaction, so a failure leaves the database on the previous version
//     rather than half-applied.
//   - Destructive statements must say so in the migration name and be called
//     out in the README's upgrade section. Migration 1 is the historical
//     baseline and does contain drops; they were part of removing the
//     server-side key modes and are only ever a no-op on a database that has
//     already been through it.
const (
	// migrationLockKey serializes migrations across replicas: two containers
	// starting at once must not both try to create the same index.
	migrationLockKey int64 = 0x70797831 // "pyx1"
)

type migration struct {
	version int
	name    string
	// stmts run in order inside one transaction. Use fn instead when a step
	// needs to inspect the database first.
	stmts []string
	fn    func(context.Context, pgx.Tx) error
}

// baselineSQL is the schema as it stood before numbered migrations existed. It
// is written to be a no-op against a database that already has it, so an
// upgrade records version 1 without changing anything, and a fresh database
// gets the whole thing.
const baselineSQL = `
CREATE TABLE IF NOT EXISTS users (
	id             UUID PRIMARY KEY,
	username       TEXT UNIQUE NOT NULL,
	email          TEXT,
	password_hash  TEXT,
	oidc_subject   TEXT UNIQUE,
	is_admin       BOOLEAN NOT NULL DEFAULT FALSE,
	is_super_admin BOOLEAN NOT NULL DEFAULT FALSE,
	created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_super_admin BOOLEAN NOT NULL DEFAULT FALSE;
-- Per-user quota overrides. NULL means "inherit the instance default" (the
-- settings rows quota.user_bytes / quota.user_files); 0 means "no limit for
-- this user specifically", which is the same 0-is-unlimited convention the
-- instance-wide limits use. The two are deliberately distinct: an admin must
-- be able to lift a user above a restrictive default without editing it.
ALTER TABLE users ADD COLUMN IF NOT EXISTS quota_bytes BIGINT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS quota_files BIGINT;

CREATE TABLE IF NOT EXISTS settings (
	key        TEXT PRIMARY KEY,
	value      TEXT NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sessions (
	id          TEXT PRIMARY KEY,
	user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	expires_at  TIMESTAMPTZ NOT NULL,
	created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS sessions_expires_at_idx ON sessions (expires_at);

CREATE TABLE IF NOT EXISTS files (
	id              UUID PRIMARY KEY,
	original_name   TEXT NOT NULL,
	stored_name     TEXT NOT NULL,
	size_bytes      BIGINT NOT NULL,
	content_type    TEXT NOT NULL,
	uploaded_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	uploaded_by     UUID REFERENCES users(id) ON DELETE SET NULL,
	expires_at      TIMESTAMPTZ,
	password_hash   TEXT,
	max_downloads   INTEGER,
	download_count  INTEGER NOT NULL DEFAULT 0
);
ALTER TABLE files ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ;
-- key_mode is 3 (key in the URL fragment) or 4 (key derived from the share
-- password in the browser). Both are end-to-end; the server holds no key for
-- either. Modes 0-2, where the server could unwrap a file's key, are gone.
ALTER TABLE files ADD COLUMN IF NOT EXISTS key_mode INTEGER NOT NULL DEFAULT 3;
-- enc_salt holds the PBKDF2 salt for a key_mode 4 share. The name predates
-- end-to-end encryption; it has never held a server-usable secret since.
ALTER TABLE files ADD COLUMN IF NOT EXISTS enc_salt BYTEA;
ALTER TABLE files ADD COLUMN IF NOT EXISTS auth_verifier BYTEA;

-- Dropped with the server-side key modes: password_hash gated legacy share
-- passwords, enc_key held a DEK the server could unwrap, and enc_version
-- distinguished plaintext from server-encrypted blobs. Every blob is now
-- client-side ciphertext and the server can decrypt none of them.
ALTER TABLE files DROP COLUMN IF EXISTS password_hash;
ALTER TABLE files DROP COLUMN IF EXISTS enc_key;
ALTER TABLE files DROP COLUMN IF EXISTS enc_version;

-- A batch is one share link covering many files. Expiry, download limit and
-- password live here, not on the member rows: the batch is the shareable unit
-- and its members are reachable only through it.
--
-- The server holds no key material for a batch either. Each member carries a
-- wrapped_key — its own file key sealed under a batch key the browser derives
-- from the URL fragment or the share password — so the server stores an opaque
-- blob it can never unwrap.
CREATE TABLE IF NOT EXISTS batches (
	id             UUID PRIMARY KEY,
	created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	created_by     UUID REFERENCES users(id) ON DELETE SET NULL,
	expires_at     TIMESTAMPTZ,
	max_downloads  INTEGER,
	download_count INTEGER NOT NULL DEFAULT 0,
	key_mode       INTEGER NOT NULL DEFAULT 3,
	auth_salt      BYTEA,
	auth_verifier  BYTEA,
	archived_at    TIMESTAMPTZ
);
ALTER TABLE files ADD COLUMN IF NOT EXISTS batch_id UUID REFERENCES batches(id) ON DELETE CASCADE;
ALTER TABLE files ADD COLUMN IF NOT EXISTS wrapped_key BYTEA;
CREATE INDEX IF NOT EXISTS files_batch_id_idx ON files (batch_id) WHERE batch_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS batches_expires_at_idx ON batches (expires_at) WHERE expires_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS upload_reservations (
	id         UUID PRIMARY KEY,
	user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	bytes      BIGINT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS files_uploaded_at_idx ON files (uploaded_at DESC);
-- The quota bar in the page shell aggregates one user's active files on every
-- render, so that lookup must not be a sequential scan.
CREATE INDEX IF NOT EXISTS files_uploaded_by_idx ON files (uploaded_by) WHERE archived_at IS NULL;
CREATE INDEX IF NOT EXISTS files_expires_at_idx  ON files (expires_at) WHERE expires_at IS NOT NULL;
`

var migrations = []migration{
	{
		version: 1,
		name:    "baseline",
		stmts:   []string{baselineSQL},
	},
	{
		version: 2,
		name:    "hash_session_tokens",
		// The session cookie is a bearer token, and it used to be the primary
		// key verbatim: anyone who read the sessions table held every live
		// session. Store SHA-256(token) instead, the way one stores an API
		// bearer token, so a database dump yields nothing that can be replayed.
		//
		// Existing rows are hashed in place rather than deleted, so upgrading
		// does not sign everyone out. The token is base64url ASCII, so
		// convert_to(id,'UTF8') is exactly the byte string the Go side hashes.
		stmts: []string{
			`UPDATE sessions SET id = encode(sha256(convert_to(id, 'UTF8')), 'hex')`,
			// reauth_at records when this session last completed a *fresh*
			// interactive OIDC authentication; adding a first local password to
			// an SSO account requires one.
			`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS reauth_at TIMESTAMPTZ`,
		},
	},
	{
		version: 3,
		name:    "oidc_issuer_binding",
		// OpenID Connect only guarantees that (issuer, subject) identifies an
		// end user; `sub` alone is unique per issuer, not globally. Binding on
		// `sub` alone means that pointing the instance at a different IdP whose
		// subjects happen to collide silently hands those accounts — including
		// an administrator's — to whoever holds them there.
		stmts: []string{
			`ALTER TABLE users ADD COLUMN IF NOT EXISTS oidc_issuer TEXT`,
			// The global UNIQUE(oidc_subject) is exactly the constraint being
			// replaced; the same subject at two issuers is two people.
			`ALTER TABLE users DROP CONSTRAINT IF EXISTS users_oidc_subject_key`,
			// Backfill existing SSO accounts with the issuer they must have come
			// from: the one this instance is configured with. If none is
			// configured the column stays NULL and the login path adopts the row
			// on the user's next sign-in (see findUserByOIDCIdentity).
			`UPDATE users SET oidc_issuer = s.value
			   FROM settings s
			  WHERE s.key = 'oidc.issuer' AND s.value <> ''
			    AND users.oidc_subject IS NOT NULL AND users.oidc_issuer IS NULL`,
			`CREATE UNIQUE INDEX IF NOT EXISTS users_oidc_identity_idx
			   ON users (oidc_issuer, oidc_subject)
			   WHERE oidc_subject IS NOT NULL AND oidc_issuer IS NOT NULL`,
			// NULLs are distinct in a unique index, so the not-yet-adopted rows
			// need their own constraint or duplicates could accumulate there.
			`CREATE UNIQUE INDEX IF NOT EXISTS users_oidc_unclaimed_idx
			   ON users (oidc_subject)
			   WHERE oidc_subject IS NOT NULL AND oidc_issuer IS NULL`,
		},
	},
	{
		version: 4,
		name:    "username_case_insensitive_unique",
		// Account creation has always checked lower(username), but the database
		// only enforced a case-sensitive UNIQUE. Two concurrent transactions
		// could therefore both pass the check and create "Alice" and "alice",
		// after which the case-insensitive login lookup is ambiguous and which
		// account you reach depends on the plan.
		fn: migrateUsernameCaseUnique,
	},
	{
		version: 5,
		name:    "e2e_protocol_v2",
		// Version the container format so a future change to the framing or the
		// KDF labels can be introduced without stranding shares that are still
		// alive: old rows keep their version and keep decrypting through the
		// routine that produced them.
		stmts: []string{
			`ALTER TABLE files ADD COLUMN IF NOT EXISTS e2e_version INTEGER NOT NULL DEFAULT 1`,
			// The authenticated manifest, stored exactly as the browser produced
			// it. It is the AAD of every chunk, so a single changed byte makes
			// the file undecryptable — the server must return it verbatim and
			// must never rewrite it.
			`ALTER TABLE files ADD COLUMN IF NOT EXISTS manifest BYTEA`,
			`ALTER TABLE batches ADD COLUMN IF NOT EXISTS e2e_version INTEGER NOT NULL DEFAULT 1`,
			// The sealed batch roster: the member list, authenticated under a
			// key derived from the batch secret, so the server cannot add,
			// remove or rename members undetected.
			`ALTER TABLE batches ADD COLUMN IF NOT EXISTS roster BYTEA`,
			`ALTER TABLE batches ADD COLUMN IF NOT EXISTS roster_seq BIGINT NOT NULL DEFAULT 0`,
		},
	},
	{
		version: 6,
		name:    "auth_failure_counters",
		// Authentication rate limiting used to live only in process memory, so
		// it neither survived a restart nor coordinated across replicas: two
		// containers behind the proxy doubled every allowance, and a rolling
		// deploy reset them all. The shared counter lives here.
		stmts: []string{
			`CREATE TABLE IF NOT EXISTS auth_failures (
				key          TEXT PRIMARY KEY,
				fails        INTEGER NOT NULL DEFAULT 0,
				window_start TIMESTAMPTZ NOT NULL DEFAULT NOW()
			)`,
			`CREATE INDEX IF NOT EXISTS auth_failures_window_idx ON auth_failures (window_start)`,
		},
	},
}

// migrateUsernameCaseUnique adds the case-insensitive uniqueness constraint,
// reporting the offending names when existing data already violates it. The
// bare index error ("could not create unique index") names neither the column
// values nor what to do about them, and an operator hitting this on a
// production upgrade needs both.
func migrateUsernameCaseUnique(ctx context.Context, tx pgx.Tx) error {
	rows, err := tx.Query(ctx,
		`SELECT string_agg(username, ', ' ORDER BY username)
		   FROM users GROUP BY lower(username) HAVING COUNT(*) > 1`)
	if err != nil {
		return err
	}
	var clashes []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			rows.Close()
			return err
		}
		clashes = append(clashes, s)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(clashes) > 0 {
		return fmt.Errorf("usernames that differ only in case already exist and must be "+
			"renamed by hand before this upgrade can proceed: %s", strings.Join(clashes, "; "))
	}
	_, err = tx.Exec(ctx,
		`CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_idx ON users (lower(username))`)
	return err
}

func connectDB(ctx context.Context, dsn string, attempts int, wait time.Duration) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	cfg.MaxConns = 10

	var lastErr error
	for i := 1; i <= attempts; i++ {
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err == nil {
			pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			pingErr := pool.Ping(pctx)
			cancel()
			if pingErr == nil {
				return pool, nil
			}
			pool.Close()
			lastErr = pingErr
		} else {
			lastErr = err
		}
		log.Printf("db not ready (attempt %d/%d): %v", i, attempts, lastErr)
		time.Sleep(wait)
	}
	return nil, lastErr
}

// runMigrations applies every migration the database has not recorded yet, in
// order, one transaction each.
func runMigrations(ctx context.Context, db *pgxpool.Pool) error {
	if _, err := db.Exec(ctx,
		`CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INTEGER PRIMARY KEY,
			name       TEXT NOT NULL,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	conn, err := db.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	// Session-scoped, not transaction-scoped: each migration gets its own
	// transaction and the lock has to span all of them.
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationLockKey); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		if _, err := conn.Exec(context.Background(),
			`SELECT pg_advisory_unlock($1)`, migrationLockKey); err != nil {
			log.Printf("release migration lock: %v", err)
		}
	}()

	applied, err := appliedMigrations(ctx, conn.Conn())
	if err != nil {
		return err
	}
	for _, m := range migrations {
		if applied[m.version] {
			continue
		}
		if err := applyMigration(ctx, conn.Conn(), m); err != nil {
			return fmt.Errorf("migration %d (%s): %w", m.version, m.name, err)
		}
		log.Printf("migration %d applied: %s", m.version, m.name)
	}
	return nil
}

func appliedMigrations(ctx context.Context, conn *pgx.Conn) (map[int]bool, error) {
	rows, err := conn.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int]bool{}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out[v] = true
	}
	return out, rows.Err()
}

func applyMigration(ctx context.Context, conn *pgx.Conn, m migration) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	for _, stmt := range m.stmts {
		if _, err := tx.Exec(ctx, stmt); err != nil {
			return err
		}
	}
	if m.fn != nil {
		if err := m.fn(ctx, tx); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO schema_migrations (version, name) VALUES ($1, $2)`,
		m.version, m.name); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// schemaVersion reports the highest migration the database has recorded. Used
// by /healthz and by the upgrade test.
func schemaVersion(ctx context.Context, db *pgxpool.Pool) (int, error) {
	var v *int
	if err := db.QueryRow(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&v); err != nil {
		return 0, err
	}
	if v == nil {
		return 0, nil
	}
	return *v, nil
}

// latestSchemaVersion is the version a freshly migrated database lands on.
func latestSchemaVersion() int {
	max := 0
	for _, m := range migrations {
		if m.version > max {
			max = m.version
		}
	}
	return max
}
