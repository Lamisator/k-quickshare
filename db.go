package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const schemaSQL = `
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
CREATE INDEX IF NOT EXISTS files_expires_at_idx  ON files (expires_at) WHERE expires_at IS NOT NULL;
`

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

func runMigrations(ctx context.Context, db *pgxpool.Pool) error {
	_, err := db.Exec(ctx, schemaSQL)
	return err
}
