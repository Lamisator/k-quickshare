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
ALTER TABLE files ADD COLUMN IF NOT EXISTS enc_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE files ADD COLUMN IF NOT EXISTS enc_key BYTEA;
ALTER TABLE files ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ;
ALTER TABLE files ADD COLUMN IF NOT EXISTS key_mode INTEGER NOT NULL DEFAULT 0;
ALTER TABLE files ADD COLUMN IF NOT EXISTS enc_salt BYTEA;

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
