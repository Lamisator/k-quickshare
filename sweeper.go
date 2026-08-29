package main

import (
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"time"
)

func (a *App) startSweeper(ctx context.Context, interval time.Duration) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		a.sweepOnce(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				a.sweepOnce(ctx)
			}
		}
	}()
}

func (a *App) sweepOnce(ctx context.Context) {
	if err := a.sweepExpiredFiles(ctx); err != nil {
		log.Printf("sweeper: files: %v", err)
	}
	if err := a.sweepExpiredSessions(ctx); err != nil {
		log.Printf("sweeper: sessions: %v", err)
	}
}

func (a *App) sweepExpiredFiles(ctx context.Context) error {
	rows, err := a.db.Query(ctx,
		`DELETE FROM files
		 WHERE (expires_at IS NOT NULL AND expires_at <= NOW())
		    OR (max_downloads IS NOT NULL AND download_count >= max_downloads
		        AND uploaded_at < NOW() - INTERVAL '1 hour')
		 RETURNING stored_name`)
	if err != nil {
		return err
	}
	defer rows.Close()

	var stored []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return err
		}
		stored = append(stored, name)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, name := range stored {
		p := filepath.Join(a.filesDir, name)
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("sweeper: remove %s: %v", p, err)
		}
	}
	if n := len(stored); n > 0 {
		log.Printf("sweeper: purged %d expired file(s)", n)
	}
	return nil
}

func (a *App) sweepExpiredSessions(ctx context.Context) error {
	_, err := a.db.Exec(ctx, `DELETE FROM sessions WHERE expires_at <= NOW()`)
	return err
}
