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
	if err := a.sweepExpiredBatches(ctx); err != nil {
		log.Printf("sweeper: batches: %v", err)
	}
	if err := a.sweepExpiredSessions(ctx); err != nil {
		log.Printf("sweeper: sessions: %v", err)
	}
	if err := a.sweepStaleReservations(ctx); err != nil {
		log.Printf("sweeper: reservations: %v", err)
	}
}

// sweepStaleReservations removes reservation rows abandoned by crashed or
// interrupted uploads; loadUsage already ignores them once past the TTL.
func (a *App) sweepStaleReservations(ctx context.Context) error {
	_, err := a.db.Exec(ctx,
		`DELETE FROM upload_reservations WHERE created_at <= NOW() - $1::interval`,
		reservationTTL.String())
	return err
}

const archiveRetention = 30 * 24 * time.Hour

// sweepExpiredFiles implements the two-stage lifecycle: a file whose link
// expired or whose download limit is used up is ARCHIVED immediately (blob
// deleted, metadata row kept and shown as expired), and archived rows are
// purged entirely after 30 days.
func (a *App) sweepExpiredFiles(ctx context.Context) error {
	// Stage 1: archive newly dead links and drop their blobs.
	archived, err := a.collectStored(ctx,
		`UPDATE files SET archived_at = NOW()
		 WHERE archived_at IS NULL
		   AND ((expires_at IS NOT NULL AND expires_at <= NOW())
		     OR (max_downloads IS NOT NULL AND download_count >= max_downloads))
		 RETURNING stored_name`)
	if err != nil {
		return err
	}
	a.removeBlobs(archived)
	if len(archived) > 0 {
		log.Printf("sweeper: archived %d dead link(s), blobs deleted", len(archived))
	}

	// Stage 2: purge archive entries past retention.
	purged, err := a.collectStored(ctx,
		`DELETE FROM files WHERE archived_at <= NOW() - $1::interval
		 RETURNING stored_name`, archiveRetention.String())
	if err != nil {
		return err
	}
	a.removeBlobs(purged) // belt and braces; blobs are gone since archiving
	if len(purged) > 0 {
		log.Printf("sweeper: purged %d archived row(s)", len(purged))
	}
	return nil
}

func (a *App) collectStored(ctx context.Context, query string, args ...any) ([]string, error) {
	rows, err := a.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var stored []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		stored = append(stored, name)
	}
	return stored, rows.Err()
}

func (a *App) removeBlobs(stored []string) {
	for _, name := range stored {
		p := filepath.Join(a.filesDir, name)
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("sweeper: remove %s: %v", p, err)
		}
	}
}

// archiveFile retires a single file's blob immediately (final download slot
// consumed) while keeping its metadata row listed for the archive window.
func (a *App) archiveFile(ctx context.Context, id, storedName string) {
	tag, err := a.db.Exec(ctx,
		`UPDATE files SET archived_at = NOW() WHERE id = $1 AND archived_at IS NULL`, id)
	if err != nil {
		log.Printf("archive file %s: %v", id[:8], err)
		return
	}
	if tag.RowsAffected() == 0 {
		return // concurrent request archived it and removed the blob
	}
	if err := os.Remove(filepath.Join(a.filesDir, storedName)); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("archive file %s: remove blob: %v", id[:8], err)
	}
}

// sweepExpiredBatches mirrors sweepExpiredFiles one level up. Member files
// carry no expiry or limit of their own — the batch holds both — so they are
// invisible to the file sweeper and have to be retired through here.
func (a *App) sweepExpiredBatches(ctx context.Context) error {
	rows, err := a.db.Query(ctx,
		`UPDATE batches SET archived_at = NOW()
		 WHERE archived_at IS NULL
		   AND ((expires_at IS NOT NULL AND expires_at <= NOW())
		     OR (max_downloads IS NOT NULL AND download_count >= max_downloads))
		 RETURNING id`)
	if err != nil {
		return err
	}
	var dead []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		dead = append(dead, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range dead {
		a.archiveBatchMembers(ctx, id)
	}
	if len(dead) > 0 {
		log.Printf("sweeper: archived %d dead batch link(s), blobs deleted", len(dead))
	}

	// Purging the batch row cascades its member file rows away; their blobs
	// went at archive time.
	tag, err := a.db.Exec(ctx,
		`DELETE FROM batches WHERE archived_at <= NOW() - $1::interval`,
		archiveRetention.String())
	if err != nil {
		return err
	}
	if n := tag.RowsAffected(); n > 0 {
		log.Printf("sweeper: purged %d archived batch(es)", n)
	}
	return nil
}

// archiveBatch retires a whole batch immediately — used when the final download
// slot is spent, the same way archiveFile works for a single share.
func (a *App) archiveBatch(ctx context.Context, id string) {
	tag, err := a.db.Exec(ctx,
		`UPDATE batches SET archived_at = NOW() WHERE id = $1 AND archived_at IS NULL`, id)
	if err != nil {
		log.Printf("archive batch %s: %v", id[:8], err)
		return
	}
	if tag.RowsAffected() == 0 {
		return // a concurrent request got there first
	}
	a.archiveBatchMembers(ctx, id)
}

func (a *App) archiveBatchMembers(ctx context.Context, id string) {
	stored, err := a.collectStored(ctx,
		`UPDATE files SET archived_at = NOW()
		 WHERE batch_id = $1 AND archived_at IS NULL
		 RETURNING stored_name`, id)
	if err != nil {
		log.Printf("archive batch %s members: %v", id[:8], err)
		return
	}
	a.removeBlobs(stored)
}

func (a *App) sweepExpiredSessions(ctx context.Context) error {
	_, err := a.db.Exec(ctx, `DELETE FROM sessions WHERE expires_at <= NOW()`)
	return err
}
