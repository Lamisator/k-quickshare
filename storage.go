package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var errQuotaExceeded = errors.New("storage quota exceeded")

// quotaLockKey serializes all quota accounting through one PostgreSQL
// advisory lock so concurrent uploads cannot each observe the same free
// budget and collectively overshoot it.
const quotaLockKey int64 = 0x6b667331 // "kfs1"

// reservationTTL bounds how long an in-flight upload may hold its byte
// reservation; stale rows (crashed uploads) expire out of the accounting and
// are swept from the table.
const reservationTTL = 15 * time.Minute

type usageSnapshot struct {
	userBytes     int64 // active file bytes owned by the user
	userFiles     int64 // active file count owned by the user
	totalBytes    int64 // active file bytes instance-wide
	userReserved  int64 // live reservation bytes held by the user
	userResCount  int64 // live reservation count held by the user
	totalReserved int64 // live reservation bytes instance-wide
}

func loadUsage(ctx context.Context, tx pgx.Tx, userID string) (usageSnapshot, error) {
	var u usageSnapshot
	err := tx.QueryRow(ctx,
		`SELECT COALESCE(SUM(size_bytes) FILTER (WHERE uploaded_by = $1), 0),
		        COUNT(*)                 FILTER (WHERE uploaded_by = $1),
		        COALESCE(SUM(size_bytes), 0)
		 FROM files
		 WHERE archived_at IS NULL AND (expires_at IS NULL OR expires_at > NOW())`, userID).
		Scan(&u.userBytes, &u.userFiles, &u.totalBytes)
	if err != nil {
		return u, err
	}
	err = tx.QueryRow(ctx,
		`SELECT COALESCE(SUM(bytes) FILTER (WHERE user_id = $1), 0),
		        COUNT(*)            FILTER (WHERE user_id = $1),
		        COALESCE(SUM(bytes), 0)
		 FROM upload_reservations
		 WHERE created_at > NOW() - $2::interval`,
		userID, reservationTTL.String()).
		Scan(&u.userReserved, &u.userResCount, &u.totalReserved)
	return u, err
}

func (a *App) quotaViolation(user *User, u usageSnapshot, incoming int64) error {
	if a.quota.TotalBytes > 0 && u.totalBytes+u.totalReserved+incoming > a.quota.TotalBytes {
		return fmt.Errorf("%w: instance storage limit reached", errQuotaExceeded)
	}
	if !user.IsAdmin {
		if a.quota.UserBytes > 0 && u.userBytes+u.userReserved+incoming > a.quota.UserBytes {
			return fmt.Errorf("%w: personal storage limit reached", errQuotaExceeded)
		}
		if a.quota.UserFiles > 0 && u.userFiles+u.userResCount+1 > a.quota.UserFiles {
			return fmt.Errorf("%w: personal file-count limit reached", errQuotaExceeded)
		}
	}
	return nil
}

// DiskStats describes the filesystem holding the uploads.
type DiskStats struct {
	Total   int64
	Used    int64
	Free    int64
	Percent float64
	OK      bool
}

// diskStats reports usage of the files volume the way `df` reports Use%:
// against the capacity actually usable by this (unprivileged) process, i.e.
// used + available. Filesystems such as ext4 hold back ~5% for root, which is
// neither usable nor meaningful here — counting it would make the bar read
// several points lower than df and every monitoring dashboard.
func (a *App) diskStats() DiskStats {
	var st syscall.Statfs_t
	if err := syscall.Statfs(a.filesDir, &st); err != nil {
		return DiskStats{}
	}
	bs := int64(st.Bsize)
	free := int64(st.Bavail) * bs
	used := int64(st.Blocks-st.Bfree) * bs
	total := used + free
	if total <= 0 {
		return DiskStats{}
	}
	return DiskStats{
		Total:   total,
		Used:    used,
		Free:    free,
		Percent: float64(used) / float64(total) * 100,
		OK:      true,
	}
}

func (a *App) checkDiskFree(incoming int64) error {
	if a.quota.MinFreeBytes <= 0 {
		return nil
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(a.filesDir, &st); err != nil {
		return nil // never let a stat failure block uploads
	}
	free := int64(st.Bavail) * st.Bsize
	if free-incoming < a.quota.MinFreeBytes {
		return fmt.Errorf("%w: insufficient free disk space", errQuotaExceeded)
	}
	return nil
}

// reserveUpload atomically books estBytes against the quota before any data
// is written to disk. The reservation is released by finalizeUpload (success)
// or releaseReservation (failure); stale ones expire after reservationTTL.
func (a *App) reserveUpload(ctx context.Context, user *User, estBytes int64) (uuid.UUID, error) {
	if estBytes <= 0 || estBytes > a.maxUpload {
		estBytes = a.maxUpload
	}
	if err := a.checkDiskFree(estBytes); err != nil {
		return uuid.Nil, err
	}
	tx, err := a.db.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, quotaLockKey); err != nil {
		return uuid.Nil, err
	}
	u, err := loadUsage(ctx, tx, user.ID.String())
	if err != nil {
		return uuid.Nil, err
	}
	if err := a.quotaViolation(user, u, estBytes); err != nil {
		return uuid.Nil, err
	}
	resID := uuid.New()
	if _, err := tx.Exec(ctx,
		`INSERT INTO upload_reservations (id, user_id, bytes) VALUES ($1, $2, $3)`,
		resID.String(), user.ID.String(), estBytes); err != nil {
		return uuid.Nil, err
	}
	return resID, tx.Commit(ctx)
}

// finalizeUpload swaps the reservation for the real files row under the same
// advisory lock, re-checking the quota against the actual written size.
func (a *App) finalizeUpload(ctx context.Context, user *User, resID uuid.UUID,
	written int64, insertFile func(pgx.Tx) error) error {
	tx, err := a.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, quotaLockKey); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM upload_reservations WHERE id = $1`, resID.String()); err != nil {
		return err
	}
	u, err := loadUsage(ctx, tx, user.ID.String())
	if err != nil {
		return err
	}
	if err := a.quotaViolation(user, u, written); err != nil {
		return err
	}
	if err := insertFile(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (a *App) releaseReservation(resID uuid.UUID) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := a.db.Exec(ctx,
		`DELETE FROM upload_reservations WHERE id = $1`, resID.String()); err != nil {
		log.Printf("release reservation %s: %v", resID, err)
	}
}
