package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
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

// encryptLegacyFiles migrates plaintext blobs (enc_version=0) to the
// encrypted format in the background. Each file gets a fresh stored name and
// its DB row is updated atomically before the plaintext blob is removed, so a
// crash mid-migration never leaves a row pointing at missing or half-written
// data.
func (a *App) encryptLegacyFiles(ctx context.Context) {
	if len(a.fileKEK) == 0 {
		return
	}
	go func() {
		rows, err := a.db.Query(ctx,
			`SELECT id::text, stored_name FROM files WHERE enc_version = 0`)
		if err != nil {
			log.Printf("encrypt-migration: query: %v", err)
			return
		}
		type item struct{ id, stored string }
		var items []item
		for rows.Next() {
			var it item
			if err := rows.Scan(&it.id, &it.stored); err != nil {
				rows.Close()
				log.Printf("encrypt-migration: scan: %v", err)
				return
			}
			items = append(items, it)
		}
		rows.Close()
		if len(items) == 0 {
			return
		}

		migrated := 0
		for _, it := range items {
			if err := a.encryptOneLegacy(ctx, it.id, it.stored); err != nil {
				log.Printf("encrypt-migration: file %s: %v", it.id[:8], err)
				continue
			}
			migrated++
		}
		log.Printf("encrypt-migration: encrypted %d/%d legacy file(s)", migrated, len(items))
	}()
}

func (a *App) encryptOneLegacy(ctx context.Context, id, stored string) error {
	src, err := os.Open(filepath.Join(a.filesDir, stored))
	if err != nil {
		return err
	}
	defer src.Close()

	dek := randomBytes(32)
	wrapped, err := a.wrapDEK(dek)
	if err != nil {
		return err
	}

	newStored := uuid.NewString()
	dstPath := filepath.Join(a.filesDir, newStored)
	dst, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}
	if _, err := encryptStream(dst, src, dek); err != nil {
		dst.Close()
		_ = os.Remove(dstPath)
		return err
	}
	if err := dst.Close(); err != nil {
		_ = os.Remove(dstPath)
		return err
	}

	tag, err := a.db.Exec(ctx,
		`UPDATE files SET stored_name = $1, enc_version = $2, enc_key = $3
		 WHERE id = $4 AND enc_version = 0`,
		newStored, encVersionGCM, wrapped, id)
	if err != nil || tag.RowsAffected() == 0 {
		_ = os.Remove(dstPath)
		if err == nil {
			err = errors.New("row changed concurrently")
		}
		return err
	}
	if err := os.Remove(filepath.Join(a.filesDir, stored)); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("encrypt-migration: remove plaintext %s: %v", stored, err)
	}
	return nil
}

// openFileBlob opens a stored blob for reading as plaintext. The caller
// supplies the already-resolved DEK (nil only for plaintext legacy files).
func (a *App) openFileBlob(fm *fileMeta, dek []byte) (io.ReadSeeker, io.Closer, error) {
	f, err := os.Open(filepath.Join(a.filesDir, fm.StoredName))
	if err != nil {
		return nil, nil, err
	}
	if fm.EncVersion == encVersionPlain {
		return f, f, nil
	}
	if len(dek) == 0 {
		f.Close()
		return nil, nil, errors.New("encrypted file served without a DEK")
	}
	r, err := newEncReader(f, dek, fm.Size)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return r, f, nil
}
