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

	"github.com/google/uuid"
)

var errQuotaExceeded = errors.New("storage quota exceeded")

// storageUsage returns the caller's active bytes/file count and the
// instance-wide active bytes.
func (a *App) storageUsage(ctx context.Context, userID string) (userBytes, userFiles, totalBytes int64, err error) {
	err = a.db.QueryRow(ctx,
		`SELECT COALESCE(SUM(size_bytes) FILTER (WHERE uploaded_by = $1), 0),
		        COUNT(*)                 FILTER (WHERE uploaded_by = $1),
		        COALESCE(SUM(size_bytes), 0)
		 FROM files
		 WHERE expires_at IS NULL OR expires_at > NOW()`, userID).
		Scan(&userBytes, &userFiles, &totalBytes)
	return
}

// checkQuota verifies that storing incoming more bytes for user stays within
// the per-user (non-admins), instance and free-disk limits.
func (a *App) checkQuota(ctx context.Context, user *User, incoming int64) error {
	if a.quota.MinFreeBytes > 0 {
		var st syscall.Statfs_t
		if err := syscall.Statfs(a.filesDir, &st); err == nil {
			free := int64(st.Bavail) * st.Bsize
			if free-incoming < a.quota.MinFreeBytes {
				return fmt.Errorf("%w: insufficient free disk space", errQuotaExceeded)
			}
		}
	}
	userBytes, userFiles, totalBytes, err := a.storageUsage(ctx, user.ID.String())
	if err != nil {
		return err
	}
	if a.quota.TotalBytes > 0 && totalBytes+incoming > a.quota.TotalBytes {
		return fmt.Errorf("%w: instance storage limit reached", errQuotaExceeded)
	}
	if !user.IsAdmin {
		if a.quota.UserBytes > 0 && userBytes+incoming > a.quota.UserBytes {
			return fmt.Errorf("%w: personal storage limit reached", errQuotaExceeded)
		}
		if a.quota.UserFiles > 0 && userFiles+1 > a.quota.UserFiles {
			return fmt.Errorf("%w: personal file-count limit reached", errQuotaExceeded)
		}
	}
	return nil
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

// openFileBlob opens a stored blob for reading as plaintext, decrypting when
// the file is encrypted at rest.
func (a *App) openFileBlob(fm *fileMeta) (io.ReadSeeker, io.Closer, error) {
	f, err := os.Open(filepath.Join(a.filesDir, fm.StoredName))
	if err != nil {
		return nil, nil, err
	}
	if fm.EncVersion == encVersionPlain {
		return f, f, nil
	}
	if len(a.fileKEK) == 0 {
		f.Close()
		return nil, nil, errors.New("file is encrypted but no FILE_ENCRYPTION_KEY configured")
	}
	dek, err := a.unwrapDEK(fm.EncKey)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	r, err := newEncReader(f, dek, fm.Size)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return r, f, nil
}
