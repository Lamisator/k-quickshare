package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// A batch is one share link over many files. Expiry, download limit and
// password live on the batch row; member files carry none of their own and are
// reachable only through the batch, which is what makes the batch the single
// enforcement point.
//
// The server still cannot decrypt anything: each member's file key is sealed
// under a batch key derived in the browser from the URL fragment or the share
// password, and stored here as an opaque wrapped_key.
type batchMeta struct {
	ID            string
	CreatedAt     time.Time
	CreatedBy     *string
	ExpiresAt     *time.Time
	MaxDownloads  *int
	DownloadCount int
	KeyMode       int
	AuthSalt      []byte
	AuthVerifier  []byte
	ArchivedAt    *time.Time
}

// 12-byte GCM nonce + 32-byte file key + 16-byte tag, as produced by
// wrapFileKey() in web/static/e2e.js.
const batchWrappedKeyLen = 12 + 32 + 16

type batchMember struct {
	ID          string
	Name        string
	Size        int64
	ContentType string
	StoredName  string
	WrappedKey  []byte
}

func (bm *batchMeta) isPassword() bool { return bm.KeyMode == keyModeE2EPassword }

// handleCreateBatch opens an empty batch and returns its id. The client creates
// one per upload session, before the first file, so every file it then uploads
// can be pinned to it.
func (a *App) handleCreateBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user := userFromContext(r.Context())
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	expiresAt, err := parseExpiry(r.FormValue("expires_hours"), r.FormValue("expires_at"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	maxDownloads, err := parseMaxDownloads(r.FormValue("max_downloads"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Password batches gate the ciphertext on a token derived from the password
	// on a separate KDF branch. As with single files, the password itself never
	// reaches the server and cannot be recovered from what is stored.
	keyMode := keyModeE2EURL
	var authSalt, authVerifier []byte
	if tokenStr := r.FormValue("auth_verifier"); tokenStr != "" {
		token, terr := base64.RawURLEncoding.DecodeString(tokenStr)
		authSalt, _ = base64.RawURLEncoding.DecodeString(r.FormValue("auth_salt"))
		if terr != nil || len(token) != 32 || len(authSalt) != encSaltLen {
			http.Error(w, "invalid auth material", http.StatusBadRequest)
			return
		}
		keyMode = keyModeE2EPassword
		sum := sha256.Sum256(token)
		authVerifier = sum[:]
	}

	id := uuid.New()
	_, err = a.db.Exec(r.Context(),
		`INSERT INTO batches (id, created_by, expires_at, max_downloads,
		                      key_mode, auth_salt, auth_verifier)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		id.String(), user.ID.String(), expiresAt, maxDownloads,
		keyMode, authSalt, authVerifier)
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":        id.String(),
		"url":       "/b/" + id.String(),
		"expiresAt": expiresAt,
	})
}

// loadBatchForUpload fetches a batch the given user may still add files to.
// Ownership matters: without it, anyone holding a batch id could inject files
// into somebody else's share link.
func (a *App) loadBatchForUpload(r *http.Request, id uuid.UUID, userID string) (*batchMeta, error) {
	bm, err := a.loadBatchMeta(r, id)
	if err != nil {
		return nil, err
	}
	if bm.CreatedBy == nil || *bm.CreatedBy != userID {
		return nil, errNotBatchOwner
	}
	if bm.ArchivedAt != nil || (bm.ExpiresAt != nil && time.Now().After(*bm.ExpiresAt)) {
		return nil, errBatchClosed
	}
	return bm, nil
}

var (
	errNotBatchOwner = errors.New("batch belongs to another user")
	errBatchClosed   = errors.New("batch is expired or archived")
)

func (a *App) loadBatchMeta(r *http.Request, id uuid.UUID) (*batchMeta, error) {
	bm := &batchMeta{ID: id.String()}
	err := a.db.QueryRow(r.Context(),
		`SELECT created_at, created_by, expires_at, max_downloads, download_count,
		        key_mode, auth_salt, auth_verifier, archived_at
		 FROM batches WHERE id = $1`, id.String()).
		Scan(&bm.CreatedAt, &bm.CreatedBy, &bm.ExpiresAt, &bm.MaxDownloads,
			&bm.DownloadCount, &bm.KeyMode, &bm.AuthSalt, &bm.AuthVerifier, &bm.ArchivedAt)
	if err != nil {
		return nil, err
	}
	return bm, nil
}

func (a *App) loadBatchMembers(r *http.Request, batchID string) ([]batchMember, error) {
	rows, err := a.db.Query(r.Context(),
		`SELECT id, original_name, size_bytes, content_type, stored_name, wrapped_key
		 FROM files
		 WHERE batch_id = $1 AND archived_at IS NULL
		 ORDER BY uploaded_at, id`, batchID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []batchMember
	for rows.Next() {
		var m batchMember
		if err := rows.Scan(&m.ID, &m.Name, &m.Size, &m.ContentType,
			&m.StoredName, &m.WrappedKey); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// dispatchBatchRoutes handles /b/{id}, /b/{id}/unlock, /b/{id}/manifest and
// /b/{id}/f/{fileID}/raw.
func (a *App) dispatchBatchRoutes(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/b/")
	idStr, action, _ := strings.Cut(rest, "/")
	id, err := uuid.Parse(idStr)
	if err != nil {
		a.renderGone(w, r, http.StatusNotFound, "dl.not_found")
		return
	}
	bm, err := a.loadBatchMeta(r, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			a.renderGone(w, r, http.StatusNotFound, "dl.not_found")
			return
		}
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	if bm.MaxDownloads != nil && bm.DownloadCount >= *bm.MaxDownloads {
		a.renderGone(w, r, http.StatusGone, "dl.gone_limit")
		return
	}
	if bm.ArchivedAt != nil || (bm.ExpiresAt != nil && time.Now().After(*bm.ExpiresAt)) {
		a.renderGone(w, r, http.StatusGone, "dl.gone_expired")
		return
	}

	switch {
	case action == "":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		a.renderBatchLanding(w, r, bm)
	case action == "unlock":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		a.handleBatchUnlock(w, r, bm)
	case action == "manifest":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		a.handleBatchManifest(w, r, bm)
	case strings.HasPrefix(action, "f/"):
		fileID, sub, _ := strings.Cut(strings.TrimPrefix(action, "f/"), "/")
		if sub != "raw" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		a.handleBatchFileRaw(w, r, bm, fileID)
	default:
		http.NotFound(w, r)
	}
}

func (a *App) renderBatchLanding(w http.ResponseWriter, r *http.Request, bm *batchMeta) {
	members, err := a.loadBatchMembers(r, bm.ID)
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	var total int64
	for _, m := range members {
		total += m.Size
	}
	mode := "url"
	if bm.isPassword() {
		mode = "password"
	}
	data := map[string]any{
		"Title":      a.tr(r, "batch.title") + " · Pyxis",
		"State":      "batch",
		"E2EMode":    mode,
		"Unlocked":   !bm.isPassword() || a.batchUnlocked(r, bm),
		"ID":         bm.ID,
		"FileCount":  len(members),
		"TotalSize":  total,
		"UploadedAt": bm.CreatedAt,
		"HasLimit":   false,
	}
	if len(bm.AuthSalt) > 0 {
		data["AuthSalt"] = base64.RawURLEncoding.EncodeToString(bm.AuthSalt)
	}
	if bm.ExpiresAt != nil {
		data["ExpiresAt"] = bm.ExpiresAt.UTC()
	}
	if bm.MaxDownloads != nil {
		data["HasLimit"] = true
		data["MaxDL"] = *bm.MaxDownloads
		data["DownloadsLeft"] = *bm.MaxDownloads - bm.DownloadCount
	}
	a.render(w, r, "batch.html", data)
}

// handleBatchManifest lists the members and their wrapped keys. A wrapped key
// is inert without the batch key, which only the link fragment or the password
// can produce — but a password batch still withholds the whole listing until
// unlock, so a bare link leaks neither file names nor the file count.
func (a *App) handleBatchManifest(w http.ResponseWriter, r *http.Request, bm *batchMeta) {
	if bm.isPassword() && !a.batchUnlocked(r, bm) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	members, err := a.loadBatchMembers(r, bm.ID)
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	// Previewing pulls the member's ciphertext, which spends a download slot.
	// On a limited batch that would burn the link invisibly, so limited batches
	// offer no previews at all — the same rule single-file shares follow.
	previews := bm.MaxDownloads == nil

	files := make([]map[string]any, 0, len(members))
	for _, m := range members {
		kind := ""
		if previews {
			kind = previewKind(m.ContentType, m.Size)
		}
		files = append(files, map[string]any{
			"id":          m.ID,
			"name":        m.Name,
			"size":        m.Size,
			"contentType": m.ContentType,
			"wrappedKey":  base64.RawURLEncoding.EncodeToString(m.WrappedKey),
			"previewKind": kind,
			"iconKind":    iconKind(m.ContentType, m.Name),
		})
	}
	left := -1
	if bm.MaxDownloads != nil {
		left = *bm.MaxDownloads - bm.DownloadCount
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":             bm.ID,
		"files":          files,
		"downloadsLeft":  left,
		"downloadsTotal": bm.MaxDownloads,
	})
}

func (a *App) handleBatchUnlock(w http.ResponseWriter, r *http.Request, bm *batchMeta) {
	if !bm.isPassword() {
		http.Error(w, "not password protected", http.StatusBadRequest)
		return
	}
	limitKey := a.clientIP(r) + "|b|" + bm.ID
	if !a.shareLimiter.allow(limitKey) {
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}
	_ = r.ParseForm()
	token, err := base64.RawURLEncoding.DecodeString(r.PostFormValue("auth"))
	if err == nil && len(token) == 32 {
		sum := sha256.Sum256(token)
		if hmac.Equal(sum[:], bm.AuthVerifier) {
			a.shareLimiter.reset(limitKey)
			a.setBatchUnlockCookie(w, bm)
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	a.shareLimiter.fail(limitKey)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// handleBatchFileRaw serves one member's ciphertext. This is the only way into
// a batch member's bytes: /files/{id}/raw refuses anything with a batch_id, so
// the batch's password, expiry and limit cannot be sidestepped by addressing
// the member directly.
func (a *App) handleBatchFileRaw(w http.ResponseWriter, r *http.Request, bm *batchMeta, fileID string) {
	id, err := uuid.Parse(fileID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if bm.isPassword() && !a.batchUnlocked(r, bm) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var storedName, origName string
	var uploadedAt time.Time
	err = a.db.QueryRow(r.Context(),
		`SELECT stored_name, original_name, uploaded_at FROM files
		 WHERE id = $1 AND batch_id = $2 AND archived_at IS NULL`,
		id.String(), bm.ID).Scan(&storedName, &origName, &uploadedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		httpError(w, err, http.StatusInternalServerError)
		return
	}

	if !a.consumeBatchDownload(w, r, bm) {
		return
	}
	f, err := os.Open(filepath.Join(a.filesDir, storedName))
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="%s.enc"`, quoteForHeader(origName)))
	http.ServeContent(w, r, origName+".enc", uploadedAt, f)

	a.archiveBatchIfSpent(r, bm)
}

// consumeBatchDownload burns one slot off the batch. The limit counts FILE
// downloads, not link opens: a "download all" over five members spends five,
// because five blobs leave the server. The UI says so in as many words.
func (a *App) consumeBatchDownload(w http.ResponseWriter, r *http.Request, bm *batchMeta) bool {
	res, err := a.db.Exec(r.Context(),
		`UPDATE batches SET download_count = download_count + 1
		 WHERE id = $1
		   AND (max_downloads IS NULL OR download_count < max_downloads)
		   AND (expires_at IS NULL OR expires_at > NOW())`, bm.ID)
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return false
	}
	if res.RowsAffected() == 0 {
		http.Error(w, "download limit reached", http.StatusGone)
		return false
	}
	return true
}

func (a *App) archiveBatchIfSpent(r *http.Request, bm *batchMeta) {
	if bm.MaxDownloads == nil || bm.DownloadCount+1 < *bm.MaxDownloads {
		return
	}
	a.archiveBatch(r.Context(), bm.ID)
}

// --- batch unlock cookies ---------------------------------------------------

func (a *App) batchUnlockCookieName(id string) string {
	return "pxb_" + strings.ReplaceAll(id, "-", "")
}

func (a *App) batchUnlockToken(bm *batchMeta) string {
	mac := hmac.New(sha256.New, a.unlockKey)
	mac.Write([]byte("batch"))
	mac.Write([]byte{0})
	mac.Write([]byte(bm.ID))
	mac.Write([]byte{0})
	mac.Write(bm.AuthVerifier)
	return hex.EncodeToString(mac.Sum(nil))
}

func (a *App) batchUnlocked(r *http.Request, bm *batchMeta) bool {
	c, err := r.Cookie(a.batchUnlockCookieName(bm.ID))
	if err != nil {
		return false
	}
	return hmac.Equal([]byte(c.Value), []byte(a.batchUnlockToken(bm)))
}

func (a *App) setBatchUnlockCookie(w http.ResponseWriter, bm *batchMeta) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.batchUnlockCookieName(bm.ID),
		Value:    a.batchUnlockToken(bm),
		Path:     "/b/" + bm.ID,
		Expires:  time.Now().Add(6 * time.Hour),
		HttpOnly: true,
		Secure:   a.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}
