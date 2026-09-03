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
	"strconv"
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
	E2EVersion    int
	Roster        []byte
	RosterSeq     int64

	// Set when this batch is a SUBMISSION to a drop rather than a share the
	// owner created. KemCT is the X-Wing encapsulation its key schedule
	// descends from and EncNote the sender's sealed note; both are opaque here.
	DropID  *string
	KemCT   []byte
	EncNote []byte
}

// isSubmission reports whether this batch belongs to a drop. A submission is
// reachable ONLY through its drop's inbox: /b/{id} refuses it, exactly as
// /files/{id}/raw refuses a batch member. Otherwise the batch page would offer
// a second door into files whose terms — and whose expiry — belong to the drop.
func (bm *batchMeta) isSubmission() bool { return bm.DropID != nil }

// 12-byte GCM nonce + 32-byte file key + 16-byte tag, as produced by
// wrapFileKey() in web/static/e2e.js.
const batchWrappedKeyLen = 12 + 32 + 16

// A sealed roster is 12-byte nonce || AES-GCM(roster JSON) || 16-byte tag, and
// grows with the member count. The ceiling is generous enough for a very large
// batch and still bounds what one POST can park in the row.
const maxRosterLen = 256 << 10

type batchMember struct {
	ID          string
	Name        string // empty from container version 4 on; the name is in EncName
	EncName     []byte // sealed name blob, opaque to the server
	Size        int64
	ContentType string
	StoredName  string
	WrappedKey  []byte
	E2EVersion  int
	Manifest    []byte
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
		                      key_mode, auth_salt, auth_verifier, e2e_version)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		id.String(), user.ID.String(), expiresAt, maxDownloads,
		keyMode, authSalt, authVerifier, e2eCurrentVersion)
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         id.String(),
		"url":        "/b/" + id.String(),
		"expiresAt":  expiresAt,
		"e2eVersion": e2eCurrentVersion,
	})
}

// dispatchBatchOwnerRoutes handles the authenticated side of a batch:
// /batches/{id}/roster.
func (a *App) dispatchBatchOwnerRoutes(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/batches/")
	idStr, action, _ := strings.Cut(rest, "/")
	id, err := uuid.Parse(idStr)
	if err != nil || action != "roster" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.handleBatchRosterUpdate(w, r, id)
}

// handleBatchRosterUpdate stores the sealed member list for a batch.
//
// The roster is what makes the batch's MEMBERSHIP authenticated, not just each
// member's bytes. Without it the server chooses which files a link resolves to:
// it can drop a member from the listing, or splice in one the sender never
// added, and every individual file still decrypts perfectly. The uploader seals
// the list under a key derived from the batch secret, so the server stores an
// opaque blob it can neither read nor forge, and the downloader checks the
// listing it was served against it.
//
// It is re-sealed after each member so the link is complete at every moment
// during an upload session, not only once it finishes. `seq` must not go
// backwards: that is what stops the roster being rolled back to a state with
// fewer members by anyone replaying an earlier POST.
func (a *App) handleBatchRosterUpdate(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	user := userFromContext(r.Context())
	bm, err := a.loadBatchForUpload(r, id, user.ID.String())
	if err != nil {
		switch {
		case errors.Is(err, pgx.ErrNoRows), errors.Is(err, errNotBatchOwner):
			http.Error(w, "batch not found", http.StatusNotFound)
		case errors.Is(err, errBatchClosed):
			http.Error(w, "batch is no longer open", http.StatusGone)
		default:
			httpError(w, err, http.StatusInternalServerError)
		}
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	sealed, derr := base64.RawURLEncoding.DecodeString(r.PostFormValue("roster"))
	if derr != nil || len(sealed) == 0 {
		http.Error(w, "roster is not base64url", http.StatusBadRequest)
		return
	}
	if len(sealed) > maxRosterLen {
		http.Error(w, "roster too large", http.StatusRequestEntityTooLarge)
		return
	}
	seq, serr := strconv.ParseInt(r.PostFormValue("seq"), 10, 64)
	if serr != nil || seq <= 0 {
		http.Error(w, "seq must be a positive integer", http.StatusBadRequest)
		return
	}

	tag, err := a.db.Exec(r.Context(),
		`UPDATE batches SET roster = $1, roster_seq = $2
		  WHERE id = $3 AND roster_seq < $2`, sealed, seq, bm.ID)
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	if tag.RowsAffected() == 0 {
		// A newer roster is already stored. Not an error worth failing an
		// upload over — the client simply lost a race with itself.
		w.WriteHeader(http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusNoContent)
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
	// A drop submission is not a batch its owner may add to. It was created by
	// a stranger holding the public link, its roster is theirs to seal, and the
	// owner has no key for it — being able to inject a file into someone else's
	// delivery would make the sealed roster say something untrue.
	if bm.isSubmission() {
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
		        key_mode, auth_salt, auth_verifier, archived_at,
		        e2e_version, roster, roster_seq, drop_id::text, kem_ct, enc_note
		 FROM batches WHERE id = $1`, id.String()).
		Scan(&bm.CreatedAt, &bm.CreatedBy, &bm.ExpiresAt, &bm.MaxDownloads,
			&bm.DownloadCount, &bm.KeyMode, &bm.AuthSalt, &bm.AuthVerifier, &bm.ArchivedAt,
			&bm.E2EVersion, &bm.Roster, &bm.RosterSeq, &bm.DropID, &bm.KemCT, &bm.EncNote)
	if err != nil {
		return nil, err
	}
	return bm, nil
}

func (a *App) loadBatchMembers(r *http.Request, batchID string) ([]batchMember, error) {
	rows, err := a.db.Query(r.Context(),
		`SELECT id, original_name, enc_name, size_bytes, content_type, stored_name, wrapped_key,
		        e2e_version, manifest
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
		var name, contentType *string
		if err := rows.Scan(&m.ID, &name, &m.EncName, &m.Size, &contentType,
			&m.StoredName, &m.WrappedKey, &m.E2EVersion, &m.Manifest); err != nil {
			return nil, err
		}
		if name != nil {
			m.Name = *name
		}
		if contentType != nil {
			m.ContentType = *contentType
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
	if bm.isSubmission() {
		// Only the drop's inbox serves this, and only with the key in its
		// private link. Answering "not found" rather than "forbidden" is right:
		// to anyone without that link there is nothing here.
		a.renderGone(w, r, http.StatusNotFound, "dl.not_found")
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
			"id": m.ID,
			// Empty from container version 4 on (name) and 5 on (type, and with
			// it the icon and the preview decision that follow from it).
			// `encName` is the sealed blob the browser opens instead — one short
			// decryption per member, no ciphertext fetched and no download slot
			// spent, which is the whole reason these are sealed apart from the
			// file. What is left here is what the server cannot help knowing.
			"name":        m.Name,
			"encName":     base64.RawURLEncoding.EncodeToString(m.EncName),
			"manifestId":  manifestIDOf(m.Manifest),
			"size":        m.Size,
			"contentType": m.ContentType,
			"wrappedKey":  base64.RawURLEncoding.EncodeToString(m.WrappedKey),
			"previewKind": kind,
			"iconKind":    iconKind(m.ContentType, m.Name),
			// Whether previews are on offer at all is a fact about the download
			// limit, not about the file, so the client is told it directly and
			// works the rest out once it has opened the name.
			"previewsAllowed": previews,
			"e2eVersion":      m.E2EVersion,
			// Verbatim: the AAD of every one of this member's chunks.
			"manifest": base64.RawURLEncoding.EncodeToString(m.Manifest),
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
		"e2eVersion":     bm.E2EVersion,
		// The sealed member list. The browser opens it with a key derived from
		// the batch secret and checks the listing above against it, so this
		// response cannot quietly gain or lose a file.
		"roster":    base64.RawURLEncoding.EncodeToString(bm.Roster),
		"rosterSeq": bm.RosterSeq,
	})
}

func (a *App) handleBatchUnlock(w http.ResponseWriter, r *http.Request, bm *batchMeta) {
	if !bm.isPassword() {
		http.Error(w, "not password protected", http.StatusBadRequest)
		return
	}
	limitKey := a.clientIP(r) + "|b|" + bm.ID
	if !a.shareLimiter.allow(r.Context(), limitKey) {
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}
	_ = r.ParseForm()
	token, err := base64.RawURLEncoding.DecodeString(r.PostFormValue("auth"))
	if err == nil && len(token) == 32 {
		sum := sha256.Sum256(token)
		if hmac.Equal(sum[:], bm.AuthVerifier) {
			a.shareLimiter.reset(r.Context(), limitKey)
			a.setBatchUnlockCookie(w, bm)
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	a.shareLimiter.fail(r.Context(), limitKey)
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

	var storedName string
	var origName *string
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
	name := id.String()
	if origName != nil {
		name = downloadName(*origName, id.String())
	}
	a.serveBlob(w, r, storedName, name, uploadedAt)

	a.archiveBatchIfSpent(r, bm)
}

// serveBlob streams one stored object as an opaque attachment. It is always
// ciphertext: the name is a hint for the browser's downloads folder and the
// type is deliberately octet-stream, because from container version 5 the
// server has not been told what any of this is.
func (a *App) serveBlob(w http.ResponseWriter, r *http.Request, storedName, name string, modTime time.Time) {
	f, err := os.Open(filepath.Join(a.filesDir, storedName))
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="%s.enc"`, quoteForHeader(name)))
	http.ServeContent(w, r, name+".enc", modTime, f)
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
