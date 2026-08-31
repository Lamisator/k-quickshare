package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type File struct {
	ID            string
	OriginalName  string
	StoredName    string
	Size          int64
	ContentType   string
	UploadedAt    time.Time
	UploadedBy    *string
	UploaderName  string
	ExpiresAt     *time.Time
	HasPassword   bool
	HasLimit      bool
	MaxDL         int // dereferenced max_downloads; templates must never format the pointer
	DownloadCount int
	Archived      bool
	Keyed         bool // decryption key lives only in the original share link
	CanDelete     bool
	IconKind      string
	BatchID       *string // set when this file is shared as part of a batch link
}

// --- pages ----------------------------------------------------------------

func (a *App) handleUploadPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	a.render(w, r, "index.html", map[string]any{
		"Title":     a.tr(r, "title.upload") + " · Pyxis",
		"Active":    "upload",
		"MaxUpload": a.maxUpload,
	})
}

func (a *App) handleHistory(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())

	// Share IDs are bearer secrets: a regular user must only ever see their
	// own uploads. Admins intentionally get the instance-wide view.
	// Archived rows (blob deleted, metadata kept 30 days) stay listed.
	// A batch member holds no expiry, limit or password of its own — the batch
	// row does — so those columns are coalesced through the join. Without it
	// every member would list as "never expires, no limit", which is the
	// opposite of what its link actually enforces.
	const baseQuery = `SELECT f.id::text, f.original_name, f.stored_name, f.size_bytes, f.content_type,
		        f.uploaded_at, f.uploaded_by::text, u.username,
		        COALESCE(b.expires_at, f.expires_at),
		        (f.key_mode = 4),
		        COALESCE(b.max_downloads, f.max_downloads),
		        COALESCE(b.download_count, f.download_count),
		        COALESCE(b.archived_at, f.archived_at),
		        f.key_mode, f.batch_id::text, b.key_mode
		 FROM files f
		 LEFT JOIN users u ON u.id = f.uploaded_by
		 LEFT JOIN batches b ON b.id = f.batch_id
		 WHERE (COALESCE(b.archived_at, f.archived_at) IS NOT NULL
		     OR COALESCE(b.expires_at, f.expires_at) IS NULL
		     OR COALESCE(b.expires_at, f.expires_at) > NOW())`
	var (
		rows pgx.Rows
		err  error
	)
	if user.IsAdmin {
		rows, err = a.db.Query(r.Context(),
			baseQuery+` ORDER BY f.uploaded_at DESC LIMIT 500`)
	} else {
		rows, err = a.db.Query(r.Context(),
			baseQuery+` AND f.uploaded_by = $1 ORDER BY f.uploaded_at DESC LIMIT 500`,
			user.ID.String())
	}
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var (
		files       []File
		activeCount int
		totalSize   int64
		totalDL     int
	)
	for rows.Next() {
		var (
			f            File
			uploaderID   *string
			uploader     *string
			expires      *time.Time
			maxDL        *int
			archivedAt   *time.Time
			keyMode      int
			batchKeyMode *int
		)
		if err := rows.Scan(&f.ID, &f.OriginalName, &f.StoredName, &f.Size, &f.ContentType,
			&f.UploadedAt, &uploaderID, &uploader,
			&expires, &f.HasPassword, &maxDL, &f.DownloadCount, &archivedAt, &keyMode,
			&f.BatchID, &batchKeyMode); err != nil {
			httpError(w, err, http.StatusInternalServerError)
			return
		}
		f.Keyed = keyMode == keyModeE2EURL
		if batchKeyMode != nil {
			// The batch, not the member, decides how the share is unlocked: a
			// password batch has a reproducible link, a fragment batch does not.
			f.HasPassword = *batchKeyMode == keyModeE2EPassword
			f.Keyed = *batchKeyMode == keyModeE2EURL
		}
		f.UploadedBy = uploaderID
		if uploader != nil {
			f.UploaderName = *uploader
		}
		f.ExpiresAt = expires
		if maxDL != nil {
			f.HasLimit = true
			f.MaxDL = *maxDL
		}
		f.Archived = archivedAt != nil ||
			(expires != nil && time.Now().After(*expires)) ||
			(f.HasLimit && f.DownloadCount >= f.MaxDL)
		f.CanDelete = user.IsAdmin || (uploaderID != nil && *uploaderID == user.ID.String())
		f.IconKind = iconKind(f.ContentType, f.OriginalName)
		if !f.Archived {
			activeCount++
			totalSize += f.Size
		}
		totalDL += f.DownloadCount
		files = append(files, f)
	}
	if err := rows.Err(); err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}

	a.render(w, r, "history.html", map[string]any{
		"Title":       a.tr(r, "title.files") + " · Pyxis",
		"Active":      "files",
		"Files":       files,
		"ActiveCount": activeCount,
		"TotalSize":   totalSize,
		"TotalDL":     totalDL,
	})
}

func (a *App) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if userFromContext(r.Context()) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	next := r.URL.Query().Get("next")
	if !isSafeNext(next) {
		next = "/"
	}
	a.render(w, r, "login.html", map[string]any{
		"Title":       a.tr(r, "title.login") + " · Pyxis",
		"OIDCEnabled": a.getOIDC() != nil,
		"Next":        next,
	})
}

func (a *App) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.PostFormValue("username"))
	password := r.PostFormValue("password")
	next := r.PostFormValue("next")
	if !isSafeNext(next) {
		next = "/"
	}
	if username == "" || password == "" {
		a.renderLoginError(w, r, a.tr(r, "login.err_empty"), next)
		return
	}
	// Two counters gate a login attempt. The narrow one protects a single
	// account from being guessed at; the per-source one bounds how much
	// password hashing any one address can make the server do, which the
	// narrow counter never sees because a new username starts a new key.
	ip := a.clientIP(r)
	limitKey := ip + "|" + strings.ToLower(username)
	sourceKey := "src|" + ip
	if !a.loginLimiter.allow(r.Context(), limitKey) ||
		!a.loginSourceLimiter.allow(r.Context(), sourceKey) {
		a.renderStatus(w, r, http.StatusTooManyRequests, "login.html", map[string]any{
			"Title":       a.tr(r, "title.login") + " · Pyxis",
			"OIDCEnabled": a.getOIDC() != nil,
			"Error":       a.tr(r, "login.too_many"),
			"Next":        next,
		})
		return
	}
	user, hash, err := a.findUserByUsername(r.Context(), username)
	if err != nil || !checkPassword(hash, password) {
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			log.Printf("login lookup: %v", err)
		}
		a.loginLimiter.fail(r.Context(), limitKey)
		a.loginSourceLimiter.fail(r.Context(), sourceKey)
		a.renderLoginError(w, r, a.tr(r, "login.err_invalid"), next)
		return
	}
	a.loginLimiter.reset(r.Context(), limitKey)
	a.loginSourceLimiter.reset(r.Context(), sourceKey)
	// The stored hash may predate Argon2id. This is the only moment the plain
	// password is available to rewrite it with, so take it.
	a.rehashIfLegacy(r.Context(), user.ID, hash, password)
	sid, expires, err := a.createSession(r.Context(), user.ID, nil)
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	setSessionCookie(w, sid, expires, a.cookieSecure)
	log.Printf("local login: %s", user.Username)
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (a *App) renderLoginError(w http.ResponseWriter, r *http.Request, msg, next string) {
	a.renderStatus(w, r, http.StatusUnauthorized, "login.html", map[string]any{
		"Title":       a.tr(r, "title.login") + " · Pyxis",
		"OIDCEnabled": a.getOIDC() != nil,
		"Error":       msg,
		"Next":        next,
	})
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	// POST-only: logout mutates state, and the same-origin middleware only
	// covers non-GET methods — a GET logout would remain CSRF-triggerable
	// via a simple cross-site <img> tag.
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sid := readSessionCookie(r)
	a.deleteSession(r.Context(), sid)
	clearSessionCookie(w, a.cookieSecure)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// --- uploads --------------------------------------------------------------

// rejectUnparsableUpload answers a multipart parse failure with something the
// uploader can act on. httpError sends http.StatusText for the status, so every
// one of these used to arrive as a bare "Bad Request": a file over the size
// limit, a dropped connection and a genuinely malformed request were one
// indistinguishable message, with the actual reason kept in the server log
// where the person uploading could never see it.
func (a *App) rejectUnparsableUpload(w http.ResponseWriter, r *http.Request, err error) {
	var tooBig *http.MaxBytesError
	switch {
	case errors.As(err, &tooBig):
		// The reader's ceiling is maxUpload plus slack for multipart framing,
		// so quote the limit that was actually breached, not the ceiling.
		log.Printf("upload refused: body over the %s limit", humanSize(a.maxUpload))
		http.Error(w, fmt.Sprintf("file is larger than the %s upload limit", humanSize(a.maxUpload)),
			http.StatusRequestEntityTooLarge)
	case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF),
		errors.Is(r.Context().Err(), context.Canceled):
		// The client went away mid-body. Usually nobody is left to read the
		// response, but a proxy can still deliver it, and saying so keeps the
		// log honest about what is a failure and what is a disconnect.
		log.Printf("upload interrupted before the body finished")
		http.Error(w, "the upload was interrupted before it finished; nothing was stored",
			http.StatusBadRequest)
	default:
		httpError(w, fmt.Errorf("parse form: %w", err), http.StatusBadRequest)
	}
}

func (a *App) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user := userFromContext(r.Context())
	r.Body = http.MaxBytesReader(w, r.Body, a.maxUpload+32<<20)

	if err := r.ParseMultipartForm(32 << 20); err != nil {
		a.rejectUnparsableUpload(w, r, err)
		return
	}
	// net/http normally deletes the temp files multipart spills for anything
	// over the 32 MiB memory budget, but it does that through the Request it
	// built itself (server.go: `w.req.MultipartForm`). withOptionalUser hands
	// the chain a *copy* — Request.WithContext is a shallow copy — so
	// ParseMultipartForm above sets MultipartForm on the copy, w.req's stays
	// nil, and the built-in cleanup silently never runs. Every authenticated
	// upload above 32 MiB then leaked its spill file until the container was
	// restarted. Clean up explicitly; this is correct whatever the middleware
	// does, and RemoveAll is safe to call more than once.
	defer func() {
		if r.MultipartForm != nil {
			if err := r.MultipartForm.RemoveAll(); err != nil {
				log.Printf("upload: remove multipart temp files: %v", err)
			}
		}
	}()
	file, _, err := r.FormFile("file")
	if err != nil {
		httpError(w, err, http.StatusBadRequest)
		return
	}
	defer file.Close()

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

	// A batch member inherits expiry, limit and password from the batch row and
	// keeps none of its own: the batch is the share, and leaving these set on
	// the member would create a second, conflicting set of rules for the same
	// bytes. Ownership is checked so a leaked batch id cannot be used to inject
	// files into someone else's link.
	var (
		batch      *batchMeta
		wrappedKey []byte
	)
	if bidStr := r.FormValue("batch_id"); bidStr != "" {
		bid, perr := uuid.Parse(bidStr)
		if perr != nil {
			http.Error(w, "invalid batch_id", http.StatusBadRequest)
			return
		}
		batch, err = a.loadBatchForUpload(r, bid, user.ID.String())
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
		if r.FormValue("e2e") != "1" {
			http.Error(w, "batch uploads must be end-to-end encrypted", http.StatusBadRequest)
			return
		}
		wrappedKey, err = base64.RawURLEncoding.DecodeString(r.FormValue("wrapped_key"))
		if err != nil || len(wrappedKey) != batchWrappedKeyLen {
			http.Error(w, "invalid wrapped_key", http.StatusBadRequest)
			return
		}
		expiresAt, maxDownloads = nil, nil
	}

	// Reserve quota atomically BEFORE writing anything to disk. The request
	// Content-Length is a slight overestimate of the file size (multipart
	// overhead), which is exactly the conservative direction we want; when
	// it's unknown the full per-file maximum is reserved.
	resID, err := a.reserveUpload(r.Context(), user, r.ContentLength)
	if err != nil {
		if errors.Is(err, errQuotaExceeded) {
			http.Error(w, err.Error(), http.StatusInsufficientStorage)
			return
		}
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	reserved := true
	defer func() {
		if reserved {
			a.releaseReservation(resID)
		}
	}()

	id := uuid.New()
	storedName := id.String()
	dstPath := filepath.Join(a.filesDir, storedName)

	dst, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}

	// Uploads are ciphertext, always. The browser encrypted the file under a
	// key the server never sees, so all the server can check is that the
	// blob's length is consistent with a well-formed container — the only
	// statement possible about a payload nobody on this side can read.
	var (
		keyMode      = keyModeE2EURL
		salt         []byte
		authVerifier []byte
		written      int64
		copyErr      error
	)
	if r.FormValue("e2e") != "1" {
		dst.Close()
		_ = os.Remove(dstPath)
		http.Error(w, "uploads must be end-to-end encrypted", http.StatusBadRequest)
		return
	}
	plainSize, perr := strconv.ParseInt(r.FormValue("plain_size"), 10, 64)
	token, terr := base64.RawURLEncoding.DecodeString(r.FormValue("auth_verifier"))
	salt, _ = base64.RawURLEncoding.DecodeString(r.FormValue("auth_salt"))
	// A batch member's key is wrapped under the batch key, so it carries no
	// auth material of its own — the batch row holds the password verifier.
	if batch != nil {
		token, salt = nil, nil
	}
	if len(token) > 0 {
		if terr != nil || len(token) != 32 || len(salt) != encSaltLen {
			dst.Close()
			_ = os.Remove(dstPath)
			http.Error(w, "invalid auth material", http.StatusBadRequest)
			return
		}
		keyMode = keyModeE2EPassword
		sum := sha256.Sum256(token)
		authVerifier = sum[:]
	}
	if perr != nil || plainSize < 0 {
		// Not a size at all — a client bug, not a file the user can shrink.
		dst.Close()
		_ = os.Remove(dstPath)
		http.Error(w, "invalid plain_size", http.StatusBadRequest)
		return
	}
	if plainSize > a.maxUpload {
		dst.Close()
		_ = os.Remove(dstPath)
		http.Error(w, fmt.Sprintf("file is %s; the maximum is %s",
			humanSize(plainSize), humanSize(a.maxUpload)), http.StatusRequestEntityTooLarge)
		return
	}

	// Version 1 is still read — old shares must keep opening — but writing it
	// again would mean storing a file whose length, chunk count and name
	// nothing authenticates, which is the whole reason the manifest exists.
	//
	// Checked after the size limit so an over-large file still gets told its
	// size and the limit, which is the answer the person uploading can act on.
	e2eVersion, verr := strconv.Atoi(r.FormValue("e2e_version"))
	if verr != nil || e2eVersion < e2eMinUploadVersion || e2eVersion > e2eCurrentVersion {
		dst.Close()
		_ = os.Remove(dstPath)
		http.Error(w, fmt.Sprintf("uploads must use e2e_version %d..%d",
			e2eMinUploadVersion, e2eCurrentVersion), http.StatusBadRequest)
		return
	}

	// The manifest is the file's authenticated metadata: it is the AAD of every
	// chunk, so it must be stored byte for byte and handed back unchanged.
	// Re-encoding it — even into equivalent JSON — would make the file
	// permanently undecryptable.
	manifestRaw, merr := base64.RawURLEncoding.DecodeString(r.FormValue("manifest"))
	if merr != nil {
		dst.Close()
		_ = os.Remove(dstPath)
		http.Error(w, "manifest is not base64url", http.StatusBadRequest)
		return
	}
	batchIDForManifest := ""
	if batch != nil {
		batchIDForManifest = batch.ID
	}
	manifest, merr := parseManifest(manifestRaw, plainSize, batchIDForManifest, e2eVersion)
	if merr != nil {
		dst.Close()
		_ = os.Remove(dstPath)
		http.Error(w, merr.Error(), http.StatusBadRequest)
		return
	}

	// A version 3 object begins with its own manifest. Check that it is the one
	// the request declared before storing either, so the row and the file can
	// never describe different things — and write the header through unchanged,
	// because it is covered by the chunks' AAD.
	var headerWritten int64
	if e2eVersion >= e2eVersionV3 {
		head, herr := verifyContainerHeader(file, manifestRaw)
		if herr != nil {
			dst.Close()
			_ = os.Remove(dstPath)
			http.Error(w, herr.Error(), http.StatusBadRequest)
			return
		}
		n, werr := dst.Write(head)
		if werr != nil {
			dst.Close()
			_ = os.Remove(dstPath)
			httpError(w, werr, http.StatusInternalServerError)
			return
		}
		headerWritten = int64(n)
	}

	ctWritten, copyErr := io.Copy(dst, file)
	ctWritten += headerWritten
	if copyErr == nil && ctWritten != e2eCipherLen(plainSize, len(manifestRaw), e2eVersion) {
		copyErr = fmt.Errorf("ciphertext length %d does not match plain_size %d", ctWritten, plainSize)
	}
	written = plainSize

	closeErr := dst.Close()
	if copyErr != nil || closeErr != nil {
		_ = os.Remove(dstPath)
		err := copyErr
		if err == nil {
			err = closeErr
		}
		if strings.Contains(fmt.Sprint(err), "does not match plain_size") {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	if written > a.maxUpload {
		_ = os.Remove(dstPath)
		http.Error(w, fmt.Sprintf("file is %s; the maximum is %s",
			humanSize(written), humanSize(a.maxUpload)), http.StatusRequestEntityTooLarge)
		return
	}

	// Name and type come from the MANIFEST, not from the multipart headers or a
	// side form field. Those are unauthenticated: a downloader has no way to
	// tell whether the name it is shown is the one the sender chose. The
	// manifest travels inside the AAD of every chunk, so taking the stored
	// columns from it keeps what the history page and the landing page display
	// in step with what the browser can actually verify after decrypting.
	contentType := manifest.Type
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	origName := sanitizeName(manifest.Name)

	// Swap the reservation for the real row under the quota lock, re-checking
	// against the actual size.
	err = a.finalizeUpload(r.Context(), user, resID, written, func(tx pgx.Tx) error {
		var batchID *string
		if batch != nil {
			batchID = &batch.ID
		}
		_, err := tx.Exec(r.Context(),
			`INSERT INTO files (id, original_name, stored_name, size_bytes, content_type,
			                    uploaded_by, expires_at, max_downloads,
			                    key_mode, enc_salt, auth_verifier, batch_id, wrapped_key,
			                    e2e_version, manifest)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
			id.String(), origName, storedName, written, contentType,
			user.ID.String(), expiresAt, maxDownloads,
			keyMode, salt, authVerifier, batchID, wrappedKey,
			e2eVersion, manifestRaw)
		return err
	})
	if err != nil {
		// The rollback restored the reservation row; the deferred release
		// removes it.
		_ = os.Remove(dstPath)
		if errors.Is(err, errQuotaExceeded) {
			http.Error(w, err.Error(), http.StatusInsufficientStorage)
			return
		}
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	reserved = false // reservation row consumed by finalizeUpload

	// For URL-keyed files the fragment is the only copy of the secret. In the
	// server-assisted mode it is returned here once and never stored; in E2E
	// mode the client generated the key itself and appends its own fragment.
	// A batch member has no link of its own: the batch link is the share, and
	// the client already holds its fragment from when it created the batch.
	// The fragment is generated in the browser and never reaches the server,
	// so the URL returned here is always fragment-less; the client appends its
	// own key material.
	shareURL := "/files/" + id.String()
	if batch != nil {
		shareURL = "/b/" + batch.ID
	}
	if wantsJSON(r) {
		res := map[string]any{
			"id":          id.String(),
			"name":        origName,
			"size":        written,
			"url":         shareURL,
			"expiresAt":   expiresAt,
			"hasPassword": keyMode == keyModeE2EPassword,
			"keyed":       keyMode == keyModeE2EURL,
		}
		if batch != nil {
			res["batchId"] = batch.ID
			res["hasPassword"] = batch.isPassword()
			res["keyed"] = !batch.isPassword()
		}
		writeJSON(w, http.StatusCreated, res)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// --- public file routes ----------------------------------------------------

type fileMeta struct {
	ID            string
	OriginalName  string
	StoredName    string
	Size          int64
	ContentType   string
	UploadedAt    time.Time
	ExpiresAt     *time.Time
	MaxDownloads  *int
	DownloadCount int
	KeyMode       int
	EncSalt       []byte
	AuthVerifier  []byte
	ArchivedAt    *time.Time
	BatchID       *string
	E2EVersion    int
	Manifest      []byte // authenticated metadata, served back verbatim
}

// dispatchFileRoutes handles /files/{id}, /files/{id}/download, /files/{id}/preview.
func (a *App) dispatchFileRoutes(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/files/")
	idStr, action, _ := strings.Cut(rest, "/")
	id, err := uuid.Parse(idStr)
	if err != nil {
		a.renderGone(w, r, http.StatusNotFound, "dl.not_found")
		return
	}

	fm, err := a.loadFileMeta(r, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			a.renderGone(w, r, http.StatusNotFound, "dl.not_found")
			return
		}
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	// A batch member is reachable only through its batch, which is where the
	// password, expiry and download limit live. Serving it from here would hand
	// out the bytes with none of those checks applied.
	if fm.BatchID != nil {
		if action == "" {
			// Someone following a stale per-file link gets sent to the share.
			http.Redirect(w, r, "/b/"+*fm.BatchID, http.StatusSeeOther)
			return
		}
		http.NotFound(w, r)
		return
	}
	if fm.MaxDownloads != nil && fm.DownloadCount >= *fm.MaxDownloads {
		a.renderGone(w, r, http.StatusGone, "dl.gone_limit")
		return
	}
	if fm.ArchivedAt != nil || (fm.ExpiresAt != nil && time.Now().After(*fm.ExpiresAt)) {
		a.renderGone(w, r, http.StatusGone, "dl.gone_expired")
		return
	}

	switch action {
	case "":
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		a.handleFileLanding(w, r, fm)
	case "raw":
		// GET only: a download is consumed exactly by a counted GET. HEAD
		// probes and other methods must not burn scarce download slots.
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		a.handleFileRaw(w, r, fm)
	default:
		http.NotFound(w, r)
	}
}

func (a *App) loadFileMeta(r *http.Request, id uuid.UUID) (*fileMeta, error) {
	fm := &fileMeta{ID: id.String()}
	err := a.db.QueryRow(r.Context(),
		`SELECT original_name, stored_name, size_bytes, content_type, uploaded_at,
		        expires_at, max_downloads, download_count,
		        key_mode, enc_salt, auth_verifier, archived_at, batch_id,
		        e2e_version, manifest
		 FROM files WHERE id = $1`, id.String()).
		Scan(&fm.OriginalName, &fm.StoredName, &fm.Size, &fm.ContentType, &fm.UploadedAt,
			&fm.ExpiresAt, &fm.MaxDownloads, &fm.DownloadCount,
			&fm.KeyMode, &fm.EncSalt, &fm.AuthVerifier, &fm.ArchivedAt, &fm.BatchID,
			&fm.E2EVersion, &fm.Manifest)
	if err != nil {
		return nil, err
	}
	return fm, nil
}

func (a *App) renderGone(w http.ResponseWriter, r *http.Request, status int, msgKey string) {
	a.renderStatus(w, r, status, "download.html", map[string]any{
		"Title": a.tr(r, "title.download") + " · Pyxis",
		"State": "gone",
		"Gone":  a.tr(r, msgKey),
	})
}

// handleE2EUnlock verifies the client-derived auth token for an E2E password
// file. The password itself never reaches the server — only a token derived
// from it via a KDF branch that cannot yield the encryption key.
func (a *App) handleE2EUnlock(w http.ResponseWriter, r *http.Request, fm *fileMeta) {
	limitKey := a.clientIP(r) + "|" + fm.ID
	if !a.shareLimiter.allow(r.Context(), limitKey) {
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}
	_ = r.ParseForm()
	token, err := base64.RawURLEncoding.DecodeString(r.PostFormValue("auth"))
	if err == nil && len(token) == 32 {
		sum := sha256.Sum256(token)
		if hmac.Equal(sum[:], fm.AuthVerifier) {
			a.shareLimiter.reset(r.Context(), limitKey)
			a.setUnlockCookie(w, fm)
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	a.shareLimiter.fail(r.Context(), limitKey)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// handleFileLanding renders the share landing page, or handles the unlock
// POST for a password share. Every file is end-to-end encrypted, so this is
// always the client-side landing page — the server has nothing to decrypt.
func (a *App) handleFileLanding(w http.ResponseWriter, r *http.Request, fm *fileMeta) {
	if fm.KeyMode == keyModeE2EPassword && r.Method == http.MethodPost {
		a.handleE2EUnlock(w, r, fm)
		return
	}
	a.renderE2ELanding(w, r, fm)
}

// renderE2ELanding renders the landing page for end-to-end encrypted files.
// All key handling happens in the browser; the page only ships metadata and
// (for password links) whether the ciphertext is still gated.
func (a *App) renderE2ELanding(w http.ResponseWriter, r *http.Request, fm *fileMeta) {
	mode := "url"
	if fm.KeyMode == keyModeE2EPassword {
		mode = "password"
	}
	data := map[string]any{
		"Title":      fm.OriginalName + " · Pyxis",
		"State":      "e2e",
		"E2EMode":    mode,
		"Unlocked":   fm.KeyMode == keyModeE2EPassword && a.isUnlocked(r, fm),
		"ID":         fm.ID,
		"Name":       fm.OriginalName,
		"E2EVersion": fm.E2EVersion,
		// Verbatim, exactly as stored: this is the AAD of every chunk, so the
		// browser can only decrypt if these bytes survive the round trip.
		"Manifest":    base64.RawURLEncoding.EncodeToString(fm.Manifest),
		"Size":        fm.Size,
		"ContentType": fm.ContentType,
		"UploadedAt":  fm.UploadedAt,
		"HasLimit":    false,
		"PreviewKind": previewKind(fm.ContentType, fm.Size),
		"IconKind":    iconKind(fm.ContentType, fm.OriginalName),
	}
	if len(fm.EncSalt) > 0 {
		data["AuthSalt"] = base64.RawURLEncoding.EncodeToString(fm.EncSalt)
	}
	if fm.ExpiresAt != nil {
		data["ExpiresAt"] = fm.ExpiresAt.UTC()
	}
	if fm.MaxDownloads != nil {
		data["HasLimit"] = true
		data["MaxDL"] = *fm.MaxDownloads
		data["DownloadsLeft"] = *fm.MaxDownloads - fm.DownloadCount
		data["PreviewKind"] = ""
	}
	a.render(w, r, "download.html", data)
}

// consumeDownload atomically burns one download slot; returns false (having
// written the response) when the link just ran out.
func (a *App) consumeDownload(w http.ResponseWriter, r *http.Request, fm *fileMeta) bool {
	res, err := a.db.Exec(r.Context(),
		`UPDATE files SET download_count = download_count + 1
		 WHERE id = $1
		   AND (max_downloads IS NULL OR download_count < max_downloads)
		   AND (expires_at IS NULL OR expires_at > NOW())`, fm.ID)
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return false
	}
	if res.RowsAffected() == 0 {
		a.renderGone(w, r, http.StatusGone, "dl.gone_limit")
		return false
	}
	return true
}

// archiveIfSpent retires the blob when the final download slot was consumed.
func (a *App) archiveIfSpent(r *http.Request, fm *fileMeta) {
	if fm.MaxDownloads != nil && fm.DownloadCount+1 >= *fm.MaxDownloads {
		a.archiveFile(r.Context(), fm.ID, fm.StoredName)
	}
}

// handleFileRaw serves the stored ciphertext of an end-to-end encrypted file
// verbatim; the browser decrypts locally. Counts as a download.
func (a *App) handleFileRaw(w http.ResponseWriter, r *http.Request, fm *fileMeta) {
	if fm.KeyMode == keyModeE2EPassword && !a.isUnlocked(r, fm) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !a.consumeDownload(w, r, fm) {
		return
	}
	f, err := os.Open(filepath.Join(a.filesDir, fm.StoredName))
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="%s.enc"`, quoteForHeader(fm.OriginalName)))
	http.ServeContent(w, r, fm.OriginalName+".enc", fm.UploadedAt, f)

	a.archiveIfSpent(r, fm)
}

// --- unlock cookies ---------------------------------------------------------

func (a *App) unlockCookieName(id string) string {
	return "pxu_" + strings.ReplaceAll(id, "-", "")
}

func (a *App) unlockToken(fm *fileMeta) string {
	mac := hmac.New(sha256.New, a.unlockKey)
	mac.Write([]byte(fm.ID))
	mac.Write([]byte{0})
	mac.Write(fm.AuthVerifier)
	return hex.EncodeToString(mac.Sum(nil))
}

func (a *App) isUnlocked(r *http.Request, fm *fileMeta) bool {
	c, err := r.Cookie(a.unlockCookieName(fm.ID))
	if err != nil {
		return false
	}
	return hmac.Equal([]byte(c.Value), []byte(a.unlockToken(fm)))
}

func (a *App) setUnlockCookie(w http.ResponseWriter, fm *fileMeta) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.unlockCookieName(fm.ID),
		Value:    a.unlockToken(fm),
		Path:     "/files/" + fm.ID,
		Expires:  time.Now().Add(6 * time.Hour),
		HttpOnly: true,
		Secure:   a.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

// --- delete ---------------------------------------------------------------

func (a *App) handleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user := userFromContext(r.Context())
	idStr := strings.TrimPrefix(r.URL.Path, "/delete/")
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	var (
		stored     string
		uploadedBy *string
	)
	err = a.db.QueryRow(r.Context(),
		`SELECT stored_name, uploaded_by::text FROM files WHERE id = $1`, id.String()).
		Scan(&stored, &uploadedBy)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	if !user.IsAdmin && (uploadedBy == nil || *uploadedBy != user.ID.String()) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if _, err := a.db.Exec(r.Context(), `DELETE FROM files WHERE id = $1`, id.String()); err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	a.removeBlob(stored)
	if wantsJSON(r) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
		return
	}
	http.Redirect(w, r, "/history", http.StatusSeeOther)
}

// removeBlob drops the ciphertext a deleted row pointed at. An archived row's
// blob is already gone, so a missing file is the normal case, not an error.
func (a *App) removeBlob(stored string) {
	if stored == "" {
		return
	}
	if err := os.Remove(filepath.Join(a.filesDir, stored)); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("delete blob %s: %v", stored, err)
	}
}

// maxBulkDelete caps one request. The file list itself is capped at 500 rows,
// so "select all" can never legitimately ask for more than this.
const maxBulkDelete = 500

// handleBulkDelete removes several files in one request — the file list's
// multi-select. Ownership is enforced in the DELETE itself rather than in a
// separate SELECT: a check-then-delete would have to decide what to do when
// only some of the ids pass, and this way a row simply is not touched unless
// the caller may touch it.
func (a *App) handleBulkDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user := userFromContext(r.Context())
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	raw := r.Form["id"]
	if len(raw) > maxBulkDelete {
		http.Error(w, fmt.Sprintf("too many files selected (max %d)", maxBulkDelete),
			http.StatusRequestEntityTooLarge)
		return
	}

	// Placeholders rather than one array parameter: the ids are still bound,
	// never interpolated, and it keeps the query readable in the logs.
	args := make([]any, 0, len(raw)+1)
	holes := make([]string, 0, len(raw))
	seen := make(map[string]bool, len(raw))
	for _, s := range raw {
		id, err := uuid.Parse(s)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if seen[id.String()] {
			continue
		}
		seen[id.String()] = true
		holes = append(holes, fmt.Sprintf("$%d", len(args)+1))
		args = append(args, id.String())
	}
	if len(args) == 0 {
		a.bulkDeleteDone(w, r, 0)
		return
	}

	q := `DELETE FROM files WHERE id IN (` + strings.Join(holes, ",") + `)`
	if !user.IsAdmin {
		q += fmt.Sprintf(" AND uploaded_by = $%d", len(args)+1)
		args = append(args, user.ID.String())
	}
	q += ` RETURNING stored_name`

	rows, err := a.db.Query(r.Context(), q, args...)
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	var stored []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			httpError(w, err, http.StatusInternalServerError)
			return
		}
		stored = append(stored, name)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	// Only once the rows are certainly gone: a blob removed for a DELETE that
	// then failed would leave a listed file that cannot be downloaded.
	for _, name := range stored {
		a.removeBlob(name)
	}
	a.bulkDeleteDone(w, r, len(stored))
}

func (a *App) bulkDeleteDone(w http.ResponseWriter, r *http.Request, n int) {
	if wantsJSON(r) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "deleted", "count": n})
		return
	}
	http.Redirect(w, r, "/history", http.StatusSeeOther)
}

// --- health ---------------------------------------------------------------

func (a *App) handleHealth(w http.ResponseWriter, r *http.Request) {
	if err := a.db.Ping(r.Context()); err != nil {
		http.Error(w, "db unhealthy", http.StatusServiceUnavailable)
		return
	}
	// The schema version is what tells a deploy whether the migrations this
	// binary expects actually ran. Reporting "ok" while the database is a
	// version behind is how a half-finished upgrade goes unnoticed.
	v, err := schemaVersion(r.Context(), a.db)
	if err != nil {
		http.Error(w, "schema unknown", http.StatusServiceUnavailable)
		return
	}
	if v != latestSchemaVersion() {
		http.Error(w, fmt.Sprintf("schema is v%d, this binary needs v%d",
			v, latestSchemaVersion()), http.StatusServiceUnavailable)
		return
	}
	fmt.Fprintf(w, "ok schema=v%d\n", v)
}

// --- helpers --------------------------------------------------------------

// parseExpiry accepts either a preset in hours ("24") or an absolute RFC3339
// timestamp / datetime-local value for arbitrary expiry dates.
func parseExpiry(hoursStr, atStr string) (*time.Time, error) {
	atStr = strings.TrimSpace(atStr)
	if atStr != "" {
		t, err := time.Parse(time.RFC3339, atStr)
		if err != nil {
			// datetime-local fallback (no timezone → treat as UTC)
			t, err = time.Parse("2006-01-02T15:04", atStr)
			if err != nil {
				return nil, fmt.Errorf("expires_at must be RFC3339 or YYYY-MM-DDTHH:MM")
			}
			t = t.UTC()
		}
		if t.Before(time.Now().Add(time.Minute)) {
			return nil, fmt.Errorf("expiry must be in the future")
		}
		if t.After(time.Now().AddDate(5, 0, 0)) {
			return nil, fmt.Errorf("expiry too far in the future (max 5 years)")
		}
		return &t, nil
	}

	hoursStr = strings.TrimSpace(hoursStr)
	if hoursStr == "" || hoursStr == "0" {
		return nil, nil
	}
	hours, err := strconv.Atoi(hoursStr)
	if err != nil {
		return nil, fmt.Errorf("expires_hours must be an integer")
	}
	if hours < 0 || hours > 24*365 {
		return nil, fmt.Errorf("expires_hours out of range")
	}
	t := time.Now().Add(time.Duration(hours) * time.Hour)
	return &t, nil
}

func parseMaxDownloads(v string) (*int, error) {
	v = strings.TrimSpace(v)
	if v == "" || v == "0" {
		return nil, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return nil, fmt.Errorf("max_downloads must be a non-negative integer")
	}
	if n == 0 {
		return nil, nil
	}
	return &n, nil
}

// previewKind decides whether and how a file can be previewed inline.
func previewKind(contentType string, size int64) string {
	ct := strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	switch {
	case ct == "image/svg+xml":
		return "image"
	case strings.HasPrefix(ct, "image/"):
		return "image"
	case strings.HasPrefix(ct, "video/"):
		return "video"
	case strings.HasPrefix(ct, "audio/"):
		return "audio"
	case ct == "application/pdf":
		return "pdf"
	case strings.HasPrefix(ct, "text/"), ct == "application/json", ct == "application/xml":
		if size <= 2<<20 {
			return "text"
		}
	}
	return ""
}

// iconKind picks a file-type icon bucket for lists and the landing page.
func iconKind(contentType, name string) string {
	ct := strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(name), "."))
	switch {
	case strings.HasPrefix(ct, "image/"):
		return "image"
	case strings.HasPrefix(ct, "video/"):
		return "video"
	case strings.HasPrefix(ct, "audio/"):
		return "audio"
	case ct == "application/pdf" || ext == "pdf":
		return "pdf"
	case strings.HasPrefix(ct, "text/"), ct == "application/json", ct == "application/xml":
		return "text"
	}
	switch ext {
	case "zip", "tar", "gz", "tgz", "bz2", "xz", "zst", "7z", "rar":
		return "archive"
	case "doc", "docx", "odt", "xls", "xlsx", "ods", "ppt", "pptx", "odp":
		return "doc"
	}
	return "generic"
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func sanitizeName(name string) string {
	name = filepath.Base(name)
	if name == "." || name == "/" || name == "" {
		return "unnamed"
	}
	return name
}

func quoteForHeader(s string) string {
	r := strings.NewReplacer(`"`, `'`, "\r", "", "\n", "")
	return r.Replace(s)
}
