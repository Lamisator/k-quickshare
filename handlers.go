package main

import (
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
}

// --- pages ----------------------------------------------------------------

func (a *App) handleUploadPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	a.render(w, r, "index.html", map[string]any{
		"Title":     a.tr(r, "title.upload") + " · k-fileshare",
		"Active":    "upload",
		"MaxUpload": a.maxUpload,
	})
}

func (a *App) handleHistory(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())

	// Share IDs are bearer secrets: a regular user must only ever see their
	// own uploads. Admins intentionally get the instance-wide view.
	// Archived rows (blob deleted, metadata kept 30 days) stay listed.
	const baseQuery = `SELECT f.id::text, f.original_name, f.stored_name, f.size_bytes, f.content_type,
		        f.uploaded_at, f.uploaded_by::text, u.username,
		        f.expires_at, (f.password_hash IS NOT NULL OR f.key_mode = 4),
		        f.max_downloads, f.download_count, f.archived_at, f.key_mode
		 FROM files f
		 LEFT JOIN users u ON u.id = f.uploaded_by
		 WHERE (f.archived_at IS NOT NULL OR f.expires_at IS NULL OR f.expires_at > NOW())`
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
			f          File
			uploaderID *string
			uploader   *string
			expires    *time.Time
			maxDL      *int
			archivedAt *time.Time
			keyMode    int
		)
		if err := rows.Scan(&f.ID, &f.OriginalName, &f.StoredName, &f.Size, &f.ContentType,
			&f.UploadedAt, &uploaderID, &uploader,
			&expires, &f.HasPassword, &maxDL, &f.DownloadCount, &archivedAt, &keyMode); err != nil {
			httpError(w, err, http.StatusInternalServerError)
			return
		}
		f.Keyed = keyMode == keyModeURL || keyMode == keyModeE2EURL
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
		"Title":       a.tr(r, "title.files") + " · k-fileshare",
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
		"Title":       a.tr(r, "title.login") + " · k-fileshare",
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
	limitKey := a.clientIP(r) + "|" + strings.ToLower(username)
	if !a.loginLimiter.allow(limitKey) {
		a.renderStatus(w, r, http.StatusTooManyRequests, "login.html", map[string]any{
			"Title":       a.tr(r, "title.login") + " · k-fileshare",
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
		a.loginLimiter.fail(limitKey)
		a.renderLoginError(w, r, a.tr(r, "login.err_invalid"), next)
		return
	}
	a.loginLimiter.reset(limitKey)
	sid, expires, err := a.createSession(r.Context(), user.ID)
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
		"Title":       a.tr(r, "title.login") + " · k-fileshare",
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

func (a *App) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user := userFromContext(r.Context())
	r.Body = http.MaxBytesReader(w, r.Body, a.maxUpload+32<<20)

	if err := r.ParseMultipartForm(32 << 20); err != nil {
		httpError(w, fmt.Errorf("parse form: %w", err), http.StatusBadRequest)
		return
	}
	file, header, err := r.FormFile("file")
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
	password := r.FormValue("password")
	var passwordHash *string
	if password != "" {
		h, err := hashPassword(password)
		if err != nil {
			httpError(w, err, http.StatusInternalServerError)
			return
		}
		passwordHash = &h
	}
	maxDownloads, err := parseMaxDownloads(r.FormValue("max_downloads"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
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

	// Two upload flavors, both leaving the server unable to decrypt at rest:
	//
	// End-to-end (e2e=1, the browser UI): the client already encrypted the
	// blob in the shared chunk format and holds all key material. The server
	// only validates the ciphertext geometry and stores it. For password
	// links the client sends a separately-derived auth token whose hash
	// gates the ciphertext; the password itself never reaches the server.
	//
	// Server-assisted (API/curl uploads of plaintext): the server encrypts
	// with a fresh DEK wrapped either by an HKDF of the URL-fragment secret
	// or by an Argon2id derivation of the password.
	var (
		keyMode      = keyModeURL
		urlSecret    []byte
		salt         []byte
		wrappedDEK   []byte
		authVerifier []byte
		written      int64
		copyErr      error
	)
	if r.FormValue("e2e") == "1" {
		plainSize, perr := strconv.ParseInt(r.FormValue("plain_size"), 10, 64)
		token, terr := base64.RawURLEncoding.DecodeString(r.FormValue("auth_verifier"))
		salt, _ = base64.RawURLEncoding.DecodeString(r.FormValue("auth_salt"))
		keyMode = keyModeE2EURL
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
		if perr != nil || plainSize < 0 || plainSize > a.maxUpload {
			dst.Close()
			_ = os.Remove(dstPath)
			http.Error(w, "invalid plain_size", http.StatusRequestEntityTooLarge)
			return
		}
		var ctWritten int64
		ctWritten, copyErr = io.Copy(dst, file)
		if copyErr == nil && ctWritten != e2eCipherLen(plainSize) {
			copyErr = fmt.Errorf("ciphertext length %d does not match plain_size %d", ctWritten, plainSize)
		}
		written = plainSize
	} else {
		salt = randomBytes(encSaltLen)
		var wrapKey []byte
		if password != "" {
			keyMode = keyModePassword
			wrapKey = derivePasswordWrapKey(password, salt)
		} else {
			urlSecret = randomBytes(urlSecretLen)
			wrapKey, err = deriveURLWrapKey(urlSecret, salt)
			if err != nil {
				dst.Close()
				_ = os.Remove(dstPath)
				httpError(w, err, http.StatusInternalServerError)
				return
			}
		}
		dek := randomBytes(32)
		wrappedDEK, err = wrapKeyWith(wrapKey, dek)
		if err != nil {
			dst.Close()
			_ = os.Remove(dstPath)
			httpError(w, err, http.StatusInternalServerError)
			return
		}
		written, copyErr = encryptStream(dst, file, dek)
	}
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
		http.Error(w, "file exceeds max size", http.StatusRequestEntityTooLarge)
		return
	}

	contentType := header.Header.Get("Content-Type")
	if keyMode == keyModeE2EURL || keyMode == keyModeE2EPassword {
		// The blob arrives as opaque ciphertext; the client passes the real
		// MIME type separately. Passwords are never sent on E2E uploads.
		contentType = r.FormValue("content_type")
		passwordHash = nil
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	origName := sanitizeName(header.Filename)

	// Swap the reservation for the real row under the quota lock, re-checking
	// against the actual size.
	err = a.finalizeUpload(r.Context(), user, resID, written, func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(),
			`INSERT INTO files (id, original_name, stored_name, size_bytes, content_type,
			                    uploaded_by, expires_at, password_hash, max_downloads,
			                    enc_version, enc_key, key_mode, enc_salt, auth_verifier)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
			id.String(), origName, storedName, written, contentType,
			user.ID.String(), expiresAt, passwordHash, maxDownloads,
			encVersionGCM, wrappedDEK, keyMode, salt, authVerifier)
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
	shareURL := "/files/" + id.String()
	if keyMode == keyModeURL {
		shareURL += "#" + base64.RawURLEncoding.EncodeToString(urlSecret)
	}
	if wantsJSON(r) {
		writeJSON(w, http.StatusCreated, map[string]any{
			"id":          id.String(),
			"name":        origName,
			"size":        written,
			"url":         shareURL,
			"expiresAt":   expiresAt,
			"hasPassword": passwordHash != nil || keyMode == keyModeE2EPassword,
			"keyed":       keyMode == keyModeURL || keyMode == keyModeE2EURL,
		})
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
	PasswordHash  *string
	MaxDownloads  *int
	DownloadCount int
	EncVersion    int
	EncKey        []byte
	KeyMode       int
	EncSalt       []byte
	AuthVerifier  []byte
	ArchivedAt    *time.Time
}

func (fm *fileMeta) isE2E() bool {
	return fm.KeyMode == keyModeE2EURL || fm.KeyMode == keyModeE2EPassword
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
	case "download":
		// GET only: a download is consumed exactly by a counted GET. HEAD
		// probes and other methods must not burn scarce download slots.
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		a.handleFileDownload(w, r, fm)
	case "preview":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		a.handleFilePreview(w, r, fm)
	case "raw":
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
		        expires_at, password_hash, max_downloads, download_count,
		        enc_version, enc_key, key_mode, enc_salt, auth_verifier, archived_at
		 FROM files WHERE id = $1`, id.String()).
		Scan(&fm.OriginalName, &fm.StoredName, &fm.Size, &fm.ContentType, &fm.UploadedAt,
			&fm.ExpiresAt, &fm.PasswordHash, &fm.MaxDownloads, &fm.DownloadCount,
			&fm.EncVersion, &fm.EncKey, &fm.KeyMode, &fm.EncSalt, &fm.AuthVerifier, &fm.ArchivedAt)
	if err != nil {
		return nil, err
	}
	return fm, nil
}

func (a *App) renderGone(w http.ResponseWriter, r *http.Request, status int, msgKey string) {
	a.renderStatus(w, r, status, "download.html", map[string]any{
		"Title": a.tr(r, "title.download") + " · k-fileshare",
		"State": "gone",
		"Gone":  a.tr(r, msgKey),
	})
}

// keyCookieName names the per-file cookie that carries the client-held key
// material (URL secret for keyModeURL, derived wrap key for keyModePassword).
func keyCookieName(id string) string {
	return "fsk_" + strings.ReplaceAll(id, "-", "")
}

func (a *App) setKeyCookie(w http.ResponseWriter, fm *fileMeta, value []byte, httpOnly bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     keyCookieName(fm.ID),
		Value:    base64.RawURLEncoding.EncodeToString(value),
		Path:     "/files/" + fm.ID,
		Expires:  time.Now().Add(6 * time.Hour),
		HttpOnly: httpOnly,
		Secure:   a.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func readKeyCookie(r *http.Request, fm *fileMeta) []byte {
	c, err := r.Cookie(keyCookieName(fm.ID))
	if err != nil {
		return nil
	}
	b, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return nil
	}
	return b
}

// passwordUnlocked reports whether the request carries key material that
// actually unwraps the DEK of a password-protected (keyModePassword) file.
func (a *App) passwordUnlocked(r *http.Request, fm *fileMeta) bool {
	wk := readKeyCookie(r, fm)
	if len(wk) != 32 {
		return false
	}
	_, err := unwrapKeyWith(wk, fm.EncKey)
	return err == nil
}

// handleE2EUnlock verifies the client-derived auth token for an E2E password
// file. The password itself never reaches the server — only a token derived
// from it via a KDF branch that cannot yield the encryption key.
func (a *App) handleE2EUnlock(w http.ResponseWriter, r *http.Request, fm *fileMeta) {
	limitKey := a.clientIP(r) + "|" + fm.ID
	if !a.shareLimiter.allow(limitKey) {
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}
	_ = r.ParseForm()
	token, err := base64.RawURLEncoding.DecodeString(r.PostFormValue("auth"))
	if err == nil && len(token) == 32 {
		sum := sha256.Sum256(token)
		if hmac.Equal(sum[:], fm.AuthVerifier) {
			a.shareLimiter.reset(limitKey)
			a.setUnlockCookie(w, fm)
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	a.shareLimiter.fail(limitKey)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// handleFileLanding renders the share landing page (details + preview +
// download button), or the password gate for protected files.
func (a *App) handleFileLanding(w http.ResponseWriter, r *http.Request, fm *fileMeta) {
	if fm.KeyMode == keyModeE2EPassword && r.Method == http.MethodPost {
		a.handleE2EUnlock(w, r, fm)
		return
	}
	if fm.isE2E() {
		a.renderE2ELanding(w, r, fm)
		return
	}

	locked := fm.PasswordHash != nil
	if locked {
		switch fm.KeyMode {
		case keyModePassword:
			locked = !a.passwordUnlocked(r, fm)
		default:
			locked = !a.isUnlocked(r, fm)
		}
	}

	if r.Method == http.MethodPost && locked {
		limitKey := a.clientIP(r) + "|" + fm.ID
		if !a.shareLimiter.allow(limitKey) {
			a.renderStatus(w, r, http.StatusTooManyRequests, "download.html", map[string]any{
				"Title": a.tr(r, "title.download") + " · k-fileshare",
				"State": "locked",
				"ID":    fm.ID,
				"Name":  fm.OriginalName,
				"Size":  fm.Size,
				"Error": a.tr(r, "dl.too_many"),
			})
			return
		}
		_ = r.ParseForm()
		submitted := r.PostFormValue("password")
		if submitted != "" && checkPassword(*fm.PasswordHash, submitted) {
			a.shareLimiter.reset(limitKey)
			if fm.KeyMode == keyModePassword {
				// Hand the browser the Argon2id-derived wrap key so follow-up
				// preview/download requests can unwrap the DEK without the
				// server ever holding a stored copy.
				wk := derivePasswordWrapKey(submitted, fm.EncSalt)
				if _, err := unwrapKeyWith(wk, fm.EncKey); err != nil {
					httpError(w, fmt.Errorf("password verified but DEK unwrap failed: %w", err),
						http.StatusInternalServerError)
					return
				}
				a.setKeyCookie(w, fm, wk, true)
			} else {
				a.setUnlockCookie(w, fm)
			}
			http.Redirect(w, r, "/files/"+fm.ID, http.StatusSeeOther)
			return
		}
		a.shareLimiter.fail(limitKey)
		a.renderStatus(w, r, http.StatusUnauthorized, "download.html", map[string]any{
			"Title": a.tr(r, "title.download") + " · k-fileshare",
			"State": "locked",
			"ID":    fm.ID,
			"Name":  fm.OriginalName,
			"Size":  fm.Size,
			"Error": a.tr(r, "dl.wrong_pw"),
		})
		return
	}

	if locked {
		a.render(w, r, "download.html", map[string]any{
			"Title": a.tr(r, "title.download") + " · k-fileshare",
			"State": "locked",
			"ID":    fm.ID,
			"Name":  fm.OriginalName,
			"Size":  fm.Size,
		})
		return
	}

	data := map[string]any{
		"Title":       fm.OriginalName + " · k-fileshare",
		"State":       "ready",
		"ID":          fm.ID,
		"Name":        fm.OriginalName,
		"Size":        fm.Size,
		"ContentType": fm.ContentType,
		"UploadedAt":  fm.UploadedAt,
		"HasLimit":    false,
		"PreviewKind": previewKind(fm.ContentType, fm.Size),
		"IconKind":    iconKind(fm.ContentType, fm.OriginalName),
		"Keyed":       fm.KeyMode == keyModeURL,
		"KeyCookie":   keyCookieName(fm.ID),
	}
	if fm.ExpiresAt != nil {
		data["ExpiresAt"] = fm.ExpiresAt.UTC()
	}
	if fm.MaxDownloads != nil {
		data["HasLimit"] = true
		data["MaxDL"] = *fm.MaxDownloads
		data["DownloadsLeft"] = *fm.MaxDownloads - fm.DownloadCount
		// Previews stream the original bytes without consuming a download
		// slot, which would let recipients bypass the limit — so download-
		// limited files get no preview.
		data["PreviewKind"] = ""
	}
	a.render(w, r, "download.html", data)
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
		"Title":       fm.OriginalName + " · k-fileshare",
		"State":       "e2e",
		"E2EMode":     mode,
		"Unlocked":    fm.KeyMode == keyModeE2EPassword && a.isUnlocked(r, fm),
		"ID":          fm.ID,
		"Name":        fm.OriginalName,
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
	if !fm.isE2E() {
		http.NotFound(w, r)
		return
	}
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

// resolveDEK authorizes the request AND produces the file's decryption key.
// Key material arrives via the per-file cookie or, for curl/API use, via the
// X-Share-Key (URL secret) / X-Share-Password headers — never query strings,
// which end up in browser history, proxy logs and monitoring systems. On
// failure it has already written a response (redirect to the landing page,
// or 429). For plaintext legacy files it returns (nil, true).
func (a *App) resolveDEK(w http.ResponseWriter, r *http.Request, fm *fileMeta) ([]byte, bool) {
	limitKey := a.clientIP(r) + "|" + fm.ID

	switch fm.KeyMode {
	case keyModeURL:
		secret := readKeyCookie(r, fm)
		if secret == nil {
			if h := r.Header.Get("X-Share-Key"); h != "" {
				secret, _ = base64.RawURLEncoding.DecodeString(h)
			}
		}
		if len(secret) != urlSecretLen {
			http.Redirect(w, r, "/files/"+fm.ID, http.StatusSeeOther)
			return nil, false
		}
		if !a.shareLimiter.allow(limitKey) {
			http.Error(w, "too many attempts", http.StatusTooManyRequests)
			return nil, false
		}
		wk, err := deriveURLWrapKey(secret, fm.EncSalt)
		if err != nil {
			httpError(w, err, http.StatusInternalServerError)
			return nil, false
		}
		dek, err := unwrapKeyWith(wk, fm.EncKey)
		if err != nil {
			a.shareLimiter.fail(limitKey)
			http.Redirect(w, r, "/files/"+fm.ID, http.StatusSeeOther)
			return nil, false
		}
		a.shareLimiter.reset(limitKey)
		return dek, true

	case keyModePassword:
		if wk := readKeyCookie(r, fm); len(wk) == 32 {
			if dek, err := unwrapKeyWith(wk, fm.EncKey); err == nil {
				return dek, true
			}
		}
		if pw := r.Header.Get("X-Share-Password"); pw != "" {
			if !a.shareLimiter.allow(limitKey) {
				http.Error(w, "too many attempts", http.StatusTooManyRequests)
				return nil, false
			}
			wk := derivePasswordWrapKey(pw, fm.EncSalt)
			if dek, err := unwrapKeyWith(wk, fm.EncKey); err == nil {
				a.shareLimiter.reset(limitKey)
				return dek, true
			}
			a.shareLimiter.fail(limitKey)
		}
		http.Redirect(w, r, "/files/"+fm.ID, http.StatusSeeOther)
		return nil, false

	default: // keyModeKEK: legacy files, server-held key, bcrypt password gate
		if fm.PasswordHash != nil && !a.isUnlocked(r, fm) {
			if submitted := r.Header.Get("X-Share-Password"); submitted != "" {
				if !a.shareLimiter.allow(limitKey) {
					http.Error(w, "too many attempts", http.StatusTooManyRequests)
					return nil, false
				}
				if !checkPassword(*fm.PasswordHash, submitted) {
					a.shareLimiter.fail(limitKey)
					http.Redirect(w, r, "/files/"+fm.ID, http.StatusSeeOther)
					return nil, false
				}
				a.shareLimiter.reset(limitKey)
			} else {
				http.Redirect(w, r, "/files/"+fm.ID, http.StatusSeeOther)
				return nil, false
			}
		}
		if fm.EncVersion == encVersionPlain {
			return nil, true
		}
		dek, err := a.unwrapDEK(fm.EncKey)
		if err != nil {
			httpError(w, err, http.StatusInternalServerError)
			return nil, false
		}
		return dek, true
	}
}

func (a *App) handleFileDownload(w http.ResponseWriter, r *http.Request, fm *fileMeta) {
	if fm.isE2E() {
		// Plaintext exists only client-side; the landing page drives the
		// decrypting download via /raw.
		http.Redirect(w, r, "/files/"+fm.ID, http.StatusSeeOther)
		return
	}
	dek, ok := a.resolveDEK(w, r, fm)
	if !ok {
		return
	}
	if !a.consumeDownload(w, r, fm) {
		return
	}
	a.serveFileBlob(w, r, fm, dek, true)

	// If this consumed the final download slot, retire the blob right away:
	// the row stays listed as expired for 30 days, but the bytes are gone.
	a.archiveIfSpent(r, fm)
}

// handleFilePreview streams the file inline for the landing-page preview.
// Previews don't consume download slots, so files with a download limit are
// never previewable (the bytes would bypass the limit). Script execution is
// blocked via a sandboxing CSP so user uploads can't run code on this origin.
func (a *App) handleFilePreview(w http.ResponseWriter, r *http.Request, fm *fileMeta) {
	if fm.MaxDownloads != nil || fm.isE2E() {
		http.NotFound(w, r)
		return
	}
	dek, ok := a.resolveDEK(w, r, fm)
	if !ok {
		return
	}
	if previewKind(fm.ContentType, fm.Size) == "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'; media-src 'self'; img-src 'self'; object-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'self'")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	a.serveFileBlob(w, r, fm, dek, false)
}

func (a *App) serveFileBlob(w http.ResponseWriter, r *http.Request, fm *fileMeta, dek []byte, attachment bool) {
	content, closer, err := a.openFileBlob(fm, dek)
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	defer closer.Close()

	contentType := fm.ContentType
	disposition := "inline"
	if attachment {
		disposition = "attachment"
	} else if previewKind(fm.ContentType, fm.Size) == "text" {
		// Never render user-supplied markup (e.g. text/html) on this origin.
		contentType = "text/plain; charset=utf-8"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`%s; filename="%s"`, disposition, quoteForHeader(fm.OriginalName)))
	http.ServeContent(w, r, fm.OriginalName, fm.UploadedAt, content)
}

// --- unlock cookies ---------------------------------------------------------

func (a *App) unlockCookieName(id string) string {
	return "fsu_" + strings.ReplaceAll(id, "-", "")
}

func (a *App) unlockToken(fm *fileMeta) string {
	mac := hmac.New(sha256.New, a.unlockKey)
	mac.Write([]byte(fm.ID))
	mac.Write([]byte{0})
	if fm.PasswordHash != nil {
		mac.Write([]byte(*fm.PasswordHash))
	} else if len(fm.AuthVerifier) > 0 {
		mac.Write(fm.AuthVerifier)
	}
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
	if err := os.Remove(filepath.Join(a.filesDir, stored)); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("delete blob %s: %v", stored, err)
	}
	if wantsJSON(r) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
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
	fmt.Fprintln(w, "ok")
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
