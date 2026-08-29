package main

import (
	"crypto/hmac"
	"crypto/sha256"
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
	MaxDownloads  *int
	DownloadCount int
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
	rows, err := a.db.Query(r.Context(),
		`SELECT f.id::text, f.original_name, f.stored_name, f.size_bytes, f.content_type,
		        f.uploaded_at, f.uploaded_by::text, u.username,
		        f.expires_at, (f.password_hash IS NOT NULL),
		        f.max_downloads, f.download_count
		 FROM files f
		 LEFT JOIN users u ON u.id = f.uploaded_by
		 WHERE f.expires_at IS NULL OR f.expires_at > NOW()
		 ORDER BY f.uploaded_at DESC
		 LIMIT 500`)
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var (
		files     []File
		totalSize int64
		totalDL   int
	)
	for rows.Next() {
		var (
			f          File
			uploaderID *string
			uploader   *string
			expires    *time.Time
			maxDL      *int
		)
		if err := rows.Scan(&f.ID, &f.OriginalName, &f.StoredName, &f.Size, &f.ContentType,
			&f.UploadedAt, &uploaderID, &uploader,
			&expires, &f.HasPassword, &maxDL, &f.DownloadCount); err != nil {
			httpError(w, err, http.StatusInternalServerError)
			return
		}
		f.UploadedBy = uploaderID
		if uploader != nil {
			f.UploaderName = *uploader
		}
		f.ExpiresAt = expires
		f.MaxDownloads = maxDL
		f.CanDelete = user.IsAdmin || (uploaderID != nil && *uploaderID == user.ID.String())
		f.IconKind = iconKind(f.ContentType, f.OriginalName)
		totalSize += f.Size
		totalDL += f.DownloadCount
		files = append(files, f)
	}
	if err := rows.Err(); err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}

	a.render(w, r, "history.html", map[string]any{
		"Title":     a.tr(r, "title.files") + " · k-fileshare",
		"Active":    "files",
		"Files":     files,
		"TotalSize": totalSize,
		"TotalDL":   totalDL,
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
	user, hash, err := a.findUserByUsername(r.Context(), username)
	if err != nil || !checkPassword(hash, password) {
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			log.Printf("login lookup: %v", err)
		}
		a.renderLoginError(w, r, a.tr(r, "login.err_invalid"), next)
		return
	}
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

	id := uuid.New()
	storedName := id.String()
	dstPath := filepath.Join(a.filesDir, storedName)

	dst, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	written, copyErr := io.Copy(dst, file)
	closeErr := dst.Close()
	if copyErr != nil || closeErr != nil {
		_ = os.Remove(dstPath)
		err := copyErr
		if err == nil {
			err = closeErr
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
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	origName := sanitizeName(header.Filename)

	_, err = a.db.Exec(r.Context(),
		`INSERT INTO files (id, original_name, stored_name, size_bytes, content_type,
		                    uploaded_by, expires_at, password_hash, max_downloads)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		id.String(), origName, storedName, written, contentType,
		user.ID.String(), expiresAt, passwordHash, maxDownloads)
	if err != nil {
		_ = os.Remove(dstPath)
		httpError(w, err, http.StatusInternalServerError)
		return
	}

	shareURL := "/files/" + id.String()
	if wantsJSON(r) {
		writeJSON(w, http.StatusCreated, map[string]any{
			"id":          id.String(),
			"name":        origName,
			"size":        written,
			"url":         shareURL,
			"expiresAt":   expiresAt,
			"hasPassword": passwordHash != nil,
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
	if fm.ExpiresAt != nil && time.Now().After(*fm.ExpiresAt) {
		a.renderGone(w, r, http.StatusGone, "dl.gone_expired")
		return
	}
	if fm.MaxDownloads != nil && fm.DownloadCount >= *fm.MaxDownloads {
		a.renderGone(w, r, http.StatusGone, "dl.gone_limit")
		return
	}

	switch action {
	case "":
		a.handleFileLanding(w, r, fm)
	case "download":
		a.handleFileDownload(w, r, fm)
	case "preview":
		a.handleFilePreview(w, r, fm)
	default:
		http.NotFound(w, r)
	}
}

func (a *App) loadFileMeta(r *http.Request, id uuid.UUID) (*fileMeta, error) {
	fm := &fileMeta{ID: id.String()}
	err := a.db.QueryRow(r.Context(),
		`SELECT original_name, stored_name, size_bytes, content_type, uploaded_at,
		        expires_at, password_hash, max_downloads, download_count
		 FROM files WHERE id = $1`, id.String()).
		Scan(&fm.OriginalName, &fm.StoredName, &fm.Size, &fm.ContentType, &fm.UploadedAt,
			&fm.ExpiresAt, &fm.PasswordHash, &fm.MaxDownloads, &fm.DownloadCount)
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

// handleFileLanding renders the share landing page (details + preview +
// download button), or the password gate for protected files.
func (a *App) handleFileLanding(w http.ResponseWriter, r *http.Request, fm *fileMeta) {
	locked := fm.PasswordHash != nil && !a.isUnlocked(r, fm)

	if r.Method == http.MethodPost && locked {
		_ = r.ParseForm()
		submitted := r.PostFormValue("password")
		if submitted != "" && checkPassword(*fm.PasswordHash, submitted) {
			a.setUnlockCookie(w, fm)
			http.Redirect(w, r, "/files/"+fm.ID, http.StatusSeeOther)
			return
		}
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
	}
	if fm.ExpiresAt != nil {
		data["ExpiresAt"] = fm.ExpiresAt.UTC()
	}
	if fm.MaxDownloads != nil {
		data["HasLimit"] = true
		data["MaxDL"] = *fm.MaxDownloads
		data["DownloadsLeft"] = *fm.MaxDownloads - fm.DownloadCount
	}
	a.render(w, r, "download.html", data)
}

// checkFileAccess enforces the password on the raw endpoints. Accepts the
// unlock cookie (set by the landing page) or an explicit password via form or
// query string (for curl-style use).
func (a *App) checkFileAccess(w http.ResponseWriter, r *http.Request, fm *fileMeta) bool {
	if fm.PasswordHash == nil || a.isUnlocked(r, fm) {
		return true
	}
	submitted := r.URL.Query().Get("password")
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err == nil && r.PostFormValue("password") != "" {
			submitted = r.PostFormValue("password")
		}
	}
	if submitted != "" && checkPassword(*fm.PasswordHash, submitted) {
		return true
	}
	http.Redirect(w, r, "/files/"+fm.ID, http.StatusSeeOther)
	return false
}

func (a *App) handleFileDownload(w http.ResponseWriter, r *http.Request, fm *fileMeta) {
	if !a.checkFileAccess(w, r, fm) {
		return
	}
	res, err := a.db.Exec(r.Context(),
		`UPDATE files SET download_count = download_count + 1
		 WHERE id = $1
		   AND (max_downloads IS NULL OR download_count < max_downloads)
		   AND (expires_at IS NULL OR expires_at > NOW())`, fm.ID)
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	if res.RowsAffected() == 0 {
		a.renderGone(w, r, http.StatusGone, "dl.gone_limit")
		return
	}
	a.serveFileBlob(w, r, fm, true)
}

// handleFilePreview streams the file inline for the landing-page preview.
// It does not count against the download limit; script execution is blocked
// via a sandboxing CSP so user uploads can't run code on this origin.
func (a *App) handleFilePreview(w http.ResponseWriter, r *http.Request, fm *fileMeta) {
	if !a.checkFileAccess(w, r, fm) {
		return
	}
	if previewKind(fm.ContentType, fm.Size) == "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'; media-src 'self'; img-src 'self'; object-src 'self'; style-src 'unsafe-inline'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	a.serveFileBlob(w, r, fm, false)
}

func (a *App) serveFileBlob(w http.ResponseWriter, r *http.Request, fm *fileMeta, attachment bool) {
	path := filepath.Join(a.filesDir, fm.StoredName)
	f, err := os.Open(path)
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	defer f.Close()

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
	http.ServeContent(w, r, fm.OriginalName, fm.UploadedAt, f)
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
