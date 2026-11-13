package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// /api/v1 — sharing files from programs, AI agents above all.
//
// Two ways in, and they differ in who holds the key:
//
//	POST /api/v1/shares    plaintext in, link out. The SERVER seals it (seal.go),
//	                       returns the key in the link's fragment and forgets it.
//	                       Easy for anything that can make an HTTP request, and
//	                       the only option for an MCP client. Not end-to-end:
//	                       the download page says so.
//	POST /api/v1/batches   the browser's own protocol, for a client that
//	POST /api/v1/upload    encrypts locally — `pyxis share` does. End-to-end in
//	POST /api/v1/batches/{id}/roster   the full sense; the server sees ciphertext.
//
// Either way a program gets the WHOLE link back, origin included, and links
// made here expire after apiDefaultExpiryHours unless the request says
// otherwise: a link handed to an agent tends to be needed once, briefly, and
// then forgotten somewhere it was pasted.

const (
	apiDefaultExpiryHours = 24
	apiMaxFilesPerShare   = 100
)

func apiError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// publicBaseURL is the origin share links are built on. PUBLIC_URL wins; the
// fallback trusts the request's Host, which is right behind a proxy that
// forwards it unchanged and is why PUBLIC_URL is recommended.
func (a *App) publicBaseURL(r *http.Request) string {
	if a.publicURL != "" {
		return a.publicURL
	}
	scheme := "http"
	if a.cookieSecure || r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func (a *App) dispatchAPI(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1"), "/")
	head, rest, _ := strings.Cut(path, "/")
	switch {
	case path == "" && r.Method == http.MethodGet:
		a.handleAPIIndex(w, r)
	case path == "shares" && r.Method == http.MethodPost:
		a.handleAPICreateShare(w, r)
	case path == "shares" && r.Method == http.MethodGet:
		a.handleAPIListShares(w, r)
	case head == "shares" && rest != "" && !strings.Contains(rest, "/") && r.Method == http.MethodDelete:
		a.handleAPIDeleteShare(w, r, rest)
	case path == "batches" && r.Method == http.MethodPost:
		// Links made by a program default to a short life; one that asks for
		// something else (including 0, "never") gets what it asked for.
		if err := r.ParseForm(); err != nil {
			apiError(w, http.StatusBadRequest, "bad form")
			return
		}
		if r.Form.Get("expires_hours") == "" && r.Form.Get("expires_at") == "" {
			r.Form.Set("expires_hours", strconv.Itoa(apiDefaultExpiryHours))
		}
		a.handleCreateBatch(w, r)
	case head == "batches" && strings.HasSuffix(rest, "/roster") && r.Method == http.MethodPost:
		id, err := uuid.Parse(strings.TrimSuffix(rest, "/roster"))
		if err != nil {
			apiError(w, http.StatusNotFound, "batch not found")
			return
		}
		a.handleBatchRosterUpdate(w, r, id)
	case path == "upload" && r.Method == http.MethodPost:
		// storeUpload answers JSON only when asked to.
		r.Header.Set("Accept", "application/json")
		a.handleUpload(w, r)
	default:
		apiError(w, http.StatusNotFound, "no such endpoint; GET /api/v1 lists them")
	}
}

func (a *App) handleAPIIndex(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"service": "pyxis",
		"user":    user.Username,
		"base":    a.publicBaseURL(r),
		"mcp":     a.publicBaseURL(r) + "/mcp",
		"defaults": map[string]any{
			"expiresHours":       apiDefaultExpiryHours,
			"serverSealMaxBytes": a.sealMaxBytes,
			"maxFileBytes":       a.maxUploadFor(user),
		},
		"endpoints": map[string]string{
			"POST /api/v1/shares":              "share files (multipart, JSON or a raw body); the server encrypts them and returns the full link",
			"GET /api/v1/shares":               "list shares made through the API",
			"DELETE /api/v1/shares/{id}":       "revoke a share now",
			"POST /api/v1/batches":             "end-to-end: open a batch for client-side encrypted uploads",
			"POST /api/v1/upload":              "end-to-end: upload one encrypted member",
			"POST /api/v1/batches/{id}/roster": "end-to-end: store the sealed member list",
		},
	})
}

// --- server-sealed shares ---------------------------------------------------

// plainFile is one file of a server-sealed share, held in memory for the
// length of the request and wiped after it is sealed.
type plainFile struct {
	Name string
	Type string
	Data []byte
}

type shareOptions struct {
	ExpiresHours string
	ExpiresAt    string
	MaxDownloads string
}

type sharedFile struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Size int64  `json:"size"`
	Type string `json:"type"`
}

type sharedResult struct {
	ID           string       `json:"id"`
	URL          string       `json:"url"`
	ExpiresAt    *time.Time   `json:"expiresAt"`
	MaxDownloads *int         `json:"maxDownloads"`
	Files        []sharedFile `json:"files"`
	ServerSealed bool         `json:"serverSealed"`
	Notice       string       `json:"notice"`
}

const serverSealedNotice = "The url is the only copy of the decryption key (after #). " +
	"Return it in full; without the fragment the files cannot be opened. " +
	"This share was encrypted by the server, not end-to-end: its download page says so."

// apiStatusError carries the HTTP status a sealing failure should map to.
type apiStatusError struct {
	status int
	msg    string
}

func (e *apiStatusError) Error() string { return e.msg }

func statusErr(status int, format string, args ...any) error {
	return &apiStatusError{status: status, msg: fmt.Sprintf(format, args...)}
}

func writeAPIErr(w http.ResponseWriter, err error) {
	var se *apiStatusError
	switch {
	case errors.As(err, &se):
		apiError(w, se.status, se.msg)
	case errors.Is(err, errQuotaExceeded):
		apiError(w, http.StatusInsufficientStorage, err.Error())
	default:
		httpError(w, err, http.StatusInternalServerError)
	}
}

// handleAPICreateShare accepts plaintext three ways:
//
//	multipart/form-data   one or more "file" parts, plus expires_hours,
//	                      expires_at, max_downloads fields (curl -F file=@x)
//	application/json      {"files":[{"name","text"|"content_base64","content_type"}],
//	                       "expires_hours", "expires_at", "max_downloads"}
//	anything else         the raw body is one file; ?name= names it, and the
//	                      options are query parameters (curl --data-binary @x)
//
// The plaintext is read into memory and never written to disk.
func (a *App) handleAPICreateShare(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())
	limit := a.sealMaxBytes
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))

	var (
		files []plainFile
		opts  shareOptions
		err   error
	)
	switch ct {
	case "multipart/form-data":
		r.Body = http.MaxBytesReader(w, r.Body, limit+1<<20)
		files, opts, err = readMultipartPlain(r, limit)
	case "application/json":
		// base64 is 4/3 the size of what it encodes.
		r.Body = http.MaxBytesReader(w, r.Body, limit/3*4+1<<20)
		files, opts, err = readJSONPlain(r.Body, limit)
	default:
		r.Body = http.MaxBytesReader(w, r.Body, limit+1)
		q := r.URL.Query()
		opts = shareOptions{q.Get("expires_hours"), q.Get("expires_at"), q.Get("max_downloads")}
		var data []byte
		data, err = io.ReadAll(r.Body)
		if err == nil {
			files = []plainFile{{Name: q.Get("name"), Type: q.Get("content_type"), Data: data}}
			if files[0].Type == "" && ct != "" && ct != "application/x-www-form-urlencoded" {
				files[0].Type = r.Header.Get("Content-Type")
			}
		}
	}
	defer wipeFiles(files)
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			err = statusErr(http.StatusRequestEntityTooLarge,
				"a server-sealed share holds at most %s; use `pyxis share` (end-to-end, streamed) for more",
				humanSize(limit))
		}
		writeAPIErr(w, err)
		return
	}
	res, err := a.sealShare(r.Context(), r, user, opts, files)
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, res)
}

func wipeFiles(files []plainFile) {
	for _, f := range files {
		wipe(f.Data)
	}
}

// readMultipartPlain streams the parts instead of calling ParseMultipartForm,
// which would spill anything over its memory budget to a temp file — and this
// is plaintext.
func readMultipartPlain(r *http.Request, limit int64) ([]plainFile, shareOptions, error) {
	var (
		files []plainFile
		opts  shareOptions
		total int64
	)
	mr, err := r.MultipartReader()
	if err != nil {
		return nil, opts, statusErr(http.StatusBadRequest, "malformed multipart body")
	}
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return files, opts, err
		}
		if part.FileName() == "" {
			v, err := io.ReadAll(io.LimitReader(part, 256))
			if err != nil {
				return files, opts, err
			}
			switch part.FormName() {
			case "expires_hours":
				opts.ExpiresHours = string(v)
			case "expires_at":
				opts.ExpiresAt = string(v)
			case "max_downloads":
				opts.MaxDownloads = string(v)
			}
			continue
		}
		var buf bytes.Buffer
		n, err := io.Copy(&buf, io.LimitReader(part, limit-total+1))
		if err != nil {
			wipe(buf.Bytes())
			return files, opts, err
		}
		total += n
		files = append(files, plainFile{Name: part.FileName(),
			Type: part.Header.Get("Content-Type"), Data: buf.Bytes()})
		if total > limit {
			return files, opts, &http.MaxBytesError{Limit: limit}
		}
	}
	return files, opts, nil
}

// shareFileJSON is one file in a JSON share request — also the MCP tool input.
type shareFileJSON struct {
	Name          string  `json:"name"`
	Text          *string `json:"text,omitempty"`
	ContentBase64 *string `json:"content_base64,omitempty"`
	ContentType   string  `json:"content_type,omitempty"`
}

type shareRequestJSON struct {
	Files        []shareFileJSON `json:"files"`
	ExpiresHours *json.Number    `json:"expires_hours,omitempty"`
	ExpiresAt    string          `json:"expires_at,omitempty"`
	MaxDownloads *json.Number    `json:"max_downloads,omitempty"`
}

func (q shareRequestJSON) options() shareOptions {
	o := shareOptions{ExpiresAt: q.ExpiresAt}
	if q.ExpiresHours != nil {
		o.ExpiresHours = q.ExpiresHours.String()
	}
	if q.MaxDownloads != nil {
		o.MaxDownloads = q.MaxDownloads.String()
	}
	return o
}

func readJSONPlain(body io.Reader, limit int64) ([]plainFile, shareOptions, error) {
	var req shareRequestJSON
	dec := json.NewDecoder(body)
	dec.UseNumber()
	if err := dec.Decode(&req); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return nil, shareOptions{}, err
		}
		return nil, shareOptions{}, statusErr(http.StatusBadRequest, "invalid JSON: %v", err)
	}
	files, err := decodeJSONFiles(req.Files, limit)
	return files, req.options(), err
}

func decodeJSONFiles(in []shareFileJSON, limit int64) ([]plainFile, error) {
	var (
		files []plainFile
		total int64
	)
	for i, f := range in {
		var data []byte
		switch {
		case f.Text != nil && f.ContentBase64 != nil:
			return files, statusErr(http.StatusBadRequest, "files[%d]: give text or content_base64, not both", i)
		case f.Text != nil:
			data = []byte(*f.Text)
			if f.ContentType == "" {
				f.ContentType = "text/plain; charset=utf-8"
			}
		case f.ContentBase64 != nil:
			var err error
			data, err = base64.StdEncoding.DecodeString(strings.TrimSpace(*f.ContentBase64))
			if err != nil {
				return files, statusErr(http.StatusBadRequest, "files[%d]: content_base64 is not standard base64", i)
			}
		default:
			return files, statusErr(http.StatusBadRequest, "files[%d]: text or content_base64 is required", i)
		}
		total += int64(len(data))
		files = append(files, plainFile{Name: f.Name, Type: f.ContentType, Data: data})
		if total > limit {
			return files, &http.MaxBytesError{Limit: limit}
		}
	}
	return files, nil
}

// sealShare encrypts files into a new URL-keyed batch, exactly as a browser
// would, stores the ciphertext, and returns the full link. The secret exists
// only inside this call and in the returned URL.
func (a *App) sealShare(ctx context.Context, r *http.Request, user *User, opts shareOptions, files []plainFile) (*sharedResult, error) {
	if len(files) == 0 {
		return nil, statusErr(http.StatusBadRequest, "no files: send at least one")
	}
	if len(files) > apiMaxFilesPerShare {
		return nil, statusErr(http.StatusBadRequest, "at most %d files per share", apiMaxFilesPerShare)
	}
	if opts.ExpiresHours == "" && opts.ExpiresAt == "" {
		opts.ExpiresHours = strconv.Itoa(apiDefaultExpiryHours)
	}
	expiresAt, err := parseExpiry(opts.ExpiresHours, opts.ExpiresAt)
	if err != nil {
		return nil, statusErr(http.StatusBadRequest, "%v", err)
	}
	maxDownloads, err := parseMaxDownloads(opts.MaxDownloads)
	if err != nil {
		return nil, statusErr(http.StatusBadRequest, "%v", err)
	}
	ceiling := a.maxUploadFor(user)
	for i := range files {
		f := &files[i]
		f.Name = strings.TrimSpace(f.Name)
		if f.Name == "" {
			f.Name = fmt.Sprintf("file-%d%s", i+1, extensionFor(f.Type))
		}
		f.Name = sanitizeName(f.Name)
		if f.Type == "" {
			f.Type = sniffType(f.Name, f.Data)
		}
		if int64(len(f.Data)) > ceiling {
			return nil, statusErr(http.StatusRequestEntityTooLarge,
				"%s is %s; the maximum is %s", f.Name, humanSize(int64(len(f.Data))), humanSize(ceiling))
		}
	}

	keys, err := newShareKeys()
	if err != nil {
		return nil, err
	}
	defer keys.forget()

	batchID, err := a.insertBatch(ctx, newBatch{
		owner: user, tokenID: apiTokenIDFromContext(ctx),
		expiresAt: expiresAt, maxDownloads: maxDownloads,
		keyMode: keyModeE2EURL, serverSealed: true,
	})
	if err != nil {
		return nil, err
	}
	var stored []string
	ok := false
	defer func() {
		if ok {
			return
		}
		// Nothing half-made survives: the batch row takes its members with it.
		if _, err := a.db.Exec(context.Background(), `DELETE FROM batches WHERE id = $1`, batchID); err != nil {
			log.Printf("api share cleanup %s: %v", batchID[:8], err)
		}
		a.removeBlobs(stored)
	}()

	entries := map[string]rosterEntry{}
	out := &sharedResult{ID: batchID, ExpiresAt: expiresAt, MaxDownloads: maxDownloads,
		ServerSealed: true, Notice: serverSealedNotice}
	for _, f := range files {
		rowID, entry, err := a.sealMember(ctx, user, keys, batchID, f)
		if rowID != "" {
			stored = append(stored, rowID)
		}
		if err != nil {
			return nil, err
		}
		wipe(f.Data)
		entries[rowID] = entry
		out.Files = append(out.Files, sharedFile{ID: rowID, Name: f.Name, Size: int64(len(f.Data)), Type: f.Type})
	}

	// The roster lists members in the order the download page will be served
	// them, so it is built from the database's order rather than assumed.
	rows, err := a.db.Query(ctx,
		`SELECT id::text FROM files WHERE batch_id = $1 ORDER BY uploaded_at, id`, batchID)
	if err != nil {
		return nil, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	roster := make([]rosterEntry, 0, len(ids))
	for _, id := range ids {
		roster = append(roster, entries[id])
	}
	sealed, err := keys.sealRoster(batchID, 1, roster)
	if err != nil {
		return nil, err
	}
	if _, err := a.db.Exec(ctx,
		`UPDATE batches SET roster = $1, roster_seq = 1 WHERE id = $2`, sealed, batchID); err != nil {
		return nil, err
	}
	ok = true
	out.URL = a.publicBaseURL(r) + "/b/" + batchID + "#" + keys.fragment()
	log.Printf("api share: %s sealed %d file(s) server-side into batch %s…", user.Username, len(files), batchID[:8])
	return out, nil
}

// sealMember stores one member. It returns the row id as soon as a blob may
// exist on disk, so a failure further on can still remove it.
func (a *App) sealMember(ctx context.Context, user *User, keys *shareKeys, batchID string, f plainFile) (string, rosterEntry, error) {
	size := int64(len(f.Data))
	m, err := keys.prepareMember(batchID, f.Name, f.Type, size)
	if err != nil {
		return "", rosterEntry{}, statusErr(http.StatusBadRequest, "%s: %v", f.Name, err)
	}
	resID, err := a.reserveUpload(ctx, user, e2eCipherLen(size, len(m.Manifest), e2eVersionV5), nil)
	if err != nil {
		return "", rosterEntry{}, err
	}
	reserved := true
	defer func() {
		if reserved {
			a.releaseReservation(resID)
		}
	}()

	rowID := uuid.NewString()
	dst, err := os.OpenFile(filepath.Join(a.filesDir, rowID), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return "", rosterEntry{}, err
	}
	bw := bufio.NewWriterSize(dst, 1<<20)
	err = m.encryptTo(bw, bytes.NewReader(f.Data))
	if err == nil {
		err = bw.Flush()
	}
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return rowID, rosterEntry{}, err
	}

	err = a.finalizeUpload(ctx, user, resID, size, nil, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO files (id, enc_name, stored_name, size_bytes, uploaded_by,
			                    key_mode, batch_id, wrapped_key, e2e_version, manifest)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			rowID, m.EncName, rowID, size, user.ID.String(),
			keyModeE2EURL, batchID, m.WrappedKey, e2eVersionV5, m.Manifest)
		return err
	})
	if err != nil {
		return rowID, rosterEntry{}, err
	}
	reserved = false
	return rowID, m.entry(rowID), nil
}

// sniffType picks a MIME type for a file nobody typed: by extension first, as
// a browser does for a picked file, then by content.
func sniffType(name string, data []byte) string {
	if t := mime.TypeByExtension(strings.ToLower(filepath.Ext(name))); t != "" {
		return t
	}
	head := data
	if len(head) > 512 {
		head = head[:512]
	}
	return http.DetectContentType(head)
}

func extensionFor(contentType string) string {
	base, _, _ := mime.ParseMediaType(contentType)
	switch base {
	case "", "application/octet-stream":
		return ".bin"
	case "text/plain":
		return ".txt"
	}
	if exts, _ := mime.ExtensionsByType(base); len(exts) > 0 {
		return exts[0]
	}
	return ".bin"
}

// --- listing and revoking ---------------------------------------------------

type apiShareRow struct {
	ID            string     `json:"id"`
	URL           string     `json:"url"`
	CreatedAt     time.Time  `json:"createdAt"`
	ExpiresAt     *time.Time `json:"expiresAt"`
	MaxDownloads  *int       `json:"maxDownloads"`
	DownloadCount int        `json:"downloadCount"`
	Files         int        `json:"files"`
	Bytes         int64      `json:"bytes"`
	ServerSealed  bool       `json:"serverSealed"`
	Active        bool       `json:"active"`
}

// handleAPIListShares lists the caller's shares made through the API. The
// links have no fragment: the server never had it for an end-to-end share, and
// forgot it for a server-sealed one.
func (a *App) handleAPIListShares(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())
	rows, err := a.db.Query(r.Context(),
		`SELECT b.id::text, b.created_at, b.expires_at, b.max_downloads, b.download_count,
		        b.server_sealed,
		        (b.archived_at IS NULL AND (b.expires_at IS NULL OR b.expires_at > NOW())
		          AND (b.max_downloads IS NULL OR b.download_count < b.max_downloads)),
		        COUNT(f.id), COALESCE(SUM(f.size_bytes), 0)
		   FROM batches b
		   LEFT JOIN files f ON f.batch_id = b.id AND f.archived_at IS NULL
		  WHERE b.created_by = $1 AND b.api_token_id IS NOT NULL AND b.drop_id IS NULL
		  GROUP BY b.id
		  ORDER BY b.created_at DESC
		  LIMIT 200`, user.ID.String())
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	base := a.publicBaseURL(r)
	out := []apiShareRow{}
	for rows.Next() {
		var s apiShareRow
		if err := rows.Scan(&s.ID, &s.CreatedAt, &s.ExpiresAt, &s.MaxDownloads, &s.DownloadCount,
			&s.ServerSealed, &s.Active, &s.Files, &s.Bytes); err != nil {
			httpError(w, err, http.StatusInternalServerError)
			return
		}
		s.URL = base + "/b/" + s.ID
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"shares": out})
}

func (a *App) handleAPIDeleteShare(w http.ResponseWriter, r *http.Request, idStr string) {
	if err := a.revokeShare(r.Context(), userFromContext(r.Context()), idStr); err != nil {
		writeAPIErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked", "id": idStr})
}

// revokeShare retires one of the user's own batch shares at once: the blobs go
// now, the row ages out with the sweeper like any expired share.
func (a *App) revokeShare(ctx context.Context, user *User, idStr string) error {
	id, err := uuid.Parse(idStr)
	if err != nil {
		return statusErr(http.StatusNotFound, "share not found")
	}
	var owner *string
	var dropID *string
	err = a.db.QueryRow(ctx,
		`SELECT created_by::text, drop_id::text FROM batches WHERE id = $1`, id.String()).Scan(&owner, &dropID)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && (owner == nil || *owner != user.ID.String() || dropID != nil)) {
		return statusErr(http.StatusNotFound, "share not found")
	}
	if err != nil {
		return err
	}
	a.archiveBatch(ctx, id.String())
	return nil
}
