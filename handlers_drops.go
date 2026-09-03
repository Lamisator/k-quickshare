package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// A DROP is a share link pointing the other way: the owner publishes a link
// that only ACCEPTS files and keeps a second one that reads them.
//
// Everything else in Pyxis is symmetric — whoever encrypted a file can decrypt
// it, and the link carries the key both ways. That cannot work here. The person
// sending a file has no account, has never met the owner, and must not be able
// to read what anyone else sent, or even what they sent themselves a moment
// earlier. So a drop is keyed with a post-quantum KEM: the browser generates an
// X-Wing keypair, the public half is published (sealed, see below) and the
// private half exists only in the fragment of the owner's link.
//
//	K — 32 random bytes, in the owner's link and nowhere else
//	├── HKDF -> the X-Wing seed -> (decapsulation key, public key)
//	└── HKDF -> S, the public link's fragment
//	            ├── HKDF -> the key that seals the public key on the drop row
//	            └── HKDF -> the upload token; the server keeps SHA-256 of it
//
// Two ids, not one. The public id addresses the upload page; the drop's own id
// addresses the inbox. Sharing one id between them would let anyone holding the
// public link query the inbox: the fragment would still stop them decrypting
// anything, but they would learn how many files arrived and how big they are.
//
// What the server holds for all this: a sealed public key it cannot read, a
// hash it cannot invert, and one KEM ciphertext per submission it cannot open.
// It generates no key and stores no private key — for a drop or anything else.
type dropMeta struct {
	ID        string
	PublicID  string
	OwnerID   string
	Label     string
	Note      string
	Version   int
	KemAlg    string
	EncPK     []byte
	UploadVer []byte

	AuthSalt     []byte
	AuthVerifier []byte

	MaxFileBytes     *int64
	MaxTotalBytes    *int64
	MaxFiles         *int
	MaxPerSubmission *int
	MaxSubmissions   *int

	ExpiresAt  *time.Time
	ClosedAt   *time.Time
	ArchivedAt *time.Time
	CreatedAt  time.Time
}

func (d *dropMeta) isPassword() bool { return len(d.AuthVerifier) > 0 }

// open reports whether the drop will still accept files. Closed, expired and
// archived are three different reasons and all end the same way for a sender.
func (d *dropMeta) open() bool {
	if d.ArchivedAt != nil || d.ClosedAt != nil {
		return false
	}
	return d.ExpiresAt == nil || time.Now().Before(*d.ExpiresAt)
}

func (d *dropMeta) limits() dropLimits {
	return dropLimits{
		MaxFileBytes:     d.MaxFileBytes,
		MaxTotalBytes:    d.MaxTotalBytes,
		MaxFiles:         d.MaxFiles,
		MaxPerSubmission: d.MaxPerSubmission,
		MaxSubmissions:   d.MaxSubmissions,
	}
}

const dropSelect = `id::text, public_id::text, owner_id::text, label, note, drop_version,
	kem_alg, enc_pk, upload_verifier, auth_salt, auth_verifier,
	max_file_bytes, max_total_bytes, max_files, max_files_per_submission, max_submissions,
	expires_at, closed_at, archived_at, created_at`

func scanDrop(row pgx.Row) (*dropMeta, error) {
	var (
		d            dropMeta
		label, note  *string
		authSalt     []byte
		authVerifier []byte
	)
	err := row.Scan(&d.ID, &d.PublicID, &d.OwnerID, &label, &note, &d.Version,
		&d.KemAlg, &d.EncPK, &d.UploadVer, &authSalt, &authVerifier,
		&d.MaxFileBytes, &d.MaxTotalBytes, &d.MaxFiles, &d.MaxPerSubmission, &d.MaxSubmissions,
		&d.ExpiresAt, &d.ClosedAt, &d.ArchivedAt, &d.CreatedAt)
	if err != nil {
		return nil, err
	}
	if label != nil {
		d.Label = *label
	}
	if note != nil {
		d.Note = *note
	}
	d.AuthSalt, d.AuthVerifier = authSalt, authVerifier
	return &d, nil
}

func (a *App) loadDrop(ctx context.Context, id uuid.UUID) (*dropMeta, error) {
	return scanDrop(a.db.QueryRow(ctx, `SELECT `+dropSelect+` FROM drops WHERE id = $1`, id.String()))
}

func (a *App) loadDropByPublicID(ctx context.Context, id uuid.UUID) (*dropMeta, error) {
	return scanDrop(a.db.QueryRow(ctx, `SELECT `+dropSelect+` FROM drops WHERE public_id = $1`, id.String()))
}

// --- the owner's side -------------------------------------------------------

// DropRow is one drop as the owner's list shows it. Names and sizes of what
// arrived cannot appear here: this page has no key. It reports what the server
// legitimately knows — how many files, how many bytes, when — and the rest is
// behind the private link.
type DropRow struct {
	ID          string
	PublicID    string
	Label       string
	CreatedAt   time.Time
	ExpiresAt   *time.Time
	ClosedAt    *time.Time
	Files       int
	Submissions int
	Bytes       int64

	// Plain values, 0 meaning "no limit". Pointers would reach the template as
	// pointers, and a *int handed to a formatting verb prints its address —
	// which has bitten this codebase twice.
	MaxFiles         int
	MaxPerSubmission int
	MaxSubmissions   int
	MaxFileBytes     int64
	MaxTotalBytes    int64
	HasPassword      bool
}

// Open mirrors dropMeta.open() for the template, which has no method to call.
func (r DropRow) Open() bool {
	if r.ClosedAt != nil {
		return false
	}
	return r.ExpiresAt == nil || time.Now().Before(*r.ExpiresAt)
}

func (a *App) handleDrops(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.renderDropList(w, r)
	case http.MethodPost:
		a.handleCreateDrop(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *App) renderDropList(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())
	rows, err := a.db.Query(r.Context(),
		`SELECT d.id::text, d.public_id::text, d.label, d.created_at, d.expires_at, d.closed_at,
		        d.max_files, d.max_files_per_submission, d.max_submissions,
		        d.max_file_bytes, d.max_total_bytes, d.auth_verifier IS NOT NULL,
		        COALESCE(s.files, 0), COALESCE(s.bytes, 0), COALESCE(s.submissions, 0)
		 FROM drops d
		 LEFT JOIN (
		     SELECT b.drop_id,
		            COUNT(f.id) AS files,
		            COALESCE(SUM(f.size_bytes), 0) AS bytes,
		            COUNT(DISTINCT b.id) AS submissions
		     FROM batches b
		     LEFT JOIN files f ON f.batch_id = b.id AND f.archived_at IS NULL
		     WHERE b.drop_id IS NOT NULL AND b.archived_at IS NULL
		     GROUP BY b.drop_id
		 ) s ON s.drop_id = d.id
		 WHERE d.owner_id = $1 AND d.archived_at IS NULL
		 ORDER BY d.created_at DESC`, user.ID.String())
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var drops []DropRow
	for rows.Next() {
		var (
			d                            DropRow
			label                        *string
			maxFiles, maxPerSub, maxSubs *int
			maxFileBytes, maxTotalBytes  *int64
		)
		if err := rows.Scan(&d.ID, &d.PublicID, &label, &d.CreatedAt, &d.ExpiresAt, &d.ClosedAt,
			&maxFiles, &maxPerSub, &maxSubs,
			&maxFileBytes, &maxTotalBytes, &d.HasPassword,
			&d.Files, &d.Bytes, &d.Submissions); err != nil {
			httpError(w, err, http.StatusInternalServerError)
			return
		}
		if label != nil {
			d.Label = *label
		}
		d.MaxFiles = intOrZero(maxFiles)
		d.MaxPerSubmission = intOrZero(maxPerSub)
		d.MaxSubmissions = intOrZero(maxSubs)
		d.MaxFileBytes = int64OrZero(maxFileBytes)
		d.MaxTotalBytes = int64OrZero(maxTotalBytes)
		drops = append(drops, d)
	}
	if err := rows.Err(); err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}

	a.render(w, r, "drops.html", map[string]any{
		"Title":     a.tr(r, "drops.title") + " · Pyxis",
		"Active":    "drops",
		"Drops":     drops,
		"MaxUpload": a.maxUploadFor(user),
	})
}

// handleCreateDrop stores what the browser has already decided. Every value
// that matters cryptographically was produced in the tab: the sealed public
// key, and the verifier for an upload token this request does not carry.
//
// The verifier arrives pre-hashed, unlike a password share's, which sends its
// token and lets the server hash it. The difference is who is on each end: a
// share's token proves knowledge of a password the server must gate on once,
// while a drop's token is a standing write capability. Handing the raw one over
// at creation would leave the server able to fill the owner's drop for as long
// as it exists, and there is no reason it should ever see it.
func (a *App) handleCreateDrop(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	encPK, err := base64.RawURLEncoding.DecodeString(r.PostFormValue("enc_pk"))
	if err != nil || len(encPK) != dropSealedPKLen {
		http.Error(w, "invalid sealed public key", http.StatusBadRequest)
		return
	}
	verifier, err := base64.RawURLEncoding.DecodeString(r.PostFormValue("upload_verifier"))
	if err != nil || len(verifier) != sha256.Size {
		http.Error(w, "invalid upload verifier", http.StatusBadRequest)
		return
	}
	version, err := strconv.Atoi(r.PostFormValue("drop_version"))
	if err != nil || version < 1 || version > dropCurrentVersion {
		http.Error(w, fmt.Sprintf("drop_version must be 1..%d — reload the page and try again",
			dropCurrentVersion), http.StatusBadRequest)
		return
	}
	alg := r.PostFormValue("kem_alg")
	if alg == "" || len(alg) > 40 {
		http.Error(w, "invalid kem_alg", http.StatusBadRequest)
		return
	}

	expiresAt, err := parseExpiry(r.PostFormValue("expires_hours"), r.PostFormValue("expires_at"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Optional second gate. The password never reaches the server: the browser
	// derives an auth token from it on its own KDF branch, exactly as a
	// password share does, and only SHA-256 of that token is stored.
	var authSalt, authVerifier []byte
	if tokenStr := r.PostFormValue("auth_verifier"); tokenStr != "" {
		token, terr := base64.RawURLEncoding.DecodeString(tokenStr)
		authSalt, _ = base64.RawURLEncoding.DecodeString(r.PostFormValue("auth_salt"))
		if terr != nil || len(token) != 32 || len(authSalt) != encSaltLen {
			http.Error(w, "invalid auth material", http.StatusBadRequest)
			return
		}
		sum := sha256.Sum256(token)
		authVerifier = sum[:]
	}

	// The owner's own per-file ceiling bounds what they may promise. A drop can
	// only ever ask for LESS: a link that lifted its owner's limit would be a
	// way around a number an admin set.
	ceiling := a.maxUploadFor(user)
	maxFileBytes, err := parseDropBytes(r.PostFormValue("max_file_bytes"), ceiling)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	maxTotalBytes, err := parseDropBytes(r.PostFormValue("max_total_bytes"), 0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	maxFiles, err := parseDropCount(r.PostFormValue("max_files"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	maxPerSubmission, err := parseDropCount(r.PostFormValue("max_files_per_submission"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	maxSubmissions, err := parseDropCount(r.PostFormValue("max_submissions"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	label := strings.TrimSpace(r.PostFormValue("label"))
	if len(label) > maxDropLabelLen {
		label = label[:maxDropLabelLen]
	}
	note := strings.TrimSpace(r.PostFormValue("note"))
	if len(note) > maxDropNoteLen {
		note = note[:maxDropNoteLen]
	}

	// The public id is chosen by the browser, not here. It is the AAD of the
	// sealed public key above, so it has to exist before that key can be sealed
	// — and a server that answered with an id of its own would hand back a blob
	// nobody could open. What this side does is check it and refuse a
	// collision, which the primary key does for us.
	publicID, err := uuid.Parse(r.PostFormValue("public_id"))
	if err != nil {
		http.Error(w, "invalid public_id", http.StatusBadRequest)
		return
	}
	id := uuid.New()
	_, err = a.db.Exec(r.Context(),
		`INSERT INTO drops (id, public_id, owner_id, label, note, drop_version, kem_alg,
		                    enc_pk, upload_verifier, auth_salt, auth_verifier,
		                    max_file_bytes, max_total_bytes, max_files,
		                    max_files_per_submission, max_submissions, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
		id.String(), publicID.String(), user.ID.String(), nullIfEmpty(label), nullIfEmpty(note),
		version, alg, encPK, verifier, authSalt, authVerifier,
		maxFileBytes, maxTotalBytes, maxFiles, maxPerSubmission, maxSubmissions, expiresAt)
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}

	// Both URLs come back fragment-less. The two secrets that make them work
	// were generated in the tab and are added there.
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":          id.String(),
		"publicId":    publicID.String(),
		"inboxUrl":    "/i/" + id.String(),
		"uploadUrl":   "/r/" + publicID.String(),
		"expiresAt":   expiresAt,
		"dropVersion": version,
	})
}

// parseDropBytes reads a byte limit, refusing anything above the ceiling when
// one applies. Empty means "no limit of this kind".
func parseDropBytes(v string, ceiling int64) (*int64, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		if ceiling > 0 {
			return &ceiling, nil
		}
		return nil, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		return nil, errors.New("size limits must be whole numbers of bytes")
	}
	if n == 0 {
		if ceiling > 0 {
			return &ceiling, nil
		}
		return nil, nil
	}
	if ceiling > 0 && n > ceiling {
		n = ceiling
	}
	return &n, nil
}

// parseDropCount reads a file or delivery count. Zero and empty both mean "no
// limit"; a drop that accepted nothing would be a link with no purpose.
func parseDropCount(v string) (*int, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return nil, errors.New("counts must be whole numbers")
	}
	if n == 0 {
		return nil, nil
	}
	if n > 10000 {
		n = 10000
	}
	return &n, nil
}

func intOrZero(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

func int64OrZero(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// dispatchDropOwnerRoutes handles /drops/{id}/close and /drops/{id}/delete.
func (a *App) dispatchDropOwnerRoutes(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/drops/")
	idStr, action, _ := strings.Cut(rest, "/")
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user := userFromContext(r.Context())
	switch action {
	case "close":
		tag, err := a.db.Exec(r.Context(),
			`UPDATE drops SET closed_at = NOW()
			  WHERE id = $1 AND owner_id = $2 AND closed_at IS NULL`, id.String(), user.ID.String())
		if err != nil {
			httpError(w, err, http.StatusInternalServerError)
			return
		}
		if tag.RowsAffected() == 0 {
			http.NotFound(w, r)
			return
		}
	case "delete":
		// Deleting a drop deletes what was sent to it. The rows cascade; the
		// blobs have to be collected first, because nothing else will know
		// their names afterwards.
		stored, err := a.collectStored(r.Context(),
			`DELETE FROM files WHERE batch_id IN (
			     SELECT b.id FROM batches b JOIN drops d ON d.id = b.drop_id
			      WHERE d.id = $1 AND d.owner_id = $2)
			 RETURNING stored_name`, id.String(), user.ID.String())
		if err != nil {
			httpError(w, err, http.StatusInternalServerError)
			return
		}
		tag, err := a.db.Exec(r.Context(),
			`DELETE FROM drops WHERE id = $1 AND owner_id = $2`, id.String(), user.ID.String())
		if err != nil {
			httpError(w, err, http.StatusInternalServerError)
			return
		}
		if tag.RowsAffected() == 0 {
			http.NotFound(w, r)
			return
		}
		a.removeBlobs(stored)
	default:
		http.NotFound(w, r)
		return
	}
	if wantsJSON(r) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, "/drops", http.StatusSeeOther)
}

// closeDropIfFull closes a drop that has just reached its file limit, so the
// public page can say "this drop is complete" instead of offering a dropzone
// that will only refuse. Best effort: the limit itself is enforced in the
// upload transaction and does not depend on this.
func (a *App) closeDropIfFull(ctx context.Context, d *dropMeta) {
	if d.MaxFiles == nil || *d.MaxFiles <= 0 {
		return
	}
	if _, err := a.db.Exec(ctx,
		`UPDATE drops SET closed_at = NOW()
		  WHERE id = $1 AND closed_at IS NULL
		    AND (SELECT COUNT(*) FROM files f JOIN batches b ON b.id = f.batch_id
		          WHERE b.drop_id = $1 AND f.archived_at IS NULL) >= $2`,
		d.ID, *d.MaxFiles); err != nil {
		log.Printf("close full drop %s: %v", d.ID, err)
	}
}

// --- the public upload side -------------------------------------------------

// dispatchDropUploadRoutes handles everything under /r/{publicID}: the page, the
// sealed public key, the optional password unlock, opening a submission,
// uploading into it and sealing its roster.
func (a *App) dispatchDropUploadRoutes(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/r/")
	idStr, action, _ := strings.Cut(rest, "/")
	id, err := uuid.Parse(idStr)
	if err != nil {
		a.renderGone(w, r, http.StatusNotFound, "dl.not_found")
		return
	}
	d, err := a.loadDropByPublicID(r.Context(), id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			a.renderGone(w, r, http.StatusNotFound, "dl.not_found")
			return
		}
		httpError(w, err, http.StatusInternalServerError)
		return
	}

	switch {
	case action == "":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		a.renderDropUploadPage(w, r, d)
	case action == "key":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		a.handleDropKey(w, r, d)
	case action == "unlock":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		a.handleDropUnlock(w, r, d)
	case action == "submissions":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		a.handleOpenSubmission(w, r, d)
	case action == "upload":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		a.handleDropUpload(w, r, d)
	case strings.HasPrefix(action, "submissions/"):
		subID, sub, _ := strings.Cut(strings.TrimPrefix(action, "submissions/"), "/")
		if sub != "roster" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		a.handleSubmissionRoster(w, r, d, subID)
	default:
		http.NotFound(w, r)
	}
}

func (a *App) renderDropUploadPage(w http.ResponseWriter, r *http.Request, d *dropMeta) {
	used, err := a.dropTotals(r.Context(), d.ID)
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	data := map[string]any{
		"Title":       a.tr(r, "drop.title") + " · Pyxis",
		"PublicID":    d.PublicID,
		"Label":       d.Label,
		"Note":        d.Note,
		"Open":        d.open(),
		"Closed":      d.ClosedAt != nil || d.ArchivedAt != nil,
		"HasPassword": d.isPassword(),
		"Unlocked":    !d.isPassword() || a.dropUnlocked(r, d),
		"DropVersion": d.Version,
		"MaxUpload":   a.dropFileCeiling(r.Context(), d),
		"FilesUsed":   used.files,
		"BytesUsed":   used.bytes,
	}
	if d.ExpiresAt != nil {
		data["ExpiresAt"] = d.ExpiresAt.UTC()
	}
	if len(d.AuthSalt) > 0 {
		data["AuthSalt"] = base64.RawURLEncoding.EncodeToString(d.AuthSalt)
	}
	// Always present, 0 meaning "no limit of this kind": a template that has to
	// ask whether a key exists before comparing it is a template one missing
	// branch away from failing to render at all.
	data["MaxFiles"] = intOrZero(d.MaxFiles)
	data["MaxPerSubmission"] = intOrZero(d.MaxPerSubmission)
	data["MaxTotalBytes"] = int64OrZero(d.MaxTotalBytes)
	data["FilesLeft"] = int64(intOrZero(d.MaxFiles)) - used.files
	data["BytesLeft"] = int64OrZero(d.MaxTotalBytes) - used.bytes
	a.render(w, r, "drop_upload.html", data)
}

// dropFileCeiling is the largest single file this drop will take: the owner's
// own limit, lowered by the drop's. The upload page needs it before anything is
// encrypted, so an over-size file is refused in the picker rather than after
// minutes of work.
func (a *App) dropFileCeiling(ctx context.Context, d *dropMeta) int64 {
	max := a.getMaxUploadDefault()
	if owner, err := a.findUserByID(ctx, d.OwnerID); err == nil {
		max = a.maxUploadFor(owner)
	}
	if d.MaxFileBytes != nil && *d.MaxFileBytes > 0 && *d.MaxFileBytes < max {
		max = *d.MaxFileBytes
	}
	return max
}

type dropTotals struct {
	files       int64
	bytes       int64
	submissions int64
}

func (a *App) dropTotals(ctx context.Context, dropID string) (dropTotals, error) {
	var t dropTotals
	err := a.db.QueryRow(ctx,
		`SELECT COUNT(f.id), COALESCE(SUM(f.size_bytes), 0), COUNT(DISTINCT b.id)
		 FROM batches b
		 LEFT JOIN files f ON f.batch_id = b.id AND f.archived_at IS NULL
		 WHERE b.drop_id = $1 AND b.archived_at IS NULL`, dropID).
		Scan(&t.files, &t.bytes, &t.submissions)
	return t, err
}

// handleDropKey hands out the sealed public key and the drop's terms. The blob
// is useless without the link's fragment, and opening it is what proves the
// server did not substitute a key of its own.
func (a *App) handleDropKey(w http.ResponseWriter, r *http.Request, d *dropMeta) {
	if d.isPassword() && !a.dropUnlocked(r, d) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	used, err := a.dropTotals(r.Context(), d.ID)
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	res := map[string]any{
		"publicId":    d.PublicID,
		"encPk":       base64.RawURLEncoding.EncodeToString(d.EncPK),
		"kemAlg":      d.KemAlg,
		"dropVersion": d.Version,
		"e2eVersion":  e2eCurrentVersion,
		"open":        d.open(),
		"maxFile":     a.dropFileCeiling(r.Context(), d),
		"filesUsed":   used.files,
		"bytesUsed":   used.bytes,
	}
	if d.MaxFiles != nil {
		res["maxFiles"] = *d.MaxFiles
	}
	if d.MaxPerSubmission != nil {
		res["maxPerSubmission"] = *d.MaxPerSubmission
	}
	if d.MaxTotalBytes != nil {
		res["maxTotalBytes"] = *d.MaxTotalBytes
	}
	writeJSON(w, http.StatusOK, res)
}

// checkUploadToken gates every write to a drop on the token derived from the
// public link's fragment.
//
// This is what keeps the capability in the fragment rather than in the path. A
// URL the server can see is a URL its access log, its proxy and any Referer
// header have seen too; a fragment is never transmitted. Without this, knowing
// a drop's public id — which is exactly what those logs hold — would be enough
// to fill somebody's quota.
func (a *App) checkUploadToken(w http.ResponseWriter, r *http.Request, d *dropMeta) bool {
	limitKey := a.clientIP(r) + "|d|" + d.PublicID
	if !a.shareLimiter.allow(r.Context(), limitKey) {
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return false
	}
	token, err := base64.RawURLEncoding.DecodeString(r.PostFormValue("token"))
	if err == nil && len(token) == dropTokenLen {
		sum := sha256.Sum256(token)
		if hmac.Equal(sum[:], d.UploadVer) {
			a.shareLimiter.reset(r.Context(), limitKey)
			return true
		}
	}
	a.shareLimiter.fail(r.Context(), limitKey)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return false
}

// handleOpenSubmission creates the batch one visit's files land in and stores
// the encapsulation their keys descend from.
func (a *App) handleOpenSubmission(w http.ResponseWriter, r *http.Request, d *dropMeta) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !a.checkUploadToken(w, r, d) {
		return
	}
	if d.isPassword() && !a.dropUnlocked(r, d) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !d.open() {
		http.Error(w, "this drop is closed", http.StatusGone)
		return
	}

	kemCT, err := base64.RawURLEncoding.DecodeString(r.PostFormValue("kem_ct"))
	if err != nil || len(kemCT) != dropCiphertextLen {
		http.Error(w, "invalid encapsulation", http.StatusBadRequest)
		return
	}
	// The sender's note is optional, sealed, and padded exactly like a file
	// name — so its length says nothing about what it holds.
	var encNote []byte
	if s := r.PostFormValue("enc_note"); s != "" {
		encNote, err = base64.RawURLEncoding.DecodeString(s)
		if err != nil || !validEncNameLen(len(encNote)) {
			http.Error(w, "invalid sealed note", http.StatusBadRequest)
			return
		}
	}

	// Whether another delivery fits is decided under the same lock the byte and
	// file counting uses, so two senders arriving together cannot both take the
	// last slot of a one-delivery drop.
	tx, err := a.db.Begin(r.Context())
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(r.Context())
	if _, err := tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock($1)`, quotaLockKey); err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	if err := dropAcceptsAnotherSubmission(r.Context(), tx, d.ID, d.limits()); err != nil {
		if errors.Is(err, errDropLimit) {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		httpError(w, err, http.StatusInternalServerError)
		return
	}

	// The sender chooses the submission id, because it is the AAD of the sealed
	// note and of every one of this delivery's file manifests. A collision is
	// refused by the primary key rather than resolved: silently renaming a
	// delivery would invalidate every seal made against the id.
	id, err := uuid.Parse(r.PostFormValue("id"))
	if err != nil {
		http.Error(w, "invalid submission id", http.StatusBadRequest)
		return
	}
	if _, err := tx.Exec(r.Context(),
		`INSERT INTO batches (id, created_by, expires_at, key_mode, e2e_version,
		                      drop_id, kem_ct, enc_note)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		id.String(), d.OwnerID, d.ExpiresAt, keyModeE2EKEM, e2eCurrentVersion,
		d.ID, kemCT, encNote); err != nil {
		httpError(w, err, http.StatusConflict)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         id.String(),
		"e2eVersion": e2eCurrentVersion,
	})
}

// handleDropUpload takes one file into an open submission. Everything after the
// gate below is the ordinary upload path: same container checks, same sealed
// name rules, same reservation — but charged to the drop's owner.
func (a *App) handleDropUpload(w http.ResponseWriter, r *http.Request, d *dropMeta) {
	// The body is multipart, so the token rides in the query string: parsing
	// the form here would consume the body the upload path needs to read.
	if !a.checkUploadTokenValue(w, r, d, r.URL.Query().Get("token")) {
		return
	}
	if d.isPassword() && !a.dropUnlocked(r, d) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !d.open() {
		http.Error(w, "this drop is closed", http.StatusGone)
		return
	}
	batch, err := a.loadSubmission(r.Context(), d, r.URL.Query().Get("submission"))
	if err != nil {
		http.Error(w, "submission not found", http.StatusNotFound)
		return
	}
	owner, err := a.findUserByID(r.Context(), d.OwnerID)
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	a.storeUpload(w, r, uploadContext{owner: owner, batch: batch, drop: d})
}

// checkUploadTokenValue is checkUploadToken for a request whose body must not
// be parsed yet.
func (a *App) checkUploadTokenValue(w http.ResponseWriter, r *http.Request, d *dropMeta, value string) bool {
	limitKey := a.clientIP(r) + "|d|" + d.PublicID
	if !a.shareLimiter.allow(r.Context(), limitKey) {
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return false
	}
	token, err := base64.RawURLEncoding.DecodeString(value)
	if err == nil && len(token) == dropTokenLen {
		sum := sha256.Sum256(token)
		if hmac.Equal(sum[:], d.UploadVer) {
			a.shareLimiter.reset(r.Context(), limitKey)
			return true
		}
	}
	a.shareLimiter.fail(r.Context(), limitKey)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return false
}

func (a *App) loadSubmission(ctx context.Context, d *dropMeta, idStr string) (*batchMeta, error) {
	id, err := uuid.Parse(idStr)
	if err != nil {
		return nil, err
	}
	bm := &batchMeta{ID: id.String()}
	err = a.db.QueryRow(ctx,
		`SELECT created_at, created_by, expires_at, max_downloads, download_count,
		        key_mode, auth_salt, auth_verifier, archived_at,
		        e2e_version, roster, roster_seq, drop_id::text, kem_ct, enc_note
		 FROM batches WHERE id = $1 AND drop_id = $2 AND archived_at IS NULL`,
		id.String(), d.ID).
		Scan(&bm.CreatedAt, &bm.CreatedBy, &bm.ExpiresAt, &bm.MaxDownloads,
			&bm.DownloadCount, &bm.KeyMode, &bm.AuthSalt, &bm.AuthVerifier, &bm.ArchivedAt,
			&bm.E2EVersion, &bm.Roster, &bm.RosterSeq, &bm.DropID, &bm.KemCT, &bm.EncNote)
	if err != nil {
		return nil, err
	}
	return bm, nil
}

// handleSubmissionRoster stores the sealed member list a sender produced. Same
// contract as a batch's: opaque to the server, monotonic seq, and the inbox
// checks the listing it is served against it.
func (a *App) handleSubmissionRoster(w http.ResponseWriter, r *http.Request, d *dropMeta, subID string) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !a.checkUploadToken(w, r, d) {
		return
	}
	batch, err := a.loadSubmission(r.Context(), d, subID)
	if err != nil {
		http.Error(w, "submission not found", http.StatusNotFound)
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
		  WHERE id = $3 AND roster_seq < $2`, sealed, seq, batch.ID)
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	if tag.RowsAffected() == 0 {
		w.WriteHeader(http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) handleDropUnlock(w http.ResponseWriter, r *http.Request, d *dropMeta) {
	if !d.isPassword() {
		http.Error(w, "not password protected", http.StatusBadRequest)
		return
	}
	limitKey := a.clientIP(r) + "|dp|" + d.PublicID
	if !a.shareLimiter.allow(r.Context(), limitKey) {
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}
	_ = r.ParseForm()
	token, err := base64.RawURLEncoding.DecodeString(r.PostFormValue("auth"))
	if err == nil && len(token) == 32 {
		sum := sha256.Sum256(token)
		if hmac.Equal(sum[:], d.AuthVerifier) {
			a.shareLimiter.reset(r.Context(), limitKey)
			a.setDropUnlockCookie(w, d)
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	a.shareLimiter.fail(r.Context(), limitKey)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// --- the owner's inbox ------------------------------------------------------

// dispatchDropInboxRoutes handles /i/{id}, /i/{id}/manifest and
// /i/{id}/f/{fileID}/raw. None of these needs a session: the key is in the
// fragment, and the id is only in the private link. Requiring a login as well
// would mean the owner could not open their own drop from another device
// without signing in there — and would not make the page any safer, because
// everything it shows is decrypted in the browser.
func (a *App) dispatchDropInboxRoutes(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/i/")
	idStr, action, _ := strings.Cut(rest, "/")
	id, err := uuid.Parse(idStr)
	if err != nil {
		a.renderGone(w, r, http.StatusNotFound, "dl.not_found")
		return
	}
	d, err := a.loadDrop(r.Context(), id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			a.renderGone(w, r, http.StatusNotFound, "dl.not_found")
			return
		}
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	if d.ArchivedAt != nil {
		a.renderGone(w, r, http.StatusGone, "dl.gone_expired")
		return
	}

	switch {
	case action == "":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		a.renderInbox(w, r, d)
	case action == "manifest":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		a.handleInboxManifest(w, r, d)
	case strings.HasPrefix(action, "f/"):
		fileID, sub, _ := strings.Cut(strings.TrimPrefix(action, "f/"), "/")
		if sub != "raw" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		a.handleInboxFileRaw(w, r, d, fileID)
	default:
		http.NotFound(w, r)
	}
}

func (a *App) renderInbox(w http.ResponseWriter, r *http.Request, d *dropMeta) {
	used, err := a.dropTotals(r.Context(), d.ID)
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	data := map[string]any{
		"Title":       a.tr(r, "inbox.title") + " · Pyxis",
		"ID":          d.ID,
		"PublicID":    d.PublicID,
		"Label":       d.Label,
		"CreatedAt":   d.CreatedAt,
		"FileCount":   used.files,
		"TotalSize":   used.bytes,
		"Submissions": used.submissions,
		"Open":        d.open(),
		"DropVersion": d.Version,
	}
	if d.ExpiresAt != nil {
		data["ExpiresAt"] = d.ExpiresAt.UTC()
	}
	a.render(w, r, "inbox.html", data)
}

// handleInboxManifest lists every submission with its encapsulation, its sealed
// note, its sealed roster and its members' wrapped keys. All of it is opaque
// here: the page turns it into a listing with one decapsulation per submission,
// and the server cannot do the same because it has no seed.
func (a *App) handleInboxManifest(w http.ResponseWriter, r *http.Request, d *dropMeta) {
	rows, err := a.db.Query(r.Context(),
		`SELECT id::text, created_at, kem_ct, enc_note, roster, roster_seq, e2e_version
		 FROM batches
		 WHERE drop_id = $1 AND archived_at IS NULL
		 ORDER BY created_at, id`, d.ID)
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type submission struct {
		id        string
		createdAt time.Time
		kemCT     []byte
		encNote   []byte
		roster    []byte
		rosterSeq int64
		version   int
	}
	var subs []submission
	for rows.Next() {
		var s submission
		if err := rows.Scan(&s.id, &s.createdAt, &s.kemCT, &s.encNote,
			&s.roster, &s.rosterSeq, &s.version); err != nil {
			httpError(w, err, http.StatusInternalServerError)
			return
		}
		subs = append(subs, s)
	}
	if err := rows.Err(); err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}

	out := make([]map[string]any, 0, len(subs))
	for _, s := range subs {
		members, err := a.loadBatchMembers(r, s.id)
		if err != nil {
			httpError(w, err, http.StatusInternalServerError)
			return
		}
		files := make([]map[string]any, 0, len(members))
		for _, m := range members {
			files = append(files, map[string]any{
				"id":         m.ID,
				"encName":    base64.RawURLEncoding.EncodeToString(m.EncName),
				"manifestId": manifestIDOf(m.Manifest),
				"size":       m.Size,
				"wrappedKey": base64.RawURLEncoding.EncodeToString(m.WrappedKey),
				// A drop has no download limit to spend, so previews are always
				// on offer; which files can actually be previewed is decided in
				// the browser once the sealed type is open.
				"previewsAllowed": true,
				"e2eVersion":      m.E2EVersion,
				"manifest":        base64.RawURLEncoding.EncodeToString(m.Manifest),
			})
		}
		out = append(out, map[string]any{
			"id":         s.id,
			"receivedAt": s.createdAt.UTC(),
			"kemCt":      base64.RawURLEncoding.EncodeToString(s.kemCT),
			"encNote":    base64.RawURLEncoding.EncodeToString(s.encNote),
			"roster":     base64.RawURLEncoding.EncodeToString(s.roster),
			"rosterSeq":  s.rosterSeq,
			"e2eVersion": s.version,
			"files":      files,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":          d.ID,
		"dropVersion": d.Version,
		"kemAlg":      d.KemAlg,
		"submissions": out,
	})
}

// handleInboxFileRaw serves one received file's ciphertext. A drop counts no
// downloads — there is no limit to spend and the owner is the only reader — so
// this is the one raw route that does not consume anything.
func (a *App) handleInboxFileRaw(w http.ResponseWriter, r *http.Request, d *dropMeta, fileID string) {
	id, err := uuid.Parse(fileID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var (
		storedName string
		uploadedAt time.Time
	)
	err = a.db.QueryRow(r.Context(),
		`SELECT f.stored_name, f.uploaded_at
		 FROM files f
		 JOIN batches b ON b.id = f.batch_id
		 WHERE f.id = $1 AND b.drop_id = $2 AND f.archived_at IS NULL`,
		id.String(), d.ID).Scan(&storedName, &uploadedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	a.serveBlob(w, r, storedName, id.String(), uploadedAt)
}

// --- drop unlock cookies ----------------------------------------------------

func (a *App) dropUnlockCookieName(id string) string {
	return "pxd_" + strings.ReplaceAll(id, "-", "")
}

func (a *App) dropUnlockToken(d *dropMeta) string {
	mac := hmac.New(sha256.New, a.unlockKey)
	mac.Write([]byte("drop"))
	mac.Write([]byte{0})
	mac.Write([]byte(d.PublicID))
	mac.Write([]byte{0})
	mac.Write(d.AuthVerifier)
	return hex.EncodeToString(mac.Sum(nil))
}

func (a *App) dropUnlocked(r *http.Request, d *dropMeta) bool {
	c, err := r.Cookie(a.dropUnlockCookieName(d.PublicID))
	if err != nil {
		return false
	}
	return hmac.Equal([]byte(c.Value), []byte(a.dropUnlockToken(d)))
}

func (a *App) setDropUnlockCookie(w http.ResponseWriter, d *dropMeta) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.dropUnlockCookieName(d.PublicID),
		Value:    a.dropUnlockToken(d),
		Path:     "/r/" + d.PublicID,
		Expires:  time.Now().Add(6 * time.Hour),
		HttpOnly: true,
		Secure:   a.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}
