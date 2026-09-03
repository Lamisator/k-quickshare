package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
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

// activeFileWhere is the definition of a file that counts against a quota. It
// is spliced into three queries — the enforcement path here, the admin table
// and the account page — and the point of the constant is that those three can
// no longer drift apart and show someone a number that is not the one being
// applied. It names columns unqualified, so every caller must expose `files`
// under its own name or an alias-free subquery.
const activeFileWhere = `archived_at IS NULL AND (expires_at IS NULL OR expires_at > NOW())`

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
		 FROM files WHERE `+activeFileWhere, userID).
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

// --- per-user quota resolution --------------------------------------------

const (
	settingQuotaUserBytes = "quota.user_bytes"
	settingQuotaUserFiles = "quota.user_files"
	settingUploadMaxBytes = "upload.max_bytes"
)

// loadQuotaDefaults resolves the instance-wide per-user allowance: the values
// an admin saved, else the environment fallbacks. The env vars are only a
// fallback, never a seed — once a row exists the settings table wins, so
// changing QUOTA_USER_BYTES on a configured instance is deliberately a no-op.
func (a *App) loadQuotaDefaults(ctx context.Context, env UserQuota) error {
	m, err := a.loadAllSettings(ctx)
	if err != nil {
		return err
	}
	q := env
	if n, ok := parseStoredInt(m[settingQuotaUserBytes]); ok {
		q.Bytes = n
	}
	if n, ok := parseStoredInt(m[settingQuotaUserFiles]); ok {
		q.Files = n
	}
	a.setQuotaDefaults(q)
	log.Printf("quota defaults: %s per user, %d files per user (0 = unlimited)",
		humanSize(q.Bytes), q.Files)
	return nil
}

func parseStoredInt(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

func (a *App) getQuotaDefaults() UserQuota {
	a.quotaMu.RLock()
	defer a.quotaMu.RUnlock()
	return a.quotaDefaults
}

func (a *App) setQuotaDefaults(q UserQuota) {
	a.quotaMu.Lock()
	a.quotaDefaults = q
	a.quotaMu.Unlock()
}

func (a *App) saveQuotaDefaults(ctx context.Context, q UserQuota) error {
	if err := a.saveSettings(ctx, map[string]string{
		settingQuotaUserBytes: strconv.FormatInt(q.Bytes, 10),
		settingQuotaUserFiles: strconv.FormatInt(q.Files, 10),
	}); err != nil {
		return err
	}
	a.setQuotaDefaults(q)
	return nil
}

// --- per-file upload ceiling ----------------------------------------------
//
// This is a different kind of limit from the quota above and is resolved
// differently on purpose.
//
// A quota bounds what an account may accumulate, so "unlimited" is meaningful
// and admins are exempt from the default. A per-file ceiling bounds ONE
// request — the multipart reader's budget, the temp file it spills to, the
// reservation booked before a byte is written — so it applies to everyone,
// admins included, and it is never zero. An admin who needs to send something
// larger raises the instance limit, or gives themselves an override; both are
// two clicks away and both leave a trace, which "the rule quietly did not
// apply to me" does not.

// loadMaxUploadDefault resolves the instance-wide per-file ceiling: the value
// an admin saved, else the environment fallback. As with the quota defaults
// the env var is a fallback and never a seed — once an admin has saved one,
// changing MAX_UPLOAD_BYTES is deliberately a no-op.
func (a *App) loadMaxUploadDefault(ctx context.Context, env int64) error {
	m, err := a.loadAllSettings(ctx)
	if err != nil {
		return err
	}
	max := env
	if n, ok := parseStoredInt(m[settingUploadMaxBytes]); ok && n > 0 {
		max = n
	}
	a.setMaxUploadDefault(max)
	log.Printf("upload limit: %s per file (per-user overrides may differ)", humanSize(max))
	return nil
}

func (a *App) getMaxUploadDefault() int64 {
	a.quotaMu.RLock()
	defer a.quotaMu.RUnlock()
	return a.maxUploadDefault
}

func (a *App) setMaxUploadDefault(n int64) {
	a.quotaMu.Lock()
	a.maxUploadDefault = n
	a.quotaMu.Unlock()
}

func (a *App) saveMaxUploadDefault(ctx context.Context, n int64) error {
	if err := a.saveSettings(ctx, map[string]string{
		settingUploadMaxBytes: strconv.FormatInt(n, 10),
	}); err != nil {
		return err
	}
	a.setMaxUploadDefault(n)
	return nil
}

// effectiveMaxUpload resolves the ceiling for one user. A nil or non-positive
// override inherits the instance default: zero is not "unlimited" here, and a
// row that somehow holds one must not turn into a limitless request.
func effectiveMaxUpload(override *int64, def int64) int64 {
	if override != nil && *override > 0 {
		return *override
	}
	return def
}

// maxUploadFor is the ceiling applied to this request. The override rides on
// the session user, which is re-read from the database on every request, so an
// admin's change lands on the uploader's very next one.
func (a *App) maxUploadFor(u *User) int64 {
	if u == nil {
		return a.getMaxUploadDefault()
	}
	return effectiveMaxUpload(u.MaxUploadBytes, a.getMaxUploadDefault())
}

// applyQuotaDefaults resolves what is actually enforced for one user from the
// user's own overrides. A nil override inherits the instance default — except
// for admins, who are exempt from the default the way they always have been.
// An override set explicitly on an admin still applies: an admin who types a
// limit into another admin's row means it, and silently dropping it would look
// like a bug.
func applyQuotaDefaults(isAdmin bool, bytes, files *int64, def UserQuota) UserQuota {
	var q UserQuota
	switch {
	case bytes != nil:
		q.Bytes = *bytes
	case !isAdmin:
		q.Bytes = def.Bytes
	}
	switch {
	case files != nil:
		q.Files = *files
	case !isAdmin:
		q.Files = def.Files
	}
	return q
}

// effectiveQuota reads the user's overrides inside the caller's transaction,
// so an admin's change takes effect on the very next upload rather than at the
// user's next sign-in.
func (a *App) effectiveQuota(ctx context.Context, tx pgx.Tx, user *User) (UserQuota, error) {
	var bytes, files *int64
	err := tx.QueryRow(ctx,
		`SELECT quota_bytes, quota_files FROM users WHERE id = $1`, user.ID.String()).
		Scan(&bytes, &files)
	if err != nil {
		return UserQuota{}, err
	}
	return applyQuotaDefaults(user.IsAdmin, bytes, files, a.getQuotaDefaults()), nil
}

// UsageSummary is one user's consumption against their own allowance, for the
// account page. Percent is only meaningful when the limit is not unlimited.
type UsageSummary struct {
	UsedBytes int64
	UsedFiles int64
	Quota     UserQuota
	Custom    bool // the allowance is an override, not the instance default
}

func (s UsageSummary) BytesPercent() float64 { return pct(s.UsedBytes, s.Quota.Bytes) }
func (s UsageSummary) FilesPercent() float64 { return pct(s.UsedFiles, s.Quota.Files) }

// Limited reports whether anything actually caps this user. When nothing does,
// there is no meaningful bar to draw — a progress bar towards "unlimited" is
// decoration — and the shell omits the block entirely.
func (s UsageSummary) Limited() bool { return s.Quota.Bytes > 0 || s.Quota.Files > 0 }

// BarPercent drives the single bar in the shell: bytes when they are capped,
// otherwise the file count, which is then the only limit there is.
func (s UsageSummary) BarPercent() float64 {
	if s.Quota.Bytes > 0 {
		return s.BytesPercent()
	}
	return s.FilesPercent()
}

func pct(used, limit int64) float64 {
	if limit <= 0 {
		return 0
	}
	if used >= limit {
		return 100
	}
	return float64(used) / float64(limit) * 100
}

// usageSummary reports what a user has stored and what they are allowed. It
// counts exactly what the upload path counts (activeFileWhere), so the figure
// someone reads here is the one they will be measured against.
//
// This runs on every page render for a signed-in user, so the aggregate is
// filtered to the one user inside the subquery rather than grouping the whole
// table and joining — that is what files_uploaded_by_idx serves.
func (a *App) usageSummary(ctx context.Context, user *User) (UsageSummary, error) {
	var (
		s      UsageSummary
		qBytes *int64
		qFiles *int64
	)
	err := a.db.QueryRow(ctx,
		`SELECT u.quota_bytes, u.quota_files,
		        COALESCE(f.bytes, 0), COALESCE(f.files, 0)
		 FROM users u
		 LEFT JOIN (
		     SELECT uploaded_by, SUM(size_bytes) AS bytes, COUNT(*) AS files
		     FROM files WHERE uploaded_by = $1 AND `+activeFileWhere+`
		     GROUP BY uploaded_by
		 ) f ON f.uploaded_by = u.id
		 WHERE u.id = $1`, user.ID.String()).
		Scan(&qBytes, &qFiles, &s.UsedBytes, &s.UsedFiles)
	if err != nil {
		return s, err
	}
	s.Quota = applyQuotaDefaults(user.IsAdmin, qBytes, qFiles, a.getQuotaDefaults())
	s.Custom = qBytes != nil || qFiles != nil
	return s, nil
}

func (a *App) quotaViolation(q UserQuota, u usageSnapshot, incoming int64) error {
	if a.quota.TotalBytes > 0 && u.totalBytes+u.totalReserved+incoming > a.quota.TotalBytes {
		return fmt.Errorf("%w: instance storage limit reached", errQuotaExceeded)
	}
	if q.Bytes > 0 && u.userBytes+u.userReserved+incoming > q.Bytes {
		return fmt.Errorf("%w: personal storage limit of %s reached",
			errQuotaExceeded, humanSize(q.Bytes))
	}
	if q.Files > 0 && u.userFiles+u.userResCount+1 > q.Files {
		return fmt.Errorf("%w: personal file-count limit of %d reached",
			errQuotaExceeded, q.Files)
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

// --- drop limits -----------------------------------------------------------
//
// A drop is the one upload path with no session behind it: whoever holds the
// public link may write, and everything they write is charged to the OWNER's
// quota. So the owner's limits are not the only ones that matter — a drop
// carries its own, and they are counted here rather than in the handler,
// because the only place a count means anything is inside the transaction that
// already serialises uploads.
//
// The file COUNT is the part that is easy to get wrong. Bytes are reserved
// before a body is read, so two uploaders racing for the last megabyte both see
// the other's reservation; a count that looked only at stored rows would let
// both of them into a drop that accepts one file, because at the moment they
// both check, neither row exists yet. Reservations therefore carry their drop
// and their submission, and are counted alongside the rows.

var errDropLimit = errors.New("drop limit reached")

// dropLimits is what the owner set on the drop. A nil pointer means "no limit
// of this kind"; the owner's own quota and per-file ceiling still apply on top
// and are enforced separately.
type dropLimits struct {
	MaxFileBytes     *int64
	MaxTotalBytes    *int64
	MaxFiles         *int
	MaxPerSubmission *int
	MaxSubmissions   *int
}

// dropTarget names the drop an upload is going into and the submission within
// it. Nil for every ordinary, signed-in upload.
type dropTarget struct {
	DropID  string
	BatchID string
	Limits  dropLimits
}

type dropUsageSnapshot struct {
	bytes       int64 // active bytes already in the drop, reservations included
	files       int64 // active files already in the drop, reservations included
	submissions int64 // submissions opened on the drop
	subFiles    int64 // files already in THIS submission, reservations included
}

func loadDropUsage(ctx context.Context, tx pgx.Tx, dropID, batchID string) (dropUsageSnapshot, error) {
	var d dropUsageSnapshot
	// activeFileWhere names its columns unqualified, so the drop is selected
	// with a subquery rather than a join: a join would make expires_at
	// ambiguous between files and batches, which is an error at run time and
	// nowhere else.
	err := tx.QueryRow(ctx,
		`SELECT COALESCE(SUM(size_bytes), 0),
		        COUNT(*),
		        COUNT(*) FILTER (WHERE batch_id = $2)
		 FROM files
		 WHERE batch_id IN (SELECT id FROM batches WHERE drop_id = $1)
		   AND `+activeFileWhere, dropID, batchID).
		Scan(&d.bytes, &d.files, &d.subFiles)
	if err != nil {
		return d, err
	}
	var resBytes, resFiles, resSubFiles int64
	err = tx.QueryRow(ctx,
		`SELECT COALESCE(SUM(bytes), 0), COUNT(*), COUNT(*) FILTER (WHERE batch_id = $2)
		 FROM upload_reservations
		 WHERE drop_id = $1 AND created_at > NOW() - $3::interval`,
		dropID, batchID, reservationTTL.String()).
		Scan(&resBytes, &resFiles, &resSubFiles)
	if err != nil {
		return d, err
	}
	d.bytes += resBytes
	d.files += resFiles
	d.subFiles += resSubFiles
	err = tx.QueryRow(ctx,
		`SELECT COUNT(*) FROM batches WHERE drop_id = $1 AND archived_at IS NULL`, dropID).
		Scan(&d.submissions)
	return d, err
}

// dropViolation reports the first limit this upload would break. The messages
// are shown to a stranger who cannot see the drop's settings page, so they say
// what the limit IS rather than only that one was hit.
func dropViolation(l dropLimits, u dropUsageSnapshot, incoming int64) error {
	if l.MaxTotalBytes != nil && *l.MaxTotalBytes > 0 && u.bytes+incoming > *l.MaxTotalBytes {
		return fmt.Errorf("%w: this drop accepts %s in total", errDropLimit, humanSize(*l.MaxTotalBytes))
	}
	if l.MaxFiles != nil && *l.MaxFiles > 0 && u.files+1 > int64(*l.MaxFiles) {
		return fmt.Errorf("%w: this drop accepts %d file(s) and already has them",
			errDropLimit, *l.MaxFiles)
	}
	if l.MaxPerSubmission != nil && *l.MaxPerSubmission > 0 && u.subFiles+1 > int64(*l.MaxPerSubmission) {
		return fmt.Errorf("%w: this drop accepts %d file(s) per delivery",
			errDropLimit, *l.MaxPerSubmission)
	}
	return nil
}

// dropAcceptsAnotherSubmission is the same arithmetic one step earlier, for the
// request that OPENS a submission — before any file has been offered.
func dropAcceptsAnotherSubmission(ctx context.Context, tx pgx.Tx, dropID string, l dropLimits) error {
	u, err := loadDropUsage(ctx, tx, dropID, uuid.Nil.String())
	if err != nil {
		return err
	}
	if l.MaxSubmissions != nil && *l.MaxSubmissions > 0 && u.submissions+1 > int64(*l.MaxSubmissions) {
		return fmt.Errorf("%w: this drop accepts %d delivery(ies)", errDropLimit, *l.MaxSubmissions)
	}
	if l.MaxFiles != nil && *l.MaxFiles > 0 && u.files >= int64(*l.MaxFiles) {
		return fmt.Errorf("%w: this drop accepts %d file(s) and already has them",
			errDropLimit, *l.MaxFiles)
	}
	return nil
}

// reserveUpload atomically books estBytes against the quota before any data
// is written to disk. The reservation is released by finalizeUpload (success)
// or releaseReservation (failure); stale ones expire after reservationTTL.
func (a *App) reserveUpload(ctx context.Context, user *User, estBytes int64, drop *dropTarget) (uuid.UUID, error) {
	ceiling := a.maxUploadFor(user)
	if drop != nil && drop.Limits.MaxFileBytes != nil && *drop.Limits.MaxFileBytes > 0 &&
		*drop.Limits.MaxFileBytes < ceiling {
		ceiling = *drop.Limits.MaxFileBytes
	}
	if estBytes <= 0 || estBytes > ceiling {
		estBytes = ceiling
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
	q, err := a.effectiveQuota(ctx, tx, user)
	if err != nil {
		return uuid.Nil, err
	}
	if err := a.quotaViolation(q, u, estBytes); err != nil {
		return uuid.Nil, err
	}
	var dropID, batchID *string
	if drop != nil {
		du, derr := loadDropUsage(ctx, tx, drop.DropID, drop.BatchID)
		if derr != nil {
			return uuid.Nil, derr
		}
		if derr := dropViolation(drop.Limits, du, estBytes); derr != nil {
			return uuid.Nil, derr
		}
		dropID, batchID = &drop.DropID, &drop.BatchID
	}
	resID := uuid.New()
	if _, err := tx.Exec(ctx,
		`INSERT INTO upload_reservations (id, user_id, bytes, drop_id, batch_id)
		 VALUES ($1, $2, $3, $4, $5)`,
		resID.String(), user.ID.String(), estBytes, dropID, batchID); err != nil {
		return uuid.Nil, err
	}
	return resID, tx.Commit(ctx)
}

// finalizeUpload swaps the reservation for the real files row under the same
// advisory lock, re-checking the quota against the actual written size.
func (a *App) finalizeUpload(ctx context.Context, user *User, resID uuid.UUID,
	written int64, drop *dropTarget, insertFile func(pgx.Tx) error) error {
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
	q, err := a.effectiveQuota(ctx, tx, user)
	if err != nil {
		return err
	}
	if err := a.quotaViolation(q, u, written); err != nil {
		return err
	}
	// The reservation is already gone above, so this counts what is actually
	// stored plus every OTHER upload still in flight — which is what makes two
	// simultaneous uploads into a one-file drop resolve to exactly one file.
	if drop != nil {
		du, derr := loadDropUsage(ctx, tx, drop.DropID, drop.BatchID)
		if derr != nil {
			return derr
		}
		if derr := dropViolation(drop.Limits, du, written); derr != nil {
			return derr
		}
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
