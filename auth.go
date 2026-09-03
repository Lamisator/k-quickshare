package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/argon2"
)

const (
	sessionCookieName = "pyxis_sid"
	sessionTTL        = 30 * 24 * time.Hour

	// How long a completed step-up (a fresh interactive OIDC sign-in) stays
	// good for. Long enough to fill in a form, short enough that a session
	// stolen afterwards cannot use it.
	reauthWindow = 10 * time.Minute
)

type User struct {
	ID           uuid.UUID
	Username     string
	Email        string
	OIDCIssuer   string
	OIDCSubject  string
	IsAdmin      bool
	IsSuperAdmin bool
	HasPassword  bool

	// Per-file upload ceiling override, as stored: nil means "inherit the
	// instance default". Read on every request with the session, so an admin's
	// change applies to the user's very next upload.
	MaxUploadBytes *int64

	// Session-scoped, filled in by sessionUser: when this session last
	// completed a fresh interactive OIDC authentication. Nil on a session that
	// never did (a local password login, or an SSO session from before the
	// step-up existed).
	ReauthAt *time.Time
}

// HasOIDC reports whether the account is backed by an external identity.
func (u *User) HasOIDC() bool { return u.OIDCSubject != "" }

// ReauthFresh reports whether this session's step-up is still inside the
// window. A password login never sets one, so this is false for those — which
// is correct: they authenticate with the credential they are being asked to
// prove, and that path checks the current password instead.
func (u *User) ReauthFresh() bool {
	return u.ReauthAt != nil && time.Since(*u.ReauthAt) < reauthWindow
}

type contextKey string

const userCtxKey contextKey = "user"

func userFromContext(ctx context.Context) *User {
	u, _ := ctx.Value(userCtxKey).(*User)
	return u
}

// --- password hashing -------------------------------------------------------
//
// Local passwords are hashed with Argon2id, and nothing else. Earlier versions
// wrote bcrypt and kept a verifier for it so existing accounts could be
// upgraded on their next sign-in; every stored hash has since been migrated, so
// that verifier and the upgrade path it fed are gone.
//
// Consequence worth knowing before restoring an old backup: a dump taken before
// the migration still holds bcrypt hashes, and those accounts can no longer log
// in at all. Their passwords have to be reset by an admin.
//
// Parameters are OWASP's first recommended Argon2id configuration: 19 MiB of
// memory, two passes, one lane. The heavier m=64MiB/p=4 variant is also
// acceptable, but every login attempt allocates that memory on the server, and
// the login form is reachable by anyone — 19 MiB keeps the memory-hardness that
// makes GPU cracking expensive without turning the sign-in page into an
// amplification lever.
const (
	argonTime    uint32 = 2
	argonMemory  uint32 = 19 * 1024 // KiB
	argonThreads uint8  = 1
	argonKeyLen  uint32 = 32
	argonSaltLen        = 16
)

func hashPassword(pw string) (string, error) {
	salt := randomBytes(argonSaltLen)
	sum := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(sum)), nil
}

// checkPassword verifies pw against a stored Argon2id hash. Anything that is
// not one — empty, bcrypt, or a corrupted row — fails closed rather than
// falling back to another algorithm.
//
// The cost parameters are read from the stored string, never from the constants
// above, so raising them later cannot invalidate hashes already written.
func checkPassword(hash, pw string) bool {
	if !strings.HasPrefix(hash, "$argon2id$") {
		return false
	}
	return checkArgon2id(hash, pw)
}

func checkArgon2id(hash, pw string) bool {
	// $argon2id$v=19$m=19456,t=2,p=1$<salt>$<digest>
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	var (
		memory  uint32
		timeArg uint32
		threads uint8
	)
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &timeArg, &threads); err != nil {
		return false
	}
	// Refuse absurd stored parameters rather than allocating whatever a
	// tampered row asks for.
	if memory == 0 || memory > 1<<20 || timeArg == 0 || timeArg > 16 || threads == 0 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, timeArg, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func randomToken(n int) string {
	return base64.RawURLEncoding.EncodeToString(randomBytes(n))
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// --- users ----------------------------------------------------------------

// userColumns is the projection every user lookup shares, so a column added to
// scanUser cannot be forgotten in one of the three queries that feed it.
const userColumns = `id::text, username, email, password_hash, oidc_issuer, oidc_subject,
	is_admin, is_super_admin`

// scanUser reads userColumns from one row and returns the stored password hash
// alongside, since only the login paths need it.
func scanUser(row pgx.Row) (*User, string, error) {
	var (
		u       User
		hash    *string
		email   *string
		issuer  *string
		subject *string
	)
	err := row.Scan(&u.ID, &u.Username, &email, &hash, &issuer, &subject,
		&u.IsAdmin, &u.IsSuperAdmin)
	if err != nil {
		return nil, "", err
	}
	if email != nil {
		u.Email = *email
	}
	if issuer != nil {
		u.OIDCIssuer = *issuer
	}
	if subject != nil {
		u.OIDCSubject = *subject
	}
	if hash != nil && *hash != "" {
		u.HasPassword = true
		return &u, *hash, nil
	}
	return &u, "", nil
}

func (a *App) findUserByUsername(ctx context.Context, username string) (*User, string, error) {
	return scanUser(a.db.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE lower(username) = lower($1)`, username))
}

// findUserByOIDCIdentity resolves the account for one external identity.
//
// OpenID Connect guarantees uniqueness only for the (issuer, subject) PAIR: a
// `sub` is unique within its issuer and says nothing outside it. Matching on
// `sub` alone means that repointing the instance at another IdP — or an
// attacker who can register at one — maps a colliding subject straight onto an
// existing account, an administrator's included.
//
// The second lookup adopts a row written before the issuer was recorded: it can
// only ever match an account this instance created itself, and it claims the
// row for the configured issuer so the ambiguity is gone from then on.
// findUserByID resolves the account an upload is charged to. A drop upload
// arrives with no session at all — the person sending the file has no account —
// so the quota, the file-count allowance and the per-file ceiling have to come
// from the drop's OWNER, loaded here.
func (a *App) findUserByID(ctx context.Context, id string) (*User, error) {
	var (
		u       User
		email   *string
		hash    *string
		issuer  *string
		subject *string
	)
	err := a.db.QueryRow(ctx,
		`SELECT id::text, username, email, password_hash, oidc_issuer, oidc_subject,
		        is_admin, is_super_admin, max_upload_bytes
		 FROM users WHERE id = $1`, id).
		Scan(&u.ID, &u.Username, &email, &hash, &issuer, &subject,
			&u.IsAdmin, &u.IsSuperAdmin, &u.MaxUploadBytes)
	if err != nil {
		return nil, err
	}
	if email != nil {
		u.Email = *email
	}
	if issuer != nil {
		u.OIDCIssuer = *issuer
	}
	if subject != nil {
		u.OIDCSubject = *subject
	}
	u.HasPassword = hash != nil && *hash != ""
	return &u, nil
}

func (a *App) findUserByOIDCIdentity(ctx context.Context, issuer, sub string) (*User, error) {
	if issuer == "" || sub == "" {
		return nil, pgx.ErrNoRows
	}
	u, _, err := scanUser(a.db.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE oidc_issuer = $1 AND oidc_subject = $2`,
		issuer, sub))
	if err == nil {
		return u, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}

	u, _, err = scanUser(a.db.QueryRow(ctx,
		`UPDATE users SET oidc_issuer = $1
		  WHERE oidc_subject = $2 AND oidc_issuer IS NULL
		  RETURNING `+userColumns, issuer, sub))
	if err != nil {
		return nil, err
	}
	log.Printf("oidc: adopted pre-issuer account %q for issuer %s", u.Username, issuer)
	return u, nil
}

func (a *App) createLocalUser(ctx context.Context, username, email, password string, isAdmin bool) (*User, error) {
	hash, err := hashPassword(password)
	if err != nil {
		return nil, err
	}
	id := uuid.New()
	var emailArg any
	if email != "" {
		emailArg = email
	}
	_, err = a.db.Exec(ctx,
		`INSERT INTO users (id, username, email, password_hash, is_admin)
		 VALUES ($1, $2, $3, $4, $5)`,
		id.String(), username, emailArg, hash, isAdmin)
	if err != nil {
		return nil, err
	}
	return &User{ID: id, Username: username, Email: email, IsAdmin: isAdmin, HasPassword: true}, nil
}

func (a *App) updatePassword(ctx context.Context, userID uuid.UUID, newPassword string) error {
	hash, err := hashPassword(newPassword)
	if err != nil {
		return err
	}
	_, err = a.db.Exec(ctx,
		`UPDATE users SET password_hash = $1 WHERE id = $2`, hash, userID.String())
	return err
}

type UserRow struct {
	ID           string
	Username     string
	Email        string
	IsAdmin      bool
	IsSuperAdmin bool
	HasPassword  bool
	HasOIDC      bool
	CreatedAt    time.Time

	// Overrides as stored: nil means "inherits the instance default".
	QuotaBytes     *int64
	QuotaFiles     *int64
	MaxUploadBytes *int64
	// Current consumption, counted exactly the way loadUsage counts it for
	// enforcement — an admin comparing the two columns must not see the
	// displayed usage disagree with the limit that is actually applied.
	UsedBytes int64
	UsedFiles int64

	// Resolved for display; filled in by renderAdminUsers, not by the query.
	EffQuota     UserQuota
	EffMaxUpload int64
	Custom       bool
	// Override values pre-rendered for the edit form, empty when inherited.
	QuotaBytesInput string
	QuotaFilesInput string
	MaxUploadInput  string
}

func (a *App) listUsers(ctx context.Context) ([]UserRow, error) {
	rows, err := a.db.Query(ctx,
		`SELECT u.id::text, u.username, u.email,
		        (u.password_hash IS NOT NULL) AS has_password,
		        (u.oidc_subject IS NOT NULL) AS has_oidc,
		        u.is_admin, u.is_super_admin, u.created_at,
		        u.quota_bytes, u.quota_files, u.max_upload_bytes,
		        COALESCE(f.bytes, 0), COALESCE(f.files, 0)
		 FROM users u
		 LEFT JOIN (
		     SELECT uploaded_by, SUM(size_bytes) AS bytes, COUNT(*) AS files
		     FROM files WHERE `+activeFileWhere+`
		     GROUP BY uploaded_by
		 ) f ON f.uploaded_by = u.id
		 ORDER BY u.created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserRow
	for rows.Next() {
		var (
			u     UserRow
			email *string
		)
		if err := rows.Scan(&u.ID, &u.Username, &email,
			&u.HasPassword, &u.HasOIDC, &u.IsAdmin, &u.IsSuperAdmin, &u.CreatedAt,
			&u.QuotaBytes, &u.QuotaFiles, &u.MaxUploadBytes,
			&u.UsedBytes, &u.UsedFiles); err != nil {
			return nil, err
		}
		if email != nil {
			u.Email = *email
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// setUserLimits writes one user's overrides — the storage allowance and the
// per-file upload ceiling, which the admin edits in one form. A nil argument
// clears that column, putting the dimension back on the instance default.
func (a *App) setUserLimits(ctx context.Context, userID uuid.UUID, bytes, files, maxUpload *int64) error {
	_, err := a.db.Exec(ctx,
		`UPDATE users SET quota_bytes = $1, quota_files = $2, max_upload_bytes = $3
		 WHERE id = $4`,
		bytes, files, maxUpload, userID.String())
	return err
}

func (a *App) countAdmins(ctx context.Context) (int, error) {
	var n int
	err := a.db.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE is_admin`).Scan(&n)
	return n, err
}

func (a *App) setAdminFlag(ctx context.Context, userID uuid.UUID, isAdmin bool) error {
	_, err := a.db.Exec(ctx,
		`UPDATE users SET is_admin = $1 WHERE id = $2`, isAdmin, userID.String())
	return err
}

func (a *App) deleteUser(ctx context.Context, userID uuid.UUID) error {
	_, err := a.db.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID.String())
	return err
}

func (a *App) upsertOIDCUser(ctx context.Context, issuer, sub, preferredUsername, email string) (*User, error) {
	if issuer == "" {
		return nil, errors.New("oidc: refusing to bind an account without an issuer")
	}
	if u, err := a.findUserByOIDCIdentity(ctx, issuer, sub); err == nil {
		return u, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}

	username := preferredUsername
	if username == "" {
		if email != "" {
			username = email
		} else {
			shortSub := sub
			if len(shortSub) > 8 {
				shortSub = shortSub[:8]
			}
			username = "user-" + shortSub
		}
	}
	base := username
	for suffix := 1; suffix < 100; suffix++ {
		var exists bool
		err := a.db.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM users WHERE lower(username) = lower($1))`, username).
			Scan(&exists)
		if err != nil {
			return nil, err
		}
		if !exists {
			break
		}
		username = base + "-" + itoa(suffix)
	}

	id := uuid.New()
	var emailArg any
	if email != "" {
		emailArg = email
	}
	_, err := a.db.Exec(ctx,
		`INSERT INTO users (id, username, email, oidc_issuer, oidc_subject, is_admin)
		 VALUES ($1, $2, $3, $4, $5, FALSE)`,
		id.String(), username, emailArg, issuer, sub)
	if err != nil {
		return nil, err
	}
	return &User{
		ID:          id,
		Username:    username,
		Email:       email,
		OIDCIssuer:  issuer,
		OIDCSubject: sub,
	}, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := [4]byte{}
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// --- sessions -------------------------------------------------------------

// sessionKey is what actually goes in the sessions table. The cookie value is a
// bearer token: storing it verbatim as the primary key meant a database dump —
// a backup, a read replica, an errant `SELECT *` in a support ticket — handed
// over every live session ready to replay. Only the SHA-256 of the token is
// stored, exactly as one stores an API bearer token, so a leaked row proves a
// session exists but cannot be used as one.
//
// The token is 32 bytes of CSPRNG output, so a plain hash is right here: there
// is no low-entropy guess to slow down, and password-style stretching on every
// request would only cost latency.
func sessionKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (a *App) createSession(ctx context.Context, userID uuid.UUID, reauthAt *time.Time) (string, time.Time, error) {
	token := randomToken(32)
	expiresAt := time.Now().Add(sessionTTL)
	_, err := a.db.Exec(ctx,
		`INSERT INTO sessions (id, user_id, expires_at, reauth_at) VALUES ($1, $2, $3, $4)`,
		sessionKey(token), userID.String(), expiresAt, reauthAt)
	if err != nil {
		return "", time.Time{}, err
	}
	return token, expiresAt, nil
}

func (a *App) sessionUser(ctx context.Context, token string) (*User, error) {
	if token == "" {
		return nil, pgx.ErrNoRows
	}
	var (
		u        User
		email    *string
		hash     *string
		issuer   *string
		subject  *string
		reauthAt *time.Time
	)
	err := a.db.QueryRow(ctx,
		`SELECT u.id::text, u.username, u.email, u.password_hash, u.oidc_issuer, u.oidc_subject,
		        u.is_admin, u.is_super_admin, u.max_upload_bytes, s.reauth_at
		 FROM sessions s
		 JOIN users u ON u.id = s.user_id
		 WHERE s.id = $1 AND s.expires_at > NOW()`, sessionKey(token)).
		Scan(&u.ID, &u.Username, &email, &hash, &issuer, &subject,
			&u.IsAdmin, &u.IsSuperAdmin, &u.MaxUploadBytes, &reauthAt)
	if err != nil {
		return nil, err
	}
	if email != nil {
		u.Email = *email
	}
	if issuer != nil {
		u.OIDCIssuer = *issuer
	}
	if subject != nil {
		u.OIDCSubject = *subject
	}
	u.HasPassword = hash != nil && *hash != ""
	u.ReauthAt = reauthAt
	return &u, nil
}

// markSessionReauth stamps a session as having just completed a fresh
// interactive sign-in with the identity provider.
func (a *App) markSessionReauth(ctx context.Context, token string, userID uuid.UUID) error {
	_, err := a.db.Exec(ctx,
		`UPDATE sessions SET reauth_at = NOW() WHERE id = $1 AND user_id = $2`,
		sessionKey(token), userID.String())
	return err
}

// clearSessionReauth spends a completed step-up across all of the user's
// sessions, so one re-authentication authorises one action.
func (a *App) clearSessionReauth(ctx context.Context, userID uuid.UUID) error {
	_, err := a.db.Exec(ctx,
		`UPDATE sessions SET reauth_at = NULL WHERE user_id = $1`, userID.String())
	return err
}

// deleteUserSessions revokes a user's sessions. exceptToken keeps one session
// alive (the one performing a self-service password change); pass "" to
// revoke everything (admin resets, privilege changes).
func (a *App) deleteUserSessions(ctx context.Context, userID uuid.UUID, exceptToken string) error {
	except := ""
	if exceptToken != "" {
		except = sessionKey(exceptToken)
	}
	_, err := a.db.Exec(ctx,
		`DELETE FROM sessions WHERE user_id = $1 AND id <> $2`,
		userID.String(), except)
	return err
}

func (a *App) deleteSession(ctx context.Context, token string) {
	if token == "" {
		return
	}
	if _, err := a.db.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, sessionKey(token)); err != nil {
		log.Printf("delete session: %v", err)
	}
}

func setSessionCookie(w http.ResponseWriter, sid string, expires time.Time, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sid,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func readSessionCookie(r *http.Request) string {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

// --- middleware -----------------------------------------------------------

func (a *App) withOptionalUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sid := readSessionCookie(r)
		if sid != "" {
			if u, err := a.sessionUser(r.Context(), sid); err == nil {
				ctx := context.WithValue(r.Context(), userCtxKey, u)
				r = r.WithContext(ctx)
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) requireUser(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if userFromContext(r.Context()) == nil {
			if wantsJSON(r) || r.Method != http.MethodGet {
				http.Error(w, "authentication required", http.StatusUnauthorized)
				return
			}
			redir := "/login?next=" + url.QueryEscape(r.URL.RequestURI())
			http.Redirect(w, r, redir, http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func wantsJSON(r *http.Request) bool {
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "application/json") ||
		strings.EqualFold(r.Header.Get("X-Requested-With"), "XMLHttpRequest")
}

// --- admin bootstrap ------------------------------------------------------

// bootstrapAdmin provisions the initial super-admin. It only ever CREATES an
// account: once any super-admin exists in the database, the routine is a
// no-op, and an existing username is never promoted — a username match says
// nothing about identity (an OIDC user could have claimed the same name), so
// promotion would be a privilege-escalation path.
func (a *App) bootstrapAdmin(ctx context.Context, username, password string) error {
	if username == "" {
		return nil
	}
	var superAdmins int
	if err := a.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM users WHERE is_super_admin`).Scan(&superAdmins); err != nil {
		return err
	}
	if superAdmins > 0 {
		return nil
	}
	u, _, err := a.findUserByUsername(ctx, username)
	if err == nil {
		log.Printf("admin bootstrap: user %q already exists (oidc=%v) — refusing to promote it; "+
			"grant super-admin manually via SQL if this is really the right account", u.Username, u.OIDCSubject != "")
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if len(password) < minPasswordLen {
		log.Printf("admin bootstrap: no super-admin exists and ADMIN_PASSWORD is unset or shorter than %d chars — skipping", minPasswordLen)
		return nil
	}
	nu, err := a.createLocalUser(ctx, username, "", password, true)
	if err != nil {
		return err
	}
	if _, err := a.db.Exec(ctx,
		`UPDATE users SET is_super_admin = TRUE WHERE id = $1`, nu.ID.String()); err != nil {
		return err
	}
	log.Printf("admin bootstrap: created super-admin %q (id=%s)", nu.Username, nu.ID)
	return nil
}

// --- settings store -------------------------------------------------------

func (a *App) loadAllSettings(ctx context.Context) (map[string]string, error) {
	rows, err := a.db.Query(ctx, `SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		m[k] = v
	}
	return m, rows.Err()
}

func (a *App) saveSettings(ctx context.Context, kv map[string]string) error {
	tx, err := a.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for k, v := range kv {
		if _, err := tx.Exec(ctx,
			`INSERT INTO settings (key, value) VALUES ($1, $2)
			 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
			k, v); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
