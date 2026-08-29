package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	sessionCookieName = "pyxis_sid"
	sessionTTL        = 30 * 24 * time.Hour
)

type User struct {
	ID           uuid.UUID
	Username     string
	Email        string
	OIDCSubject  string
	IsAdmin      bool
	IsSuperAdmin bool
	HasPassword  bool
}

type contextKey string

const userCtxKey contextKey = "user"

func userFromContext(ctx context.Context) *User {
	u, _ := ctx.Value(userCtxKey).(*User)
	return u
}

func hashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(b), err
}

func checkPassword(hash, pw string) bool {
	if hash == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
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

func (a *App) findUserByUsername(ctx context.Context, username string) (*User, string, error) {
	var (
		u       User
		hash    *string
		email   *string
		subject *string
	)
	err := a.db.QueryRow(ctx,
		`SELECT id::text, username, email, password_hash, oidc_subject, is_admin, is_super_admin
		 FROM users WHERE lower(username) = lower($1)`, username).
		Scan(&u.ID, &u.Username, &email, &hash, &subject, &u.IsAdmin, &u.IsSuperAdmin)
	if err != nil {
		return nil, "", err
	}
	if email != nil {
		u.Email = *email
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

func (a *App) findUserByOIDCSubject(ctx context.Context, sub string) (*User, error) {
	var (
		u       User
		hash    *string
		email   *string
		subject *string
	)
	err := a.db.QueryRow(ctx,
		`SELECT id::text, username, email, password_hash, oidc_subject, is_admin, is_super_admin
		 FROM users WHERE oidc_subject = $1`, sub).
		Scan(&u.ID, &u.Username, &email, &hash, &subject, &u.IsAdmin, &u.IsSuperAdmin)
	if err != nil {
		return nil, err
	}
	if email != nil {
		u.Email = *email
	}
	if subject != nil {
		u.OIDCSubject = *subject
	}
	u.HasPassword = hash != nil && *hash != ""
	return &u, nil
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
}

func (a *App) listUsers(ctx context.Context) ([]UserRow, error) {
	rows, err := a.db.Query(ctx,
		`SELECT id::text, username, email,
		        (password_hash IS NOT NULL) AS has_password,
		        (oidc_subject IS NOT NULL) AS has_oidc,
		        is_admin, is_super_admin, created_at
		 FROM users ORDER BY created_at ASC`)
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
			&u.HasPassword, &u.HasOIDC, &u.IsAdmin, &u.IsSuperAdmin, &u.CreatedAt); err != nil {
			return nil, err
		}
		if email != nil {
			u.Email = *email
		}
		out = append(out, u)
	}
	return out, rows.Err()
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

func (a *App) upsertOIDCUser(ctx context.Context, sub, preferredUsername, email string) (*User, error) {
	if u, err := a.findUserByOIDCSubject(ctx, sub); err == nil {
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
		`INSERT INTO users (id, username, email, oidc_subject, is_admin)
		 VALUES ($1, $2, $3, $4, FALSE)`,
		id.String(), username, emailArg, sub)
	if err != nil {
		return nil, err
	}
	return &User{
		ID:          id,
		Username:    username,
		Email:       email,
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

func (a *App) createSession(ctx context.Context, userID uuid.UUID) (string, time.Time, error) {
	sid := randomToken(32)
	expiresAt := time.Now().Add(sessionTTL)
	_, err := a.db.Exec(ctx,
		`INSERT INTO sessions (id, user_id, expires_at) VALUES ($1, $2, $3)`,
		sid, userID.String(), expiresAt)
	if err != nil {
		return "", time.Time{}, err
	}
	return sid, expiresAt, nil
}

func (a *App) sessionUser(ctx context.Context, sid string) (*User, error) {
	if sid == "" {
		return nil, pgx.ErrNoRows
	}
	var (
		u       User
		email   *string
		hash    *string
		subject *string
	)
	err := a.db.QueryRow(ctx,
		`SELECT u.id::text, u.username, u.email, u.password_hash, u.oidc_subject, u.is_admin, u.is_super_admin
		 FROM sessions s
		 JOIN users u ON u.id = s.user_id
		 WHERE s.id = $1 AND s.expires_at > NOW()`, sid).
		Scan(&u.ID, &u.Username, &email, &hash, &subject, &u.IsAdmin, &u.IsSuperAdmin)
	if err != nil {
		return nil, err
	}
	if email != nil {
		u.Email = *email
	}
	if subject != nil {
		u.OIDCSubject = *subject
	}
	u.HasPassword = hash != nil && *hash != ""
	return &u, nil
}

// deleteUserSessions revokes a user's sessions. exceptSID keeps one session
// alive (the one performing a self-service password change); pass "" to
// revoke everything (admin resets, privilege changes).
func (a *App) deleteUserSessions(ctx context.Context, userID uuid.UUID, exceptSID string) error {
	_, err := a.db.Exec(ctx,
		`DELETE FROM sessions WHERE user_id = $1 AND id <> $2`,
		userID.String(), exceptSID)
	return err
}

func (a *App) deleteSession(ctx context.Context, sid string) {
	if sid == "" {
		return
	}
	if _, err := a.db.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, sid); err != nil {
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
