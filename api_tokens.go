package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// API tokens let a program act as a user on /api/v1 and /mcp, which is how AI
// agents share files here. A token is a bearer secret like a session cookie,
// and it is stored the same way: SHA-256 only (sessionKey), so a database dump
// cannot be replayed. The plaintext is shown once, when it is created.
//
// Tokens authenticate ONLY the API. They are never accepted on the web routes,
// and the API never accepts a session cookie: a cookie travels with every
// request a browser makes, so an API that honoured one would be reachable by
// any page that can make the browser send a POST.

const (
	// Recognisable in a config file, a log scrubber or a secret scanner.
	apiTokenPrefix = "pyx_"

	// last_used_at is advisory, so it is written at most this often per token
	// instead of on every request.
	apiTokenTouchEvery = time.Minute

	maxAPITokenName = 80
)

type apiTokenCtxKey struct{}

// apiTokenIDFromContext is the token a request authenticated with, or nil for
// a browser session.
func apiTokenIDFromContext(ctx context.Context) *string {
	id, _ := ctx.Value(apiTokenCtxKey{}).(string)
	if id == "" {
		return nil
	}
	return &id
}

// APIToken is one row of the account page's token list. Never the secret.
type APIToken struct {
	ID         string
	Name       string
	Hint       string // the last characters, so a person can tell tokens apart
	CreatedAt  time.Time
	LastUsedAt *time.Time
	ExpiresAt  *time.Time
}

func (t APIToken) Expired() bool { return t.ExpiresAt != nil && time.Now().After(*t.ExpiresAt) }

// createAPIToken returns the plaintext token, which exists nowhere else.
func (a *App) createAPIToken(ctx context.Context, userID uuid.UUID, name string, expiresAt *time.Time) (string, error) {
	token := apiTokenPrefix + randomToken(32)
	_, err := a.db.Exec(ctx,
		`INSERT INTO api_tokens (id, user_id, name, token_hash, hint, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		uuid.NewString(), userID.String(), name, sessionKey(token), token[len(token)-4:], expiresAt)
	if err != nil {
		return "", err
	}
	return token, nil
}

func (a *App) listAPITokens(ctx context.Context, userID uuid.UUID) ([]APIToken, error) {
	rows, err := a.db.Query(ctx,
		`SELECT id::text, name, hint, created_at, last_used_at, expires_at
		   FROM api_tokens WHERE user_id = $1 AND oauth_client_id IS NULL
		  ORDER BY created_at DESC`, userID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIToken
	for rows.Next() {
		var t APIToken
		if err := rows.Scan(&t.ID, &t.Name, &t.Hint, &t.CreatedAt, &t.LastUsedAt, &t.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// apiTokenUser resolves a presented token to its user. The user row is read
// fresh, as sessionUser does, so an admin's change to the account applies to
// the token's very next request.
func (a *App) apiTokenUser(ctx context.Context, token string) (*User, string, error) {
	if !strings.HasPrefix(token, apiTokenPrefix) {
		return nil, "", pgx.ErrNoRows
	}
	var (
		u        User
		tokenID  string
		email    *string
		hash     *string
		issuer   *string
		subject  *string
		lastUsed *time.Time
	)
	err := a.db.QueryRow(ctx,
		`SELECT t.id::text, t.last_used_at,
		        u.id::text, u.username, u.email, u.password_hash, u.oidc_issuer, u.oidc_subject,
		        u.is_admin, u.is_super_admin, u.max_upload_bytes
		   FROM api_tokens t JOIN users u ON u.id = t.user_id
		  WHERE t.token_hash = $1 AND (t.expires_at IS NULL OR t.expires_at > NOW())`,
		sessionKey(token)).
		Scan(&tokenID, &lastUsed, &u.ID, &u.Username, &email, &hash, &issuer, &subject,
			&u.IsAdmin, &u.IsSuperAdmin, &u.MaxUploadBytes)
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
	u.HasPassword = hash != nil && *hash != ""
	if lastUsed == nil || time.Since(*lastUsed) > apiTokenTouchEvery {
		if _, err := a.db.Exec(ctx,
			`UPDATE api_tokens SET last_used_at = NOW() WHERE id = $1`, tokenID); err != nil {
			log.Printf("api token touch: %v", err)
		}
	}
	return &u, tokenID, nil
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// requireAPIToken authenticates a request by its bearer token and nothing
// else. Failures count against the source address with the login limiter's
// budget, so the token space cannot be walked from one place.
func (a *App) requireAPIToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Whatever withOptionalUser found in a cookie is dropped here: see the
		// comment at the top of this file.
		ctx := context.WithValue(r.Context(), userCtxKey, (*User)(nil))
		token := bearerToken(r)
		limitKey := a.clientIP(r) + "|api"
		if token == "" {
			w.Header().Set("WWW-Authenticate", a.bearerChallenge(r, ""))
			apiError(w, http.StatusUnauthorized, "an API token is required: Authorization: Bearer pyx_…")
			return
		}
		if !a.apiLimiter.allow(ctx, limitKey) {
			apiError(w, http.StatusTooManyRequests, "too many failed authentication attempts")
			return
		}
		user, tokenID, err := a.apiTokenUser(ctx, token)
		if err != nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				httpError(w, err, http.StatusInternalServerError)
				return
			}
			a.apiLimiter.fail(ctx, limitKey)
			// invalid_token tells an OAuth client to refresh or re-authorize.
			w.Header().Set("WWW-Authenticate", a.bearerChallenge(r, "invalid_token"))
			apiError(w, http.StatusUnauthorized, "the API token is invalid, expired or revoked")
			return
		}
		ctx = context.WithValue(ctx, userCtxKey, user)
		ctx = context.WithValue(ctx, apiTokenCtxKey{}, tokenID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// --- /account/tokens ------------------------------------------------------

// handleAccountTokens creates a token (POST /account/tokens) and shows it once.
func (a *App) handleAccountTokens(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user := userFromContext(r.Context())
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" || len(name) > maxAPITokenName {
		a.renderAccountWith(w, r, http.StatusBadRequest, map[string]any{
			"TokenError": a.tr(r, "tokens.err_name")})
		return
	}
	var expiresAt *time.Time
	switch days := r.PostFormValue("expires_days"); days {
	case "", "0":
	case "30", "90", "365":
		t := time.Now().AddDate(0, 0, map[string]int{"30": 30, "90": 90, "365": 365}[days])
		expiresAt = &t
	default:
		http.Error(w, "bad expiry", http.StatusBadRequest)
		return
	}
	token, err := a.createAPIToken(r.Context(), user.ID, name, expiresAt)
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	log.Printf("api token created: %s (%q)", user.Username, name)
	a.renderAccountWith(w, r, http.StatusOK, map[string]any{"NewToken": token, "NewTokenName": name})
}

// handleAccountTokenRevoke deletes one of the user's own tokens
// (POST /account/tokens/{id}/revoke). Shares it already made keep working:
// they are links, and the people they were sent to hold them.
func (a *App) handleAccountTokenRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user := userFromContext(r.Context())
	idStr, action, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/account/tokens/"), "/")
	id, err := uuid.Parse(idStr)
	if err != nil || action != "revoke" {
		http.NotFound(w, r)
		return
	}
	if _, err := a.db.Exec(r.Context(),
		`DELETE FROM api_tokens WHERE id = $1 AND user_id = $2 AND oauth_client_id IS NULL`,
		id.String(), user.ID.String()); err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	log.Printf("api token revoked: %s", user.Username)
	http.Redirect(w, r, "/account#api-tokens", http.StatusSeeOther)
}
