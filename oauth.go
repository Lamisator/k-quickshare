package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// OAuth 2.1 authorization server for MCP clients — claude.ai and ChatGPT
// connectors among them, which will not take a pasted token. It follows the
// MCP authorization spec, as Fundus and Requies already do (Fundus e/77):
// protected resource metadata (RFC 9728), authorization server metadata
// (RFC 8414), dynamic client registration (RFC 7591), the authorization code
// flow with mandatory PKCE S256, rotating refresh tokens and revocation
// (RFC 7009).
//
// The person approves on /oauth/authorize while signed in, through whatever
// sign-in this instance has (password or SSO). The access token an exchange
// yields is an ordinary api_tokens row of theirs, so /mcp and /api/v1 treat it
// exactly like a token made on the account page — with one hour to live.
//
// Pyxis has one thing to grant, sharing files as this user, so there are no
// scopes to choose between: a single "share" scope is advertised for clients
// that insist on sending one.

const (
	oauthCodeTTL    = 10 * time.Minute
	oauthAccessTTL  = time.Hour
	oauthRefreshTTL = 90 * 24 * time.Hour
	oauthScope      = "share"

	// Registration is open to anyone (RFC 7591), so it is capped, and clients
	// that never completed a grant are dropped after an hour. Open
	// registration is not open sign-up: a client gets nothing until a signed-in
	// person approves it.
	maxOAuthClients = 100
)

var (
	errOAuthInvalidGrant  = errors.New("invalid_grant")
	errOAuthInvalidClient = errors.New("invalid_client")
)

// isOAuthPublic lists the endpoints OAuth clients call server to server or
// cross-origin, with no session. sameOriginCheck lets them through.
func isOAuthPublic(p string) bool {
	switch p {
	case "/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp",
		"/.well-known/oauth-authorization-server", "/oauth/token", "/oauth/register", "/oauth/revoke":
		return true
	}
	return false
}

// bearerChallenge points an MCP client at the discovery document.
func (a *App) bearerChallenge(r *http.Request, errCode string) string {
	v := `Bearer realm="pyxis", resource_metadata="` + a.publicBaseURL(r) + `/.well-known/oauth-protected-resource"`
	if errCode != "" {
		v += `, error="` + errCode + `"`
	}
	return v
}

// withCORS lets browser-based MCP clients (MCP Inspector, say) reach the
// public OAuth endpoints and /mcp. None of them honours a cookie, so allowing
// any origin exposes nothing a curl could not already reach.
func withCORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr := w.Header()
		hdr.Set("Access-Control-Allow-Origin", "*")
		hdr.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, MCP-Protocol-Version")
		hdr.Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		hdr.Set("Access-Control-Expose-Headers", "WWW-Authenticate")
		hdr.Set("Access-Control-Max-Age", "86400")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func (a *App) handleOAuthProtectedResource(w http.ResponseWriter, r *http.Request) {
	base := a.publicBaseURL(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 base + "/mcp",
		"authorization_servers":    []string{base},
		"scopes_supported":         []string{oauthScope},
		"bearer_methods_supported": []string{"header"},
		"resource_name":            "Pyxis",
	})
}

func (a *App) handleOAuthServerMetadata(w http.ResponseWriter, r *http.Request) {
	base := a.publicBaseURL(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                         base,
		"authorization_endpoint":                         base + "/oauth/authorize",
		"token_endpoint":                                 base + "/oauth/token",
		"registration_endpoint":                          base + "/oauth/register",
		"revocation_endpoint":                            base + "/oauth/revoke",
		"response_types_supported":                       []string{"code"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"none", "client_secret_post", "client_secret_basic"},
		"revocation_endpoint_auth_methods_supported":     []string{"none", "client_secret_post", "client_secret_basic"},
		"scopes_supported":                               []string{oauthScope},
		"authorization_response_iss_parameter_supported": true,
	})
}

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

// validRedirectURI accepts https, and http only on a loopback address.
func validRedirectURI(raw string) bool {
	if len(raw) > 500 {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Fragment != "" || u.Host == "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		h := u.Hostname()
		return h == "localhost" || h == "127.0.0.1" || h == "::1"
	}
	return false
}

// redirectRegistered reports whether a requested redirect_uri is one the
// client registered. Exact match, with one exception RFC 8252 §7.3 requires:
// a native app's loopback redirect may use any port, because the app binds a
// free one each time it signs in. Claude Code does exactly that — it registers
// http://localhost:53438/callback and comes back on another port. Scheme,
// host, path and query must still match.
func redirectRegistered(registered []string, requested string) bool {
	if slices.Contains(registered, requested) {
		return true
	}
	req, err := url.Parse(requested)
	if err != nil || req.Scheme != "http" || !isLoopbackHost(req.Hostname()) || req.Fragment != "" {
		return false
	}
	for _, r := range registered {
		reg, err := url.Parse(r)
		if err != nil || reg.Scheme != "http" || !isLoopbackHost(reg.Hostname()) {
			continue
		}
		if reg.Hostname() == req.Hostname() && reg.EscapedPath() == req.EscapedPath() &&
			reg.RawQuery == req.RawQuery {
			return true
		}
	}
	return false
}

func isLoopbackHost(h string) bool {
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

// --- registration ---------------------------------------------------------

type oauthClient struct {
	ID           string
	Name         string
	RedirectURIs []string
}

func (a *App) handleOAuthRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		oauthError(w, http.StatusMethodNotAllowed, "invalid_request", "POST only")
		return
	}
	var in struct {
		ClientName    string   `json:"client_name"`
		RedirectURIs  []string `json:"redirect_uris"`
		GrantTypes    []string `json:"grant_types"`
		ResponseTypes []string `json:"response_types"`
		AuthMethod    string   `json:"token_endpoint_auth_method"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "invalid JSON body")
		return
	}
	if len(in.RedirectURIs) == 0 || len(in.RedirectURIs) > 10 {
		oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "1 to 10 redirect_uris are required")
		return
	}
	for _, u := range in.RedirectURIs {
		if !validRedirectURI(u) {
			oauthError(w, http.StatusBadRequest, "invalid_redirect_uri",
				"redirect_uris must use https (or http on localhost): "+u)
			return
		}
	}
	for _, g := range in.GrantTypes {
		if g != "authorization_code" && g != "refresh_token" {
			oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "unsupported grant_type: "+g)
			return
		}
	}
	for _, rt := range in.ResponseTypes {
		if rt != "code" {
			oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "unsupported response_type: "+rt)
			return
		}
	}
	method := in.AuthMethod
	switch method {
	case "":
		method = "client_secret_basic" // the RFC 7591 default
	case "none", "client_secret_post", "client_secret_basic":
	default:
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata",
			"unsupported token_endpoint_auth_method: "+method)
		return
	}

	ctx := r.Context()
	if _, err := a.db.Exec(ctx,
		`DELETE FROM oauth_clients WHERE last_used_at IS NULL AND created_at < NOW() - interval '1 hour'`); err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	var n int
	if err := a.db.QueryRow(ctx, `SELECT COUNT(*) FROM oauth_clients`).Scan(&n); err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	if n >= maxOAuthClients {
		oauthError(w, http.StatusTooManyRequests, "temporarily_unavailable",
			"too many registered clients, try again later")
		return
	}
	name := strings.TrimSpace(in.ClientName)
	if name == "" {
		name = "Unnamed app"
	}
	if rs := []rune(name); len(rs) > 100 {
		name = string(rs[:100])
	}
	id := "pxc_" + randomToken(16)
	var secret string
	var secretHash *string
	if method != "none" {
		secret = "pxs_" + randomToken(32)
		h := sessionKey(secret)
		secretHash = &h
	}
	var created time.Time
	if err := a.db.QueryRow(ctx,
		`INSERT INTO oauth_clients (id, name, redirect_uris, secret_hash) VALUES ($1, $2, $3, $4)
		 RETURNING created_at`, id, name, in.RedirectURIs, secretHash).Scan(&created); err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	log.Printf("oauth client registered: %s (%q) from %s", id, name, a.clientIP(r))
	out := map[string]any{
		"client_id": id, "client_id_issued_at": created.Unix(), "client_name": name,
		"redirect_uris": in.RedirectURIs, "grant_types": []string{"authorization_code", "refresh_token"},
		"response_types": []string{"code"}, "token_endpoint_auth_method": method, "scope": oauthScope,
	}
	if secret != "" {
		out["client_secret"] = secret
		out["client_secret_expires_at"] = 0
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, out)
}

func (a *App) loadOAuthClient(ctx context.Context, id string) (*oauthClient, error) {
	c := &oauthClient{}
	err := a.db.QueryRow(ctx, `SELECT id, name, redirect_uris FROM oauth_clients WHERE id = $1`, id).
		Scan(&c.ID, &c.Name, &c.RedirectURIs)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// --- authorization --------------------------------------------------------

type authzRequest struct {
	Client        *oauthClient
	RedirectURI   string
	State         string
	CodeChallenge string
	Resource      string
	Scope         string
}

type authzError struct {
	redirect bool // false: an error page, never a redirect (unknown client or redirect_uri)
	code     string
	desc     string
}

func (a *App) checkAuthorize(r *http.Request, q url.Values) (authzRequest, *authzError) {
	var ar authzRequest
	c, err := a.loadOAuthClient(r.Context(), q.Get("client_id"))
	if err != nil {
		return ar, &authzError{false, "invalid_client", a.tr(r, "oauth.err_client")}
	}
	ar.Client = c
	ar.RedirectURI = q.Get("redirect_uri")
	if ar.RedirectURI == "" && len(c.RedirectURIs) == 1 {
		ar.RedirectURI = c.RedirectURIs[0]
	}
	if !redirectRegistered(c.RedirectURIs, ar.RedirectURI) {
		log.Printf("oauth authorize: %s asked for redirect_uri %q, registered %q",
			c.ID, ar.RedirectURI, c.RedirectURIs)
		return ar, &authzError{false, "invalid_request", a.tr(r, "oauth.err_redirect")}
	}
	ar.State = q.Get("state")
	ar.Scope = q.Get("scope")
	if q.Get("response_type") != "code" {
		return ar, &authzError{true, "unsupported_response_type", "only response_type=code is supported"}
	}
	ar.CodeChallenge = q.Get("code_challenge")
	if q.Get("code_challenge_method") != "S256" || len(ar.CodeChallenge) < 43 || len(ar.CodeChallenge) > 128 {
		return ar, &authzError{true, "invalid_request", "PKCE with code_challenge_method=S256 is required"}
	}
	ar.Resource = q.Get("resource")
	if ar.Resource != "" {
		base := a.publicBaseURL(r)
		if ar.Resource != base && !strings.HasPrefix(ar.Resource, base+"/") {
			return ar, &authzError{true, "invalid_target", "unknown resource"}
		}
	}
	return ar, nil
}

func redirectWith(redirectURI string, params map[string]string) string {
	u, _ := url.Parse(redirectURI)
	q := u.Query()
	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func (a *App) errorRedirect(r *http.Request, ar authzRequest, e *authzError) string {
	return redirectWith(ar.RedirectURI, map[string]string{
		"error": e.code, "error_description": e.desc, "state": ar.State, "iss": a.publicBaseURL(r)})
}

// handleOAuthAuthorize shows the consent page (GET) and takes the decision
// (POST). Both sit behind requireUser, so a visitor without a session goes to
// the sign-in page — password or SSO — and comes back here afterwards.
//
// The decision is an ordinary form POST, protected like every other form here
// by SameSite cookies and sameOriginCheck. Its answer is a redirect to the
// client, which a CSP of form-action 'self' would block in Chrome — so the
// consent page widens form-action to exactly that client's origin.
func (a *App) handleOAuthAuthorize(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())
	var q url.Values
	switch r.Method {
	case http.MethodGet:
		q = r.URL.Query()
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		q = r.PostForm
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ar, e := a.checkAuthorize(r, q)
	if e != nil {
		if e.redirect {
			http.Redirect(w, r, a.errorRedirect(r, ar, e), http.StatusSeeOther)
			return
		}
		a.renderStatus(w, r, http.StatusBadRequest, "oauth_consent.html", map[string]any{
			"Title": a.tr(r, "oauth.title") + " · Pyxis", "Error": e.desc})
		return
	}

	if r.Method == http.MethodGet {
		u, _ := url.Parse(ar.RedirectURI)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'; "+
				"object-src 'none'; base-uri 'self'; frame-ancestors 'none'; "+
				"form-action 'self' "+u.Scheme+"://"+u.Host)
		a.render(w, r, "oauth_consent.html", map[string]any{
			"Title":        a.tr(r, "oauth.title") + " · Pyxis",
			"ClientName":   ar.Client.Name,
			"RedirectHost": u.Host,
			"Params": map[string]string{
				"client_id": ar.Client.ID, "redirect_uri": ar.RedirectURI, "state": ar.State,
				"response_type": "code", "code_challenge": ar.CodeChallenge,
				"code_challenge_method": "S256", "resource": ar.Resource, "scope": ar.Scope,
			},
		})
		return
	}

	if q.Get("decision") != "approve" {
		log.Printf("oauth denied: %s for %s", user.Username, ar.Client.ID)
		http.Redirect(w, r, a.errorRedirect(r, ar,
			&authzError{true, "access_denied", "the user denied access"}), http.StatusSeeOther)
		return
	}
	code := "pxa_" + randomToken(32)
	if _, err := a.db.Exec(r.Context(),
		`INSERT INTO oauth_codes (code_hash, client_id, user_id, redirect_uri, code_challenge, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		sessionKey(code), ar.Client.ID, user.ID.String(), ar.RedirectURI, ar.CodeChallenge,
		time.Now().Add(oauthCodeTTL)); err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	log.Printf("oauth granted: %s to %s (%q)", user.Username, ar.Client.ID, ar.Client.Name)
	http.Redirect(w, r, redirectWith(ar.RedirectURI, map[string]string{
		"code": code, "state": ar.State, "iss": a.publicBaseURL(r)}), http.StatusSeeOther)
}

// --- token endpoint -------------------------------------------------------

// clientAuth reads client credentials (HTTP Basic or form fields) and checks a
// confidential client's secret; a public client passes on PKCE alone.
func (a *App) clientAuth(r *http.Request) (string, error) {
	id, secret, ok := r.BasicAuth()
	if ok {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id == "" {
		return "", errOAuthInvalidClient
	}
	var h *string
	if err := a.db.QueryRow(r.Context(),
		`SELECT secret_hash FROM oauth_clients WHERE id = $1`, id).Scan(&h); err != nil {
		return "", errOAuthInvalidClient
	}
	if h != nil && subtle.ConstantTimeCompare([]byte(*h), []byte(sessionKey(secret))) != 1 {
		return "", errOAuthInvalidClient
	}
	return id, nil
}

func pkceMatches(verifier, challenge string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(challenge)) == 1
}

type oauthTokens struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

// issueOAuthTokens mints an access token (an api_tokens row) and a refresh
// token for one user and client.
func issueOAuthTokens(ctx context.Context, tx pgx.Tx, clientID, userID string) (oauthTokens, error) {
	var name string
	if err := tx.QueryRow(ctx,
		`UPDATE oauth_clients SET last_used_at = NOW() WHERE id = $1 RETURNING name`, clientID).Scan(&name); err != nil {
		return oauthTokens{}, errOAuthInvalidClient
	}
	access := apiTokenPrefix + randomToken(32)
	refresh := "pxr_" + randomToken(32)
	if _, err := tx.Exec(ctx,
		`INSERT INTO api_tokens (id, user_id, name, token_hash, hint, expires_at, oauth_client_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		uuid.NewString(), userID, name+" (OAuth)", sessionKey(access), access[len(access)-4:],
		time.Now().Add(oauthAccessTTL), clientID); err != nil {
		return oauthTokens{}, err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO oauth_refresh_tokens (token_hash, client_id, user_id, expires_at) VALUES ($1, $2, $3, $4)`,
		sessionKey(refresh), clientID, userID, time.Now().Add(oauthRefreshTTL)); err != nil {
		return oauthTokens{}, err
	}
	return oauthTokens{AccessToken: access, TokenType: "Bearer", ExpiresIn: int(oauthAccessTTL.Seconds()),
		RefreshToken: refresh, Scope: oauthScope}, nil
}

func (a *App) handleOAuthToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		oauthError(w, http.StatusMethodNotAllowed, "invalid_request", "POST only")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "expected an application/x-www-form-urlencoded body")
		return
	}
	ctx := r.Context()
	limitKey := a.clientIP(r) + "|oauth"
	if !a.apiLimiter.allow(ctx, limitKey) {
		oauthError(w, http.StatusTooManyRequests, "slow_down", "too many failed attempts")
		return
	}
	clientID, err := a.clientAuth(r)
	if err != nil {
		a.apiLimiter.fail(ctx, limitKey)
		w.Header().Set("WWW-Authenticate", `Basic realm="pyxis"`)
		oauthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}

	var tok oauthTokens
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		// DELETE … RETURNING: a code is used up by any attempt, failed or not.
		var userID, redirectURI, challenge, codeClient string
		var exp time.Time
		err := a.db.QueryRow(ctx,
			`DELETE FROM oauth_codes WHERE code_hash = $1
			 RETURNING user_id::text, redirect_uri, code_challenge, expires_at, client_id`,
			sessionKey(r.PostForm.Get("code"))).Scan(&userID, &redirectURI, &challenge, &exp, &codeClient)
		if err != nil || time.Now().After(exp) || codeClient != clientID {
			a.apiLimiter.fail(ctx, limitKey)
			oauthError(w, http.StatusBadRequest, "invalid_grant", "the code is invalid, expired or already used")
			return
		}
		if ru := r.PostForm.Get("redirect_uri"); ru != "" && ru != redirectURI {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match the authorization request")
			return
		}
		if !pkceMatches(r.PostForm.Get("code_verifier"), challenge) {
			a.apiLimiter.fail(ctx, limitKey)
			oauthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
			return
		}
		err = pgx.BeginFunc(ctx, a.db, func(tx pgx.Tx) error {
			var e error
			tok, e = issueOAuthTokens(ctx, tx, clientID, userID)
			return e
		})
		if err != nil {
			httpError(w, err, http.StatusInternalServerError)
			return
		}
	case "refresh_token":
		refreshHash := sessionKey(r.PostForm.Get("refresh_token"))
		err := pgx.BeginFunc(ctx, a.db, func(tx pgx.Tx) error {
			var userID string
			var exp time.Time
			// Rotation: the presented refresh token is gone after this.
			if err := tx.QueryRow(ctx,
				`DELETE FROM oauth_refresh_tokens WHERE token_hash = $1 AND client_id = $2
				 RETURNING user_id::text, expires_at`, refreshHash, clientID).Scan(&userID, &exp); err != nil ||
				time.Now().After(exp) {
				return errOAuthInvalidGrant
			}
			var e error
			tok, e = issueOAuthTokens(ctx, tx, clientID, userID)
			return e
		})
		if errors.Is(err, errOAuthInvalidGrant) || errors.Is(err, errOAuthInvalidClient) {
			// The rotated token must stay deleted though the transaction rolled back.
			_, _ = a.db.Exec(ctx, `DELETE FROM oauth_refresh_tokens WHERE token_hash = $1`, refreshHash)
			a.apiLimiter.fail(ctx, limitKey)
			oauthError(w, http.StatusBadRequest, "invalid_grant", "the refresh token is invalid or expired")
			return
		}
		if err != nil {
			httpError(w, err, http.StatusInternalServerError)
			return
		}
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "supported: authorization_code, refresh_token")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, tok)
}

func (a *App) handleOAuthRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		oauthError(w, http.StatusMethodNotAllowed, "invalid_request", "POST only")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "expected an application/x-www-form-urlencoded body")
		return
	}
	clientID, err := a.clientAuth(r)
	if err != nil {
		oauthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	h := sessionKey(r.PostForm.Get("token"))
	if _, err := a.db.Exec(r.Context(),
		`DELETE FROM oauth_refresh_tokens WHERE token_hash = $1 AND client_id = $2`, h, clientID); err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	if _, err := a.db.Exec(r.Context(),
		`DELETE FROM api_tokens WHERE token_hash = $1 AND oauth_client_id = $2`, h, clientID); err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK) // RFC 7009: also for an unknown token
}

// --- connected apps (account page) -----------------------------------------

type OAuthGrant struct {
	ClientID    string
	ClientName  string
	RedirectURI string
	GrantedAt   time.Time
	LastUsedAt  *time.Time
}

func (g OAuthGrant) RedirectHost() string {
	if u, err := url.Parse(g.RedirectURI); err == nil {
		return u.Host
	}
	return g.RedirectURI
}

func (a *App) listOAuthGrants(ctx context.Context, userID string) ([]OAuthGrant, error) {
	rows, err := a.db.Query(ctx,
		`SELECT c.id, c.name, c.redirect_uris[1], MIN(r.created_at), c.last_used_at
		   FROM oauth_clients c JOIN oauth_refresh_tokens r ON r.client_id = c.id
		  WHERE r.user_id = $1 AND r.expires_at > NOW()
		  GROUP BY c.id ORDER BY c.name, c.id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OAuthGrant
	for rows.Next() {
		var g OAuthGrant
		if err := rows.Scan(&g.ClientID, &g.ClientName, &g.RedirectURI, &g.GrantedAt, &g.LastUsedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// handleAccountAppDisconnect drops every token this user holds for a client
// (POST /account/apps/{client_id}/disconnect). The client row goes once
// nobody uses it any more.
func (a *App) handleAccountAppDisconnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user := userFromContext(r.Context())
	clientID, action, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/account/apps/"), "/")
	if clientID == "" || action != "disconnect" {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	err := pgx.BeginFunc(ctx, a.db, func(tx pgx.Tx) error {
		uid := user.ID.String()
		for _, q := range []string{
			`DELETE FROM oauth_refresh_tokens WHERE user_id = $1 AND client_id = $2`,
			`DELETE FROM api_tokens WHERE user_id = $1 AND oauth_client_id = $2`,
			`DELETE FROM oauth_codes WHERE user_id = $1 AND client_id = $2`,
		} {
			if _, err := tx.Exec(ctx, q, uid, clientID); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx, `DELETE FROM oauth_clients c WHERE id = $1
			AND NOT EXISTS (SELECT 1 FROM oauth_refresh_tokens WHERE client_id = c.id)
			AND NOT EXISTS (SELECT 1 FROM api_tokens WHERE oauth_client_id = c.id)`, clientID)
		return err
	})
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	log.Printf("oauth app disconnected: %s from %s", user.Username, clientID)
	http.Redirect(w, r, "/account#connected-apps", http.StatusSeeOther)
}

// sweepOAuth drops what has expired. Called by the sweeper.
func (a *App) sweepOAuth(ctx context.Context) error {
	for _, q := range []string{
		`DELETE FROM oauth_codes WHERE expires_at < NOW()`,
		`DELETE FROM oauth_refresh_tokens WHERE expires_at < NOW()`,
		`DELETE FROM api_tokens WHERE oauth_client_id IS NOT NULL AND expires_at < NOW()`,
		`DELETE FROM oauth_clients WHERE last_used_at IS NULL AND created_at < NOW() - interval '1 hour'`,
	} {
		if _, err := a.db.Exec(ctx, q); err != nil {
			return err
		}
	}
	return nil
}
