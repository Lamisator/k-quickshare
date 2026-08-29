package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	oidcStateCookie    = "fileshare_oidc_state"
	oidcVerifierCookie = "fileshare_oidc_verifier"
	oidcNextCookie     = "fileshare_oidc_next"
	oidcStateTTL       = 10 * time.Minute

	// Zitadel confirms the org context of a scope-restricted login via
	// urn:zitadel:iam:org:domain:primary. urn:zitadel:iam:user:resourceowner:primary_domain
	// is the user's home-org domain and is only present when the Zitadel
	// project is configured to include resource-owner claims — we accept it
	// too, as a fallback.
	oidcClaimOrgDomain           = "urn:zitadel:iam:org:domain:primary"
	oidcClaimResourceOwnerDomain = "urn:zitadel:iam:user:resourceowner:primary_domain"
	oidcScopeOrgDomainFmt        = "urn:zitadel:iam:org:domain:primary:%s"
)

// OIDCSettings mirrors the six persisted settings rows.
type OIDCSettings struct {
	Enabled       bool
	Issuer        string
	ClientID      string
	ClientSecret  string
	RedirectURL   string
	AllowedDomain string
}

func (s OIDCSettings) Ready() bool {
	return s.Enabled && s.Issuer != "" && s.ClientID != "" &&
		s.ClientSecret != "" && s.RedirectURL != ""
}

// OIDC bundles a live Zitadel provider.
type OIDC struct {
	settings OIDCSettings
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth    *oauth2.Config
}

func newOIDC(ctx context.Context, s OIDCSettings) (*OIDC, error) {
	if !s.Ready() {
		return nil, nil
	}
	provider, err := oidc.NewProvider(ctx, s.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discover %s: %w", s.Issuer, err)
	}
	scopes := []string{oidc.ScopeOpenID, "profile", "email"}
	if s.AllowedDomain != "" {
		scopes = append(scopes, fmt.Sprintf(oidcScopeOrgDomainFmt, s.AllowedDomain))
	}
	return &OIDC{
		settings: s,
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: s.ClientID}),
		oauth: &oauth2.Config{
			ClientID:     s.ClientID,
			ClientSecret: s.ClientSecret,
			RedirectURL:  s.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       scopes,
		},
	}, nil
}

// loadAndApplyOIDC reads the settings table and (re)initializes OIDC. If
// initialization fails the previous OIDC instance is left in place and the
// error is returned.
func (a *App) loadAndApplyOIDC(ctx context.Context) error {
	m, err := a.loadAllSettings(ctx)
	if err != nil {
		return err
	}
	stored := m["oidc.client_secret"]
	secret, err := a.decryptSecret(stored)
	if err != nil {
		return fmt.Errorf("decrypt oidc client secret: %w", err)
	}
	// One-time migration: re-persist a legacy plaintext secret encrypted.
	if secret != "" && stored == secret && len(a.fileKEK) > 0 {
		if err := a.saveSettings(ctx, map[string]string{
			"oidc.client_secret": a.encryptSecret(secret),
		}); err != nil {
			log.Printf("oidc: re-encrypt stored client secret: %v", err)
		} else {
			log.Print("oidc: client secret re-encrypted at rest")
		}
	}
	s := OIDCSettings{
		Enabled:       m["oidc.enabled"] == "true",
		Issuer:        m["oidc.issuer"],
		ClientID:      m["oidc.client_id"],
		ClientSecret:  secret,
		RedirectURL:   m["oidc.redirect_url"],
		AllowedDomain: m["oidc.allowed_domain"],
	}
	return a.applyOIDC(ctx, s)
}

func (a *App) applyOIDC(ctx context.Context, s OIDCSettings) error {
	oc, err := newOIDC(ctx, s)
	if err != nil {
		return err
	}
	a.oidcMu.Lock()
	a.oidc = oc
	a.oidcCfg = s
	a.oidcMu.Unlock()
	if oc == nil {
		log.Print("oidc: disabled")
	} else {
		log.Printf("oidc: enabled (issuer=%s, redirect=%s, allowed_domain=%q)",
			s.Issuer, s.RedirectURL, s.AllowedDomain)
	}
	return nil
}

func (a *App) getOIDC() *OIDC {
	a.oidcMu.RLock()
	defer a.oidcMu.RUnlock()
	return a.oidc
}

func (a *App) getOIDCSettings() OIDCSettings {
	a.oidcMu.RLock()
	defer a.oidcMu.RUnlock()
	return a.oidcCfg
}

// seedOIDCFromEnv writes settings rows from env vars only when the settings
// table has no oidc.* keys yet. Lets existing env-configured deploys migrate
// transparently on first boot after this change.
func (a *App) seedOIDCFromEnv(ctx context.Context, issuer, clientID, clientSecret, redirect, allowedDomain string) error {
	m, err := a.loadAllSettings(ctx)
	if err != nil {
		return err
	}
	for k := range m {
		if strings.HasPrefix(k, "oidc.") {
			return nil
		}
	}
	if issuer == "" && clientID == "" && clientSecret == "" && redirect == "" {
		return nil
	}
	kv := map[string]string{
		"oidc.enabled":        "true",
		"oidc.issuer":         issuer,
		"oidc.client_id":      clientID,
		"oidc.client_secret":  a.encryptSecret(clientSecret),
		"oidc.redirect_url":   redirect,
		"oidc.allowed_domain": allowedDomain,
	}
	if err := a.saveSettings(ctx, kv); err != nil {
		return err
	}
	log.Print("oidc: seeded settings from environment variables")
	return nil
}

// --- HTTP handlers --------------------------------------------------------

func (a *App) handleOIDCStart(w http.ResponseWriter, r *http.Request) {
	oc := a.getOIDC()
	if oc == nil {
		http.Error(w, "OIDC not configured", http.StatusServiceUnavailable)
		return
	}
	state := randomToken(24)
	verifier := oauth2.GenerateVerifier()
	expires := time.Now().Add(oidcStateTTL)

	setShortCookie(w, oidcStateCookie, state, expires, a.cookieSecure)
	setShortCookie(w, oidcVerifierCookie, verifier, expires, a.cookieSecure)

	if next := r.URL.Query().Get("next"); next != "" && isSafeNext(next) {
		setShortCookie(w, oidcNextCookie, next, expires, a.cookieSecure)
	}

	opts := []oauth2.AuthCodeOption{
		oauth2.AccessTypeOnline,
		oauth2.S256ChallengeOption(verifier),
	}
	// Let callers force a fresh Zitadel login prompt (useful after a
	// denied-org attempt when Zitadel would otherwise silently reuse the
	// cached session).
	if p := r.URL.Query().Get("prompt"); p == "login" || p == "select_account" || p == "consent" {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", p))
	}

	authURL := oc.oauth.AuthCodeURL(state, opts...)
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

func (a *App) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	oc := a.getOIDC()
	if oc == nil {
		http.Error(w, "OIDC not configured", http.StatusServiceUnavailable)
		return
	}
	q := r.URL.Query()
	if errParam := q.Get("error"); errParam != "" {
		http.Error(w, "OIDC error: "+errParam+" "+q.Get("error_description"), http.StatusBadRequest)
		return
	}

	stateCookie, err := r.Cookie(oidcStateCookie)
	if err != nil || stateCookie.Value == "" || stateCookie.Value != q.Get("state") {
		http.Error(w, "invalid OIDC state", http.StatusBadRequest)
		return
	}
	verCookie, err := r.Cookie(oidcVerifierCookie)
	if err != nil || verCookie.Value == "" {
		http.Error(w, "missing PKCE verifier", http.StatusBadRequest)
		return
	}

	clearShortCookie(w, oidcStateCookie, a.cookieSecure)
	clearShortCookie(w, oidcVerifierCookie, a.cookieSecure)

	code := q.Get("code")
	token, err := oc.oauth.Exchange(r.Context(), code, oauth2.VerifierOption(verCookie.Value))
	if err != nil {
		httpError(w, fmt.Errorf("token exchange: %w", err), http.StatusBadGateway)
		return
	}
	rawID, ok := token.Extra("id_token").(string)
	if !ok || rawID == "" {
		http.Error(w, "no id_token in response", http.StatusBadGateway)
		return
	}
	idt, err := oc.verifier.Verify(r.Context(), rawID)
	if err != nil {
		httpError(w, fmt.Errorf("verify id_token: %w", err), http.StatusBadGateway)
		return
	}

	claims := map[string]any{}
	if err := idt.Claims(&claims); err != nil {
		httpError(w, fmt.Errorf("parse claims: %w", err), http.StatusInternalServerError)
		return
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		http.Error(w, "id_token missing sub claim", http.StatusBadGateway)
		return
	}

	// Zitadel doesn't always include org/profile claims in the ID token
	// (depends on the "User Info Inside ID Token" project toggle), so we
	// merge in the UserInfo endpoint's claims. This gives us primary_domain
	// + name/email even when the toggle is off.
	if ui, err := oc.provider.UserInfo(r.Context(), oauth2.StaticTokenSource(token)); err == nil {
		uiClaims := map[string]any{}
		if err := ui.Claims(&uiClaims); err == nil {
			for k, v := range uiClaims {
				if _, exists := claims[k]; !exists {
					claims[k] = v
				}
			}
		}
	} else {
		log.Printf("oidc userinfo fetch failed for sub=%s: %v (falling back to id_token claims only)", sub, err)
	}

	email, _ := claims["email"].(string)
	preferredUsername, _ := claims["preferred_username"].(string)

	// Domain restriction — belt-and-suspenders. Zitadel enforces the org
	// scope at authorization time; we cross-check the claim here so a
	// misconfigured or missing scope can't silently let outsiders through.
	if allowed := oc.settings.AllowedDomain; allowed != "" {
		claim, _ := claims[oidcClaimOrgDomain].(string)
		if claim == "" {
			claim, _ = claims[oidcClaimResourceOwnerDomain].(string)
		}
		if claim == "" {
			keys := make([]string, 0, len(claims))
			for k := range claims {
				keys = append(keys, k)
			}
			log.Printf("oidc reject: user sub=%s missing org domain claim (want %s); available claims: %v",
				sub, allowed, keys)
			a.renderOIDCDenied(w, r, allowed, "")
			return
		}
		if !strings.EqualFold(claim, allowed) {
			log.Printf("oidc reject: user sub=%s org_domain=%q, want=%q", sub, claim, allowed)
			a.renderOIDCDenied(w, r, allowed, claim)
			return
		}
	}

	user, err := a.upsertOIDCUser(r.Context(), sub, preferredUsername, email)
	if err != nil {
		httpError(w, fmt.Errorf("upsert user: %w", err), http.StatusInternalServerError)
		return
	}

	sid, expires, err := a.createSession(r.Context(), user.ID)
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	setSessionCookie(w, sid, expires, a.cookieSecure)

	next := "/"
	if c, err := r.Cookie(oidcNextCookie); err == nil && isSafeNext(c.Value) {
		next = c.Value
		clearShortCookie(w, oidcNextCookie, a.cookieSecure)
	}
	log.Printf("oidc login: %s (sub=%s)", user.Username, sub)
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (a *App) renderOIDCDenied(w http.ResponseWriter, r *http.Request, allowed, actual string) {
	a.renderStatus(w, r, http.StatusForbidden, "oidc_denied.html", map[string]any{
		"Title":         a.tr(r, "denied.heading") + " · k-fileshare",
		"AllowedDomain": allowed,
		"ActualDomain":  actual,
	})
}

func setShortCookie(w http.ResponseWriter, name, value string, expires time.Time, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearShortCookie(w http.ResponseWriter, name string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func isSafeNext(s string) bool {
	if s == "" || len(s) > 1024 || s[0] != '/' {
		return false
	}
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	if u.Scheme != "" || u.Host != "" {
		return false
	}
	return true
}
