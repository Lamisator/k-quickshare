package main

import (
	"log"
	"net/http"
	"strings"
)

func (a *App) handleAdminSettings(w http.ResponseWriter, r *http.Request) {
	a.renderSettings(w, r, http.StatusOK, "", "")
}

func (a *App) renderSettings(w http.ResponseWriter, r *http.Request, status int, errMsg, okMsg string) {
	cfg := a.getOIDCSettings()
	a.renderStatus(w, r, status, "admin_settings.html", map[string]any{
		"Title":        a.tr(r, "title.settings") + " · k-fileshare",
		"Active":       "settings",
		"OIDC":         cfg,
		"OIDCLive":     a.getOIDC() != nil,
		"CallbackURL":  cfg.RedirectURL,
		"CallbackHint": "https://<your-host>/auth/oidc/callback",
		"Error":        errMsg,
		"Success":      okMsg,
	})
}

func (a *App) handleAdminSettingsOIDC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	enabled := r.PostFormValue("enabled") == "on"
	issuer := strings.TrimSpace(r.PostFormValue("issuer"))
	clientID := strings.TrimSpace(r.PostFormValue("client_id"))
	clientSecret := r.PostFormValue("client_secret")
	redirect := strings.TrimSpace(r.PostFormValue("redirect_url"))
	allowedDomain := strings.TrimSpace(r.PostFormValue("allowed_domain"))

	// If client_secret field is blank, keep the existing one (avoids blanking
	// on a save where the admin didn't re-type it).
	current := a.getOIDCSettings()
	if clientSecret == "" {
		clientSecret = current.ClientSecret
	}

	if enabled {
		if issuer == "" || clientID == "" || clientSecret == "" || redirect == "" {
			a.renderSettings(w, r, http.StatusBadRequest,
				a.tr(r, "msg.oidc_required"), "")
			return
		}
	}

	newCfg := OIDCSettings{
		Enabled:       enabled,
		Issuer:        issuer,
		ClientID:      clientID,
		ClientSecret:  clientSecret,
		RedirectURL:   redirect,
		AllowedDomain: allowedDomain,
	}

	// Try initializing against the new settings BEFORE persisting; a bad
	// issuer URL should fail with a helpful message and not knock OIDC out
	// silently on the next boot.
	if err := a.applyOIDC(r.Context(), newCfg); err != nil {
		log.Printf("oidc settings save: apply failed: %v", err)
		a.renderSettings(w, r, http.StatusBadGateway,
			a.tr(r, "msg.oidc_unreachable", err.Error()), "")
		return
	}

	if err := a.saveSettings(r.Context(), map[string]string{
		"oidc.enabled":        boolStr(enabled),
		"oidc.issuer":         issuer,
		"oidc.client_id":      clientID,
		"oidc.client_secret":  a.encryptSecret(clientSecret),
		"oidc.redirect_url":   redirect,
		"oidc.allowed_domain": allowedDomain,
	}); err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	log.Printf("oidc settings saved: enabled=%v issuer=%s allowed_domain=%q",
		enabled, issuer, allowedDomain)
	a.renderSettings(w, r, http.StatusOK, "", a.tr(r, "msg.oidc_saved"))
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
