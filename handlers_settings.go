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
	q := a.getQuotaDefaults()
	a.renderStatus(w, r, status, "admin_settings.html", map[string]any{
		"Title":        a.tr(r, "title.settings") + " · Pyxis",
		"Active":       "settings",
		"OIDC":         cfg,
		"OIDCLive":     a.getOIDC() != nil,
		"CallbackURL":  cfg.RedirectURL,
		"CallbackHint": "https://<your-host>/auth/oidc/callback",
		"QuotaBytes":   sizeInput(q.Bytes),
		"QuotaFiles":   q.Files,
		"MaxUpload":    sizeInput(a.getMaxUploadDefault()),
		"Error":        errMsg,
		"Success":      okMsg,
	})
}

// handleAdminSettingsQuota stores the instance-wide per-user allowance. It
// applies to every user who has no override of their own; 0 means unlimited.
func (a *App) handleAdminSettingsQuota(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	bytes, err := parseSize(r.PostFormValue("user_bytes"))
	if err != nil {
		a.renderSettings(w, r, http.StatusBadRequest, a.tr(r, "msg.quota_bad_size"), "")
		return
	}
	files, err := parseCount(r.PostFormValue("user_files"))
	if err != nil {
		a.renderSettings(w, r, http.StatusBadRequest, a.tr(r, "msg.quota_bad_count"), "")
		return
	}
	if err := a.saveQuotaDefaults(r.Context(), UserQuota{Bytes: bytes, Files: files}); err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	log.Printf("quota defaults saved: %s per user, %d files per user", humanSize(bytes), files)
	a.renderSettings(w, r, http.StatusOK, "", a.tr(r, "msg.quota_default_saved"))
}

// handleAdminSettingsUpload stores the instance-wide per-file upload ceiling.
// It applies to every account that has no override of its own — admins
// included, unlike the storage quota; see the note on effectiveMaxUpload.
func (a *App) handleAdminSettingsUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	max, err := parsePositiveSize(r.PostFormValue("max_bytes"))
	if err != nil {
		a.renderSettings(w, r, http.StatusBadRequest, a.tr(r, "msg.upload_bad_size"), "")
		return
	}
	if err := a.saveMaxUploadDefault(r.Context(), max); err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	log.Printf("upload limit saved: %s per file", humanSize(max))
	a.renderSettings(w, r, http.StatusOK, "", a.tr(r, "msg.upload_saved", humanSize(max)))
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

	encSecret, err := a.encryptSecret(clientSecret)
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	if err := a.saveSettings(r.Context(), map[string]string{
		"oidc.enabled":        boolStr(enabled),
		"oidc.issuer":         issuer,
		"oidc.client_id":      clientID,
		"oidc.client_secret":  encSecret,
		"oidc.redirect_url":   redirect,
		"oidc.allowed_domain": allowedDomain,
	}); err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	log.Printf("oidc settings saved: enabled=%v issuer=%s allowed_domain=%q",
		enabled, issuer, allowedDomain)

	// Accounts are bound to (issuer, subject). Repointing the instance at a
	// different provider therefore does NOT hand the existing accounts to
	// whoever holds the same subject there — they become unreachable instead,
	// and the next sign-in creates fresh accounts. That is the safe direction,
	// but it is surprising enough to say out loud.
	if current.Issuer != "" && issuer != current.Issuer {
		var orphaned int
		if err := a.db.QueryRow(r.Context(),
			`SELECT COUNT(*) FROM users WHERE oidc_issuer = $1`, current.Issuer).Scan(&orphaned); err == nil && orphaned > 0 {
			log.Printf("WARNING: issuer changed from %s to %s; %d account(s) remain bound to the "+
				"old issuer and will not be matched by logins from the new one. Re-map them by hand "+
				"if the two providers really represent the same people.",
				current.Issuer, issuer, orphaned)
		}
	}
	a.renderSettings(w, r, http.StatusOK, "", a.tr(r, "msg.oidc_saved"))
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
