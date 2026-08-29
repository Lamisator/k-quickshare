package main

import (
	"net/http"
	"time"
)

const themeCookieName = "pyxis_theme"

var supportedThemes = []string{"dark", "light"}

// themeFromRequest picks the UI theme from the cookie; dark is the default.
func themeFromRequest(r *http.Request) string {
	if c, err := r.Cookie(themeCookieName); err == nil {
		for _, t := range supportedThemes {
			if c.Value == t {
				return t
			}
		}
	}
	return "dark"
}

// handleTheme sets the theme cookie and redirects back.
func (a *App) handleTheme(w http.ResponseWriter, r *http.Request) {
	to := r.URL.Query().Get("to")
	valid := false
	for _, t := range supportedThemes {
		if to == t {
			valid = true
			break
		}
	}
	if !valid {
		to = "dark"
	}
	next := r.URL.Query().Get("next")
	if !isSafeNext(next) {
		next = "/"
	}
	http.SetCookie(w, &http.Cookie{
		Name:     themeCookieName,
		Value:    to,
		Path:     "/",
		Expires:  time.Now().Add(365 * 24 * time.Hour),
		Secure:   a.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, next, http.StatusSeeOther)
}
