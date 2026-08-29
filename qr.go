package main

import (
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	qrcode "github.com/skip2/go-qrcode"
)

var qrFragmentRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,88}$`)

// handleQR renders a PNG QR code for a share link. Authenticated users only:
// the encoded content is just the share URL (which the caller already knows),
// but the endpoint should not be an open QR generator.
//
// GET works for links that are complete on their own (legacy and password
// files). URL-keyed links carry their decryption secret only in the fragment,
// which the server does not store — so the client POSTs the full link (form
// field "url", TLS-protected, never logged) and the server validates it
// against the expected prefix before encoding it.
func (a *App) handleQR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/qr/")
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var (
		alive   bool
		keyMode int
	)
	err = a.db.QueryRow(r.Context(),
		`SELECT archived_at IS NULL AND (expires_at IS NULL OR expires_at > NOW()), key_mode
		 FROM files WHERE id = $1`, id.String()).Scan(&alive, &keyMode)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	if !alive {
		http.NotFound(w, r)
		return
	}

	scheme := "https"
	if !a.cookieSecure {
		scheme = "http"
	}
	shareURL := scheme + "://" + r.Host + "/files/" + id.String()

	switch r.Method {
	case http.MethodGet:
		if keyMode == keyModeURL {
			// A QR of the bare URL would scan into a link that cannot
			// decrypt anything; refuse rather than mislead.
			http.NotFound(w, r)
			return
		}
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		full := r.PostFormValue("url")
		frag, ok := strings.CutPrefix(full, shareURL+"#")
		if !ok || !qrFragmentRe.MatchString(frag) {
			http.Error(w, "url does not match this share", http.StatusBadRequest)
			return
		}
		shareURL = full
	}

	png, err := qrcode.Encode(shareURL, qrcode.Medium, 480)
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Length", strconv.Itoa(len(png)))
	w.Header().Set("Cache-Control", "private, no-store")
	_, _ = w.Write(png)
}
