package main

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	qrcode "github.com/skip2/go-qrcode"
)

// handleQR renders a PNG QR code for a share link. Authenticated users only:
// the encoded content is just the share URL (which the caller already knows),
// but the endpoint should not be an open QR generator.
func (a *App) handleQR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/qr/")
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var alive bool
	err = a.db.QueryRow(r.Context(),
		`SELECT archived_at IS NULL AND (expires_at IS NULL OR expires_at > NOW())
		 FROM files WHERE id = $1`, id.String()).Scan(&alive)
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

	png, err := qrcode.Encode(shareURL, qrcode.Medium, 480)
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Length", strconv.Itoa(len(png)))
	w.Header().Set("Cache-Control", "private, max-age=300")
	_, _ = w.Write(png)
}
