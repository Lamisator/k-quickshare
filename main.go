package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed web/templates/*.html
var templatesFS embed.FS

//go:embed web/static
var staticFS embed.FS

type App struct {
	db           *pgxpool.Pool
	filesDir     string
	tmpl         *template.Template
	cookieSecure bool
	unlockKey    []byte // HMAC key for per-file password-unlock cookies
	fileKEK      []byte // key-encryption key for at-rest file encryption (nil = disabled)

	quota QuotaConfig

	// The per-user allowance and the per-file upload ceiling are both
	// admin-editable at runtime, so they live behind a mutex rather than in
	// the immutable QuotaConfig above. maxUploadDefault is the instance
	// default; a user may carry an override (see maxUploadFor).
	quotaMu          sync.RWMutex
	quotaDefaults    UserQuota
	maxUploadDefault int64

	trustedProxies []*net.IPNet // networks whose X-Forwarded-For is honored
	proxyWarnOnce  sync.Once    // guards the "untrusted X-Forwarded-For" warning

	loginLimiter       *failLimiter // per (source, username)
	loginSourceLimiter *failLimiter // per source, across all usernames
	shareLimiter       *failLimiter // per (source, share)

	oidcMu  sync.RWMutex
	oidc    *OIDC
	oidcCfg OIDCSettings
}

// QuotaConfig bounds storage consumption instance-wide. Zero values mean "no
// limit" except MinFreeBytes, which always applies when > 0. These are
// infrastructure limits and stay environment-only; the per-user allowance is
// UserQuota, which admins edit at runtime.
type QuotaConfig struct {
	TotalBytes   int64 // max total bytes of active files instance-wide
	MinFreeBytes int64 // refuse uploads when the volume has less free space
}

// UserQuota is one user's allowance. Zero means "no limit". The value applied
// to an upload is the override on the user row when set, otherwise the
// instance default held in App.quotaDefaults.
type UserQuota struct {
	Bytes int64 // max total bytes of active files
	Files int64 // max active file count
}

func main() {
	dsn := mustEnv("DATABASE_URL")
	filesDir := envOr("FILES_DIR", "/data/files")
	listen := envOr("LISTEN_ADDR", ":8080")
	// Only the fallback: once an admin saves a limit on /admin/settings, the
	// settings table wins and this is ignored (as with QUOTA_USER_*).
	maxUploadEnv := envInt64("MAX_UPLOAD_BYTES", 512*1024*1024)
	cookieSecure := envBool("COOKIE_SECURE", true)

	envOIDCIssuer := os.Getenv("OIDC_ISSUER")
	envOIDCClientID := os.Getenv("OIDC_CLIENT_ID")
	envOIDCClientSecret := os.Getenv("OIDC_CLIENT_SECRET")
	envOIDCRedirect := os.Getenv("OIDC_REDIRECT_URL")
	envOIDCAllowedDomain := os.Getenv("OIDC_ALLOWED_DOMAIN")

	adminUser := os.Getenv("ADMIN_USERNAME")
	adminPass := os.Getenv("ADMIN_PASSWORD")

	if err := os.MkdirAll(filesDir, 0o755); err != nil {
		log.Fatalf("cannot create files dir %q: %v", filesDir, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool, err := connectDB(ctx, dsn, 30, 2*time.Second)
	if err != nil {
		log.Fatalf("database connect: %v", err)
	}
	defer pool.Close()

	mctx, mcancel := context.WithTimeout(ctx, 15*time.Second)
	if err := runMigrations(mctx, pool); err != nil {
		mcancel()
		log.Fatalf("migrations: %v", err)
	}
	mcancel()

	tmpl, err := loadTemplates()
	if err != nil {
		log.Fatalf("load templates: %v", err)
	}

	fileKEK, err := loadFileKEK()
	if err != nil {
		log.Fatalf("file encryption key: %v", err)
	}
	if fileKEK == nil {
		// The KEK no longer touches uploaded files — those arrive already
		// encrypted under a key the server never sees. It now protects short
		// secrets in the settings table, principally the OIDC client secret,
		// and a missing key must not silently downgrade those to plaintext.
		if !envBool("ALLOW_UNENCRYPTED_SECRETS", false) {
			log.Fatal("FILE_ENCRYPTION_KEY is required (generate one with `openssl rand -hex 32`; " +
				"set ALLOW_UNENCRYPTED_SECRETS=true to explicitly store settings secrets in plaintext)")
		}
		log.Print("WARNING: ALLOW_UNENCRYPTED_SECRETS=true — the OIDC client secret will be stored UNENCRYPTED")
	}

	app := &App{
		db:           pool,
		filesDir:     filesDir,
		tmpl:         tmpl,
		cookieSecure: cookieSecure,
		unlockKey:    randomBytes(32),
		fileKEK:      fileKEK,
		quota: QuotaConfig{
			TotalBytes:   envInt64("QUOTA_TOTAL_BYTES", 0),
			MinFreeBytes: envInt64("DISK_MIN_FREE_BYTES", 1024*1024*1024),
		},
		loginLimiter:       newFailLimiter(failMaxTries, failWindow).shared(pool, "login"),
		loginSourceLimiter: newFailLimiter(failMaxPerSource, failWindow).shared(pool, "login-src"),
		shareLimiter:       newFailLimiter(failMaxTries, failWindow).shared(pool, "share"),
	}
	app.trustedProxies, err = parseTrustedProxies(os.Getenv("TRUSTED_PROXY_CIDRS"))
	if err != nil {
		log.Fatalf("TRUSTED_PROXY_CIDRS: %v", err)
	}
	if len(app.trustedProxies) == 0 {
		log.Print("TRUSTED_PROXY_CIDRS is empty: X-Forwarded-For is ignored and rate limits key " +
			"on the TCP peer. Correct for direct client connections; behind a reverse proxy it " +
			"makes every visitor share one limiter bucket — set it to the proxy's network.")
	} else {
		log.Printf("trusting X-Forwarded-For from %d network(s)", len(app.trustedProxies))
	}

	if err := app.loadQuotaDefaults(ctx, UserQuota{
		Bytes: envInt64("QUOTA_USER_BYTES", 20*1024*1024*1024),
		Files: envInt64("QUOTA_USER_FILES", 1000),
	}); err != nil {
		log.Fatalf("quota defaults: %v", err)
	}

	if err := app.loadMaxUploadDefault(ctx, maxUploadEnv); err != nil {
		log.Fatalf("upload limit: %v", err)
	}

	if err := app.bootstrapAdmin(ctx, adminUser, adminPass); err != nil {
		log.Fatalf("admin bootstrap: %v", err)
	}
	if err := app.seedOIDCFromEnv(ctx, envOIDCIssuer, envOIDCClientID,
		envOIDCClientSecret, envOIDCRedirect, envOIDCAllowedDomain); err != nil {
		log.Fatalf("oidc seed: %v", err)
	}
	if err := app.loadAndApplyOIDC(ctx); err != nil {
		log.Printf("oidc init: %v (continuing with OIDC disabled)", err)
	}

	app.startSweeper(ctx, time.Minute)

	mux := http.NewServeMux()

	// public
	mux.HandleFunc("/healthz", app.handleHealth)
	mux.HandleFunc("/files/", app.dispatchFileRoutes)
	mux.HandleFunc("/b/", app.dispatchBatchRoutes)
	mux.HandleFunc("/lang", app.handleLang)
	mux.HandleFunc("/theme", app.handleTheme)
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			app.handleLoginPage(w, r)
		case http.MethodPost:
			app.handleLoginPost(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/logout", app.handleLogout)
	mux.HandleFunc("/auth/oidc/start", app.handleOIDCStart)
	mux.HandleFunc("/auth/oidc/callback", app.handleOIDCCallback)

	// static assets
	staticSub, _ := fs.Sub(staticFS, "web/static")
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	// gated (any user)
	mux.Handle("/", app.requireUserHandler(app.handleUploadPage))
	mux.Handle("/history", app.requireUserHandler(app.handleHistory))
	mux.Handle("/upload", app.requireUserHandler(app.handleUpload))
	mux.Handle("/usage", app.requireUserHandler(app.handleStorageBars))
	mux.Handle("/batches", app.requireUserHandler(app.handleCreateBatch))
	mux.Handle("/delete/", app.requireUserHandler(app.handleDelete))
	// Bulk delete from the file list. Registered as its own exact pattern so it
	// cannot collide with a share id under /delete/.
	mux.Handle("/delete", app.requireUserHandler(app.handleBulkDelete))
	mux.Handle("/account", app.requireUserHandler(app.handleAccount))
	mux.Handle("/account/password", app.requireUserHandler(app.handleAccountPassword))

	// gated (admin)
	mux.Handle("/admin/files", http.HandlerFunc(app.requireAdmin(app.handleAdminFiles)))
	mux.Handle("/admin/users", http.HandlerFunc(app.requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			app.handleAdminUsers(w, r)
		case http.MethodPost:
			app.handleAdminCreateUser(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})))
	mux.Handle("/admin/users/", http.HandlerFunc(app.requireAdmin(app.dispatchAdminUserAction)))
	mux.Handle("/admin/settings", http.HandlerFunc(app.requireAdmin(app.handleAdminSettings)))
	mux.Handle("/admin/settings/oidc", http.HandlerFunc(app.requireAdmin(app.handleAdminSettingsOIDC)))
	mux.Handle("/admin/settings/quota", http.HandlerFunc(app.requireAdmin(app.handleAdminSettingsQuota)))
	mux.Handle("/admin/settings/upload", http.HandlerFunc(app.requireAdmin(app.handleAdminSettingsUpload)))

	mux.Handle("/batches/", app.requireUserHandler(app.dispatchBatchOwnerRoutes))

	var handler http.Handler = mux
	handler = app.withOptionalUser(handler)
	handler = sameOriginCheck(handler)
	handler = app.securityHeaders(handler)
	handler = logRequests(handler)

	// Timeouts are explicit rather than left at Go's defaults of "none".
	//
	// WriteTimeout is deliberately absent: it is measured from the moment the
	// request headers are read, so on this service it would cap how long a
	// large upload or download may take in total, not how long the server may
	// be idle — a 512 MiB transfer on a slow line would be cut off mid-body.
	// The read side is bounded instead (headers, and the whole body through
	// MaxBytesReader), and IdleTimeout reclaims kept-alive connections.
	srv := &http.Server{
		Addr:              listen,
		Handler:           handler,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	// Shut down gracefully: in-flight uploads finish and the sweeper stops
	// before the pool closes, instead of transfers dying with the process and
	// leaving half-written blobs behind.
	shutdownErr := make(chan error, 1)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-stop
		log.Printf("received %s, shutting down (up to 30s for in-flight requests)", sig)
		cancel() // stops the sweeper
		sctx, scancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer scancel()
		shutdownErr <- srv.Shutdown(sctx)
	}()

	log.Printf("pyxis listening on %s (files dir: %s, max upload: %s, schema v%d)",
		listen, filesDir, humanSize(app.getMaxUploadDefault()), latestSchemaVersion())
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server: %v", err)
	}
	if err := <-shutdownErr; err != nil {
		log.Printf("graceful shutdown: %v", err)
	}
	log.Print("stopped")
}

func (a *App) requireUserHandler(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(a.requireUser(h))
}

func (a *App) dispatchAdminUserAction(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasSuffix(r.URL.Path, "/password"):
		a.handleAdminResetPassword(w, r)
	case strings.HasSuffix(r.URL.Path, "/admin"):
		a.handleAdminToggleAdmin(w, r)
	case strings.HasSuffix(r.URL.Path, "/quota"):
		a.handleAdminSetQuota(w, r)
	case strings.HasSuffix(r.URL.Path, "/delete"):
		a.handleAdminDeleteUser(w, r)
	default:
		http.NotFound(w, r)
	}
}

func loadTemplates() (*template.Template, error) {
	funcs := template.FuncMap{
		"humanSize": humanSize,
		"T":         tr,
		"formatTime": func(t time.Time) string {
			return t.UTC().Format("2006-01-02 15:04 UTC")
		},
		"formatDate": func(t time.Time) string {
			return t.UTC().Format("2006-01-02")
		},
		"rfc3339": func(t time.Time) string {
			return t.UTC().Format(time.RFC3339)
		},
		"until": humanUntil,
		// A {{template}} call carries one value, and the file-row partial needs
		// both the file and the language the page is rendering in.
		"dict": func(kv ...any) (map[string]any, error) {
			if len(kv)%2 != 0 {
				return nil, fmt.Errorf("dict: odd argument count")
			}
			m := make(map[string]any, len(kv)/2)
			for i := 0; i < len(kv); i += 2 {
				k, ok := kv[i].(string)
				if !ok {
					return nil, fmt.Errorf("dict: key %d is not a string", i)
				}
				m[k] = kv[i+1]
			}
			return m, nil
		},
	}
	tmpl := template.New("").Funcs(funcs)
	return tmpl.ParseFS(templatesFS, "web/templates/*.html")
}

func (a *App) render(w http.ResponseWriter, r *http.Request, name string, data map[string]any) {
	a.renderStatus(w, r, http.StatusOK, name, data)
}

func (a *App) renderStatus(w http.ResponseWriter, r *http.Request, status int, name string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	lang := langFromRequest(r)
	data["Lang"] = lang
	i18nJSON, _ := json.Marshal(jsStrings(lang))
	data["I18NJSON"] = string(i18nJSON)
	data["Theme"] = themeFromRequest(r)
	data["ReqPath"] = r.URL.RequestURI()
	if _, ok := data["User"]; !ok {
		data["User"] = userFromContext(r.Context())
	}
	if u, _ := data["User"].(*User); u != nil {
		// A statfs is cheap enough to do per render and always reflects
		// reality, including the sweeper. Only admins are shown the result,
		// so only admins pay for it.
		if _, ok := data["Disk"]; !ok && u.IsAdmin {
			data["Disk"] = a.diskStats()
		}
		// Everyone gets their own quota bar. Losing it must not cost them the
		// page, so a failure here is logged and the block is left out.
		if _, ok := data["Usage"]; !ok {
			if s, err := a.usageSummary(r.Context(), u); err != nil {
				log.Printf("usage summary for %s: %v", u.Username, err)
			} else {
				data["Usage"] = s
			}
		}
	}
	if _, ok := data["Title"]; !ok {
		data["Title"] = "Pyxis"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := a.tmpl.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("render %s: %v", name, err)
	}
}

func logRequests(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		h.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, redactPath(r.URL.Path), time.Since(start))
	})
}

// redactPath truncates share IDs in /files/ URLs: the UUID is the bearer
// secret of an unprotected share and must not be reconstructable from logs.
func redactPath(p string) string {
	const prefix = "/files/"
	if !strings.HasPrefix(p, prefix) {
		return p
	}
	rest := p[len(prefix):]
	id, action, hasAction := strings.Cut(rest, "/")
	if len(id) > 8 {
		id = id[:8] + "…"
	}
	if hasAction {
		return prefix + id + "/" + action
	}
	return prefix + id
}

// hstsMaxAge is one year, the value the preload list requires. Sent only when
// the deployment is actually HTTPS-only, which COOKIE_SECURE already states.
const hstsMaxAge = 365 * 24 * 60 * 60

// securityHeaders sets browser-hardening defaults. Handlers that stream user
// content (the preview endpoint) overwrite CSP/framing with stricter or
// embedding-compatible values of their own.
func (a *App) securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr := w.Header()
		hdr.Set("X-Content-Type-Options", "nosniff")
		// HSTS belongs in the application, not only at the proxy: the whole
		// design assumes HTTPS (WebCrypto is unavailable without it, and the
		// share fragment must never cross a plaintext hop), and a header that
		// depends on the proxy being configured correctly is a header that
		// silently disappears the day someone puts a new proxy in front.
		//
		// Gated on COOKIE_SECURE, the flag that already declares "this instance
		// is served over HTTPS", so a local plain-HTTP run cannot pin itself
		// out of reach. No `preload`: that is a one-way commitment for the
		// whole domain and is the operator's decision, not a default.
		if a.cookieSecure {
			hdr.Set("Strict-Transport-Security",
				fmt.Sprintf("max-age=%d; includeSubDomains", hstsMaxAge))
		}
		// NOT "no-referrer": per the Fetch spec browsers then serialize the
		// Origin header as "null" even on same-origin form POSTs, which the
		// same-origin middleware would reject. "same-origin" keeps the
		// referrer away from external sites while preserving Origin.
		hdr.Set("Referrer-Policy", "same-origin")
		hdr.Set("X-Frame-Options", "DENY")
		hdr.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		// blob: sources carry locally decrypted E2E previews/downloads. The
		// only script-capable blob context is the PDF iframe, which app.js
		// gates on a %PDF- magic-byte check so HTML can't ride in on a lying
		// content type.
		hdr.Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; "+
				"script-src 'self'; style-src 'self'; object-src 'none'; "+
				"base-uri 'self'; form-action 'self'; frame-ancestors 'none'; frame-src 'self' blob:")
		h.ServeHTTP(w, r)
	})
}

// sameOriginCheck rejects state-changing cross-origin browser requests
// (CSRF hardening on top of SameSite=Lax cookies). Requests without Origin
// and Referer (curl, API clients) pass — they carry no ambient cookies.
func sameOriginCheck(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			source := r.Header.Get("Origin")
			if source == "" {
				source = r.Header.Get("Referer")
			}
			if source != "" {
				u, err := url.Parse(source)
				if err != nil || !strings.EqualFold(u.Host, r.Host) {
					http.Error(w, "cross-origin request rejected", http.StatusForbidden)
					return
				}
			}
		}
		h.ServeHTTP(w, r)
	})
}

func httpError(w http.ResponseWriter, err error, code int) {
	log.Printf("error: %v", err)
	http.Error(w, http.StatusText(code), code)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("%s is required", key)
	}
	return v
}

func envInt64(key string, fallback int64) int64 {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		log.Printf("invalid %s=%q, using default %d", key, v, fallback)
		return fallback
	}
	return n
}

func envBool(key string, fallback bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch v {
	case "":
		return fallback
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

var errBadSize = errors.New("not a byte size")

// parseSize reads a byte count an admin typed: a bare number, or a number with
// a unit suffix ("20G", "20 GiB", "500 MB", "1.5T"). Every unit is 1024-based,
// including the MB/GB spellings, because humanSize renders KiB/MiB/GiB and the
// field has to round-trip what the UI shows. Negative values are rejected; 0 is
// valid and means "no limit".
func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errBadSize
	}
	// Split the numeric head from the unit tail.
	i := 0
	for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '.') {
		i++
	}
	num, unit := s[:i], strings.TrimSpace(strings.ToLower(s[i:]))
	if num == "" {
		return 0, errBadSize
	}
	val, err := strconv.ParseFloat(num, 64)
	if err != nil || val < 0 {
		return 0, errBadSize
	}

	mult := float64(1)
	switch strings.TrimSuffix(strings.TrimSuffix(unit, "ib"), "b") {
	case "":
		// bare number, or a plain "b" suffix: bytes
	case "k":
		mult = 1 << 10
	case "m":
		mult = 1 << 20
	case "g":
		mult = 1 << 30
	case "t":
		mult = 1 << 40
	case "p":
		mult = 1 << 50
	default:
		return 0, errBadSize
	}
	n := val * mult
	if n > float64(math.MaxInt64) {
		return 0, errBadSize
	}
	return int64(n), nil
}

// parsePositiveSize is parseSize for a limit that cannot be zero. A storage
// quota reads 0 as "unlimited"; a per-file upload ceiling has no such reading —
// 0 would refuse every upload — so it is rejected as the typo it almost
// certainly is.
func parsePositiveSize(s string) (int64, error) {
	n, err := parseSize(s)
	if err != nil {
		return 0, err
	}
	if n <= 0 {
		return 0, errBadSize
	}
	return n, nil
}

// sizeInput renders a byte count for an <input> the admin will edit and post
// back. Unlike humanSize it never rounds: a value that is not a whole multiple
// of a unit is shown as raw bytes, so saving the form unchanged cannot quietly
// move the limit (humanSize would turn 21474836481 into "20.0 GiB").
func sizeInput(n int64) string {
	if n <= 0 {
		return "0"
	}
	units := []struct {
		suffix string
		size   int64
	}{{"PiB", 1 << 50}, {"TiB", 1 << 40}, {"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}}
	for _, u := range units {
		if n >= u.size && n%u.size == 0 {
			return strconv.FormatInt(n/u.size, 10) + " " + u.suffix
		}
	}
	return strconv.FormatInt(n, 10)
}
