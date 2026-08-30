package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// One window and one allowance for every authentication counter: local login,
// share passwords, and the per-source login ceiling.
const (
	failWindow   = 10 * time.Minute
	failMaxTries = 10
	// A single source may burn this many failed logins across all usernames
	// before it is shut out. Each attempt costs an Argon2id derivation, so
	// without a per-source ceiling one host could keep the server hashing by
	// cycling usernames, which the per-(source, username) counter never sees.
	failMaxPerSource = 30
)

// failLimiter is a fixed-window failure counter for authentication attempts
// (local login, share passwords). Only failures count; success resets the key.
//
// Counting happens in TWO places, and both have to say yes:
//
//   - in this process, which is fast and works even when the database is
//     struggling; and
//   - in the auth_failures table, which is what makes the limit mean anything
//     across replicas and across restarts. A purely in-memory limiter gives
//     every additional container its own full allowance, and hands an attacker
//     a clean slate on every deploy.
//
// A database error opens the shared gate rather than closing it: the local
// counter still applies, and a database blip must not lock everyone out of a
// service whose whole job is behind that same database.
type failLimiter struct {
	mu       sync.Mutex
	entries  map[string]*failEntry
	maxFails int
	window   time.Duration

	// db and scope back the shared counter. db may be nil (unit tests), in
	// which case the limiter is process-local only.
	db    *pgxpool.Pool
	scope string
}

type failEntry struct {
	fails       int
	windowStart time.Time
}

func newFailLimiter(maxFails int, window time.Duration) *failLimiter {
	l := &failLimiter{
		entries:  map[string]*failEntry{},
		maxFails: maxFails,
		window:   window,
	}
	go l.cleanupLoop()
	return l
}

// shared attaches the database-backed counter. scope namespaces the keys so a
// login limiter and a share-password limiter cannot collide in one table.
func (l *failLimiter) shared(db *pgxpool.Pool, scope string) *failLimiter {
	l.db = db
	l.scope = scope
	return l
}

func (l *failLimiter) storedKey(key string) string { return l.scope + "|" + key }

// allow reports whether another attempt may be made for key right now.
func (l *failLimiter) allow(ctx context.Context, key string) bool {
	if !l.allowLocal(key) {
		return false
	}
	if l.db == nil {
		return true
	}
	var fails int
	err := l.db.QueryRow(ctx,
		`SELECT fails FROM auth_failures
		  WHERE key = $1 AND window_start > NOW() - $2::interval`,
		l.storedKey(key), l.window.String()).Scan(&fails)
	if err != nil {
		// No row is the common case: nothing has failed yet.
		if !errors.Is(err, pgx.ErrNoRows) {
			log.Printf("ratelimit: read shared counter: %v", err)
		}
		return true
	}
	return fails < l.maxFails
}

func (l *failLimiter) allowLocal(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[key]
	if !ok {
		return true
	}
	if time.Since(e.windowStart) > l.window {
		delete(l.entries, key)
		return true
	}
	return e.fails < l.maxFails
}

// fail records a failed attempt for key.
func (l *failLimiter) fail(ctx context.Context, key string) {
	l.mu.Lock()
	e, ok := l.entries[key]
	if !ok || time.Since(e.windowStart) > l.window {
		l.entries[key] = &failEntry{fails: 1, windowStart: time.Now()}
	} else {
		e.fails++
	}
	l.mu.Unlock()

	if l.db == nil {
		return
	}
	// The upsert restarts the window when the stored one has already lapsed,
	// so a counter cannot creep upwards across unrelated windows.
	if _, err := l.db.Exec(ctx,
		`INSERT INTO auth_failures (key, fails, window_start) VALUES ($1, 1, NOW())
		 ON CONFLICT (key) DO UPDATE SET
		   fails = CASE WHEN auth_failures.window_start > NOW() - $2::interval
		                THEN auth_failures.fails + 1 ELSE 1 END,
		   window_start = CASE WHEN auth_failures.window_start > NOW() - $2::interval
		                       THEN auth_failures.window_start ELSE NOW() END`,
		l.storedKey(key), l.window.String()); err != nil {
		log.Printf("ratelimit: record failure: %v", err)
	}
}

// reset clears the failure count for key (call on success).
func (l *failLimiter) reset(ctx context.Context, key string) {
	l.mu.Lock()
	delete(l.entries, key)
	l.mu.Unlock()

	if l.db == nil {
		return
	}
	if _, err := l.db.Exec(ctx, `DELETE FROM auth_failures WHERE key = $1`, l.storedKey(key)); err != nil {
		log.Printf("ratelimit: clear counter: %v", err)
	}
}

func (l *failLimiter) cleanupLoop() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for range t.C {
		l.mu.Lock()
		for k, e := range l.entries {
			if time.Since(e.windowStart) > l.window {
				delete(l.entries, k)
			}
		}
		l.mu.Unlock()
	}
}

// parseTrustedProxies parses the TRUSTED_PROXY_CIDRS env value (comma-
// separated CIDRs). An empty list means X-Forwarded-For is never trusted.
func parseTrustedProxies(v string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		_, n, err := net.ParseCIDR(part)
		if err != nil {
			return nil, err
		}
		nets = append(nets, n)
	}
	return nets, nil
}

// clientIP extracts the caller address for rate-limit keying. X-Forwarded-For
// is client-controlled, so it is honored ONLY when the direct peer is inside
// a configured trusted-proxy network — and then the LAST entry is used (the
// one our own proxy appended), never attacker-prefixed earlier hops. In all
// other cases the TCP peer address is used.
func (a *App) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer := net.ParseIP(host)
	if peer == nil || len(a.trustedProxies) == 0 {
		a.warnUntrustedForwarding(r, host)
		return host
	}
	trusted := false
	for _, n := range a.trustedProxies {
		if n.Contains(peer) {
			trusted = true
			break
		}
	}
	if !trusted {
		a.warnUntrustedForwarding(r, host)
		return host
	}
	xff := r.Header.Get("X-Forwarded-For")
	parts := strings.Split(xff, ",")
	last := strings.TrimSpace(parts[len(parts)-1])
	if net.ParseIP(last) != nil {
		return last
	}
	return host
}

// warnUntrustedForwarding says so, once, when requests arrive with a forwarding
// header from a peer the configuration does not trust.
//
// This is the shape of a misconfigured production deployment: the app sits
// behind a reverse proxy, TRUSTED_PROXY_CIDRS was never set, so every visitor
// keys to the proxy's address. Rate limits then apply to the whole instance at
// once — one person guessing a share password locks out everybody — and the
// limiter stops distinguishing between attackers and everyone else. It is
// silent by construction, which is why it gets a log line.
func (a *App) warnUntrustedForwarding(r *http.Request, peer string) {
	if r.Header.Get("X-Forwarded-For") == "" {
		return
	}
	a.proxyWarnOnce.Do(func() {
		log.Printf("WARNING: requests from %s carry X-Forwarded-For but that peer is not in "+
			"TRUSTED_PROXY_CIDRS, so every client is rate-limited as one address. "+
			"Set TRUSTED_PROXY_CIDRS to the network your reverse proxy connects from.", peer)
	})
}

// sweepAuthFailures drops lapsed shared counters.
func (a *App) sweepAuthFailures(ctx context.Context) error {
	_, err := a.db.Exec(ctx,
		`DELETE FROM auth_failures WHERE window_start <= NOW() - $1::interval`,
		(2 * failWindow).String())
	return err
}
