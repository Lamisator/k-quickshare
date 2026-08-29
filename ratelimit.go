package main

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// failLimiter is a fixed-window failure counter for authentication attempts
// (local login, share passwords). Only failures count; success resets the key.
type failLimiter struct {
	mu       sync.Mutex
	entries  map[string]*failEntry
	maxFails int
	window   time.Duration
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

// allow reports whether another attempt may be made for key right now.
func (l *failLimiter) allow(key string) bool {
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
func (l *failLimiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[key]
	if !ok || time.Since(e.windowStart) > l.window {
		l.entries[key] = &failEntry{fails: 1, windowStart: time.Now()}
		return
	}
	e.fails++
}

// reset clears the failure count for key (call on success).
func (l *failLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
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
