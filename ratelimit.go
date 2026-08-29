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

// clientIP extracts the caller address. The app is only reachable through the
// reverse proxy (no published ports), so the first X-Forwarded-For hop is
// trustworthy; RemoteAddr is the fallback.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if first, _, ok := strings.Cut(xff, ","); ok || first != "" {
			return strings.TrimSpace(first)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
