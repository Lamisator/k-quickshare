package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestChunkFormatRoundTrip exercises the Go reference implementation of the
// end-to-end container format, including the seekable reader the format was
// designed to allow. e2e_interop_test.go pins the same implementation against
// vectors from a real WebCrypto.
func TestChunkFormatRoundTrip(t *testing.T) {
	dek := randomBytes(32)

	// Odd size crossing several chunk boundaries.
	plain := randomBytes(3*chunkPlainSize + 12345)

	path := filepath.Join(t.TempDir(), "blob")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	n, err := encryptStream(f, bytes.NewReader(plain), dek)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	f.Close()
	if n != int64(len(plain)) {
		t.Fatalf("plaintext size: got %d want %d", n, len(plain))
	}

	// Ciphertext must not contain the plaintext.
	ct, _ := os.ReadFile(path)
	if bytes.Contains(ct, plain[:64]) {
		t.Fatal("ciphertext contains plaintext")
	}

	rf, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer rf.Close()
	r, err := newEncReader(rf, dek, int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("round trip mismatch")
	}

	// Random access (range-request shape): read 100 bytes at an offset
	// crossing a chunk boundary.
	off := int64(2*chunkPlainSize - 50)
	if _, err := r.Seek(off, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 100)
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatalf("ranged read: %v", err)
	}
	if !bytes.Equal(buf, plain[off:off+100]) {
		t.Fatal("ranged read mismatch")
	}
}

func TestSecretRoundTrip(t *testing.T) {
	app := &App{fileKEK: randomBytes(32)}
	enc, err := app.encryptSecret("hunter2-client-secret")
	if err != nil {
		t.Fatal(err)
	}
	if enc == "hunter2-client-secret" {
		t.Fatal("secret not encrypted")
	}
	dec, err := app.decryptSecret(enc)
	if err != nil || dec != "hunter2-client-secret" {
		t.Fatalf("decrypt: %q %v", dec, err)
	}
	// Legacy plaintext passes through.
	if v, err := app.decryptSecret("plain"); err != nil || v != "plain" {
		t.Fatalf("legacy passthrough: %q %v", v, err)
	}
	// No KEK (explicit unencrypted opt-out) → identity.
	nokek := &App{}
	if v, err := nokek.encryptSecret("x"); err != nil || v != "x" {
		t.Fatalf("no-KEK encrypt should be identity: %q %v", v, err)
	}
}

func TestClientIPTrustedProxy(t *testing.T) {
	nets, err := parseTrustedProxies("172.16.0.0/12, 10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	app := &App{trustedProxies: nets}
	req := func(remote, xff string) *http.Request {
		r := httptest.NewRequest("POST", "/login", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}

	// Trusted proxy peer: the LAST XFF entry (appended by our proxy) wins,
	// attacker-prefixed earlier entries are ignored.
	if got := app.clientIP(req("172.18.0.5:1234", "1.1.1.1, 9.9.9.9")); got != "9.9.9.9" {
		t.Errorf("trusted proxy: got %q, want 9.9.9.9", got)
	}
	// Untrusted peer: XFF is ignored entirely.
	if got := app.clientIP(req("203.0.113.7:5555", "1.1.1.1")); got != "203.0.113.7" {
		t.Errorf("untrusted peer: got %q, want 203.0.113.7", got)
	}
	// No trusted proxies configured: XFF never honored.
	bare := &App{}
	if got := bare.clientIP(req("172.18.0.5:1234", "1.1.1.1")); got != "172.18.0.5" {
		t.Errorf("no proxies: got %q, want 172.18.0.5", got)
	}
	// Garbage XFF from a trusted peer falls back to the peer address.
	if got := app.clientIP(req("172.18.0.5:1234", "not-an-ip")); got != "172.18.0.5" {
		t.Errorf("garbage XFF: got %q, want 172.18.0.5", got)
	}
}

func TestRedactPath(t *testing.T) {
	cases := map[string]string{
		"/files/550e8400-e29b-41d4-a716-446655440000":          "/files/550e8400…",
		"/files/550e8400-e29b-41d4-a716-446655440000/download": "/files/550e8400…/download",
		"/files/550e8400-e29b-41d4-a716-446655440000/preview":  "/files/550e8400…/preview",
		"/history": "/history",
		"/login":   "/login",
	}
	for in, want := range cases {
		if got := redactPath(in); got != want {
			t.Errorf("redactPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFailLimiter(t *testing.T) {
	l := &failLimiter{entries: map[string]*failEntry{}, maxFails: 3, window: time.Minute}
	key := "1.2.3.4|x"
	for i := 0; i < 3; i++ {
		if !l.allow(key) {
			t.Fatalf("blocked too early at %d", i)
		}
		l.fail(key)
	}
	if l.allow(key) {
		t.Fatal("not blocked after max failures")
	}
	l.reset(key)
	if !l.allow(key) {
		t.Fatal("reset did not unblock")
	}
}

// TestIsSafeNextRejectsFragment guards the redirect contract behind the
// language and theme switchers. `next` is a query parameter, so anything in it
// reaches the server — and on a share link the fragment is the decryption key.
// Refusing a fragment also keeps the redirect's Location fragment-free, which
// is what lets the browser re-attach the caller's own fragment afterwards.
func TestIsSafeNextRejectsFragment(t *testing.T) {
	bad := []string{
		"/b/abc#s3cret",
		"/files/abc#key",
		"/#x",
		"//evil.example/#x",
		"https://evil.example/",
		"evil",
		"",
	}
	for _, s := range bad {
		if isSafeNext(s) {
			t.Errorf("isSafeNext(%q) = true, want false", s)
		}
	}
	good := []string{"/", "/b/abc", "/history", "/files/abc?x=1"}
	for _, s := range good {
		if !isSafeNext(s) {
			t.Errorf("isSafeNext(%q) = false, want true", s)
		}
	}
}

// TestNegotiateLang covers Accept-Language handling. The q-value decides, not
// header order: RFC 9110 does not require the list to be sorted by preference,
// so picking the first supported tag can select a language the visitor ranked
// below another one they also accept.
func TestNegotiateLang(t *testing.T) {
	cases := []struct{ header, want string }{
		{"", "en"},                              // no header at all
		{"de", "de"},                            // bare tag
		{"DE", "de"},                            // case-insensitive
		{"de-DE,de;q=0.9,en;q=0.8", "de"},       // typical Chrome/Firefox
		{"en-US,en;q=0.9", "en"},                // typical English browser
		{"de-AT", "de"},                         // regional variant maps to base
		{"fr-FR,fr;q=0.9", "en"},                // nothing supported -> English
		{"*", "en"},                             // wildcard only
		{"fr, en;q=0.3, de;q=0.9", "de"},        // out of q order: German wins
		{"en;q=0.5, de;q=0.9", "de"},            // German preferred despite order
		{"de;q=0, en;q=0.5", "en"},              // q=0 rejects German
		{"de;q=0", "en"},                        // sole option rejected
		{"en, de", "en"},                        // equal q -> first wins
		{"de;q=abc, en;q=0.4", "de"},            // unparseable q treated as 1.0
		{"  de-CH ; q=0.8 , en ; q=0.2 ", "de"}, // stray whitespace
		{"zh-Hant,zh;q=0.9,en;q=0.2", "en"},     // unsupported first, English later
	}
	for _, c := range cases {
		if got := negotiateLang(c.header); got != c.want {
			t.Errorf("negotiateLang(%q) = %q, want %q", c.header, got, c.want)
		}
	}
}
