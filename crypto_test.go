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

func TestEncryptDecryptRoundTrip(t *testing.T) {
	app := &App{fileKEK: randomBytes(32)}
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

	// DEK wrap/unwrap.
	wrapped, err := app.wrapDEK(dek)
	if err != nil {
		t.Fatal(err)
	}
	back, err := app.unwrapDEK(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, dek) {
		t.Fatal("DEK wrap round trip mismatch")
	}

	// Tampering must fail authentication.
	wrapped[len(wrapped)-1] ^= 0xff
	if _, err := app.unwrapDEK(wrapped); err == nil {
		t.Fatal("tampered DEK unwrap succeeded")
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

func TestKeyModeWrapRoundTrips(t *testing.T) {
	dek := randomBytes(32)
	salt := randomBytes(encSaltLen)

	// URL-secret mode: HKDF(secret) wraps the DEK.
	secret := randomBytes(urlSecretLen)
	wk, err := deriveURLWrapKey(secret, salt)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := wrapKeyWith(wk, dek)
	if err != nil {
		t.Fatal(err)
	}
	got, err := unwrapKeyWith(wk, blob)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("url-mode round trip: %v", err)
	}
	wrongWK, _ := deriveURLWrapKey(randomBytes(urlSecretLen), salt)
	if _, err := unwrapKeyWith(wrongWK, blob); err == nil {
		t.Fatal("wrong URL secret unwrapped the DEK")
	}

	// Password mode: Argon2id(password) wraps the DEK; must be deterministic
	// for the same password+salt and fail for a wrong password.
	pw1 := derivePasswordWrapKey("correct horse", salt)
	pw1again := derivePasswordWrapKey("correct horse", salt)
	if !bytes.Equal(pw1, pw1again) {
		t.Fatal("argon2 derivation not deterministic")
	}
	blob2, err := wrapKeyWith(pw1, dek)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := unwrapKeyWith(pw1, blob2); err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("password-mode round trip: %v", err)
	}
	if _, err := unwrapKeyWith(derivePasswordWrapKey("wrong", salt), blob2); err == nil {
		t.Fatal("wrong password unwrapped the DEK")
	}
	// Different salt → different key even with the same password.
	if bytes.Equal(pw1, derivePasswordWrapKey("correct horse", randomBytes(encSaltLen))) {
		t.Fatal("salt has no effect on derivation")
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
