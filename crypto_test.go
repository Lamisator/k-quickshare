package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// TestChunkFormatRoundTrip exercises the Go reference implementation of the
// end-to-end container format, including the seekable reader the format was
// designed to allow. e2e_interop_test.go pins the same implementation against
// vectors from a real WebCrypto.
func TestChunkFormatRoundTrip(t *testing.T) {
	dek := randomBytes(32)
	manifest := []byte(`{"v":2,"id":"x","batch":"","size":209273,"chunks":4,"chunk":65536,"name":"a","type":"t"}`)

	// Odd size crossing several chunk boundaries.
	plain := randomBytes(3*chunkPlainSize + 12345)

	path := filepath.Join(t.TempDir(), "blob")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	n, err := encryptStream(f, bytes.NewReader(plain), dek, manifest)
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
	r, err := newEncReader(rf, dek, manifest, int64(len(plain)))
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
	ctx := context.Background()
	// No db: the limiter falls back to its process-local counter, which is the
	// half that has to keep working when the shared one is unavailable.
	l := &failLimiter{entries: map[string]*failEntry{}, maxFails: 3, window: time.Minute}
	key := "1.2.3.4|x"
	for i := 0; i < 3; i++ {
		if !l.allow(ctx, key) {
			t.Fatalf("blocked too early at %d", i)
		}
		l.fail(ctx, key)
	}
	if l.allow(ctx, key) {
		t.Fatal("not blocked after max failures")
	}
	l.reset(ctx, key)
	if !l.allow(ctx, key) {
		t.Fatal("reset did not unblock")
	}
}

// TestPasswordHashing covers the Argon2id migration. Bcrypt hashes written by
// earlier versions must keep verifying — otherwise an upgrade locks every local
// account out — while new ones are Argon2id and are flagged for rehash.
func TestPasswordHashing(t *testing.T) {
	const pw = "correct horse battery staple"

	hash, err := hashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("new hashes must be argon2id, got %q", hash)
	}
	if !checkPassword(hash, pw) {
		t.Error("argon2id hash did not verify its own password")
	}
	if checkPassword(hash, pw+"!") {
		t.Error("argon2id hash verified the wrong password")
	}
	if isLegacyHash(hash) {
		t.Error("a fresh argon2id hash was flagged for rehash")
	}

	// Two hashes of the same password must differ: the salt is random.
	other, err := hashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	if other == hash {
		t.Error("two hashes of the same password are identical — the salt is not random")
	}

	// A bcrypt hash of the same password, as written before this change.
	legacy, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if !checkPassword(string(legacy), pw) {
		t.Error("an existing bcrypt hash stopped verifying")
	}
	if checkPassword(string(legacy), "wrong") {
		t.Error("bcrypt hash verified the wrong password")
	}
	if !isLegacyHash(string(legacy)) {
		t.Error("a bcrypt hash was not flagged for rehash")
	}

	// Malformed and hostile stored values must fail closed, not panic and not
	// pass. The parameter fields are attacker-controlled if the database is.
	for _, bad := range []string{
		"", "not-a-hash", "$argon2id$", "$argon2id$v=19$m=19456,t=2,p=1$$",
		"$argon2id$v=13$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaA",
		"$argon2id$v=19$m=99999999,t=2,p=1$c2FsdHNhbHQ$aGFzaA",
		"$argon2id$v=19$m=19456,t=0,p=1$c2FsdHNhbHQ$aGFzaA",
		"$argon2id$v=19$m=x,t=2,p=1$c2FsdHNhbHQ$aGFzaA",
	} {
		if checkPassword(bad, pw) {
			t.Errorf("malformed hash %q verified a password", bad)
		}
	}
}

// TestSessionKeyHashing pins the property the sessions table depends on: what
// is stored is not what is presented, so a leaked row cannot be replayed as a
// cookie.
func TestSessionKeyHashing(t *testing.T) {
	token := randomToken(32)
	key := sessionKey(token)
	if key == token {
		t.Fatal("the session key is the token itself — a database leak would hand over live sessions")
	}
	if len(key) != sha256.Size*2 {
		t.Fatalf("session key is %d chars, want %d hex chars", len(key), sha256.Size*2)
	}
	if sessionKey(token) != key {
		t.Error("session key is not deterministic")
	}
	if sessionKey(randomToken(32)) == key {
		t.Error("two tokens produced the same key")
	}
}

// TestReauthFreshness covers the step-up window used before an SSO-only account
// may set a local password.
func TestReauthFreshness(t *testing.T) {
	recent := time.Now().Add(-time.Minute)
	stale := time.Now().Add(-2 * reauthWindow)

	cases := []struct {
		name    string
		user    User
		stepUp  bool
		freshOK bool
	}{
		{"sso-only, never re-authenticated",
			User{OIDCSubject: "s"}, true, false},
		{"sso-only, just re-authenticated",
			User{OIDCSubject: "s", ReauthAt: &recent}, false, true},
		{"sso-only, step-up expired",
			User{OIDCSubject: "s", ReauthAt: &stale}, true, false},
		{"already has a password: gated on that password instead",
			User{OIDCSubject: "s", HasPassword: true}, false, false},
		{"local-only account",
			User{HasPassword: true}, false, false},
		// No password and no external identity: nothing to step up with, and
		// nothing this gate could ask for.
		{"neither credential", User{}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := tc.user
			if got := needsPasswordStepUp(&u); got != tc.stepUp {
				t.Errorf("needsPasswordStepUp = %v, want %v", got, tc.stepUp)
			}
			if got := u.ReauthFresh(); got != tc.freshOK {
				t.Errorf("ReauthFresh = %v, want %v", got, tc.freshOK)
			}
		})
	}
}

// TestHSTSOnlyWhenSecure pins the header to the flag that declares the
// deployment is HTTPS: pinning a plain-HTTP dev instance would make it
// unreachable in that browser until the max-age ran out.
func TestHSTSOnlyWhenSecure(t *testing.T) {
	for _, secure := range []bool{true, false} {
		app := &App{cookieSecure: secure}
		rec := httptest.NewRecorder()
		app.securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).
			ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
		got := rec.Header().Get("Strict-Transport-Security")
		if secure && got == "" {
			t.Error("no HSTS header on an HTTPS deployment")
		}
		if !secure && got != "" {
			t.Errorf("HSTS sent on a plain-HTTP deployment: %q", got)
		}
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
