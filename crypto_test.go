package main

import (
	"bytes"
	"io"
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
	enc := app.encryptSecret("hunter2-client-secret")
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
	// No KEK → identity.
	nokek := &App{}
	if nokek.encryptSecret("x") != "x" {
		t.Fatal("no-KEK encrypt should be identity")
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
