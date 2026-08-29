package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

// Vectors produced by the browser implementation (web/static/e2e.js, run on
// Node's WebCrypto). Regenerated when the HKDF info strings were renamed to
// the pyxis-e2e-* namespace, which changes every derived key by design. They pin the wire format across both implementations:
// the chunked AES-256-GCM container is deterministic given key + plaintext
// (nonces are counters), so any divergence in chunk size, nonce layout or
// key derivation breaks these byte-exact comparisons.
const (
	jsURLKeyHex    = "0325291e9aab6ccfee3b3de894e78c62b169a9fec1229d0ffce335c1f1bd5788"
	jsEncKeyHex    = "ce6888382034c7ea58a919faf1eb70e239f7f03e5c09b63aa793e81ddc8b3966"
	jsAuthHex      = "1695abc0c830d8bc246dbc8ae6b005181ceaba419e0cffe4fbea23fa85aa83ab"
	jsPlainLen     = 197842
	jsCipherLen    = 197906
	jsCipherSHA256 = "1515d2b8e2d8ed0c3e0aedcbc9ac3c23aeeeae5b07a6ebfe04ea96285dc10fe6"

	jsPassword = "correct horse battery staple"
)

func vectorSecret() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func vectorSalt() []byte {
	b := make([]byte, 16)
	for i := range b {
		b[i] = byte(0xa0 + i)
	}
	return b
}

func vectorPlaintext() []byte {
	b := make([]byte, jsPlainLen)
	for i := range b {
		b[i] = byte((i*31 + 7) & 0xff)
	}
	return b
}

func hkdf32Go(t *testing.T, material, salt []byte, info string) []byte {
	t.Helper()
	out := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, material, salt, []byte(info)), out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestE2EKeyDerivationMatchesBrowser checks that Go reproduces the exact key
// material the browser derives, for both the URL-secret and password modes.
func TestE2EKeyDerivationMatchesBrowser(t *testing.T) {
	urlKey := hkdf32Go(t, vectorSecret(), nil, "pyxis-e2e-url-v1")
	if got := hex.EncodeToString(urlKey); got != jsURLKeyHex {
		t.Errorf("url key: got %s, want %s", got, jsURLKeyHex)
	}

	master := pbkdf2.Key([]byte(jsPassword), vectorSalt(), 600000, 32, sha256.New)
	encKey := hkdf32Go(t, master, vectorSalt(), "pyxis-e2e-enc-v1")
	auth := hkdf32Go(t, master, vectorSalt(), "pyxis-e2e-auth-v1")
	if got := hex.EncodeToString(encKey); got != jsEncKeyHex {
		t.Errorf("password enc key: got %s, want %s", got, jsEncKeyHex)
	}
	if got := hex.EncodeToString(auth); got != jsAuthHex {
		t.Errorf("password auth token: got %s, want %s", got, jsAuthHex)
	}
	if bytes.Equal(encKey, auth) {
		t.Error("auth token equals encryption key — KDF branches are not separated")
	}
}

// TestE2ECiphertextMatchesBrowser encrypts the same plaintext with the same
// key on the Go side and requires a byte-identical container, then decrypts
// it back through the reader the download path uses.
func TestE2ECiphertextMatchesBrowser(t *testing.T) {
	key, err := hex.DecodeString(jsURLKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	plain := vectorPlaintext()

	var buf bytes.Buffer
	n, err := encryptStream(&buf, bytes.NewReader(plain), key)
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(len(plain)) {
		t.Fatalf("plaintext size: got %d, want %d", n, len(plain))
	}
	if buf.Len() != jsCipherLen {
		t.Fatalf("ciphertext size: got %d, want %d", buf.Len(), jsCipherLen)
	}
	if got := int64(jsCipherLen); e2eCipherLen(int64(len(plain))) != got {
		t.Fatalf("e2eCipherLen: got %d, want %d", e2eCipherLen(int64(len(plain))), got)
	}
	sum := sha256.Sum256(buf.Bytes())
	if got := hex.EncodeToString(sum[:]); got != jsCipherSHA256 {
		t.Fatalf("ciphertext differs from browser output:\n got %s\nwant %s", got, jsCipherSHA256)
	}

	// Round-trip through the seekable reader used to serve downloads.
	path := filepath.Join(t.TempDir(), "ct")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := newEncReader(f, key, int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("decrypted browser-format ciphertext does not match the plaintext")
	}
}
