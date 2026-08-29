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
// Node's WebCrypto). They pin the wire format across both implementations:
// the chunked AES-256-GCM container is deterministic given key + plaintext
// (nonces are counters), so any divergence in chunk size, nonce layout or
// key derivation breaks these byte-exact comparisons.
const (
	jsURLKeyHex    = "eed10ad633a62dfd71655723e3c6fe2fc68e6573d998b07922d7840d8e7e56d9"
	jsEncKeyHex    = "92b556df6118097b8cdc28eb7bede2faf2e5d00cfda4e5c35c95b130fc6ed924"
	jsAuthHex      = "6db911cebad1276c8783f5e5c55ac8a435a8b5784cce8dd1af195c99aa100340"
	jsPlainLen     = 197842
	jsCipherLen    = 197906
	jsCipherSHA256 = "c4be2131935f500252de7584691865aafcc1d341fc492ed2d63465b23754900a"

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
	urlKey := hkdf32Go(t, vectorSecret(), nil, "k-fileshare-e2e-url-v1")
	if got := hex.EncodeToString(urlKey); got != jsURLKeyHex {
		t.Errorf("url key: got %s, want %s", got, jsURLKeyHex)
	}

	master := pbkdf2.Key([]byte(jsPassword), vectorSalt(), 600000, 32, sha256.New)
	encKey := hkdf32Go(t, master, vectorSalt(), "k-fileshare-e2e-enc-v1")
	auth := hkdf32Go(t, master, vectorSalt(), "k-fileshare-e2e-auth-v1")
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
