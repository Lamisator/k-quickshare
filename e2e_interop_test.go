package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

// Vectors produced by the browser implementation (web/static/e2e.js) running on
// Node's WebCrypto. They pin the wire format across both implementations: the
// chunked AES-256-GCM container is deterministic given key + plaintext (nonces
// are counters, and the manifest is the only additional input), so any
// divergence in chunk size, nonce layout, AAD handling or key derivation breaks
// these byte-exact comparisons.
//
// Regenerate them whenever the container format or an HKDF info string changes,
// by loading web/static/e2e.js in Node and re-running the same fixtures.
const (
	// Key derivation. Unchanged by container version 2, which altered the
	// framing and not the key schedule — that is precisely why version 1 shares
	// still open.
	jsURLKeyHex       = "0325291e9aab6ccfee3b3de894e78c62b169a9fec1229d0ffce335c1f1bd5788"
	jsBatchKeyHex     = "624c84cc65fd6eb06e276b132a91163c543ce0b5d24ad6eff71511cc005f3f95"
	jsRosterURLKeyHex = "7e6dbd8b4a56112ed265d439fb45875313c75c59cdac7881a0b26931e7b4ef38"
	jsEncKeyHex       = "ce6888382034c7ea58a919faf1eb70e239f7f03e5c09b63aa793e81ddc8b3966"
	jsAuthHex         = "1695abc0c830d8bc246dbc8ae6b005181ceaba419e0cffe4fbea23fa85aa83ab"
	jsRosterPwKeyHex  = "9033d58c129c0b62638e245497478ccd0472e5c6dce921a47eca47d48230938a"

	jsPlainLen = 197842

	// Version 1: bare chunks, no AAD.
	jsLegacyCipherLen    = 197906
	jsLegacyCipherSHA256 = "1515d2b8e2d8ed0c3e0aedcbc9ac3c23aeeeae5b07a6ebfe04ea96285dc10fe6"

	// Version 2: the same plaintext under the same key, with the manifest bound
	// into every chunk. Same length, different bytes — which is the whole point.
	jsManifestJSON  = `{"v":2,"id":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","batch":"11111111-2222-3333-4444-555555555555","size":197842,"chunks":4,"chunk":65536,"name":"report.bin","type":"application/octet-stream"}`
	jsV2CipherLen   = 197906
	jsV2CipherSHA25 = "e5a755c178ab33b232ccdb5e00f0dbdf3d5d1e22c92efaa350675b0c2abf46d4"

	// An empty file is one chunk with no plaintext: 16 bytes of tag over the
	// manifest and nothing else. Without it, "the blob is gone" would decrypt
	// to a valid empty file.
	jsEmptyManifestJSON = `{"v":2,"id":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","batch":"","size":0,"chunks":1,"chunk":65536,"name":"empty.txt","type":"text/plain"}`
	jsEmptyCipherHex    = "e0d1152c612878d73ccaa568d43ec6fd"

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

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestE2EKeyDerivationMatchesBrowser checks that Go reproduces the exact key
// material the browser derives, for every branch of the key schedule.
func TestE2EKeyDerivationMatchesBrowser(t *testing.T) {
	empty := []byte(nil)
	for _, tc := range []struct {
		name string
		got  []byte
		want string
	}{
		{"url", hkdf32Go(t, vectorSecret(), empty, "pyxis-e2e-url-v1"), jsURLKeyHex},
		{"batch", hkdf32Go(t, vectorSecret(), empty, "pyxis-e2e-batch-v1"), jsBatchKeyHex},
		{"roster(url)", hkdf32Go(t, vectorSecret(), empty, "pyxis-e2e-roster-v1"), jsRosterURLKeyHex},
	} {
		if got := hex.EncodeToString(tc.got); got != tc.want {
			t.Errorf("%s key: got %s, want %s", tc.name, got, tc.want)
		}
	}

	master := pbkdf2.Key([]byte(jsPassword), vectorSalt(), 600000, 32, sha256.New)
	encKey := hkdf32Go(t, master, vectorSalt(), "pyxis-e2e-enc-v1")
	auth := hkdf32Go(t, master, vectorSalt(), "pyxis-e2e-auth-v1")
	rosterKey := hkdf32Go(t, master, vectorSalt(), "pyxis-e2e-roster-v1")
	for _, tc := range []struct {
		name string
		got  []byte
		want string
	}{
		{"password enc", encKey, jsEncKeyHex},
		{"password auth", auth, jsAuthHex},
		{"password roster", rosterKey, jsRosterPwKeyHex},
	} {
		if got := hex.EncodeToString(tc.got); got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}

	// The branches must be independent: the server holds the auth branch, so
	// any relationship between it and the others would leak the file key.
	for _, pair := range [][2][]byte{
		{encKey, auth}, {encKey, rosterKey}, {auth, rosterKey},
	} {
		if bytes.Equal(pair[0], pair[1]) {
			t.Error("two KDF branches produced the same key — domain separation is broken")
		}
	}
}

// TestE2ELegacyCiphertextMatchesBrowser pins the version 1 container. Nothing
// writes it any more, but shares created before version 2 still have to open,
// and this is what proves the legacy reader was not quietly changed with the
// new one.
func TestE2ELegacyCiphertextMatchesBrowser(t *testing.T) {
	key := mustHex(t, jsURLKeyHex)
	plain := vectorPlaintext()

	var buf bytes.Buffer
	n, err := encryptStream(&buf, bytes.NewReader(plain), key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(len(plain)) {
		t.Fatalf("plaintext size: got %d, want %d", n, len(plain))
	}
	if buf.Len() != jsLegacyCipherLen {
		t.Fatalf("ciphertext size: got %d, want %d", buf.Len(), jsLegacyCipherLen)
	}
	if got := e2eCipherLen(int64(len(plain)), e2eVersionLegacy); got != jsLegacyCipherLen {
		t.Fatalf("e2eCipherLen(v1): got %d, want %d", got, jsLegacyCipherLen)
	}
	sum := sha256.Sum256(buf.Bytes())
	if got := hex.EncodeToString(sum[:]); got != jsLegacyCipherSHA256 {
		t.Fatalf("ciphertext differs from browser output:\n got %s\nwant %s", got, jsLegacyCipherSHA256)
	}
	if got := readAll(t, buf.Bytes(), key, nil, int64(len(plain))); !bytes.Equal(got, plain) {
		t.Fatal("decrypted browser-format ciphertext does not match the plaintext")
	}
}

// TestE2EV2CiphertextMatchesBrowser pins the version 2 container: same key,
// same plaintext, manifest bound in as AAD.
func TestE2EV2CiphertextMatchesBrowser(t *testing.T) {
	key := mustHex(t, jsURLKeyHex)
	plain := vectorPlaintext()
	manifest := []byte(jsManifestJSON)

	var buf bytes.Buffer
	if _, err := encryptStream(&buf, bytes.NewReader(plain), key, manifest); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != jsV2CipherLen {
		t.Fatalf("ciphertext size: got %d, want %d", buf.Len(), jsV2CipherLen)
	}
	if got := e2eCipherLen(int64(len(plain)), e2eVersionV2); got != jsV2CipherLen {
		t.Fatalf("e2eCipherLen(v2): got %d, want %d", got, jsV2CipherLen)
	}
	sum := sha256.Sum256(buf.Bytes())
	if got := hex.EncodeToString(sum[:]); got != jsV2CipherSHA25 {
		t.Fatalf("ciphertext differs from browser output:\n got %s\nwant %s", got, jsV2CipherSHA25)
	}
	if got := readAll(t, buf.Bytes(), key, manifest, int64(len(plain))); !bytes.Equal(got, plain) {
		t.Fatal("decrypted browser-format ciphertext does not match the plaintext")
	}

	// The same bytes under version 1 rules must NOT verify: that is the AAD
	// doing its job, and it is what makes a v1/v2 mix-up fail loudly instead of
	// producing plausible garbage.
	if _, err := tryReadAll(buf.Bytes(), key, nil, int64(len(plain))); err == nil {
		t.Error("version 2 ciphertext verified without its manifest as AAD")
	}
}

// TestE2EManifestBindsMetadata is the reason version 2 exists: every field of
// the manifest is authenticated, so changing any of them makes the file refuse
// to decrypt rather than silently arriving under a different description.
func TestE2EManifestBindsMetadata(t *testing.T) {
	key := mustHex(t, jsURLKeyHex)
	plain := vectorPlaintext()
	manifest := []byte(jsManifestJSON)

	var buf bytes.Buffer
	if _, err := encryptStream(&buf, bytes.NewReader(plain), key, manifest); err != nil {
		t.Fatal(err)
	}
	cipher := buf.Bytes()

	var m fileManifest
	if err := json.Unmarshal(manifest, &m); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name  string
		mutot func(*fileManifest)
	}{
		{"renamed", func(x *fileManifest) { x.Name = "invoice.bin" }},
		{"retyped", func(x *fileManifest) { x.Type = "text/html" }},
		{"resized", func(x *fileManifest) { x.Size = 1 }},
		{"moved to another batch", func(x *fileManifest) { x.Batch = "00000000-0000-0000-0000-000000000000" }},
		{"different file id", func(x *fileManifest) { x.ID = "BBECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tampered := m
			tc.mutot(&tampered)
			raw, err := json.Marshal(tampered)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tryReadAll(cipher, key, raw, int64(len(plain))); err == nil {
				t.Errorf("a %s manifest still decrypted the file", tc.name)
			}
		})
	}
}

// TestE2ETruncationIsDetected covers the two failures the version 1 container
// could not see: whole trailing chunks removed, and the blob replaced with
// nothing at all.
func TestE2ETruncationIsDetected(t *testing.T) {
	key := mustHex(t, jsURLKeyHex)
	plain := vectorPlaintext()
	manifest := []byte(jsManifestJSON)

	var buf bytes.Buffer
	if _, err := encryptStream(&buf, bytes.NewReader(plain), key, manifest); err != nil {
		t.Fatal(err)
	}
	cipher := buf.Bytes()

	var m fileManifest
	if err := json.Unmarshal(manifest, &m); err != nil {
		t.Fatal(err)
	}
	if m.Chunks < 2 {
		t.Fatal("the fixture needs more than one chunk to test truncation")
	}

	// Dropping the last whole chunk leaves every remaining tag valid; only the
	// authenticated chunk count catches it. Under version 1 rules the same
	// bytes are an entirely well-formed, shorter file.
	short := cipher[:len(cipher)-chunkCipherLen]
	if _, err := tryReadAll(short, key, manifest, m.Size); err == nil {
		t.Error("a truncated file decrypted without complaint")
	}

	// And an empty body is not a valid empty file: version 2 declares one
	// chunk even for zero bytes.
	if e2eCipherLen(0, e2eVersionV2) != gcmOverhead {
		t.Errorf("an empty version 2 file must still be %d bytes, got %d",
			gcmOverhead, e2eCipherLen(0, e2eVersionV2))
	}
	if e2eCipherLen(0, e2eVersionLegacy) != 0 {
		t.Error("version 1 geometry changed; legacy shares would stop opening")
	}
}

// TestE2EEmptyFileAuthenticatesItsManifest pins the empty-file vector against
// the browser: one chunk, no plaintext, a tag over the manifest.
func TestE2EEmptyFileAuthenticatesItsManifest(t *testing.T) {
	key := mustHex(t, jsURLKeyHex)
	manifest := []byte(jsEmptyManifestJSON)

	var buf bytes.Buffer
	if _, err := encryptStream(&buf, bytes.NewReader(nil), key, manifest); err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(buf.Bytes()); got != jsEmptyCipherHex {
		t.Fatalf("empty-file ciphertext differs from browser output:\n got %s\nwant %s",
			got, jsEmptyCipherHex)
	}
	if _, err := tryReadAll(buf.Bytes(), key, manifest, 0); err != nil {
		t.Fatalf("empty file did not verify: %v", err)
	}
	// The point of the chunk: with no bytes at all there is nothing to verify.
	if _, err := tryReadAll(nil, key, manifest, 0); err == nil {
		t.Error("an absent ciphertext passed as a valid empty file")
	}
}

// TestParseManifestRejectsInconsistentUploads covers the server-side check.
// The server cannot verify a manifest cryptographically, but it can refuse one
// that contradicts the upload it arrived with.
func TestParseManifestRejectsInconsistentUploads(t *testing.T) {
	const batch = "11111111-2222-3333-4444-555555555555"
	good := []byte(jsManifestJSON)

	if _, err := parseManifest(good, jsPlainLen, batch); err != nil {
		t.Fatalf("the browser's own manifest was rejected: %v", err)
	}

	for _, tc := range []struct {
		name  string
		raw   string
		size  int64
		batch string
	}{
		{"empty", "", jsPlainLen, batch},
		{"not JSON", "nonsense", jsPlainLen, batch},
		{"wrong version", `{"v":1,"id":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","batch":"","size":0,"chunks":1,"chunk":65536,"name":"a","type":"t"}`, 0, ""},
		{"size disagrees with plain_size", jsManifestJSON, 12, batch},
		{"batch disagrees", jsManifestJSON, jsPlainLen, "99999999-2222-3333-4444-555555555555"},
		{"claims a batch when there is none", jsManifestJSON, jsPlainLen, ""},
		{"short id", `{"v":2,"id":"abc","batch":"","size":0,"chunks":1,"chunk":65536,"name":"a","type":"t"}`, 0, ""},
		{"no name", `{"v":2,"id":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","batch":"","size":0,"chunks":1,"chunk":65536,"name":"","type":"t"}`, 0, ""},
		{"wrong chunk count", `{"v":2,"id":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","batch":"","size":0,"chunks":9,"chunk":65536,"name":"a","type":"t"}`, 0, ""},
		{"wrong chunk size", `{"v":2,"id":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","batch":"","size":0,"chunks":1,"chunk":1024,"name":"a","type":"t"}`, 0, ""},
		{"oversized", `{"v":2,"id":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","batch":"","size":0,"chunks":1,"chunk":65536,"name":"` +
			string(bytes.Repeat([]byte("a"), maxManifestLen)) + `","type":"t"}`, 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseManifest([]byte(tc.raw), tc.size, tc.batch); err == nil {
				t.Error("accepted an inconsistent manifest")
			}
		})
	}
}

// readAll decrypts through the seekable reader the container format was
// designed around, failing the test on error.
func readAll(t *testing.T, cipher, key, aad []byte, plainSize int64) []byte {
	t.Helper()
	got, err := tryReadAll(cipher, key, aad, plainSize)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func tryReadAll(cipher, key, aad []byte, plainSize int64) ([]byte, error) {
	dir, err := os.MkdirTemp("", "pyxis-ct")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "ct")
	if err := os.WriteFile(path, cipher, 0o600); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r, err := newEncReader(f, key, aad, plainSize)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}
