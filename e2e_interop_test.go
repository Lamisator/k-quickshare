package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

	// Version 4's name branch, off the same secret and the same password. It is
	// what seals a file name apart from the file, and it must be independent of
	// every other branch — the auth branch above is handed to the server.
	jsNameKeyHex   = "095e8feb2e25f0ee2555ed781a6c3fa864102e4cb3ecf10fcc6dfa450e86be14"
	jsNamePwKeyHex = "e2da56191687930473318731e333da92eccff015d250a645f51e529f93777a67"

	// A name sealed by the browser under jsNameKeyHex for the manifest id below.
	// The nonce is random, so this is one captured blob rather than a value Go
	// can recompute — which is the point: the server stores it and can say
	// nothing about what is inside. It is padded, so its length says nothing
	// about the name's length either: 12-byte nonce + 512-byte padded body +
	// 16-byte tag, for every ordinary name there is.
	jsSealedNamePlain = "a.txt"
	jsSealedName      = "FPCCFybCBlG0gANQkqSAdFnsB5jHSE-G4NdbIHnGF_ytPW8sZ2IrqDgr2YUpESPpizeUXzB4lrEc2zzHHx6z9hGmqfV9LrUoVl9Yw4wGE5y0kX2eTrGVgEpulbJUqTNzRSPHYaTOaYNI10QiMQ-21DdXSqEGgUimq03V4B1O2BKxRjIMttqYfgRZjgPrK4SKSgsfWwgXmqlVzL6ubDfC7o4zXtPd-5901AYOdcRXdrmeIjCQZaSUZ6DsPFXcY9oyc3SKhscKwmO8JK77icpuTjNuCAMh7bY_54k7XUjaih_80fwrKHP_B9lg1O4sC20nbeeRsouxbUXfF5yVPVY6uE-ZzXSj6o54RdBqm1k3nb1WIkU6pizdO3u8Q89x48qTCFf4kMEqurZ1EQZ6ofpFYYmoTqricweiHurEpS-OOqd88TqYTJUFK4yJgWE1CrKPS7oEfqcKy4IEWQ271NMq999SQA7HEX6SCuVqNiJFimZP5re5kKPzt3dFEtj7rcW8VxmVJlF8CH9X6X-Qwygj6pyA3hr4egFedbu_vq6faI1977YcrA3ijX3HVXCyP3ZWBCwVsnB6LLXX4vcx2__333gzTamTqLftOfjxU2Yzl1wxkvKD__M6byX1ULwQAdiQUZMvPHO_xAZItXOqYngxmw7vfi-hC5IOJOOgcUsoHmJuJrj8d2oKp1OvA3CxGgWtFHgtfTBx9tSpKftp"

	// The version 4 manifest for that file: no name, but still a type.
	jsV4ManifestJSON = `{"v":4,"id":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","batch":"","size":0,"chunks":1,"chunk":65536,"type":"application/pdf"}`

	// The version 5 manifest, as e2e.js writes it: nothing about the content at
	// all, only what the ciphertext's own length already gives away.
	jsV5ManifestJSON = `{"v":5,"id":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","batch":"","size":0,"chunks":1,"chunk":65536}`

	jsPlainLen = 197842

	// Version 1: bare chunks, no AAD.
	jsLegacyCipherLen    = 197906
	jsLegacyCipherSHA256 = "1515d2b8e2d8ed0c3e0aedcbc9ac3c23aeeeae5b07a6ebfe04ea96285dc10fe6"

	// Version 3: the same plaintext under the same key, with the manifest bound
	// into every chunk AND embedded in front of them, so the stored object says
	// what it is without any database beside it.
	jsManifestJSON  = `{"v":3,"id":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","batch":"11111111-2222-3333-4444-555555555555","size":197842,"chunks":4,"chunk":65536,"name":"report.bin","type":"application/octet-stream"}`
	jsV3HeaderLen   = 204 // 4-byte magic + uint16 length + 198-byte manifest
	jsV3CipherLen   = 198110
	jsV3CipherSHA25 = "d46c14e5701151f91f5c7750964e6dd4cb7fbab47d01e5e27a8894db574545f7"

	// An empty file is a header plus one chunk with no plaintext: 16 bytes of
	// tag over the manifest and nothing else. Without that chunk, "the blob is
	// gone" would decrypt to a valid empty file.
	jsEmptyManifestJSON = `{"v":3,"id":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","batch":"","size":0,"chunks":1,"chunk":65536,"name":"empty.txt","type":"text/plain"}`
	jsEmptyCipherHex    = "50595833008e7b2276223a332c226964223a2241414543417751464267634943516f4c4441304f4478415245684d554652595847426b6147787764486838222c226261746368223a22222c2273697a65223a302c226368756e6b73223a312c226368756e6b223a36353533362c226e616d65223a22656d7074792e747874222c2274797065223a22746578742f706c61696e227d5df0ca218c7443e0e3266bef5a81d2ac"

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
		{"name(url)", hkdf32Go(t, vectorSecret(), empty, "pyxis-e2e-name-v1"), jsNameKeyHex},
	} {
		if got := hex.EncodeToString(tc.got); got != tc.want {
			t.Errorf("%s key: got %s, want %s", tc.name, got, tc.want)
		}
	}

	master := pbkdf2.Key([]byte(jsPassword), vectorSalt(), 600000, 32, sha256.New)
	encKey := hkdf32Go(t, master, vectorSalt(), "pyxis-e2e-enc-v1")
	auth := hkdf32Go(t, master, vectorSalt(), "pyxis-e2e-auth-v1")
	rosterKey := hkdf32Go(t, master, vectorSalt(), "pyxis-e2e-roster-v1")
	nameKey := hkdf32Go(t, master, vectorSalt(), "pyxis-e2e-name-v1")
	for _, tc := range []struct {
		name string
		got  []byte
		want string
	}{
		{"password enc", encKey, jsEncKeyHex},
		{"password auth", auth, jsAuthHex},
		{"password roster", rosterKey, jsRosterPwKeyHex},
		{"password name", nameKey, jsNamePwKeyHex},
	} {
		if got := hex.EncodeToString(tc.got); got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}

	// The branches must be independent: the server holds the auth branch, so
	// any relationship between it and the others would leak the file key.
	for _, pair := range [][2][]byte{
		{encKey, auth}, {encKey, rosterKey}, {auth, rosterKey},
		{encKey, nameKey}, {auth, nameKey}, {rosterKey, nameKey},
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
	if got := e2eCipherLen(int64(len(plain)), 0, e2eVersionLegacy); got != jsLegacyCipherLen {
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

// TestE2EV3CiphertextMatchesBrowser pins the version 3 container: same key,
// same plaintext, manifest embedded in the object and bound in as AAD.
func TestE2EV3CiphertextMatchesBrowser(t *testing.T) {
	key := mustHex(t, jsURLKeyHex)
	plain := vectorPlaintext()
	manifest := []byte(jsManifestJSON)

	var buf bytes.Buffer
	if _, err := encryptStream(&buf, bytes.NewReader(plain), key, manifest); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != jsV3CipherLen {
		t.Fatalf("ciphertext size: got %d, want %d", buf.Len(), jsV3CipherLen)
	}
	if got := e2eCipherLen(int64(len(plain)), len(manifest), e2eVersionV3); got != jsV3CipherLen {
		t.Fatalf("e2eCipherLen(v3): got %d, want %d", got, jsV3CipherLen)
	}
	sum := sha256.Sum256(buf.Bytes())
	if got := hex.EncodeToString(sum[:]); got != jsV3CipherSHA25 {
		t.Fatalf("ciphertext differs from browser output:\n got %s\nwant %s", got, jsV3CipherSHA25)
	}
	if got := readAll(t, buf.Bytes(), key, manifest, int64(len(plain))); !bytes.Equal(got, plain) {
		t.Fatal("decrypted browser-format ciphertext does not match the plaintext")
	}

	// The header must be exactly where the format says it is, and must describe
	// this file — that is what makes the stored object self-explanatory.
	if got := int64(jsV3HeaderLen); e2eHeaderLen(len(manifest), e2eVersionV3) != got {
		t.Errorf("e2eHeaderLen: got %d, want %d", e2eHeaderLen(len(manifest), e2eVersionV3), got)
	}
	if !bytes.Equal(buf.Bytes()[:jsV3HeaderLen], buildContainerHeader(manifest, e2eVersionV3)) {
		t.Error("the object does not begin with its own manifest")
	}
	if !bytes.HasPrefix(buf.Bytes(), []byte("PYX3")) {
		t.Error("the object carries no version magic")
	}

	// The same bytes under version 1 rules must NOT verify: that is the AAD
	// doing its job, and it is what makes a version mix-up fail loudly instead
	// of producing plausible garbage.
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
	if e2eCipherLen(0, 0, e2eVersionV2) != gcmOverhead {
		t.Errorf("an empty version 2 file must still be %d bytes, got %d",
			gcmOverhead, e2eCipherLen(0, 0, e2eVersionV2))
	}
	if e2eCipherLen(0, 0, e2eVersionLegacy) != 0 {
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

	if _, err := parseManifest(good, jsPlainLen, batch, e2eVersionV3); err != nil {
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
		{"wrong version", `{"v":2,"id":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","batch":"","size":0,"chunks":1,"chunk":65536,"name":"a","type":"t"}`, 0, ""},
		{"size disagrees with plain_size", jsManifestJSON, 12, batch},
		{"batch disagrees", jsManifestJSON, jsPlainLen, "99999999-2222-3333-4444-555555555555"},
		{"claims a batch when there is none", jsManifestJSON, jsPlainLen, ""},
		{"short id", `{"v":3,"id":"abc","batch":"","size":0,"chunks":1,"chunk":65536,"name":"a","type":"t"}`, 0, ""},
		{"no name", `{"v":3,"id":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","batch":"","size":0,"chunks":1,"chunk":65536,"name":"","type":"t"}`, 0, ""},
		{"wrong chunk count", `{"v":3,"id":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","batch":"","size":0,"chunks":9,"chunk":65536,"name":"a","type":"t"}`, 0, ""},
		{"wrong chunk size", `{"v":3,"id":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","batch":"","size":0,"chunks":1,"chunk":1024,"name":"a","type":"t"}`, 0, ""},
		{"oversized", `{"v":3,"id":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","batch":"","size":0,"chunks":1,"chunk":65536,"name":"` +
			string(bytes.Repeat([]byte("a"), maxManifestLen)) + `","type":"t"}`, 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseManifest([]byte(tc.raw), tc.size, tc.batch, e2eVersionV3); err == nil {
				t.Error("accepted an inconsistent manifest")
			}
		})
	}
}

// TestManifestKeepsNothingAboutTheContent pins the rule these versions exist
// for. A manifest is stored and served in the clear — it is the AAD, so it
// cannot be encrypted — which means anything in it is something the server
// knows and can hand to anyone who asks. Version 4 took out the name, version 5
// the type; a client that puts either back is refused rather than stored.
func TestManifestKeepsNothingAboutTheContent(t *testing.T) {
	const id = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	head := `{"v":%d,"id":"` + id + `","batch":"","size":0,"chunks":1,"chunk":65536`

	for _, tc := range []struct {
		name    string
		raw     string
		version int
	}{
		{"version 4 carrying a name", fmt.Sprintf(head, 4) + `,"name":"secret-plans.pdf","type":"t"}`, e2eVersionV4},
		{"version 5 carrying a name", fmt.Sprintf(head, 5) + `,"name":"secret-plans.pdf"}`, e2eVersionV5},
		{"version 5 carrying a type", fmt.Sprintf(head, 5) + `,"type":"image/jpeg"}`, e2eVersionV5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseManifest([]byte(tc.raw), 0, "", tc.version); err == nil {
				t.Error("accepted a manifest that hands the server what the version exists to hide")
			}
		})
	}

	m, err := parseManifest([]byte(jsV5ManifestJSON), 0, "", e2eVersionV5)
	if err != nil {
		t.Fatalf("the browser's own version 5 manifest was rejected: %v", err)
	}
	if m.Name != "" || m.Type != "" {
		t.Errorf("parsed name = %q, type = %q, want both empty", m.Name, m.Type)
	}

	// The rules apply from their own version onwards, and not before: those
	// shares have no other copy of what their manifests carry.
	if _, err := parseManifest([]byte(jsV4ManifestJSON), 0, "", e2eVersionV4); err != nil {
		t.Errorf("a version 4 manifest with a type was rejected: %v", err)
	}
	if _, err := parseManifest([]byte(fmt.Sprintf(head, 3)+`,"type":"t"}`), 0, "", e2eVersionV3); err == nil {
		t.Error("a version 3 manifest with no name was accepted")
	}
	if _, err := parseManifest([]byte(fmt.Sprintf(head, 4)+`}`), 0, "", e2eVersionV4); err == nil {
		t.Error("a version 4 manifest with no type was accepted")
	}
}

// TestSealedNameLengthSaysNothing pins the padding. Without it the sealed blob
// is exactly as long as the name inside it, so the column would still be
// telling anyone holding the database how long each file's name is.
func TestSealedNameLengthSaysNothing(t *testing.T) {
	sealed, err := base64.RawURLEncoding.DecodeString(jsSealedName)
	if err != nil {
		t.Fatalf("vector is not base64url: %v", err)
	}
	// The browser sealed a five-character name into this. Anything shorter than
	// a full pad block would mean the padding had stopped happening.
	if len(sealed) != encNameExact {
		t.Errorf("sealed %q is %d bytes, want the padded %d", jsSealedNamePlain, len(sealed), encNameExact)
	}
	if !validEncNameLen(len(sealed)) {
		t.Error("the browser's own sealed name is rejected by the server's length rule")
	}
	for _, n := range []int{0, 28, 27 + encNamePad, 29 + encNamePad, encNameExact + 1, maxEncNameLen + encNamePad} {
		if validEncNameLen(n) {
			t.Errorf("accepted %d bytes, which no padded sealed name can be", n)
		}
	}
	// Two pad blocks is a long name, and still a length the server accepts —
	// the point is that it is a bucket, not a measurement.
	if !validEncNameLen(encNameNonce + 2*encNamePad + gcmOverhead) {
		t.Error("a two-block sealed name was rejected")
	}
}

// TestSealedNameMatchesBrowser pins the sealed-name blob against bytes produced
// by the browser's own e2e.js under Node's WebCrypto. The server never opens one
// — it holds the ciphertext and no key — so what it must never do is corrupt or
// truncate it. These vectors are what a downloader has to be handed back.
func TestSealedNameMatchesBrowser(t *testing.T) {
	sealed, err := base64.RawURLEncoding.DecodeString(jsSealedName)
	if err != nil {
		t.Fatalf("vector is not base64url: %v", err)
	}
	// 12-byte nonce, then AES-GCM over the padded body, then a 16-byte tag.
	if len(sealed) <= encNameNonce+gcmOverhead {
		t.Fatalf("sealed name is %d bytes, too short to be nonce+ciphertext+tag", len(sealed))
	}
	if len(sealed) > maxEncNameLen {
		t.Errorf("sealed name is %d bytes, over the %d the server accepts", len(sealed), maxEncNameLen)
	}
	// The name must not be recoverable from the blob by anyone holding it
	// alone — that is the whole claim being made about the column.
	if bytes.Contains(sealed, []byte(jsSealedNamePlain)) {
		t.Error("the plaintext name appears inside the sealed blob")
	}
}

// TestVerifyContainerHeader covers the one structural claim the server can make
// about an object it cannot read: that the manifest inside it is the manifest
// sent with it. Without this the database row and the file could describe
// different things, and only the downloader would ever find out.
func TestVerifyContainerHeader(t *testing.T) {
	manifest := []byte(jsManifestJSON)
	good := buildContainerHeader(manifest, e2eVersionV3)

	if got, err := verifyContainerHeader(bytes.NewReader(append(good, 'x')), manifest, e2eVersionV3); err != nil {
		t.Fatalf("a well-formed header was rejected: %v", err)
	} else if !bytes.Equal(got, good) {
		t.Error("the header returned for storage is not the one that was read")
	}

	other := []byte(jsEmptyManifestJSON)
	for _, tc := range []struct {
		name string
		body []byte
		want []byte
	}{
		{"empty object", nil, manifest},
		{"truncated header", good[:4], manifest},
		{"bad magic", append([]byte("XXXX"), good[4:]...), manifest},
		{"length disagrees with the manifest", buildContainerHeader(manifest[:len(manifest)-1], e2eVersionV3), manifest},
		{"embedded manifest is a different file", buildContainerHeader(other, e2eVersionV3), manifest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := verifyContainerHeader(bytes.NewReader(tc.body), tc.want, e2eVersionV3); err == nil {
				t.Error("accepted a header that does not match the declared manifest")
			}
		})
	}
}

// TestContainerGeometryPerVersion pins the stored size of each version, which
// is what the upload handler measures a body against.
func TestContainerGeometryPerVersion(t *testing.T) {
	const manifestLen = 198
	cases := []struct {
		version int
		plain   int64
		want    int64
	}{
		// Version 1 has no header and no chunk for an empty file.
		{e2eVersionLegacy, 0, 0},
		{e2eVersionLegacy, 1, 1 + gcmOverhead},
		// Version 2 gained the empty-file chunk, still no header.
		{e2eVersionV2, 0, gcmOverhead},
		{e2eVersionV2, chunkPlainSize, chunkPlainSize + gcmOverhead},
		// Version 3 adds the header on top of exactly that.
		{e2eVersionV3, 0, containerHeaderFixed + manifestLen + gcmOverhead},
		{e2eVersionV3, chunkPlainSize + 1,
			containerHeaderFixed + manifestLen + chunkPlainSize + 1 + 2*gcmOverhead},
		// Versions 4 and 5 changed what the manifest says, not the geometry.
		{e2eVersionV4, 0, containerHeaderFixed + manifestLen + gcmOverhead},
		{e2eVersionV5, 0, containerHeaderFixed + manifestLen + gcmOverhead},
	}
	for _, c := range cases {
		if got := e2eCipherLen(c.plain, manifestLen, c.version); got != c.want {
			t.Errorf("e2eCipherLen(%d, v%d) = %d, want %d", c.plain, c.version, got, c.want)
		}
	}
	// Only version 3 has a header, and its size follows the manifest.
	if e2eHeaderLen(manifestLen, e2eVersionV2) != 0 {
		t.Error("version 2 must have no header")
	}
	if e2eHeaderLen(manifestLen, e2eVersionV3) != containerHeaderFixed+manifestLen {
		t.Error("version 3 header length does not follow the manifest")
	}
	if e2eHeaderLen(manifestLen, e2eVersionV5) != containerHeaderFixed+manifestLen {
		t.Error("version 5 header length does not follow the manifest")
	}
	// Each version's magic must be its own, or a reader could be talked into
	// interpreting one format as another.
	if bytes.Equal(magicForVersion(e2eVersionV3), magicForVersion(e2eVersionV4)) ||
		bytes.Equal(magicForVersion(e2eVersionV4), magicForVersion(e2eVersionV5)) {
		t.Error("two container versions share a magic")
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
