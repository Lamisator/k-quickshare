package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// A Go implementation of the SEALING half of web/static/e2e.js: a URL-keyed
// batch share (key mode 3, container version 5), byte-compatible with what the
// browser writes, so the ordinary download page opens it without knowing who
// produced it.
//
// Two callers use it, and they sit on opposite sides of the trust boundary:
//
//   - `pyxis share` (cli.go) runs it on the sender's own machine and uploads
//     ciphertext through the API. That is end-to-end in exactly the sense a
//     browser upload is: the server never sees a key.
//   - the agent API (handlers_api.go, mcp.go) runs it INSIDE the server, on
//     plaintext a client handed over. The key is generated, used, returned in
//     the link and dropped, and the batch row records server_sealed so the
//     download page says what happened. That is not end-to-end, and nothing
//     downstream pretends it is.
//
// Every label, AAD prefix and JSON field order below is protocol. Changing one
// makes every share sealed here undecryptable in the browser; seal_test.go pins
// them against e2e.js.

const (
	sealLabelBatch  = "pyxis-e2e-batch-v1"
	sealLabelRoster = "pyxis-e2e-roster-v1"
	sealLabelName   = "pyxis-e2e-name-v1"

	sealNameAADPrefix   = "pyxis-name-v1|"
	sealRosterAADPrefix = "pyxis-roster-v2|"

	sealNonceLen  = 12
	sealSecretLen = 32
)

// shareKeys is the key schedule of one batch secret, as deriveBatchKeys in
// e2e.js produces it.
type shareKeys struct {
	secret []byte
	wrap   cipher.AEAD // seals each member's own file key
	roster cipher.AEAD // seals the member list
	name   cipher.AEAD // seals each member's name and type
}

// newShareKeys draws a fresh batch secret and derives its branches.
func newShareKeys() (*shareKeys, error) {
	return deriveShareKeys(randomBytes(sealSecretLen))
}

func deriveShareKeys(secret []byte) (*shareKeys, error) {
	if len(secret) != sealSecretLen {
		return nil, errors.New("a share secret is 32 bytes")
	}
	k := &shareKeys{secret: secret}
	for _, b := range []struct {
		label string
		dst   *cipher.AEAD
	}{
		{sealLabelBatch, &k.wrap},
		{sealLabelRoster, &k.roster},
		{sealLabelName, &k.name},
	} {
		raw := make([]byte, 32)
		if _, err := io.ReadFull(hkdf.New(sha256.New, secret, nil, []byte(b.label)), raw); err != nil {
			return nil, err
		}
		aead, err := newAEAD(raw)
		wipe(raw)
		if err != nil {
			return nil, err
		}
		*b.dst = aead
	}
	return k, nil
}

// fragment is what goes after the # in the share link: the secret, base64url.
func (k *shareKeys) fragment() string {
	return base64.RawURLEncoding.EncodeToString(k.secret)
}

// forget overwrites the secret. The derived AEADs hold expanded key schedules
// Go gives no way to clear, so this is best effort — but the one value that
// opens the share should not outlive the request that returned it.
func (k *shareKeys) forget() {
	wipe(k.secret)
	k.wrap, k.roster, k.name = nil, nil, nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// sealWithNonce is nonce || AES-GCM(plain, aad), the layout every small sealed
// blob in e2e.js uses.
func sealWithNonce(aead cipher.AEAD, plain, aad []byte) []byte {
	nonce := randomBytes(sealNonceLen)
	return aead.Seal(nonce, nonce, plain, aad)
}

// marshalCompact is JSON.stringify: no HTML escaping, no trailing newline.
// Field order comes from the struct, which is why the structs below exist.
func marshalCompact(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// sealedMember is one file ready to upload: everything storeUpload expects,
// plus what the roster needs to vouch for it.
type sealedMember struct {
	Manifest   []byte
	EncName    []byte
	WrappedKey []byte
	PlainSize  int64
	Name       string
	Type       string

	fileKey []byte
}

// v5Manifest is buildManifest in e2e.js, field for field and in its order.
type v5Manifest struct {
	V      int    `json:"v"`
	ID     string `json:"id"`
	Batch  string `json:"batch"`
	Size   int64  `json:"size"`
	Chunks int64  `json:"chunks"`
	Chunk  int64  `json:"chunk"`
}

type sealedNameBody struct {
	V    int    `json:"v"`
	Name string `json:"name"`
	Type string `json:"type"`
}

// prepareMember draws a file key, wraps it, and builds the manifest and the
// sealed name for one member of batchID. The plaintext is encrypted separately
// (encryptTo), so a caller can stream it.
func (k *shareKeys) prepareMember(batchID, name, contentType string, size int64) (*sealedMember, error) {
	if name == "" {
		return nil, errors.New("a file needs a name")
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	fileKey := randomBytes(32)
	id := base64.RawURLEncoding.EncodeToString(randomBytes(32))

	manifest, err := marshalCompact(v5Manifest{
		V: e2eVersionV5, ID: id, Batch: batchID, Size: size,
		Chunks: e2eChunkCount(size, e2eVersionV5), Chunk: chunkPlainSize,
	})
	if err != nil {
		return nil, err
	}

	nameJSON, err := marshalCompact(sealedNameBody{V: 2, Name: name, Type: contentType})
	if err != nil {
		return nil, err
	}
	if 2+len(nameJSON) > 4096 {
		return nil, errors.New("file name is too long to seal")
	}
	// padNameBody: uint16be length || json || zeros, to a multiple of 512.
	body := make([]byte, ((2+len(nameJSON)+encNamePad-1)/encNamePad)*encNamePad)
	binary.BigEndian.PutUint16(body, uint16(len(nameJSON)))
	copy(body[2:], nameJSON)
	encName := sealWithNonce(k.name, body, []byte(sealNameAADPrefix+id))
	wipe(body)

	return &sealedMember{
		Manifest:   manifest,
		EncName:    encName,
		WrappedKey: sealWithNonce(k.wrap, fileKey, nil),
		PlainSize:  size,
		Name:       name,
		Type:       contentType,
		fileKey:    fileKey,
	}, nil
}

// encryptTo writes the whole container — "PYX5" header, then the chunks — for
// exactly m.PlainSize bytes of src. It refuses a source that is shorter or
// longer than declared, because the size is already sealed into the manifest.
// The file key is wiped once the last chunk is sealed.
func (m *sealedMember) encryptTo(dst io.Writer, src io.Reader) error {
	defer wipe(m.fileKey)
	block, err := aes.NewCipher(m.fileKey)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	if _, err := dst.Write(buildContainerHeader(m.Manifest, e2eVersionV5)); err != nil {
		return err
	}
	buf := make([]byte, chunkPlainSize)
	defer wipe(buf)
	nonce := make([]byte, sealNonceLen)
	chunks := e2eChunkCount(m.PlainSize, e2eVersionV5)
	var done int64
	for i := int64(0); i < chunks; i++ {
		want := m.PlainSize - done
		if want > chunkPlainSize {
			want = chunkPlainSize
		}
		if _, err := io.ReadFull(src, buf[:want]); err != nil {
			return fmt.Errorf("source ended after %d of %d bytes", done, m.PlainSize)
		}
		binary.BigEndian.PutUint64(nonce[4:], uint64(i))
		if _, err := dst.Write(aead.Seal(nil, nonce, buf[:want], m.Manifest)); err != nil {
			return err
		}
		done += want
	}
	if n, _ := src.Read(buf[:1]); n > 0 {
		return fmt.Errorf("source is longer than the declared %d bytes", m.PlainSize)
	}
	return nil
}

// rosterEntry is what recordMember in app.js pushes for each file. `id` is the
// SERVER's row id, not the manifest id: the download page matches the listing
// it is served against these.
type rosterEntry struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Size     int64  `json:"size"`
	Type     string `json:"type"`
	Manifest string `json:"manifest"`
}

type rosterBody struct {
	V     int           `json:"v"`
	Batch string        `json:"batch"`
	Seq   int64         `json:"seq"`
	Files []rosterEntry `json:"files"`
}

// entry is this member's roster line once the server has given it a row id.
func (m *sealedMember) entry(rowID string) rosterEntry {
	sum := sha256.Sum256(m.Manifest)
	return rosterEntry{
		ID: rowID, Name: m.Name, Size: m.PlainSize, Type: m.Type,
		Manifest: base64.RawURLEncoding.EncodeToString(sum[:]),
	}
}

// sealRoster seals the member list, in the order the server will list it.
func (k *shareKeys) sealRoster(batchID string, seq int64, files []rosterEntry) ([]byte, error) {
	body, err := marshalCompact(rosterBody{V: e2eVersionV5, Batch: batchID, Seq: seq, Files: files})
	if err != nil {
		return nil, err
	}
	return sealWithNonce(k.roster, body, []byte(sealRosterAADPrefix+batchID)), nil
}
