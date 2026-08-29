package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// Files are encrypted at rest with AES-256-GCM in fixed-size chunks so that
// range requests (http.ServeContent) still work: each chunk is independently
// sealed and addressable. A random per-file DEK encrypts the content; the DEK
// itself is wrapped with the application KEK and stored in the files table.
//
// On-disk chunk layout: chunk i occupies i*(chunkPlainSize+gcmOverhead) and
// holds seal(nonce(i), plaintext[i*chunkPlainSize : ...]). The GCM nonce is
// the 12-byte big-endian chunk index — unique per DEK because every file has
// its own random DEK.

const (
	chunkPlainSize = 64 * 1024
	gcmOverhead    = 16
	chunkCipherLen = chunkPlainSize + gcmOverhead

	encVersionPlain = 0
	encVersionGCM   = 1

	secretPrefix = "enc:v1:"
)

// loadFileKEK reads the 32-byte key-encryption key from FILE_ENCRYPTION_KEY
// (hex or base64) or FILE_ENCRYPTION_KEY_FILE. Returns nil when unset.
func loadFileKEK() ([]byte, error) {
	raw := strings.TrimSpace(os.Getenv("FILE_ENCRYPTION_KEY"))
	if path := strings.TrimSpace(os.Getenv("FILE_ENCRYPTION_KEY_FILE")); raw == "" && path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read FILE_ENCRYPTION_KEY_FILE: %w", err)
		}
		raw = strings.TrimSpace(string(b))
	}
	if raw == "" {
		return nil, nil
	}
	if b, err := hex.DecodeString(raw); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(raw); err == nil && len(b) == 32 {
		return b, nil
	}
	return nil, errors.New("FILE_ENCRYPTION_KEY must be 32 bytes, hex- or base64-encoded")
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func chunkNonce(idx int64) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[4:], uint64(idx))
	return n
}

// wrapDEK seals a fresh random DEK with the KEK; blob = nonce || ciphertext.
func (a *App) wrapDEK(dek []byte) ([]byte, error) {
	aead, err := newAEAD(a.fileKEK)
	if err != nil {
		return nil, err
	}
	nonce := randomBytes(aead.NonceSize())
	return append(nonce, aead.Seal(nil, nonce, dek, nil)...), nil
}

func (a *App) unwrapDEK(blob []byte) ([]byte, error) {
	aead, err := newAEAD(a.fileKEK)
	if err != nil {
		return nil, err
	}
	if len(blob) < aead.NonceSize() {
		return nil, errors.New("wrapped DEK too short")
	}
	return aead.Open(nil, blob[:aead.NonceSize()], blob[aead.NonceSize():], nil)
}

// encryptStream encrypts src to dst in chunks and returns the plaintext size.
func encryptStream(dst io.Writer, src io.Reader, dek []byte) (int64, error) {
	aead, err := newAEAD(dek)
	if err != nil {
		return 0, err
	}
	var (
		total int64
		idx   int64
		buf   = make([]byte, chunkPlainSize)
	)
	for {
		n, rerr := io.ReadFull(src, buf)
		if n > 0 {
			sealed := aead.Seal(nil, chunkNonce(idx), buf[:n], nil)
			if _, werr := dst.Write(sealed); werr != nil {
				return total, werr
			}
			total += int64(n)
			idx++
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			return total, nil
		}
		if rerr != nil {
			return total, rerr
		}
	}
}

// encReader decrypts a chunked file and supports Seek for range requests.
type encReader struct {
	f         *os.File
	aead      cipher.AEAD
	plainSize int64
	off       int64
	chunkIdx  int64 // index of the chunk in buf, -1 if none
	buf       []byte
}

func newEncReader(f *os.File, dek []byte, plainSize int64) (*encReader, error) {
	aead, err := newAEAD(dek)
	if err != nil {
		return nil, err
	}
	return &encReader{f: f, aead: aead, plainSize: plainSize, chunkIdx: -1}, nil
}

func (r *encReader) Read(p []byte) (int, error) {
	if r.off >= r.plainSize {
		return 0, io.EOF
	}
	idx := r.off / chunkPlainSize
	if idx != r.chunkIdx {
		if err := r.loadChunk(idx); err != nil {
			return 0, err
		}
	}
	inChunk := int(r.off - idx*chunkPlainSize)
	n := copy(p, r.buf[inChunk:])
	r.off += int64(n)
	return n, nil
}

func (r *encReader) loadChunk(idx int64) error {
	raw := make([]byte, chunkCipherLen)
	n, err := r.f.ReadAt(raw, idx*chunkCipherLen)
	if err != nil && err != io.EOF {
		return err
	}
	if n <= gcmOverhead {
		return io.ErrUnexpectedEOF
	}
	plain, err := r.aead.Open(raw[:0], chunkNonce(idx), raw[:n], nil)
	if err != nil {
		return fmt.Errorf("decrypt chunk %d: %w", idx, err)
	}
	r.buf = plain
	r.chunkIdx = idx
	return nil
}

func (r *encReader) Seek(offset int64, whence int) (int64, error) {
	var abs int64
	switch whence {
	case io.SeekStart:
		abs = offset
	case io.SeekCurrent:
		abs = r.off + offset
	case io.SeekEnd:
		abs = r.plainSize + offset
	default:
		return 0, errors.New("invalid whence")
	}
	if abs < 0 {
		return 0, errors.New("negative position")
	}
	r.off = abs
	return abs, nil
}

// --- small-secret encryption (settings values) ------------------------------

// encryptSecret protects a short string with the KEK. It returns the input
// unchanged only when at-rest encryption is disabled entirely (no KEK, which
// requires the explicit ALLOW_UNENCRYPTED_STORAGE opt-out at startup); any
// cryptographic failure is an error, never a silent plaintext fallback.
func (a *App) encryptSecret(s string) (string, error) {
	if len(a.fileKEK) == 0 || s == "" {
		return s, nil
	}
	aead, err := newAEAD(a.fileKEK)
	if err != nil {
		return "", fmt.Errorf("encrypt secret: %w", err)
	}
	nonce := randomBytes(aead.NonceSize())
	blob := append(nonce, aead.Seal(nil, nonce, []byte(s), nil)...)
	return secretPrefix + base64.StdEncoding.EncodeToString(blob), nil
}

// decryptSecret reverses encryptSecret; plaintext legacy values pass through.
func (a *App) decryptSecret(s string) (string, error) {
	if !strings.HasPrefix(s, secretPrefix) {
		return s, nil
	}
	if len(a.fileKEK) == 0 {
		return "", errors.New("encrypted setting present but no FILE_ENCRYPTION_KEY configured")
	}
	blob, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, secretPrefix))
	if err != nil {
		return "", err
	}
	aead, err := newAEAD(a.fileKEK)
	if err != nil {
		return "", err
	}
	if len(blob) < aead.NonceSize() {
		return "", errors.New("encrypted setting too short")
	}
	plain, err := aead.Open(nil, blob[:aead.NonceSize()], blob[aead.NonceSize():], nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
