package main

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

// A Go reference implementation of the end-to-end container format.
//
// The server never encrypts or decrypts a file — browsers do, in
// web/static/e2e.js. This exists only so the tests can state the format
// independently and check it against byte-exact vectors produced by a real
// WebCrypto implementation (see e2e_interop_test.go). If these and the
// browser ever disagree, every file uploaded since the divergence is
// undecryptable, so the check is worth keeping even though nothing in the
// shipped binary uses this code.
//
// Layout: chunk i occupies i*chunkCipherLen and holds
// seal(nonce(i), plaintext[i*chunkPlainSize : ...], aad), with the nonce being
// 4 zero bytes followed by the big-endian uint64 chunk index. In version 1 the
// aad is empty; in version 2 it is the file's manifest bytes, which is what
// binds the chunks to the file's length, count, name, type and batch.

const chunkCipherLen = chunkPlainSize + gcmOverhead

func chunkNonce(idx int64) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[4:], uint64(idx))
	return n
}

// encryptStream encrypts src to dst in chunks and returns the plaintext size.
// A nil aad reproduces the version 1 container; passing the manifest bytes
// reproduces version 2.
func encryptStream(dst io.Writer, src io.Reader, key, aad []byte) (int64, error) {
	aead, err := newAEAD(key)
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
			sealed := aead.Seal(nil, chunkNonce(idx), buf[:n], aad)
			if _, werr := dst.Write(sealed); werr != nil {
				return total, werr
			}
			total += int64(n)
			idx++
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			// Version 2 emits a chunk even for an empty input: its tag is the
			// only thing authenticating the manifest of a zero-byte file.
			if idx == 0 && len(aad) > 0 {
				if _, werr := dst.Write(aead.Seal(nil, chunkNonce(0), nil, aad)); werr != nil {
					return total, werr
				}
			}
			return total, nil
		}
		if rerr != nil {
			return total, rerr
		}
	}
}

// encReader decrypts a chunked file and supports Seek, which is how the format
// was designed to keep range requests possible.
type encReader struct {
	f         *os.File
	aead      cipher.AEAD
	aad       []byte
	plainSize int64
	off       int64
	chunkIdx  int64 // index of the chunk in buf, -1 if none
	buf       []byte
}

func newEncReader(f *os.File, key, aad []byte, plainSize int64) (*encReader, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	// Version 2 fixes the ciphertext length: the manifest declares the chunk
	// count, so a body that is not exactly that long is rejected before a
	// single tag is checked. This mirrors decryptFile in e2e.js, and it is what
	// catches the two cases per-chunk tags never could — a file truncated at a
	// chunk boundary, and a blob replaced with nothing at all, which otherwise
	// reads as a perfectly valid empty file.
	if len(aad) > 0 {
		st, err := f.Stat()
		if err != nil {
			return nil, err
		}
		if want := e2eCipherLen(plainSize, e2eVersionV2); st.Size() != want {
			return nil, fmt.Errorf("ciphertext is %d bytes, the manifest requires %d",
				st.Size(), want)
		}
	}
	r := &encReader{f: f, aead: aead, aad: aad, plainSize: plainSize, chunkIdx: -1}
	// An empty version 2 file has a chunk but no bytes to read, so Read would
	// return EOF without ever checking a tag. Verify it here, otherwise the one
	// case the empty chunk exists for would go unverified.
	if plainSize == 0 && len(aad) > 0 {
		if err := r.loadChunk(0); err != nil {
			return nil, err
		}
	}
	return r, nil
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
	// A tag with no plaintext is legitimate in version 2 (the empty file), and
	// impossible in version 1, where a chunk always carries bytes.
	if n < gcmOverhead || (n == gcmOverhead && len(r.aad) == 0) {
		return io.ErrUnexpectedEOF
	}
	plain, err := r.aead.Open(raw[:0], chunkNonce(idx), raw[:n], r.aad)
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
