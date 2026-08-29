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
// seal(nonce(i), plaintext[i*chunkPlainSize : ...]), with the nonce being
// 4 zero bytes followed by the big-endian uint64 chunk index.

const chunkCipherLen = chunkPlainSize + gcmOverhead

func chunkNonce(idx int64) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[4:], uint64(idx))
	return n
}

// encryptStream encrypts src to dst in chunks and returns the plaintext size.
func encryptStream(dst io.Writer, src io.Reader, key []byte) (int64, error) {
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

// encReader decrypts a chunked file and supports Seek, which is how the format
// was designed to keep range requests possible.
type encReader struct {
	f         *os.File
	aead      cipher.AEAD
	plainSize int64
	off       int64
	chunkIdx  int64 // index of the chunk in buf, -1 if none
	buf       []byte
}

func newEncReader(f *os.File, key []byte, plainSize int64) (*encReader, error) {
	aead, err := newAEAD(key)
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
