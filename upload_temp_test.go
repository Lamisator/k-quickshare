package main

import (
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestUploadRemovesMultipartTempFiles guards a leak that leaves no trace in the
// application at all: mime/multipart spills anything past the 32 MiB memory
// budget to a temp file, and net/http's automatic cleanup reads the Request it
// built itself, which withOptionalUser has by then replaced with a shallow
// copy. The built-in cleanup therefore no-ops, and every authenticated upload
// over 32 MiB used to strand its spill file until the container restarted —
// invisible to quotas, invisible to /history, reclaimed by nothing.
//
// The request is driven through the real middleware chain on purpose. Calling
// handleUpload directly would pass even with the fix removed, because it is the
// request copying in the middleware that breaks the standard-library cleanup.
func TestUploadRemovesMultipartTempFiles(t *testing.T) {
	a, ctx := newQuotaTestApp(t)

	// mime/multipart spills into os.TempDir(), which honours TMPDIR per call.
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)

	a.filesDir = t.TempDir()
	a.maxUpload = 128 << 20

	u := mkUser(t, a, ctx, "upload-tmp-"+uuid.NewString()[:8], false)
	sid, _, err := a.createSession(ctx, u.ID)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	t.Cleanup(func() { a.deleteSession(context.Background(), sid) })

	srv := httptest.NewServer(a.withOptionalUser(
		http.HandlerFunc(a.requireUser(a.handleUpload))))
	defer srv.Close()

	// Comfortably past the 32 MiB in-memory budget, so a spill file is certain.
	const bodyBytes = 40 << 20
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		part, err := mw.CreateFormFile("file", "big.bin")
		if err != nil {
			pw.CloseWithError(err)
			return
		}
		if _, err := io.CopyN(part, zeroReader{}, bodyBytes); err != nil {
			pw.CloseWithError(err)
			return
		}
		mw.Close()
		pw.Close()
	}()

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/upload", pr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()

	// The upload is rejected — it carries no e2e material — which is fine and
	// is in fact the point: cleanup has to happen on every return path, not
	// just the successful one.
	if res.StatusCode == http.StatusOK {
		t.Fatalf("expected the upload to be refused, got 200")
	}

	leaked, err := filepath.Glob(filepath.Join(tmp, "multipart-*"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(leaked) > 0 {
		var sizes []string
		for _, p := range leaked {
			if fi, err := os.Stat(p); err == nil {
				sizes = append(sizes, filepath.Base(p)+" ("+humanSize(fi.Size())+")")
			}
		}
		t.Errorf("upload leaked %d multipart temp file(s) that nothing will ever "+
			"reclaim: %s", len(leaked), strings.Join(sizes, ", "))
	}

	// The rejected upload must not leave a blob behind either.
	blobs, err := os.ReadDir(a.filesDir)
	if err != nil {
		t.Fatalf("read files dir: %v", err)
	}
	if len(blobs) != 0 {
		t.Errorf("a refused upload left %d file(s) in the files dir", len(blobs))
	}
}

// TestUploadRejectionsAreDistinguishable pins the three ways a multipart parse
// can fail. All three used to answer with a bare "Bad Request", which is what
// made an over-size file and a dropped connection look identical in the UI —
// and put the file over the size limit into the retryable bucket, offering a
// Retry button that could never succeed.
func TestUploadRejectionsAreDistinguishable(t *testing.T) {
	a, ctx := newQuotaTestApp(t)
	t.Setenv("TMPDIR", t.TempDir())
	a.filesDir = t.TempDir()
	a.maxUpload = 8 << 20 // small, so the oversize case is cheap to send

	u := mkUser(t, a, ctx, "upload-rej-"+uuid.NewString()[:8], false)
	sid, _, err := a.createSession(ctx, u.ID)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	t.Cleanup(func() { a.deleteSession(context.Background(), sid) })

	srv := httptest.NewServer(a.withOptionalUser(
		http.HandlerFunc(a.requireUser(a.handleUpload))))
	defer srv.Close()

	post := func(body io.Reader, contentType string) (int, string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/upload", body)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Content-Type", contentType)
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0, err.Error()
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, strings.TrimSpace(string(b))
	}

	// Over the size limit: must be 413 so the client shows "File too large"
	// and withholds the pointless Retry button, and must name the limit.
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		part, _ := mw.CreateFormFile("file", "big.bin")
		io.CopyN(part, zeroReader{}, int64(a.maxUpload)+(64<<20))
		mw.Close()
		pw.Close()
	}()
	code, body := post(pr, mw.FormDataContentType())
	if code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversize upload: got HTTP %d %q, want 413", code, body)
	}
	if !strings.Contains(body, humanSize(a.maxUpload)) {
		t.Errorf("oversize upload: %q does not name the %s limit", body, humanSize(a.maxUpload))
	}

	// A well-formed but oversize plain_size takes the other 413 path, and must
	// report both numbers rather than "invalid plain_size".
	var buf strings.Builder
	mw2 := multipart.NewWriter(&buf)
	mw2.WriteField("e2e", "1")
	mw2.WriteField("plain_size", "999999999")
	part, _ := mw2.CreateFormFile("file", "small.bin")
	part.Write([]byte("not really ciphertext"))
	mw2.Close()
	code, body = post(strings.NewReader(buf.String()), mw2.FormDataContentType())
	if code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversize plain_size: got HTTP %d %q, want 413", code, body)
	}
	if !strings.Contains(body, humanSize(a.maxUpload)) || strings.Contains(body, "invalid plain_size") {
		t.Errorf("oversize plain_size: %q should state the file size and the limit", body)
	}

	// An interrupted body must not be reported as a malformed request.
	pr2, pw2 := io.Pipe()
	mw3 := multipart.NewWriter(pw2)
	go func() {
		part, _ := mw3.CreateFormFile("file", "cut.bin")
		io.CopyN(part, zeroReader{}, 1<<20)
		// Abandon the body mid-part, the way a dropped connection does.
		pw2.CloseWithError(io.ErrUnexpectedEOF)
	}()
	code, body = post(pr2, mw3.FormDataContentType())
	// The client is gone, so a transport error here is the honest outcome too;
	// what must not happen is a response blaming the request's shape.
	if code != 0 && body == http.StatusText(http.StatusBadRequest) {
		t.Errorf("interrupted upload answered with a bare %q, which is "+
			"indistinguishable from a malformed request", body)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}
