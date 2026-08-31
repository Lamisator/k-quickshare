package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// Bulk delete decides two things in one statement: which rows go, and whether
// the caller may touch them. Getting the second wrong is not a bug that shows
// up in a template test — it deletes other people's files — so it is checked
// against a real database.
//
// Runs only with TEST_DATABASE_URL set; see quota_db_test.go.

// mkFile inserts an owned file together with the blob it points at, and returns
// the row id and the blob's path.
func mkFile(t *testing.T, a *App, ctx context.Context, u *User, name string) (string, string) {
	t.Helper()
	id := uuid.NewString()
	stored := uuid.NewString()
	path := filepath.Join(a.filesDir, stored)
	if err := os.WriteFile(path, []byte("ciphertext"), 0o600); err != nil {
		t.Fatalf("write blob: %v", err)
	}
	_, err := a.db.Exec(ctx,
		`INSERT INTO files (id, original_name, stored_name, size_bytes, content_type, uploaded_by)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		id, name, stored, 10, "application/octet-stream", u.ID.String())
	if err != nil {
		t.Fatalf("insert file: %v", err)
	}
	t.Cleanup(func() {
		_, _ = a.db.Exec(context.Background(), `DELETE FROM files WHERE id = $1`, id)
	})
	return id, path
}

func bulkDeleteAs(t *testing.T, a *App, u *User, ids ...string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{}
	for _, id := range ids {
		form.Add("id", id)
	}
	r := httptest.NewRequest(http.MethodPost, "/delete", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(context.WithValue(r.Context(), userCtxKey, u))
	w := httptest.NewRecorder()
	a.handleBulkDelete(w, r)
	return w
}

func fileExists(t *testing.T, a *App, ctx context.Context, id string) bool {
	t.Helper()
	var n int
	if err := a.db.QueryRow(ctx, `SELECT count(*) FROM files WHERE id = $1`, id).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n > 0
}

func TestBulkDeleteRemovesOwnFilesAndBlobs(t *testing.T) {
	a, ctx := newQuotaTestApp(t)
	a.filesDir = t.TempDir()
	u := mkUser(t, a, ctx, "bulk-own-"+uuid.NewString()[:8], false)

	idA, blobA := mkFile(t, a, ctx, u, "a.bin")
	idB, blobB := mkFile(t, a, ctx, u, "b.bin")
	idKeep, blobKeep := mkFile(t, a, ctx, u, "keep.bin")

	if code := bulkDeleteAs(t, a, u, idA, idB).Code; code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", code)
	}
	for _, id := range []string{idA, idB} {
		if fileExists(t, a, ctx, id) {
			t.Errorf("file %s still listed", id)
		}
	}
	for _, p := range []string{blobA, blobB} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("blob %s not removed (err=%v)", p, err)
		}
	}
	// The unselected file is the whole point of a checkbox list.
	if !fileExists(t, a, ctx, idKeep) {
		t.Error("unselected file was deleted")
	}
	if _, err := os.Stat(blobKeep); err != nil {
		t.Errorf("unselected blob removed: %v", err)
	}
}

// A member must not be able to delete a file they do not own by naming its id,
// not even by hiding it among their own.
func TestBulkDeleteIgnoresOtherPeoplesFiles(t *testing.T) {
	a, ctx := newQuotaTestApp(t)
	a.filesDir = t.TempDir()
	owner := mkUser(t, a, ctx, "bulk-owner-"+uuid.NewString()[:8], false)
	other := mkUser(t, a, ctx, "bulk-other-"+uuid.NewString()[:8], false)

	mine, _ := mkFile(t, a, ctx, other, "mine.bin")
	theirs, theirBlob := mkFile(t, a, ctx, owner, "theirs.bin")

	bulkDeleteAs(t, a, other, mine, theirs)

	if fileExists(t, a, ctx, mine) {
		t.Error("own file survived")
	}
	if !fileExists(t, a, ctx, theirs) {
		t.Fatal("deleted another user's file")
	}
	if _, err := os.Stat(theirBlob); err != nil {
		t.Errorf("another user's blob removed: %v", err)
	}
}

func TestBulkDeleteAdminMayDeleteAnything(t *testing.T) {
	a, ctx := newQuotaTestApp(t)
	a.filesDir = t.TempDir()
	owner := mkUser(t, a, ctx, "bulk-victim-"+uuid.NewString()[:8], false)
	admin := mkUser(t, a, ctx, "bulk-admin-"+uuid.NewString()[:8], true)

	id, blob := mkFile(t, a, ctx, owner, "theirs.bin")
	bulkDeleteAs(t, a, admin, id)

	if fileExists(t, a, ctx, id) {
		t.Error("admin delete left the row")
	}
	if _, err := os.Stat(blob); !os.IsNotExist(err) {
		t.Errorf("admin delete left the blob (err=%v)", err)
	}
}

func TestBulkDeleteRejectsBadInput(t *testing.T) {
	a, ctx := newQuotaTestApp(t)
	a.filesDir = t.TempDir()
	u := mkUser(t, a, ctx, "bulk-bad-"+uuid.NewString()[:8], false)
	id, _ := mkFile(t, a, ctx, u, "a.bin")

	// One unparseable id fails the whole request rather than being skipped: a
	// selection that did not mean what the page showed should not half-apply.
	if code := bulkDeleteAs(t, a, u, id, "not-a-uuid").Code; code != http.StatusBadRequest {
		t.Errorf("bad uuid: status = %d, want 400", code)
	}
	if !fileExists(t, a, ctx, id) {
		t.Error("a rejected request deleted a row anyway")
	}

	// An empty selection is a no-op, not an error — the form can be submitted
	// with nothing ticked.
	if code := bulkDeleteAs(t, a, u).Code; code != http.StatusSeeOther {
		t.Errorf("empty selection: status = %d, want 303", code)
	}

	over := make([]string, maxBulkDelete+1)
	for i := range over {
		over[i] = uuid.NewString()
	}
	if code := bulkDeleteAs(t, a, u, over...).Code; code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversize selection: status = %d, want 413", code)
	}

	// A GET must not delete: this endpoint is only reachable by POST.
	r := httptest.NewRequest(http.MethodGet, "/delete?id="+id, nil)
	r = r.WithContext(context.WithValue(r.Context(), userCtxKey, u))
	w := httptest.NewRecorder()
	a.handleBulkDelete(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: status = %d, want 405", w.Code)
	}
	if !fileExists(t, a, ctx, id) {
		t.Error("GET deleted a row")
	}
}
