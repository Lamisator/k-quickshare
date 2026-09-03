package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// A drop's limits are decided in SQL, inside the transaction that already
// serialises uploads, and that is the only place they mean anything. A count
// checked in the handler would be a count two simultaneous senders both pass.
//
// Runs only with TEST_DATABASE_URL pointing at a throwaway database.

// newDropTestApp is the quota harness with a per-file ceiling set: without one
// every reservation books the ceiling, which is zero, and the byte limits below
// would pass for the wrong reason.
func newDropTestApp(t *testing.T) (*App, context.Context) {
	t.Helper()
	a, ctx := newQuotaTestApp(t)
	a.setMaxUploadDefault(1 << 20)
	return a, ctx
}

func mkDrop(t *testing.T, a *App, ctx context.Context, owner *User, d dropMeta) *dropMeta {
	t.Helper()
	if d.ID == "" {
		d.ID = uuid.NewString()
	}
	if d.PublicID == "" {
		d.PublicID = uuid.NewString()
	}
	sum := sha256.Sum256([]byte("token"))
	_, err := a.db.Exec(ctx,
		`INSERT INTO drops (id, public_id, owner_id, drop_version, kem_alg, enc_pk,
		                    upload_verifier, max_file_bytes, max_total_bytes,
		                    max_files, max_files_per_submission, max_submissions, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		d.ID, d.PublicID, owner.ID.String(), dropCurrentVersion, "xwing-draft10",
		make([]byte, dropSealedPKLen), sum[:],
		d.MaxFileBytes, d.MaxTotalBytes, d.MaxFiles, d.MaxPerSubmission, d.MaxSubmissions,
		d.ExpiresAt)
	if err != nil {
		t.Fatalf("insert drop: %v", err)
	}
	d.OwnerID = owner.ID.String()
	t.Cleanup(func() {
		_, _ = a.db.Exec(context.Background(), `DELETE FROM drops WHERE id = $1`, d.ID)
	})
	return &d
}

func mkSubmission(t *testing.T, a *App, ctx context.Context, d *dropMeta) string {
	t.Helper()
	id := uuid.NewString()
	_, err := a.db.Exec(ctx,
		`INSERT INTO batches (id, created_by, key_mode, e2e_version, drop_id, kem_ct)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		id, d.OwnerID, keyModeE2EKEM, e2eCurrentVersion, d.ID, make([]byte, dropCiphertextLen))
	if err != nil {
		t.Fatalf("insert submission: %v", err)
	}
	return id
}

func addSubmissionFile(t *testing.T, a *App, ctx context.Context, owner *User, batchID string, size int64) {
	t.Helper()
	_, err := a.db.Exec(ctx,
		`INSERT INTO files (id, original_name, stored_name, size_bytes, content_type,
		                    uploaded_by, batch_id, key_mode, e2e_version)
		 VALUES ($1, NULL, $2, $3, NULL, $4, $5, $6, $7)`,
		uuid.NewString(), uuid.NewString(), size, owner.ID.String(), batchID,
		keyModeE2EKEM, e2eCurrentVersion)
	if err != nil {
		t.Fatalf("insert file: %v", err)
	}
}

// TestDropFileCountIsEnforced is the "just allow the drop of a single file"
// case: a drop with max_files 1 takes one file and refuses the second.
func TestDropFileCountIsEnforced(t *testing.T) {
	a, ctx := newDropTestApp(t)
	owner := mkUser(t, a, ctx, "drop-owner-count", false)
	one := 1
	d := mkDrop(t, a, ctx, owner, dropMeta{MaxFiles: &one})
	sub := mkSubmission(t, a, ctx, d)

	res, err := a.reserveUpload(ctx, owner, 100, &dropTarget{DropID: d.ID, BatchID: sub, Limits: d.limits()})
	if err != nil {
		t.Fatalf("first file refused: %v", err)
	}
	err = a.finalizeUpload(ctx, owner, res, 100,
		&dropTarget{DropID: d.ID, BatchID: sub, Limits: d.limits()},
		func(tx pgx.Tx) error {
			_, e := tx.Exec(ctx,
				`INSERT INTO files (id, original_name, stored_name, size_bytes, content_type,
				                    uploaded_by, batch_id, key_mode, e2e_version)
				 VALUES ($1, NULL, $2, $3, NULL, $4, $5, $6, $7)`,
				uuid.NewString(), uuid.NewString(), int64(100), owner.ID.String(), sub,
				keyModeE2EKEM, e2eCurrentVersion)
			return e
		})
	if err != nil {
		t.Fatalf("first file not stored: %v", err)
	}

	_, err = a.reserveUpload(ctx, owner, 100, &dropTarget{DropID: d.ID, BatchID: sub, Limits: d.limits()})
	if !errors.Is(err, errDropLimit) {
		t.Fatalf("second file into a one-file drop: got %v, want errDropLimit", err)
	}
}

// TestDropPerSubmissionCountIsEnforced separates the two counts: a drop may
// hold twenty files and still allow only one per delivery.
func TestDropPerSubmissionCountIsEnforced(t *testing.T) {
	a, ctx := newDropTestApp(t)
	owner := mkUser(t, a, ctx, "drop-owner-persub", false)
	one, twenty := 1, 20
	d := mkDrop(t, a, ctx, owner, dropMeta{MaxFiles: &twenty, MaxPerSubmission: &one})

	first := mkSubmission(t, a, ctx, d)
	addSubmissionFile(t, a, ctx, owner, first, 10)
	if _, err := a.reserveUpload(ctx, owner, 10,
		&dropTarget{DropID: d.ID, BatchID: first, Limits: d.limits()}); !errors.Is(err, errDropLimit) {
		t.Fatalf("second file in a one-file delivery: got %v, want errDropLimit", err)
	}

	// A different sender is a different delivery, and is not affected.
	second := mkSubmission(t, a, ctx, d)
	if _, err := a.reserveUpload(ctx, owner, 10,
		&dropTarget{DropID: d.ID, BatchID: second, Limits: d.limits()}); err != nil {
		t.Fatalf("first file of a second delivery refused: %v", err)
	}
}

// TestDropCountSurvivesARace is the reason reservations carry their drop. Two
// senders reserve at the same moment against a drop that accepts one file;
// exactly one may get through, and the loser must be told the drop is full
// rather than the server storing two.
func TestDropCountSurvivesARace(t *testing.T) {
	a, ctx := newDropTestApp(t)
	owner := mkUser(t, a, ctx, "drop-owner-race", false)
	one := 1
	d := mkDrop(t, a, ctx, owner, dropMeta{MaxFiles: &one})
	subs := []string{mkSubmission(t, a, ctx, d), mkSubmission(t, a, ctx, d)}

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		ok   int
		full int
	)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id, err := a.reserveUpload(context.Background(), owner, 100,
				&dropTarget{DropID: d.ID, BatchID: subs[i], Limits: d.limits()})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
				t.Cleanup(func() { a.releaseReservation(id) })
			case errors.Is(err, errDropLimit):
				full++
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if ok != 1 || full != 1 {
		t.Errorf("two senders into a one-file drop: %d accepted, %d refused; want 1 and 1", ok, full)
	}
}

// TestDropBytesAreChargedToTheOwner is the quota half: a drop's files count
// against the person who published the link, not the stranger who filled it.
func TestDropBytesAreChargedToTheOwner(t *testing.T) {
	a, ctx := newDropTestApp(t)
	owner := mkUser(t, a, ctx, "drop-owner-quota", false)
	if err := a.setUserLimits(ctx, owner.ID, ptrInt64(1000), nil, nil); err != nil {
		t.Fatalf("set quota: %v", err)
	}
	d := mkDrop(t, a, ctx, owner, dropMeta{})
	sub := mkSubmission(t, a, ctx, d)
	addSubmissionFile(t, a, ctx, owner, sub, 900)

	_, err := a.reserveUpload(ctx, owner, 500, &dropTarget{DropID: d.ID, BatchID: sub, Limits: d.limits()})
	if !errors.Is(err, errQuotaExceeded) {
		t.Fatalf("over the owner's quota: got %v, want errQuotaExceeded", err)
	}
}

// TestDropTotalBytesAreEnforced: the drop's own ceiling binds even when the
// owner has room to spare.
func TestDropTotalBytesAreEnforced(t *testing.T) {
	a, ctx := newDropTestApp(t)
	owner := mkUser(t, a, ctx, "drop-owner-total", false)
	total := int64(1000)
	d := mkDrop(t, a, ctx, owner, dropMeta{MaxTotalBytes: &total})
	sub := mkSubmission(t, a, ctx, d)
	addSubmissionFile(t, a, ctx, owner, sub, 900)

	_, err := a.reserveUpload(ctx, owner, 500, &dropTarget{DropID: d.ID, BatchID: sub, Limits: d.limits()})
	if !errors.Is(err, errDropLimit) {
		t.Fatalf("over the drop's total: got %v, want errDropLimit", err)
	}
}

// TestDropSubmissionCountIsEnforced covers the gate one step earlier, before
// any file is offered: a drop that accepts one delivery refuses the second.
func TestDropSubmissionCountIsEnforced(t *testing.T) {
	a, ctx := newDropTestApp(t)
	owner := mkUser(t, a, ctx, "drop-owner-subs", false)
	one := 1
	d := mkDrop(t, a, ctx, owner, dropMeta{MaxSubmissions: &one})
	mkSubmission(t, a, ctx, d)

	tx, err := a.db.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)
	if err := dropAcceptsAnotherSubmission(ctx, tx, d.ID, d.limits()); !errors.Is(err, errDropLimit) {
		t.Fatalf("second delivery into a one-delivery drop: got %v, want errDropLimit", err)
	}
}

// TestExpiredDropIsSwept walks the lifecycle: an expired drop archives its
// deliveries and their files, so the bytes stop counting against the owner.
func TestExpiredDropIsSwept(t *testing.T) {
	a, ctx := newDropTestApp(t)
	a.filesDir = t.TempDir()
	owner := mkUser(t, a, ctx, "drop-owner-sweep", false)
	past := time.Now().Add(-time.Hour)
	d := mkDrop(t, a, ctx, owner, dropMeta{ExpiresAt: &past})
	sub := mkSubmission(t, a, ctx, d)
	addSubmissionFile(t, a, ctx, owner, sub, 400)

	if err := a.sweepExpiredDrops(ctx); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	var active int
	if err := a.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM files WHERE batch_id = $1 AND archived_at IS NULL`, sub).
		Scan(&active); err != nil {
		t.Fatalf("count: %v", err)
	}
	if active != 0 {
		t.Errorf("expired drop still has %d active file(s)", active)
	}
}

func ptrInt64(v int64) *int64 { return &v }
