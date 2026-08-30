package main

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

// The quota rules that matter are decided in SQL: the nullable override
// columns, the usage aggregate behind the admin table, and the resolution that
// runs inside the upload transaction. None of that is exercised by the
// pure-function tests, and all of it compiles fine while being wrong.
//
// Runs only with TEST_DATABASE_URL pointing at a throwaway database — it
// creates and drops rows.
func newQuotaTestApp(t *testing.T) (*App, context.Context) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := connectDB(ctx, dsn, 5, time.Second)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := runMigrations(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	a := &App{db: pool, quota: QuotaConfig{}}
	a.setQuotaDefaults(UserQuota{Bytes: 20 << 30, Files: 1000})
	return a, ctx
}

func mkUser(t *testing.T, a *App, ctx context.Context, name string, isAdmin bool) *User {
	t.Helper()
	u, err := a.createLocalUser(ctx, name, "", "password123", isAdmin)
	if err != nil {
		t.Fatalf("create user %s: %v", name, err)
	}
	t.Cleanup(func() { _ = a.deleteUser(context.Background(), u.ID) })
	return u
}

// addFile inserts an active file owned by u. archived and expired rows must not
// count, so those variants are inserted too.
func addFile(t *testing.T, a *App, ctx context.Context, u *User, size int64, state string) {
	t.Helper()
	var expires, archived any
	switch state {
	case "active":
	case "expired":
		expires = time.Now().Add(-time.Hour)
	case "archived":
		archived = time.Now().Add(-time.Hour)
	default:
		t.Fatalf("bad state %q", state)
	}
	_, err := a.db.Exec(ctx,
		`INSERT INTO files (id, original_name, stored_name, size_bytes, content_type,
		                    uploaded_by, expires_at, archived_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		uuid.NewString(), "f.bin", uuid.NewString(), size, "application/octet-stream",
		u.ID.String(), expires, archived)
	if err != nil {
		t.Fatalf("insert file: %v", err)
	}
}

func TestUserQuotaOverridesRoundTrip(t *testing.T) {
	a, ctx := newQuotaTestApp(t)
	u := mkUser(t, a, ctx, "quota-rt-"+uuid.NewString()[:8], false)

	find := func() UserRow {
		t.Helper()
		rows, err := a.listUsers(ctx)
		if err != nil {
			t.Fatalf("listUsers: %v", err)
		}
		for _, r := range rows {
			if r.ID == u.ID.String() {
				return r
			}
		}
		t.Fatal("user missing from listUsers")
		return UserRow{}
	}

	// A fresh user inherits: both columns NULL.
	got := find()
	if got.QuotaBytes != nil || got.QuotaFiles != nil {
		t.Fatalf("new user should inherit, got bytes=%v files=%v", got.QuotaBytes, got.QuotaFiles)
	}

	// Setting only one dimension must leave the other inheriting — that is the
	// case the two-field form makes easy to get wrong.
	b := int64(5 << 30)
	if err := a.setUserQuota(ctx, u.ID, &b, nil); err != nil {
		t.Fatalf("setUserQuota: %v", err)
	}
	got = find()
	if got.QuotaBytes == nil || *got.QuotaBytes != b {
		t.Errorf("quota_bytes = %v, want %d", got.QuotaBytes, b)
	}
	if got.QuotaFiles != nil {
		t.Errorf("quota_files = %v, want nil (inherited)", *got.QuotaFiles)
	}

	// An explicit 0 must persist as 0, not collapse back to NULL: 0 is
	// "unlimited for this user", NULL is "use the default".
	zero := int64(0)
	if err := a.setUserQuota(ctx, u.ID, &zero, nil); err != nil {
		t.Fatalf("setUserQuota zero: %v", err)
	}
	got = find()
	if got.QuotaBytes == nil {
		t.Fatal("explicit 0 was stored as NULL — unlimited became inherit")
	}
	if *got.QuotaBytes != 0 {
		t.Errorf("quota_bytes = %d, want 0", *got.QuotaBytes)
	}

	// Clearing puts it back on the default.
	if err := a.setUserQuota(ctx, u.ID, nil, nil); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if got = find(); got.QuotaBytes != nil {
		t.Errorf("quota_bytes = %v after clear, want nil", *got.QuotaBytes)
	}
}

// The admin table's usage figures and the numbers the uploader is actually
// measured against come from two different queries. If they disagree, an admin
// sets a limit against a number that is not the one being enforced.
func TestListUsersUsageMatchesEnforcement(t *testing.T) {
	a, ctx := newQuotaTestApp(t)
	u := mkUser(t, a, ctx, "quota-use-"+uuid.NewString()[:8], false)

	addFile(t, a, ctx, u, 1000, "active")
	addFile(t, a, ctx, u, 2000, "active")
	addFile(t, a, ctx, u, 4000, "expired")  // must not count
	addFile(t, a, ctx, u, 8000, "archived") // must not count

	var row UserRow
	rows, err := a.listUsers(ctx)
	if err != nil {
		t.Fatalf("listUsers: %v", err)
	}
	for _, r := range rows {
		if r.ID == u.ID.String() {
			row = r
		}
	}
	if row.UsedBytes != 3000 || row.UsedFiles != 2 {
		t.Errorf("listUsers reports %d bytes / %d files, want 3000 / 2",
			row.UsedBytes, row.UsedFiles)
	}

	tx, err := a.db.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)
	usage, err := loadUsage(ctx, tx, u.ID.String())
	if err != nil {
		t.Fatalf("loadUsage: %v", err)
	}
	if usage.userBytes != row.UsedBytes || usage.userFiles != row.UsedFiles {
		t.Errorf("enforcement sees %d bytes / %d files but the admin table shows %d / %d",
			usage.userBytes, usage.userFiles, row.UsedBytes, row.UsedFiles)
	}

	// The account page is the third reader of the same fact.
	sum, err := a.usageSummary(ctx, u)
	if err != nil {
		t.Fatalf("usageSummary: %v", err)
	}
	if sum.UsedBytes != usage.userBytes || sum.UsedFiles != usage.userFiles {
		t.Errorf("the account page shows %d bytes / %d files but %d / %d is enforced",
			sum.UsedBytes, sum.UsedFiles, usage.userBytes, usage.userFiles)
	}
	if sum.Quota != a.getQuotaDefaults() {
		t.Errorf("account quota = %+v, want the default %+v", sum.Quota, a.getQuotaDefaults())
	}
	if sum.Custom {
		t.Error("Custom set for a user with no override")
	}
}

func TestEffectiveQuotaResolution(t *testing.T) {
	a, ctx := newQuotaTestApp(t)
	member := mkUser(t, a, ctx, "quota-mem-"+uuid.NewString()[:8], false)
	admin := mkUser(t, a, ctx, "quota-adm-"+uuid.NewString()[:8], true)
	def := a.getQuotaDefaults()

	resolve := func(u *User) UserQuota {
		t.Helper()
		tx, err := a.db.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(ctx)
		q, err := a.effectiveQuota(ctx, tx, u)
		if err != nil {
			t.Fatalf("effectiveQuota: %v", err)
		}
		return q
	}

	if got := resolve(member); got != def {
		t.Errorf("member without an override: got %+v, want the default %+v", got, def)
	}
	if got := resolve(admin); got != (UserQuota{}) {
		t.Errorf("admin without an override should be unlimited, got %+v", got)
	}

	// An override applies to an admin as well, and takes effect immediately —
	// effectiveQuota reads it in the upload transaction, not at sign-in.
	b := int64(7 << 30)
	if err := a.setUserQuota(ctx, admin.ID, &b, nil); err != nil {
		t.Fatalf("setUserQuota: %v", err)
	}
	got := resolve(admin)
	if got.Bytes != b {
		t.Errorf("admin override not applied: got %d, want %d", got.Bytes, b)
	}
	if got.Files != 0 {
		t.Errorf("admin file limit = %d, want 0 (still exempt from the default)", got.Files)
	}
}
