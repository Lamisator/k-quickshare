package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The upgrade path is the part of this service with the least room for a second
// attempt: it runs unattended at container start, against the one database that
// holds every account. These tests exercise it against a real PostgreSQL rather
// than trusting that the SQL parses.
//
// Runs only with TEST_DATABASE_URL pointing at a throwaway database.
func newMigrationTestApp(t *testing.T) (*App, context.Context) {
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
	return &App{db: pool}, ctx
}

// TestMigrationsAreRecordedAndIdempotent is the whole point of numbering them:
// a database says which version it is on, and re-running the process does not
// re-apply anything.
func TestMigrationsAreRecordedAndIdempotent(t *testing.T) {
	a, ctx := newMigrationTestApp(t)

	v, err := schemaVersion(ctx, a.db)
	if err != nil {
		t.Fatal(err)
	}
	if v != latestSchemaVersion() {
		t.Fatalf("schema is v%d after migrating, want v%d", v, latestSchemaVersion())
	}

	var before time.Time
	if err := a.db.QueryRow(ctx,
		`SELECT MAX(applied_at) FROM schema_migrations`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := runMigrations(ctx, a.db); err != nil {
		t.Fatalf("second run: %v", err)
	}
	var after time.Time
	if err := a.db.QueryRow(ctx,
		`SELECT MAX(applied_at) FROM schema_migrations`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if !after.Equal(before) {
		t.Error("a second migration run re-applied something")
	}

	// Every migration in the table must be one this binary knows about, or the
	// database has been through a newer version and rolling back is not safe.
	known := map[int]bool{}
	for _, m := range migrations {
		known[m.version] = true
	}
	rows, err := a.db.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var got int
		if err := rows.Scan(&got); err != nil {
			t.Fatal(err)
		}
		if !known[got] {
			t.Errorf("the database records migration %d, which this binary does not define", got)
		}
	}
}

// TestSessionsAreStoredHashed checks the property end to end, against the real
// table: the value in the primary key is not the cookie.
func TestSessionsAreStoredHashed(t *testing.T) {
	a, ctx := newMigrationTestApp(t)
	u := mkUser(t, a, ctx, "sess-"+uuid.NewString()[:8], false)

	token, _, err := a.createSession(ctx, u.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.deleteSession(context.Background(), token) })

	var storedRaw int
	if err := a.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM sessions WHERE id = $1`, token).Scan(&storedRaw); err != nil {
		t.Fatal(err)
	}
	if storedRaw != 0 {
		t.Error("the session cookie is stored verbatim; a database leak would hand over live sessions")
	}
	var storedHashed int
	if err := a.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM sessions WHERE id = $1`, sessionKey(token)).Scan(&storedHashed); err != nil {
		t.Fatal(err)
	}
	if storedHashed != 1 {
		t.Fatal("the hashed session key is not in the table")
	}

	// The cookie still resolves, and the stored key presented AS a cookie does
	// not — otherwise hashing would have bought nothing.
	if got, err := a.sessionUser(ctx, token); err != nil || got.ID != u.ID {
		t.Fatalf("the real token did not resolve: %v", err)
	}
	if _, err := a.sessionUser(ctx, sessionKey(token)); !errors.Is(err, pgx.ErrNoRows) {
		t.Error("the stored key worked as a session cookie")
	}
}

// TestSessionReauthStamp covers the step-up bookkeeping the account page reads.
func TestSessionReauthStamp(t *testing.T) {
	a, ctx := newMigrationTestApp(t)
	u := mkUser(t, a, ctx, "reauth-"+uuid.NewString()[:8], false)

	token, _, err := a.createSession(ctx, u.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.deleteSession(context.Background(), token) })

	got, err := a.sessionUser(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if got.ReauthFresh() {
		t.Error("a plain session claims a fresh step-up")
	}

	if err := a.markSessionReauth(ctx, token, u.ID); err != nil {
		t.Fatal(err)
	}
	if got, err = a.sessionUser(ctx, token); err != nil {
		t.Fatal(err)
	}
	if !got.ReauthFresh() {
		t.Error("a stamped session does not report a fresh step-up")
	}

	if err := a.clearSessionReauth(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if got, err = a.sessionUser(ctx, token); err != nil {
		t.Fatal(err)
	}
	if got.ReauthFresh() {
		t.Error("a spent step-up is still fresh")
	}
}

// TestUsernameCaseUniquenessIsEnforcedBySQL is the race the application check
// could not close: two transactions both pass lower(username) lookups that see
// no conflict, and both insert.
func TestUsernameCaseUniquenessIsEnforcedBySQL(t *testing.T) {
	a, ctx := newMigrationTestApp(t)
	name := "Case" + uuid.NewString()[:8]

	u, err := a.createLocalUser(ctx, name, "", "correct horse battery", false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.deleteUser(context.Background(), u.ID) })

	if _, err := a.createLocalUser(ctx, strings.ToUpper(name), "", "correct horse battery", false); err == nil {
		t.Error("the database accepted two usernames differing only in case")
	}
}

// TestOIDCIdentityIsScopedToIssuer is the HIGH-severity finding: `sub` is
// unique per issuer and says nothing across issuers, so binding on it alone
// lets a colliding subject at another provider land on an existing account.
func TestOIDCIdentityIsScopedToIssuer(t *testing.T) {
	a, ctx := newMigrationTestApp(t)
	sub := "subject-" + uuid.NewString()
	const issuerA = "https://idp-a.example"
	const issuerB = "https://idp-b.example"

	mine, err := a.upsertOIDCUser(ctx, issuerA, sub, "alice-"+uuid.NewString()[:8], "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.deleteUser(context.Background(), mine.ID) })

	// Same issuer, same subject: the same person.
	again, err := a.upsertOIDCUser(ctx, issuerA, sub, "ignored", "")
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != mine.ID {
		t.Error("the same (issuer, subject) produced two accounts")
	}

	// A different issuer with a colliding subject must NOT reach that account.
	other, err := a.upsertOIDCUser(ctx, issuerB, sub, "mallory-"+uuid.NewString()[:8], "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.deleteUser(context.Background(), other.ID) })
	if other.ID == mine.ID {
		t.Fatal("a colliding subject from a different issuer took over the existing account")
	}

	// An account written before the issuer was recorded is adopted once, by the
	// configured issuer, and is then bound like any other.
	legacyID := uuid.New()
	legacySub := "legacy-" + uuid.NewString()
	if _, err := a.db.Exec(ctx,
		`INSERT INTO users (id, username, oidc_subject) VALUES ($1, $2, $3)`,
		legacyID.String(), "legacy-"+uuid.NewString()[:8], legacySub); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.deleteUser(context.Background(), legacyID) })

	adopted, err := a.findUserByOIDCIdentity(ctx, issuerA, legacySub)
	if err != nil {
		t.Fatalf("a pre-issuer account was not adopted: %v", err)
	}
	if adopted.ID != legacyID {
		t.Fatal("adoption reached the wrong account")
	}
	if adopted.OIDCIssuer != issuerA {
		t.Errorf("adopted account has issuer %q, want %q", adopted.OIDCIssuer, issuerA)
	}
	// Adopted once means adopted: the other issuer no longer matches it.
	if _, err := a.findUserByOIDCIdentity(ctx, issuerB, legacySub); !errors.Is(err, pgx.ErrNoRows) {
		t.Error("an adopted account is still reachable from a second issuer")
	}
}

// TestSharedRateLimiterCountsAcrossProcesses stands in for two replicas: two
// limiter instances over one database, as a rolling deploy or a scaled service
// would have.
func TestSharedRateLimiterCountsAcrossProcesses(t *testing.T) {
	a, ctx := newMigrationTestApp(t)
	key := "test|" + uuid.NewString()

	replicaA := newFailLimiter(3, time.Minute).shared(a.db, "test")
	replicaB := newFailLimiter(3, time.Minute).shared(a.db, "test")
	t.Cleanup(func() { replicaA.reset(context.Background(), key) })

	for i := 0; i < 3; i++ {
		replicaA.fail(ctx, key)
	}
	if replicaB.allow(ctx, key) {
		t.Error("a second replica granted a fresh allowance after the limit was reached on the first")
	}

	replicaA.reset(ctx, key)
	if !replicaB.allow(ctx, key) {
		t.Error("a successful attempt on one replica did not clear the shared counter")
	}
}

// TestE2EColumnsExist checks that the version-2 storage actually arrived: the
// upload path writes these on every file and the download path reads them, so a
// missing column is a total outage rather than a degraded feature.
func TestE2EColumnsExist(t *testing.T) {
	a, ctx := newMigrationTestApp(t)
	for _, c := range []struct{ table, column string }{
		{"files", "e2e_version"},
		{"files", "manifest"},
		{"batches", "e2e_version"},
		{"batches", "roster"},
		{"batches", "roster_seq"},
		{"sessions", "reauth_at"},
		{"users", "oidc_issuer"},
	} {
		var n int
		if err := a.db.QueryRow(ctx,
			`SELECT COUNT(*) FROM information_schema.columns
			  WHERE table_name = $1 AND column_name = $2`, c.table, c.column).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Errorf("%s.%s is missing", c.table, c.column)
		}
	}
}
