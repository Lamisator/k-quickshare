package main

import "testing"

func TestParseSize(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{"0", 0},
		{"512", 512},
		{"512B", 512},
		{"1K", 1 << 10},
		{"20G", 20 << 30},
		{"20 GiB", 20 << 30},
		{"20 gb", 20 << 30},
		{"  20GB  ", 20 << 30},
		{"1.5G", 1536 << 20},
		{"2T", 2 << 40},
	}
	for _, c := range cases {
		got, err := parseSize(c.in)
		if err != nil {
			t.Errorf("parseSize(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseSize(%q) = %d, want %d", c.in, got, c.want)
		}
	}

	for _, bad := range []string{"", "   ", "-1", "G", "20X", "20 GG", "abc", "1.2.3"} {
		if got, err := parseSize(bad); err == nil {
			t.Errorf("parseSize(%q) = %d, want an error", bad, got)
		}
	}
}

// sizeInput must survive a round trip through the form, or an admin who opens
// the quota editor and saves without touching anything silently moves the
// limit. humanSize cannot do this — it rounds to one decimal.
func TestSizeInputRoundTrips(t *testing.T) {
	for _, n := range []int64{0, 1, 512, 1023, 1 << 10, 20 << 30, 21474836481, 1<<40 + 7} {
		s := sizeInput(n)
		got, err := parseSize(s)
		if err != nil {
			t.Errorf("sizeInput(%d) = %q, which parseSize rejects: %v", n, s, err)
			continue
		}
		if got != n {
			t.Errorf("round trip of %d via %q gave %d", n, s, got)
		}
	}
}

func TestApplyQuotaDefaults(t *testing.T) {
	def := UserQuota{Bytes: 20 << 30, Files: 1000}
	zero := int64(0)
	small := int64(5 << 30)

	cases := []struct {
		name    string
		isAdmin bool
		bytes   *int64
		files   *int64
		want    UserQuota
	}{
		{"member inherits the default", false, nil, nil, def},
		{"admin is exempt from the default", true, nil, nil, UserQuota{}},
		{"override wins for a member", false, &small, nil,
			UserQuota{Bytes: small, Files: def.Files}},
		// The point of storing NULL separately from 0: an explicit 0 lifts one
		// user above a restrictive default without editing the default.
		{"explicit zero means unlimited, not inherit", false, &zero, nil,
			UserQuota{Bytes: 0, Files: def.Files}},
		// An admin who types a limit into another admin's row means it.
		{"override applies to an admin too", true, &small, nil,
			UserQuota{Bytes: small}},
	}
	for _, c := range cases {
		if got := applyQuotaDefaults(c.isAdmin, c.bytes, c.files, def); got != c.want {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
	}
}

func TestUsagePercent(t *testing.T) {
	cases := []struct {
		used, limit int64
		want        float64
	}{
		{0, 100, 0},
		{25, 100, 25},
		{100, 100, 100},
		// Over quota can happen — an admin can lower a limit below what a user
		// already stores — and the bar must clamp instead of overflowing.
		{150, 100, 100},
		// Unlimited has no meaningful percentage; 0 keeps the bar empty.
		{500, 0, 0},
	}
	for _, c := range cases {
		if got := pct(c.used, c.limit); got != c.want {
			t.Errorf("pct(%d, %d) = %v, want %v", c.used, c.limit, got, c.want)
		}
	}
}

func TestUsageSummaryBar(t *testing.T) {
	cases := []struct {
		name    string
		s       UsageSummary
		limited bool
		bar     float64
	}{
		{"no limit at all", UsageSummary{UsedBytes: 1 << 30, UsedFiles: 9}, false, 0},
		{"bytes capped: the bar tracks bytes",
			UsageSummary{UsedBytes: 5, UsedFiles: 900, Quota: UserQuota{Bytes: 10, Files: 1000}},
			true, 50},
		// With no byte limit the file count is the only limit there is, so the
		// bar has to follow it or it would sit at zero while the user is
		// one upload away from being refused.
		{"files capped only: the bar tracks files",
			UsageSummary{UsedBytes: 1 << 40, UsedFiles: 9, Quota: UserQuota{Files: 10}},
			true, 90},
	}
	for _, c := range cases {
		if got := c.s.Limited(); got != c.limited {
			t.Errorf("%s: Limited() = %v, want %v", c.name, got, c.limited)
		}
		if got := c.s.BarPercent(); got != c.bar {
			t.Errorf("%s: BarPercent() = %v, want %v", c.name, got, c.bar)
		}
	}
}

func TestQuotaViolation(t *testing.T) {
	a := &App{quota: QuotaConfig{TotalBytes: 100}}
	q := UserQuota{Bytes: 50, Files: 2}

	if err := a.quotaViolation(q, usageSnapshot{userBytes: 10, userFiles: 1}, 10); err != nil {
		t.Errorf("upload within every limit rejected: %v", err)
	}
	if err := a.quotaViolation(q, usageSnapshot{userBytes: 45, userFiles: 1}, 10); err == nil {
		t.Error("byte quota not enforced")
	}
	if err := a.quotaViolation(q, usageSnapshot{userBytes: 1, userFiles: 2}, 1); err == nil {
		t.Error("file-count quota not enforced")
	}
	// Reservations held by in-flight uploads count against the limit too.
	if err := a.quotaViolation(q, usageSnapshot{userBytes: 20, userReserved: 25}, 10); err == nil {
		t.Error("live reservations not counted against the byte quota")
	}
	// Zero means unlimited for the user...
	unlimited := UserQuota{}
	noCeiling := &App{quota: QuotaConfig{}}
	if err := noCeiling.quotaViolation(unlimited, usageSnapshot{userBytes: 1 << 40}, 1<<40); err != nil {
		t.Errorf("zero quota should be unlimited: %v", err)
	}
	// ...but never lifts the instance-wide ceiling.
	if err := a.quotaViolation(unlimited, usageSnapshot{totalBytes: 95}, 10); err == nil {
		t.Error("instance-wide ceiling not enforced")
	}
}

// TestParsePositiveSize pins the one way the upload ceiling differs from a
// quota at the parsing stage: a quota of 0 is "unlimited", an upload limit of
// 0 would refuse every file, so it is rejected instead of stored.
func TestParsePositiveSize(t *testing.T) {
	for _, good := range []string{"1", "512M", "2G", "1 GiB"} {
		if _, err := parsePositiveSize(good); err != nil {
			t.Errorf("parsePositiveSize(%q): %v", good, err)
		}
	}
	for _, bad := range []string{"0", "0G", "", "-1", "abc"} {
		if got, err := parsePositiveSize(bad); err == nil {
			t.Errorf("parsePositiveSize(%q) = %d, want an error", bad, got)
		}
	}
}

// TestEffectiveMaxUpload states the resolution rules for the per-file ceiling,
// and in particular the two places it deliberately parts company with
// applyQuotaDefaults: an admin is NOT exempt, and 0 is not "unlimited".
func TestEffectiveMaxUpload(t *testing.T) {
	const def = 512 << 20
	override := int64(2 << 30)
	zero := int64(0)
	negative := int64(-1)

	if got := effectiveMaxUpload(nil, def); got != def {
		t.Errorf("no override: got %d, want the instance default %d", got, def)
	}
	if got := effectiveMaxUpload(&override, def); got != override {
		t.Errorf("override: got %d, want %d", got, override)
	}
	// A row holding 0 (or worse) must fall back, never become limitless: the
	// body reader is sized from this number.
	if got := effectiveMaxUpload(&zero, def); got != def {
		t.Errorf("zero override: got %d, want the instance default %d", got, def)
	}
	if got := effectiveMaxUpload(&negative, def); got != def {
		t.Errorf("negative override: got %d, want the instance default %d", got, def)
	}

	// An admin with no override of their own gets the instance limit, unlike
	// the storage quota, which exempts them. maxUploadFor takes the user, so
	// this is the check that the admin flag plays no part.
	a := &App{}
	a.setMaxUploadDefault(def)
	admin := &User{IsAdmin: true, IsSuperAdmin: true}
	if got := a.maxUploadFor(admin); got != def {
		t.Errorf("admin: got %d, want the instance limit %d — admins are not exempt "+
			"from the per-file ceiling", got, def)
	}
	admin.MaxUploadBytes = &override
	if got := a.maxUploadFor(admin); got != override {
		t.Errorf("admin with an override: got %d, want %d", got, override)
	}
	// No user at all (a path that does not upload) still resolves to something
	// finite rather than zero.
	if got := a.maxUploadFor(nil); got != def {
		t.Errorf("nil user: got %d, want %d", got, def)
	}
}
