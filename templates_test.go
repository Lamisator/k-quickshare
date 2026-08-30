package main

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestTemplatesRender executes every page template with representative data in
// both languages to catch exec-time errors (bad pipelines, wrong arg types).
func TestTemplatesRender(t *testing.T) {
	tmpl, err := loadTemplates()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	now := time.Now()
	exp := now.Add(48 * time.Hour)
	user := &User{ID: uuid.New(), Username: "marius", Email: "m@example.com",
		IsAdmin: true, IsSuperAdmin: true, HasPassword: true, OIDCSubject: "sub123"}
	uid := user.ID.String()
	batchID := uuid.NewString()
	files := []File{
		{ID: uuid.NewString(), OriginalName: "photo.jpg", Size: 12345, ContentType: "image/jpeg",
			UploadedAt: now, UploaderName: "marius", UploadedBy: &uid, ExpiresAt: &exp,
			HasPassword: true, HasLimit: true, MaxDL: 3, DownloadCount: 3, CanDelete: true, IconKind: "image"},
		{ID: uuid.NewString(), OriginalName: "notes.txt", Size: 42, ContentType: "text/plain",
			UploadedAt: now, DownloadCount: 1, IconKind: "text", Keyed: true},
		{ID: uuid.NewString(), OriginalName: "old.zip", Size: 99, ContentType: "application/zip",
			UploadedAt: now, DownloadCount: 5, Archived: true, CanDelete: true, IconKind: "archive"},
		// Batch member: links to /b/{batch}, not /files/{id}.
		{ID: uuid.NewString(), OriginalName: "in-batch.png", Size: 512, ContentType: "image/png",
			UploadedAt: now, UploaderName: "marius", UploadedBy: &uid, ExpiresAt: &exp,
			CanDelete: true, IconKind: "image", BatchID: &batchID},
	}

	customBytes := int64(5 << 30)
	userRows := []UserRow{
		// An admin on the default: unlimited, no override to render.
		{ID: uid, Username: "marius", Email: "m@example.com", IsAdmin: true,
			IsSuperAdmin: true, HasPassword: true, HasOIDC: true, CreatedAt: now,
			UsedBytes: 3 << 30, UsedFiles: 12},
		// A member with a custom byte quota but an inherited file limit, which
		// is the case where the two form fields disagree about being blank.
		{ID: uuid.NewString(), Username: "guest", CreatedAt: now,
			QuotaBytes: &customBytes, UsedBytes: 1 << 30, UsedFiles: 3,
			EffQuota: UserQuota{Bytes: customBytes, Files: 1000}, Custom: true,
			QuotaBytesInput: sizeInput(customBytes)},
	}

	base := func(lang string) map[string]any {
		return map[string]any{
			"Lang": lang, "I18N": jsStrings(lang), "ReqPath": "/", "Title": "t",
			"Theme": "light", "User": user, "Active": "upload",
			"Disk": DiskStats{Total: 500 << 30, Used: 142 << 30, Free: 358 << 30,
				Percent: 28.4, OK: true},
			// The quota bar lives in the shell, so every page renders it.
			"Usage": UsageSummary{UsedBytes: 3 << 30, UsedFiles: 12,
				Quota: UserQuota{Bytes: 20 << 30, Files: 1000}},
		}
	}
	merge := func(lang string, extra map[string]any) map[string]any {
		m := base(lang)
		for k, v := range extra {
			m[k] = v
		}
		return m
	}

	cases := map[string]map[string]any{
		"index.html": {"MaxUpload": int64(1 << 30)},
		"history.html": {"Active": "files", "Files": files, "ActiveCount": 2,
			"TotalSize": int64(999), "TotalDL": 4},
		"login.html": {"User": (*User)(nil), "OIDCEnabled": true, "Next": "/", "Error": "x"},
		"account.html": {"Active": "account", "Error": "", "Success": "ok",
			"StepUpRequired": false, "MinPasswordLen": minPasswordLen},
		"admin_users.html": {"Active": "users", "Users": userRows, "MeID": uid,
			"MeIsSuper": false, "Error": "", "Success": ""},
		"admin_settings.html": {"Active": "settings", "OIDC": OIDCSettings{Issuer: "https://x"},
			"OIDCLive": false, "Error": "", "Success": "",
			"QuotaBytes": sizeInput(20 << 30), "QuotaFiles": int64(1000)},
		"oidc_denied.html": {"User": (*User)(nil), "AllowedDomain": "a.example", "ActualDomain": "b.example"},
	}
	// Only two states survive: "gone", and the end-to-end landing page. The
	// server-decrypted and server-password-gated states went with key modes 0-2.
	dlCases := []map[string]any{
		{"State": "gone", "Gone": "gone msg", "User": (*User)(nil)},
		{"State": "e2e", "E2EMode": "url", "ID": "id1", "Name": "photo.jpg", "Size": int64(5),
			"ContentType": "image/jpeg", "UploadedAt": now, "ExpiresAt": exp.UTC(),
			"HasLimit": true, "MaxDL": 3, "DownloadsLeft": 2,
			"PreviewKind": "", "IconKind": "image", "User": (*User)(nil),
			"E2EVersion": e2eVersionV2, "Manifest": "eyJ2IjoyfQ"},
		{"State": "e2e", "E2EMode": "url", "ID": "id1", "Name": "blob.bin", "Size": int64(5),
			"ContentType": "application/octet-stream", "UploadedAt": now,
			"HasLimit": false, "PreviewKind": "", "IconKind": "generic", "User": (*User)(nil),
			// A share from before the manifest existed: version 1, no manifest.
			"E2EVersion": e2eVersionLegacy, "Manifest": ""},
		{"State": "e2e", "E2EMode": "password", "ID": "id1", "Name": "secret.txt", "Size": int64(5),
			"ContentType": "text/plain", "UploadedAt": now, "AuthSalt": "c2FsdHNhbHRzYWx0c2E",
			"HasLimit": false, "PreviewKind": "text", "IconKind": "text", "User": (*User)(nil),
			"E2EVersion": e2eVersionV2, "Manifest": "eyJ2IjoyfQ"},
	}
	// Shapes of the shell quota bar that the case above never reaches: a file
	// limit with no byte limit (the bar then tracks files), an entirely
	// unlimited user (no bar at all), a custom allowance, and Usage missing
	// because the summary query failed.
	// The account page has two shapes now: the password form, and the step-up
	// prompt an SSO-only account sees instead of it.
	accountCases := []map[string]any{
		{"Active": "account", "StepUpRequired": false, "MinPasswordLen": minPasswordLen,
			"Error": "", "Success": ""},
		{"Active": "account", "StepUpRequired": true, "MinPasswordLen": minPasswordLen,
			"Error": "", "Success": "",
			"User": &User{ID: uuid.New(), Username: "sso", OIDCSubject: "s",
				OIDCIssuer: "https://idp.example"}},
	}
	shellCases := []map[string]any{
		{"Usage": UsageSummary{UsedBytes: 1 << 30, UsedFiles: 900,
			Quota: UserQuota{Files: 1000}}},
		{"Usage": UsageSummary{UsedBytes: 1 << 30, UsedFiles: 4}},
		{"Usage": UsageSummary{UsedBytes: 19 << 30, UsedFiles: 4,
			Quota: UserQuota{Bytes: 20 << 30}, Custom: true}},
		{"Usage": nil},
	}
	batchCases := []map[string]any{
		{"State": "batch", "E2EMode": "url", "Unlocked": true, "ID": uuid.NewString(),
			"FileCount": 3, "TotalSize": int64(4096), "UploadedAt": now,
			"ExpiresAt": exp.UTC(), "HasLimit": true, "MaxDL": 10, "DownloadsLeft": 7,
			"User": (*User)(nil)},
		// Password batch before unlock: no count, no size, no expiry.
		{"State": "batch", "E2EMode": "password", "Unlocked": false, "ID": uuid.NewString(),
			"FileCount": 0, "TotalSize": int64(0), "UploadedAt": now,
			"AuthSalt": "c2FsdHNhbHRzYWx0c2E", "HasLimit": false, "User": (*User)(nil)},
	}

	for _, lang := range supportedLangs {
		for name, extra := range cases {
			var sb strings.Builder
			if err := tmpl.ExecuteTemplate(&sb, name, merge(lang, extra)); err != nil {
				t.Errorf("%s [%s]: %v", name, lang, err)
			}
		}
		for i, extra := range dlCases {
			var sb strings.Builder
			if err := tmpl.ExecuteTemplate(&sb, "download.html", merge(lang, extra)); err != nil {
				t.Errorf("download.html case %d [%s]: %v", i, lang, err)
			}
		}
		for i, extra := range accountCases {
			var sb strings.Builder
			if err := tmpl.ExecuteTemplate(&sb, "account.html", merge(lang, extra)); err != nil {
				t.Errorf("account.html case %d [%s]: %v", i, lang, err)
			}
		}
		for i, extra := range shellCases {
			var sb strings.Builder
			extra["StepUpRequired"] = false
			extra["MinPasswordLen"] = minPasswordLen
			if err := tmpl.ExecuteTemplate(&sb, "account.html", merge(lang, extra)); err != nil {
				t.Errorf("shell quota bar case %d [%s]: %v", i, lang, err)
			}
		}
		for i, extra := range batchCases {
			var sb strings.Builder
			if err := tmpl.ExecuteTemplate(&sb, "batch.html", merge(lang, extra)); err != nil {
				t.Errorf("batch.html case %d [%s]: %v", i, lang, err)
			}
		}
	}
}

// TestStorageBarVisibility pins who sees which bar. Free space on the volume
// is instance capacity, which a member cannot act on and which says more about
// the host than they need — the disk bar is admin-only, and a member gets the
// bar for the limit that actually binds them. Both rules are decided in the
// layout precisely so they can be checked here.
func TestStorageBarVisibility(t *testing.T) {
	tmpl, err := loadTemplates()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	disk := DiskStats{Total: 500 << 30, Used: 142 << 30, Free: 358 << 30, Percent: 28.4, OK: true}
	limited := UsageSummary{UsedBytes: 3 << 30, UsedFiles: 12,
		Quota: UserQuota{Bytes: 20 << 30, Files: 1000}}

	render := func(u *User, data map[string]any) string {
		t.Helper()
		m := map[string]any{
			"Lang": "en", "I18N": jsStrings("en"), "ReqPath": "/", "Title": "t",
			"Theme": "dark", "User": u, "Active": "upload", "MaxUpload": int64(1 << 30),
		}
		for k, v := range data {
			m[k] = v
		}
		var sb strings.Builder
		if err := tmpl.ExecuteTemplate(&sb, "index.html", m); err != nil {
			t.Fatalf("render: %v", err)
		}
		return sb.String()
	}

	member := &User{ID: uuid.New(), Username: "guest"}
	admin := &User{ID: uuid.New(), Username: "root", IsAdmin: true}

	// Even handed Disk outright, a member must never be shown it.
	out := render(member, map[string]any{"Disk": disk, "Usage": limited})
	if strings.Contains(out, `aria-label="Disk usage"`) {
		t.Error("a non-admin was shown the instance disk usage bar")
	}
	if !strings.Contains(out, `aria-label="Your storage"`) {
		t.Error("a limited non-admin was not shown their quota bar")
	}

	out = render(admin, map[string]any{"Disk": disk, "Usage": limited})
	if !strings.Contains(out, `aria-label="Disk usage"`) {
		t.Error("an admin lost the disk usage bar")
	}
	if !strings.Contains(out, `aria-label="Your storage"`) {
		t.Error("an admin with an explicit quota was not shown their quota bar")
	}

	// Nothing caps this user, so a bar towards "unlimited" would be decoration.
	out = render(admin, map[string]any{"Disk": disk, "Usage": UsageSummary{UsedBytes: 1 << 30}})
	if strings.Contains(out, `aria-label="Your storage"`) {
		t.Error("a quota bar was drawn for a user with no limit")
	}

	// A signed-out visitor gets neither, and no nil dereference.
	out = render(nil, map[string]any{})
	if strings.Contains(out, `aria-label="Disk usage"`) ||
		strings.Contains(out, `aria-label="Your storage"`) {
		t.Error("a storage bar rendered with no signed-in user")
	}
}

// TestE2EScriptIncluded guards the wiring between e2e.js and app.js. app.js
// reads window.PYXIS_E2E and fails every upload closed with "Encryption
// unavailable" when it is missing, so a layout that forgets the script tag
// breaks uploads in every browser while all other tests still pass — which is
// exactly how it shipped once. Both shells need it: the app shell uploads, the
// bare shell decrypts on the download landing page.
func TestE2EScriptIncluded(t *testing.T) {
	tmpl, err := loadTemplates()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	user := &User{ID: uuid.New(), Username: "marius", HasPassword: true}
	data := map[string]any{
		"Lang": "en", "I18N": jsStrings("en"), "ReqPath": "/", "Title": "t",
		"Theme": "dark", "User": user, "Active": "upload",
		"Disk":      DiskStats{Total: 1 << 30, Free: 1 << 30, OK: true},
		"MaxUpload": int64(1 << 30),
		// download.html (bare shell) fields:
		"State": "ready", "ID": "id1", "Name": "f.bin", "Size": int64(5),
		"ContentType": "application/octet-stream", "UploadedAt": time.Now(),
		"IconKind": "generic",
	}

	for _, name := range []string{"index.html", "download.html"} {
		var sb strings.Builder
		if err := tmpl.ExecuteTemplate(&sb, name, data); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out := sb.String()
		e2e := strings.Index(out, "/static/e2e.js")
		app := strings.Index(out, "/static/app.js")
		if e2e < 0 {
			t.Errorf("%s: does not load /static/e2e.js; window.PYXIS_E2E will be "+
				"undefined and every upload fails closed", name)
			continue
		}
		if app >= 0 && e2e > app {
			t.Errorf("%s: loads e2e.js after app.js", name)
		}
	}
}

// TestSwitcherLinkShape pins the URL shape app.js keys off when it re-attaches
// the fragment to the language/theme switchers. On a share page that fragment
// is the decryption key: if these links stop starting with "/lang?" / "/theme?"
// the selector silently stops matching, switching language drops the key, and
// nothing else fails. The share pages use the bare shell, so it is checked there.
func TestSwitcherLinkShape(t *testing.T) {
	tmpl, err := loadTemplates()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	data := map[string]any{
		"Lang": "en", "I18N": jsStrings("en"), "ReqPath": "/b/abc", "Title": "t",
		"Theme": "dark", "User": (*User)(nil), "State": "gone", "Gone": "g",
		"Disk": DiskStats{OK: true},
	}
	var sb strings.Builder
	if err := tmpl.ExecuteTemplate(&sb, "download.html", data); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := sb.String()
	for _, want := range []string{`href="/lang?`, `href="/theme?`} {
		if !strings.Contains(out, want) {
			t.Errorf("bare shell has no link starting %s — app.js cannot re-attach "+
				"the URL fragment, so switching language would drop the share key", want)
		}
	}
	// The key must never ride in `next`: that is a query string, and reaches
	// the server. The fragment is re-attached client-side instead.
	if strings.Contains(out, "next=%2Fb%2Fabc%23") || strings.Contains(out, "next=/b/abc#") {
		t.Error("switcher link puts a fragment in `next`, sending it to the server")
	}
}

// TestJSStringsResolve catches a key listed in jsStrings but absent from the
// translations map. tr() falls back to the key itself, so the mistake shows up
// only as a raw "reason_network" rendered in the UI — never as a failure.
func TestJSStringsResolve(t *testing.T) {
	for _, lang := range supportedLangs {
		for key, val := range jsStrings(lang) {
			// tr() echoes the key on a miss. jsStrings strips a "js." prefix,
			// so an unresolved entry shows up either bare or still prefixed.
			if val == key || val == "js."+key || strings.TrimSpace(val) == "" {
				t.Errorf("jsStrings[%s][%q] unresolved: %q", lang, key, val)
			}
		}
	}
}

func TestTranslationsComplete(t *testing.T) {
	for key, entry := range translations {
		for _, lang := range supportedLangs {
			if strings.TrimSpace(entry[lang]) == "" {
				t.Errorf("key %q missing %s translation", key, lang)
			}
		}
	}
}
