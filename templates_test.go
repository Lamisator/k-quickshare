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
			"UsageOK": true, "Usage": UsageSummary{UsedBytes: 3 << 30, UsedFiles: 12,
				Quota: UserQuota{Bytes: 20 << 30, Files: 1000}, Custom: true}},
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
			"PreviewKind": "", "IconKind": "image", "User": (*User)(nil)},
		{"State": "e2e", "E2EMode": "url", "ID": "id1", "Name": "blob.bin", "Size": int64(5),
			"ContentType": "application/octet-stream", "UploadedAt": now,
			"HasLimit": false, "PreviewKind": "", "IconKind": "generic", "User": (*User)(nil)},
		{"State": "e2e", "E2EMode": "password", "ID": "id1", "Name": "secret.txt", "Size": int64(5),
			"ContentType": "text/plain", "UploadedAt": now, "AuthSalt": "c2FsdHNhbHRzYWx0c2E",
			"HasLimit": false, "PreviewKind": "text", "IconKind": "text", "User": (*User)(nil)},
	}
	// The unlimited and unavailable branches of the account storage panel emit
	// different markup (no bar, no percentage, or nothing at all) and are never
	// reached by the case above.
	accountCases := []map[string]any{
		{"Active": "account", "UsageOK": true,
			"Usage": UsageSummary{UsedBytes: 1 << 30, UsedFiles: 4}},
		{"Active": "account", "UsageOK": false},
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
		for i, extra := range batchCases {
			var sb strings.Builder
			if err := tmpl.ExecuteTemplate(&sb, "batch.html", merge(lang, extra)); err != nil {
				t.Errorf("batch.html case %d [%s]: %v", i, lang, err)
			}
		}
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
