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

	userRows := []UserRow{
		{ID: uid, Username: "marius", Email: "m@example.com", IsAdmin: true,
			IsSuperAdmin: true, HasPassword: true, HasOIDC: true, CreatedAt: now},
		{ID: uuid.NewString(), Username: "guest", CreatedAt: now},
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
		"login.html":   {"User": (*User)(nil), "OIDCEnabled": true, "Next": "/", "Error": "x"},
		"account.html": {"Active": "account", "Error": "", "Success": "ok"},
		"admin_users.html": {"Active": "users", "Users": userRows, "MeID": uid,
			"MeIsSuper": false, "Error": "", "Success": ""},
		"admin_settings.html": {"Active": "settings", "OIDC": OIDCSettings{Issuer: "https://x"},
			"OIDCLive": false, "Error": "", "Success": ""},
		"oidc_denied.html": {"User": (*User)(nil), "AllowedDomain": "a.example", "ActualDomain": "b.example"},
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
	dlCases := []map[string]any{
		{"State": "gone", "Gone": "gone msg", "User": (*User)(nil)},
		{"State": "locked", "ID": "id1", "Name": "f.bin", "Size": int64(5), "Error": "bad", "User": (*User)(nil)},
		{"State": "ready", "ID": "id1", "Name": "photo.jpg", "Size": int64(5),
			"ContentType": "image/jpeg", "UploadedAt": now, "ExpiresAt": exp.UTC(),
			"HasLimit": true, "MaxDL": 3, "DownloadsLeft": 2,
			"PreviewKind": "image", "IconKind": "image", "User": (*User)(nil),
			"Keyed": false, "KeyCookie": "fsk_x"},
		{"State": "ready", "ID": "id1", "Name": "blob.bin", "Size": int64(5),
			"ContentType": "application/octet-stream", "UploadedAt": now,
			"HasLimit": false, "PreviewKind": "", "IconKind": "generic", "User": (*User)(nil),
			"Keyed": false, "KeyCookie": "fsk_x"},
		{"State": "ready", "ID": "id1", "Name": "keyed.png", "Size": int64(5),
			"ContentType": "image/png", "UploadedAt": now,
			"HasLimit": false, "PreviewKind": "image", "IconKind": "image", "User": (*User)(nil),
			"Keyed": true, "KeyCookie": "fsk_x"},
		{"State": "ready", "ID": "id1", "Name": "keyed.txt", "Size": int64(5),
			"ContentType": "text/plain", "UploadedAt": now,
			"HasLimit": false, "PreviewKind": "text", "IconKind": "text", "User": (*User)(nil),
			"Keyed": true, "KeyCookie": "fsk_x"},
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
		for i, extra := range batchCases {
			var sb strings.Builder
			if err := tmpl.ExecuteTemplate(&sb, "batch.html", merge(lang, extra)); err != nil {
				t.Errorf("batch.html case %d [%s]: %v", i, lang, err)
			}
		}
	}
}

// TestE2EScriptIncluded guards the wiring between e2e.js and app.js. app.js
// reads window.KFS_E2E and fails every upload closed with "Encryption
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
		"IconKind": "generic", "KeyCookie": "fsk_x",
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
			t.Errorf("%s: does not load /static/e2e.js; window.KFS_E2E will be "+
				"undefined and every upload fails closed", name)
			continue
		}
		if app >= 0 && e2e > app {
			t.Errorf("%s: loads e2e.js after app.js", name)
		}
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
