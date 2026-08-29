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
	files := []File{
		{ID: uuid.NewString(), OriginalName: "photo.jpg", Size: 12345, ContentType: "image/jpeg",
			UploadedAt: now, UploaderName: "marius", UploadedBy: &uid, ExpiresAt: &exp,
			HasPassword: true, HasLimit: true, MaxDL: 3, DownloadCount: 3, CanDelete: true, IconKind: "image"},
		{ID: uuid.NewString(), OriginalName: "notes.txt", Size: 42, ContentType: "text/plain",
			UploadedAt: now, DownloadCount: 1, IconKind: "text", Keyed: true},
		{ID: uuid.NewString(), OriginalName: "old.zip", Size: 99, ContentType: "application/zip",
			UploadedAt: now, DownloadCount: 5, Archived: true, CanDelete: true, IconKind: "archive"},
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
