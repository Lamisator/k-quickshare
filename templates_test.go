package main

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
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
	loneBatchID := uuid.NewString()
	files := []File{
		{ID: uuid.NewString(), OriginalName: "photo.jpg", Size: 12345, ContentType: "image/jpeg",
			UploadedAt: now, UploaderName: "marius", UploadedBy: &uid, ExpiresAt: &exp,
			HasPassword: true, HasLimit: true, MaxDL: 3, DownloadCount: 3, CanDelete: true, IconKind: "image"},
		{ID: uuid.NewString(), OriginalName: "notes.txt", Size: 42, ContentType: "text/plain",
			UploadedAt: now, DownloadCount: 1, IconKind: "text", Keyed: true},
		{ID: uuid.NewString(), OriginalName: "old.zip", Size: 99, ContentType: "application/zip",
			UploadedAt: now, DownloadCount: 5, Archived: true, CanDelete: true, IconKind: "archive"},
		// Batch members: two of them, so they fold under a group header that
		// links to /b/{batch} rather than each row linking for itself.
		{ID: uuid.NewString(), OriginalName: "in-batch.png", Size: 512, ContentType: "image/png",
			UploadedAt: now, UploaderName: "marius", UploadedBy: &uid, ExpiresAt: &exp,
			CanDelete: true, IconKind: "image", BatchID: &batchID},
		{ID: uuid.NewString(), OriginalName: "in-batch.pdf", Size: 900, ContentType: "application/pdf",
			UploadedAt: now, UploaderName: "marius", UploadedBy: &uid, ExpiresAt: &exp,
			CanDelete: true, IconKind: "pdf", BatchID: &batchID},
		// A batch with one member stays a plain row: there is nothing to fold.
		{ID: uuid.NewString(), OriginalName: "alone.txt", Size: 12, ContentType: "text/plain",
			UploadedAt: now, UploaderName: "marius", UploadedBy: &uid,
			CanDelete: true, IconKind: "text", BatchID: &loneBatchID},
		// A container version 4 upload: the server has no name for it, only a
		// sealed blob, so the row has to render without one.
		{ID: uuid.NewString(), Size: 4096, ContentType: "application/pdf",
			EncName: "c2VhbGVkLW5hbWUtYmxvYg", UploadedAt: now, UploaderName: "marius",
			UploadedBy: &uid, CanDelete: true, IconKind: "pdf"},
		// A version 5 upload: no name AND no type, so not even the icon is
		// anything but generic.
		{ID: uuid.NewString(), Size: 8192, EncName: "c2VhbGVkLW5hbWUtYmxvYg",
			UploadedAt: now, UploaderName: "marius", UploadedBy: &uid,
			CanDelete: true, IconKind: "generic"},
	}
	fileGroups, hasBatches := groupFiles(files)

	// One drop of each shape the list has to draw: an open one with limits, and
	// a closed one with none.
	dropRows := []DropRow{
		{ID: uuid.NewString(), PublicID: uuid.NewString(), Label: "Signed contract",
			CreatedAt: now, ExpiresAt: &exp, Files: 2, Submissions: 1, Bytes: 4096,
			MaxFiles: 3, MaxPerSubmission: 1, MaxSubmissions: 2,
			MaxFileBytes: 1 << 20, MaxTotalBytes: 1 << 30, HasPassword: true},
		{ID: uuid.NewString(), PublicID: uuid.NewString(),
			CreatedAt: now, ClosedAt: &now, Files: 0, Submissions: 0, Bytes: 0},
	}

	customBytes := int64(5 << 30)
	customUpload := int64(2 << 30)
	userRows := []UserRow{
		// An admin on the default: unlimited, no override to render.
		{ID: uid, Username: "marius", Email: "m@example.com", IsAdmin: true,
			IsSuperAdmin: true, HasPassword: true, HasOIDC: true, CreatedAt: now,
			UsedBytes: 3 << 30, UsedFiles: 12, EffMaxUpload: 512 << 20},
		// A member with a custom byte quota but an inherited file limit, which
		// is the case where the two form fields disagree about being blank.
		{ID: uuid.NewString(), Username: "guest", CreatedAt: now,
			QuotaBytes: &customBytes, UsedBytes: 1 << 30, UsedFiles: 3,
			EffQuota: UserQuota{Bytes: customBytes, Files: 1000}, Custom: true,
			QuotaBytesInput: sizeInput(customBytes),
			// An upload ceiling of their own, which is a separate override
			// from the quota and renders its own chip.
			MaxUploadBytes: &customUpload, EffMaxUpload: customUpload,
			MaxUploadInput: sizeInput(customUpload)},
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
		"history.html": {"Active": "files", "Groups": fileGroups, "HasBatches": hasBatches,
			"Heading": "My files", "Sub": "yours", "Everyone": false,
			"ActiveCount": 2, "TotalSize": int64(999), "TotalDL": 4},
		"login.html": {"User": (*User)(nil), "OIDCEnabled": true, "Next": "/", "Error": "x"},
		"account.html": {"Active": "account", "Error": "", "Success": "ok",
			"StepUpRequired": false, "MinPasswordLen": minPasswordLen},
		"admin_users.html": {"Active": "users", "Users": userRows, "MeID": uid,
			"MeIsSuper": false, "Error": "", "Success": ""},
		"admin_settings.html": {"Active": "settings", "OIDC": OIDCSettings{Issuer: "https://x"},
			"OIDCLive": false, "Error": "", "Success": "",
			"QuotaBytes": sizeInput(20 << 30), "QuotaFiles": int64(1000),
			"MaxUpload": sizeInput(512 << 20)},
		"oidc_denied.html": {"User": (*User)(nil), "AllowedDomain": "a.example", "ActualDomain": "b.example"},
		// A drop's three pages. The owner's list renders what the server may
		// know — counts, sizes, terms — and nothing it may not, because it
		// holds no key for any of it.
		"drops.html": {"Active": "drops", "MaxUpload": int64(1 << 30), "Drops": dropRows},
		// The public page as a stranger sees it: no session, no listing, and
		// the recipient's key still sealed.
		"drop_upload.html": {"User": (*User)(nil), "PublicID": uuid.NewString(),
			"Label": "Signed contract", "Note": "Please send the countersigned copy.",
			"Open": true, "Closed": false, "HasPassword": true, "Unlocked": false,
			"DropVersion": dropCurrentVersion, "MaxUpload": int64(512 << 20),
			"AuthSalt": "c2FsdA", "ExpiresAt": exp.UTC(),
			"MaxFiles": 3, "MaxPerSubmission": 1, "MaxTotalBytes": int64(1 << 30),
			"FilesLeft": int64(2), "BytesLeft": int64(1 << 29),
			"FilesUsed": int64(1), "BytesUsed": int64(1 << 29)},
		// The inbox is the batch page with a different front door, so it is
		// rendered with the same empty shell: everything in it arrives as
		// ciphertext and is built by app.js.
		"inbox.html": {"User": (*User)(nil), "ID": uuid.NewString(), "PublicID": uuid.NewString(),
			"Label": "Signed contract", "CreatedAt": now, "ExpiresAt": exp.UTC(),
			"FileCount": int64(4), "TotalSize": int64(4096), "Submissions": int64(2),
			"Open": true, "DropVersion": dropCurrentVersion},
	}
	// Only two states survive: "gone", and the end-to-end landing page. The
	// server-decrypted and server-password-gated states went with key modes 0-2.
	dlCases := []map[string]any{
		{"State": "gone", "Gone": "gone msg", "User": (*User)(nil)},
		{"State": "e2e", "E2EMode": "url", "ID": "id1", "Name": "photo.jpg", "Size": int64(5),
			"ContentType": "image/jpeg", "UploadedAt": now, "ExpiresAt": exp.UTC(),
			"HasLimit": true, "MaxDL": 3, "DownloadsLeft": 2,
			"PreviewKind": "", "IconKind": "image", "User": (*User)(nil),
			"E2EVersion": e2eVersionV3, "Manifest": "eyJ2IjoyfQ", "EncName": "", "ManifestID": ""},
		// Version 4: no name on the page at all, only the sealed blob and the
		// manifest id that binds it, which is what the browser opens it with.
		{"State": "e2e", "E2EMode": "url", "ID": "id4", "Name": "", "Size": int64(4096),
			"ContentType": "application/pdf", "UploadedAt": now,
			"HasLimit": false, "PreviewKind": "", "IconKind": "pdf", "User": (*User)(nil),
			"E2EVersion": e2eVersionV4, "Manifest": "eyJ2Ijo0fQ",
			"EncName": "c2VhbGVkLW5hbWUtYmxvYg", "ManifestID": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"},
		// Version 5: no type either, so no icon bucket and no preview decision
		// until the browser opens the sealed blob.
		{"State": "e2e", "E2EMode": "url", "ID": "id5", "Name": "", "Size": int64(8192),
			"ContentType": "", "UploadedAt": now,
			"HasLimit": false, "PreviewKind": "", "IconKind": "generic", "User": (*User)(nil),
			"E2EVersion": e2eVersionV5, "Manifest": "eyJ2Ijo1fQ",
			"EncName": "c2VhbGVkLW5hbWUtYmxvYg", "ManifestID": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"},
		{"State": "e2e", "E2EMode": "url", "ID": "id1", "Name": "blob.bin", "Size": int64(5),
			"ContentType": "application/octet-stream", "UploadedAt": now,
			"HasLimit": false, "PreviewKind": "", "IconKind": "generic", "User": (*User)(nil),
			// A share from before the manifest existed: version 1, no manifest.
			"E2EVersion": e2eVersionLegacy, "Manifest": "", "EncName": "", "ManifestID": ""},
		{"State": "e2e", "E2EMode": "password", "ID": "id1", "Name": "secret.txt", "Size": int64(5),
			"ContentType": "text/plain", "UploadedAt": now, "AuthSalt": "c2FsdHNhbHRzYWx0c2E",
			"HasLimit": false, "PreviewKind": "text", "IconKind": "text", "User": (*User)(nil),
			"E2EVersion": e2eVersionV3, "Manifest": "eyJ2IjoyfQ", "EncName": "", "ManifestID": ""},
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
	// The same template serves /admin/files, and an empty list on either page.
	listCases := []map[string]any{
		{"Active": "allfiles", "Groups": fileGroups, "HasBatches": hasBatches,
			"Heading": "All files", "Sub": "everyone's", "Everyone": true,
			"ActiveCount": 2, "TotalSize": int64(999), "TotalDL": 4},
		{"Active": "allfiles", "Groups": []FileGroup(nil), "HasBatches": false,
			"Heading": "All files", "Sub": "everyone's", "Everyone": true,
			"ActiveCount": 0, "TotalSize": int64(0), "TotalDL": 0},
		{"Active": "files", "Groups": []FileGroup(nil), "HasBatches": false,
			"Heading": "My files", "Sub": "yours", "Everyone": false,
			"ActiveCount": 0, "TotalSize": int64(0), "TotalDL": 0},
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
		for i, extra := range listCases {
			var sb strings.Builder
			if err := tmpl.ExecuteTemplate(&sb, "history.html", merge(lang, extra)); err != nil {
				t.Errorf("history.html case %d [%s]: %v", i, lang, err)
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

// TestStorageBarsRefreshable pins the two halves of the live refresh: the
// shell must carry the slot app.js replaces, and "storagebars" must render on
// its own, because that is what /usage answers with. Rendering the bars only
// as part of the page would leave the figures frozen until the next
// navigation — which on the upload page is precisely when nobody navigates.
func TestStorageBarsRefreshable(t *testing.T) {
	tmpl, err := loadTemplates()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	admin := &User{ID: uuid.New(), Username: "root", IsAdmin: true}
	data := map[string]any{
		"Lang": "en", "I18N": jsStrings("en"), "ReqPath": "/", "Title": "t",
		"Theme": "dark", "User": admin, "Active": "upload", "MaxUpload": int64(1 << 30),
		"Disk": DiskStats{Total: 500 << 30, Used: 142 << 30, Free: 358 << 30,
			Percent: 28.4, OK: true},
		"Usage": UsageSummary{UsedBytes: 3 << 30, UsedFiles: 12,
			Quota: UserQuota{Bytes: 20 << 30, Files: 1000}},
	}

	var page strings.Builder
	if err := tmpl.ExecuteTemplate(&page, "index.html", data); err != nil {
		t.Fatalf("render page: %v", err)
	}
	if !strings.Contains(page.String(), `id="storage-bars"`) {
		t.Error(`the shell has no id="storage-bars" slot — app.js has nothing to ` +
			`replace after an upload, so both bars stay at their page-load figures`)
	}

	// What /usage returns, standing alone.
	var frag strings.Builder
	if err := tmpl.ExecuteTemplate(&frag, "storagebars", data); err != nil {
		t.Fatalf("render fragment: %v", err)
	}
	for _, want := range []string{`aria-label="Disk usage"`, `aria-label="Your storage"`,
		`class="disk-fill" data-pct=`} {
		if !strings.Contains(frag.String(), want) {
			t.Errorf("the /usage fragment is missing %s", want)
		}
	}
	// The fragment is spliced into a live page, so it must be the bars and
	// nothing else — a stray <body> or a second copy of the sidebar would be
	// grafted into the middle of the document.
	if strings.Contains(frag.String(), "<body") || strings.Contains(frag.String(), "<aside") {
		t.Error("the /usage fragment carries page chrome; it must be the bars alone")
	}
}

// TestUploadLimitIsEditable pins the admin surface for the per-file ceiling.
// The limit exists in three places — the instance form, the per-user override
// and the hint the uploader reads — and a rename in one of them that silently
// stops matching the handler would leave a form that saves nothing.
func TestUploadLimitIsEditable(t *testing.T) {
	tmpl, err := loadTemplates()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	admin := &User{ID: uuid.New(), Username: "root", IsAdmin: true}
	base := map[string]any{
		"Lang": "en", "I18N": jsStrings("en"), "ReqPath": "/", "Title": "t",
		"Theme": "dark", "User": admin, "Error": "", "Success": "",
	}
	render := func(name string, extra map[string]any) string {
		t.Helper()
		m := map[string]any{}
		for k, v := range base {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		var sb strings.Builder
		if err := tmpl.ExecuteTemplate(&sb, name, m); err != nil {
			t.Fatalf("render %s: %v", name, err)
		}
		return sb.String()
	}

	// The instance-wide form must post the field handleAdminSettingsUpload reads.
	out := render("admin_settings.html", map[string]any{
		"Active": "settings", "OIDC": OIDCSettings{}, "OIDCLive": false,
		"QuotaBytes": sizeInput(20 << 30), "QuotaFiles": int64(1000),
		"MaxUpload": sizeInput(512 << 20),
	})
	for _, want := range []string{`action="/admin/settings/upload"`, `name="max_bytes"`, "512 MiB"} {
		if !strings.Contains(out, want) {
			t.Errorf("admin settings: no %s — the instance upload limit cannot be saved", want)
		}
	}

	// The per-user override rides on the row's existing limits form, so it must
	// post to the same place handleAdminSetQuota is routed to.
	custom := int64(2 << 30)
	out = render("admin_users.html", map[string]any{
		"Active": "users", "MeID": admin.ID.String(), "MeIsSuper": true,
		"Users": []UserRow{{
			ID: uuid.NewString(), Username: "guest", CreatedAt: time.Now(),
			EffQuota: UserQuota{Bytes: 5 << 30}, EffMaxUpload: custom,
			MaxUploadBytes: &custom, MaxUploadInput: sizeInput(custom),
		}},
	})
	for _, want := range []string{`name="max_upload"`, `value="2 GiB"`, "max per file:"} {
		if !strings.Contains(out, want) {
			t.Errorf("admin users: no %s — the per-user upload limit cannot be set or read", want)
		}
	}

	// And the uploader is told the ceiling that will actually be applied to
	// them, which is what app.js checks a file against before encrypting it.
	out = render("index.html", map[string]any{"Active": "upload", "MaxUpload": custom})
	if !strings.Contains(out, `data-max-upload="2147483648"`) {
		t.Error("the upload form does not carry the user's own limit; app.js would " +
			"pre-flight files against the wrong size")
	}
}

// TestUserRowsCarryTheirColumnNames guards the narrow-screen layout of the
// users page. Below 900px the table becomes one card per account and the
// heading row is hidden, so each cell's label comes from its own data-label
// attribute; a cell that loses the attribute renders as a bare value under no
// heading, and only on a phone, where nobody is looking when the test suite
// runs on a desktop.
func TestUserRowsCarryTheirColumnNames(t *testing.T) {
	tmpl, err := loadTemplates()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	admin := &User{ID: uuid.New(), Username: "root", IsAdmin: true}
	var sb strings.Builder
	err = tmpl.ExecuteTemplate(&sb, "admin_users.html", map[string]any{
		"Lang": "en", "I18N": jsStrings("en"), "ReqPath": "/", "Title": "t",
		"Theme": "dark", "User": admin, "Active": "users", "Error": "", "Success": "",
		"MeID": admin.ID.String(), "MeIsSuper": true,
		"Users": []UserRow{{
			ID: uuid.NewString(), Username: "guest", Email: "g@example.com",
			CreatedAt: time.Now(), EffQuota: UserQuota{Bytes: 5 << 30}, EffMaxUpload: 512 << 20,
		}},
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	out := sb.String()

	// Every column the card layout has to caption, in the words the hidden
	// header row would have used.
	for _, want := range []string{
		`data-label="Email"`, `data-label="Methods"`, `data-label="Role"`,
		`data-label="Usage / quota"`, `data-label="Created"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("a user row cell has no %s; on a phone that value renders "+
				"under no heading at all", want)
		}
	}

	// The limits editor's captions are the other half: stacked on a phone, a
	// field holding a value shows no placeholder, and two of the three read the
	// same. They are wrapped in labels, which is also what names them for a
	// screen reader.
	for _, want := range []string{
		`class="inline-field"`, "<span>Storage</span>", "<span>Files</span>",
		"<span>Max per file</span>",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the limits editor is missing %s", want)
		}
	}
}

// TestE2EScriptIncluded guards the wiring between e2e.js and app.js.// TestE2EScriptIncluded guards the wiring between e2e.js and app.js.// TestE2EScriptIncluded guards the wiring between e2e.js and app.js. app.js
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
// TestCopyButtonsCarryTheirHandlerClass pins the one thing that makes a copy
// button work.
//
// app.js binds copying through ONE delegated listener keyed on `.btn-copy`, so
// that buttons added after load (a share panel, a drop's two links) work without
// rebinding. A button that carries data-copy but not the class is inert: it
// renders, it highlights on hover, and clicking it does nothing at all. That is
// precisely what happened to the drop links, and nothing else failed — no error,
// no console message, no test.
func TestCopyButtonsCarryTheirHandlerClass(t *testing.T) {
	entries, err := os.ReadDir("web/templates")
	if err != nil {
		t.Fatalf("read templates: %v", err)
	}
	// The opening tag of an element carrying data-copy, back to its "<".
	tagWithCopy := regexp.MustCompile(`(?s)<[a-zA-Z][^<>]*\bdata-copy=[^<>]*>`)
	checked := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".html") {
			continue
		}
		src, err := os.ReadFile(filepath.Join("web/templates", e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		for _, tag := range tagWithCopy.FindAllString(string(src), -1) {
			checked++
			if !strings.Contains(tag, "btn-copy") {
				t.Errorf("%s: an element has data-copy but not the btn-copy class, so "+
					"clicking it does nothing:\n  %s", e.Name(), strings.TrimSpace(tag))
			}
		}
	}
	if checked == 0 {
		t.Fatal("no data-copy elements found; the guard would pass vacuously")
	}
}

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

// TestGroupFilesFolding pins how the history list folds. A batch has to appear
// once, at the position of its newest member, with the whole share summed under
// it; anything else — a lone file, or a batch that only ever held one file —
// has to stay the plain row it was, or the list would grow a fold control that
// hides nothing.
func TestGroupFilesFolding(t *testing.T) {
	b1, b2 := "batch-1", "batch-2"
	files := []File{
		{ID: "a", Size: 100, BatchID: &b1, CanDelete: true},
		{ID: "b", Size: 10},
		{ID: "c", Size: 200, BatchID: &b1},
		{ID: "d", Size: 5, BatchID: &b2, CanDelete: true},
		{ID: "e", Size: 300, BatchID: &b1, CanDelete: true},
	}
	groups, batched := groupFiles(files)
	if !batched {
		t.Fatal("batched = false with a multi-member batch present")
	}
	if len(groups) != 3 {
		t.Fatalf("got %d groups, want 3", len(groups))
	}

	// batch-1 keeps the slot of its newest member — ahead of the lone file that
	// was uploaded after its second member.
	g := groups[0]
	if !g.IsBatch() || g.BatchID != b1 || g.Count() != 3 {
		t.Errorf("group 0 = %+v, want the 3-file batch-1", g)
	}
	if g.Size != 600 {
		t.Errorf("batch-1 size = %d, want 600", g.Size)
	}
	if g.Deletable != 2 {
		t.Errorf("batch-1 deletable = %d, want 2", g.Deletable)
	}
	if g.Head().ID != "a" {
		t.Errorf("batch-1 head = %q, want the newest member \"a\"", g.Head().ID)
	}
	for i, want := range []string{"a", "c", "e"} {
		if g.Files[i].ID != want {
			t.Errorf("batch-1 member %d = %q, want %q", i, g.Files[i].ID, want)
		}
	}

	if groups[1].IsBatch() || groups[1].Files[0].ID != "b" || groups[1].BatchID != "" {
		t.Errorf("group 1 = %+v, want the unbatched file \"b\"", groups[1])
	}
	// One member: a batch id, but nothing to fold.
	if groups[2].IsBatch() || groups[2].Files[0].ID != "d" || groups[2].BatchID != b2 {
		t.Errorf("group 2 = %+v, want the single-member batch-2", groups[2])
	}

	if _, batched := groupFiles(files[1:2]); batched {
		t.Error("batched = true for a list with no batch in it")
	}
}

// TestFileIconsResolve pins the sprite wiring. The icons moved from repeated
// inline SVG to one <symbol> set referenced by <use href="#fi-...">, which puts
// an action inside a URL attribute — exactly the context html/template rewrites
// — so "it executed without error" is not evidence that the reference survived.
// A mangled href renders a blank chip, which no other test would notice.
func TestFileIconsResolve(t *testing.T) {
	tmpl, err := loadTemplates()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Every bucket iconKind() can return must have a symbol to point at.
	kinds := []string{"image", "video", "audio", "pdf", "text", "doc", "archive", "generic"}
	for _, ct := range []string{"image/png", "video/mp4", "audio/ogg", "application/pdf",
		"text/plain", "application/json", "application/octet-stream"} {
		got := iconKind(ct, "f.bin")
		if !slices.Contains(kinds, got) {
			t.Errorf("iconKind(%q) = %q, which has no sprite symbol", ct, got)
		}
	}
	for _, name := range []string{"a.zip", "a.7z", "a.docx", "a.xlsx", "a.odp", "a.unknown"} {
		got := iconKind("application/octet-stream", name)
		if !slices.Contains(kinds, got) {
			t.Errorf("iconKind(name=%q) = %q, which has no sprite symbol", name, got)
		}
	}

	var sprite strings.Builder
	if err := tmpl.ExecuteTemplate(&sprite, "filesprite", nil); err != nil {
		t.Fatalf("filesprite: %v", err)
	}
	for _, k := range kinds {
		if !strings.Contains(sprite.String(), `id="fi-`+k+`"`) {
			t.Errorf("sprite has no symbol for kind %q", k)
		}
	}

	for _, k := range kinds {
		var out strings.Builder
		if err := tmpl.ExecuteTemplate(&out, "fileicon", k); err != nil {
			t.Fatalf("fileicon %q: %v", k, err)
		}
		want := `<use href="#fi-` + k + `"/>`
		if !strings.Contains(out.String(), want) {
			t.Errorf("fileicon %q rendered %q, want it to contain %q", k, out.String(), want)
		}
	}

	// A page that draws icons but forgets the sprite shows empty chips, so the
	// two have to travel together.
	for _, page := range []string{"history.html", "download.html", "batch.html"} {
		src, err := templatesFS.ReadFile("web/templates/" + page)
		if err != nil {
			t.Fatalf("read %s: %v", page, err)
		}
		if !strings.Contains(string(src), `{{template "filesprite" .}}`) {
			t.Errorf("%s renders file icons but does not include the sprite", page)
		}
	}
}
