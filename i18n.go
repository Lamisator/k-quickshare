package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

const langCookieName = "fileshare_lang"

var supportedLangs = []string{"en", "de"}

// translations maps key -> lang -> string. English is the fallback.
var translations = map[string]map[string]string{
	// --- app / nav ---
	"app.name":          {"en": "k-fileshare", "de": "k-fileshare"},
	"app.tagline":       {"en": "Private file sharing", "de": "Privates Dateiteilen"},
	"nav.section.share": {"en": "Share", "de": "Teilen"},
	"nav.upload":        {"en": "Upload", "de": "Hochladen"},
	"nav.files":         {"en": "My files", "de": "Meine Dateien"},
	"nav.section.admin": {"en": "Administration", "de": "Verwaltung"},
	"nav.users":         {"en": "Users", "de": "Benutzer"},
	"nav.settings":      {"en": "Settings", "de": "Einstellungen"},
	"nav.section.you":   {"en": "You", "de": "Du"},
	"nav.account":       {"en": "Account", "de": "Konto"},
	"nav.logout":        {"en": "Log out", "de": "Abmelden"},
	"badge.admin":       {"en": "admin", "de": "Admin"},
	"badge.super":       {"en": "super", "de": "Super"},
	"badge.you":         {"en": "you", "de": "du"},
	"disk.label":        {"en": "Disk usage", "de": "Speicherbelegung"},
	"disk.of":           {"en": "of", "de": "von"},
	"disk.free":         {"en": "%s free", "de": "%s frei"},
	"theme.dark":        {"en": "Dark mode", "de": "Dunkler Modus"},
	"theme.light":       {"en": "Light mode", "de": "Heller Modus"},

	// --- titles ---
	"title.upload":   {"en": "Upload", "de": "Hochladen"},
	"title.files":    {"en": "My files", "de": "Meine Dateien"},
	"title.login":    {"en": "Sign in", "de": "Anmelden"},
	"title.account":  {"en": "Account", "de": "Konto"},
	"title.users":    {"en": "Users", "de": "Benutzer"},
	"title.settings": {"en": "Settings", "de": "Einstellungen"},
	"title.download": {"en": "Shared file", "de": "Geteilte Datei"},

	// --- upload page ---
	"upload.heading":     {"en": "Share files", "de": "Dateien teilen"},
	"upload.sub":         {"en": "Drop files below, set your sharing options, and get a link to send around.", "de": "Dateien unten ablegen, Freigabe-Optionen wählen und einen Link zum Verschicken erhalten."},
	"upload.drop":        {"en": "Drop files here or", "de": "Dateien hier ablegen oder"},
	"upload.browse":      {"en": "browse", "de": "durchsuchen"},
	"upload.hint":        {"en": "Multiple files supported · up to %s each", "de": "Mehrere Dateien möglich · bis zu %s pro Datei"},
	"upload.options":     {"en": "Options for this batch", "de": "Optionen für diese Übertragung"},
	"upload.expiry":      {"en": "Link expires", "de": "Link läuft ab"},
	"expiry.never":       {"en": "Never", "de": "Nie"},
	"expiry.1h":          {"en": "After 1 hour", "de": "Nach 1 Stunde"},
	"expiry.24h":         {"en": "After 24 hours", "de": "Nach 24 Stunden"},
	"expiry.7d":          {"en": "After 7 days", "de": "Nach 7 Tagen"},
	"expiry.30d":         {"en": "After 30 days", "de": "Nach 30 Tagen"},
	"expiry.custom":      {"en": "On a specific date…", "de": "Zu einem Datum…"},
	"upload.expiry_at":   {"en": "Expiry date & time", "de": "Ablaufdatum & Uhrzeit"},
	"upload.password":    {"en": "Password", "de": "Passwort"},
	"upload.password_ph": {"en": "empty = public link", "de": "leer = öffentlicher Link"},
	"upload.maxdl":       {"en": "Download limit", "de": "Download-Limit"},
	"upload.maxdl_ph":    {"en": "unlimited", "de": "unbegrenzt"},
	"upload.queue":       {"en": "Uploads in this session", "de": "Uploads in dieser Sitzung"},
	"upload.view_all":    {"en": "View all files →", "de": "Alle Dateien ansehen →"},
	"upload.e2e":         {"en": "Files are encrypted in your browser before upload — the server only ever stores ciphertext. Without a password the key lives in the share link, so copy it right away: it can't be recovered later.", "de": "Dateien werden vor dem Hochladen in deinem Browser verschlüsselt — der Server speichert nur Chiffretext. Ohne Passwort steckt der Schlüssel im Freigabe-Link: kopiere ihn sofort, er lässt sich später nicht wiederherstellen."},

	// --- js strings (shared) ---
	"js.done":            {"en": "Done", "de": "Fertig"},
	"js.failed":          {"en": "Failed", "de": "Fehlgeschlagen"},
	"js.too_large":       {"en": "File too large", "de": "Datei zu groß"},
	"js.login":           {"en": "Sign-in required", "de": "Anmeldung erforderlich"},
	"js.network":         {"en": "Network error", "de": "Netzwerkfehler"},
	"js.copy":            {"en": "Copy link", "de": "Link kopieren"},
	"js.copied":          {"en": "Copied!", "de": "Kopiert!"},
	"js.toast_copied":    {"en": "Link copied to clipboard", "de": "Link in die Zwischenablage kopiert"},
	"js.toast_copyerr":   {"en": "Copy failed — check clipboard permissions", "de": "Kopieren fehlgeschlagen — Zwischenablage-Berechtigung prüfen"},
	"js.confirm_delete":  {"en": "Delete “%s”? The link stops working immediately.", "de": "„%s“ löschen? Der Link funktioniert danach sofort nicht mehr."},
	"js.protected":       {"en": "password-protected", "de": "passwortgeschützt"},
	"js.no_results":      {"en": "No files match your search.", "de": "Keine Dateien entsprechen deiner Suche."},
	"js.quota":           {"en": "Storage limit reached", "de": "Speicherlimit erreicht"},
	"js.rate_limited":    {"en": "Too many attempts", "de": "Zu viele Versuche"},
	"js.qr_title":        {"en": "Scan to open the share link", "de": "Scannen, um den Freigabe-Link zu öffnen"},
	"js.e2e_encrypting":  {"en": "Encrypting…", "de": "Verschlüsseln…"},
	"js.e2e_decrypting":  {"en": "Decrypting…", "de": "Entschlüsseln…"},
	"js.e2e_downloading": {"en": "Downloading…", "de": "Herunterladen…"},
	"js.e2e_deriving":    {"en": "Deriving key…", "de": "Schlüssel ableiten…"},
	"js.e2e_failed":      {"en": "Decryption failed", "de": "Entschlüsselung fehlgeschlagen"},
	"js.e2e_wrong_pw":    {"en": "Wrong password — please try again.", "de": "Falsches Passwort — bitte erneut versuchen."},
	"js.e2e_unsupported": {"en": "This browser cannot decrypt the file (WebCrypto unavailable over an insecure connection).", "de": "Dieser Browser kann die Datei nicht entschlüsseln (WebCrypto ist über eine unsichere Verbindung nicht verfügbar)."},
	"js.e2e_unavailable": {"en": "Encryption unavailable — upload refused", "de": "Verschlüsselung nicht verfügbar — Upload abgelehnt"},
	"js.e2e_insecure":    {"en": "Nothing was sent: encryption requires a secure (HTTPS) connection.", "de": "Es wurde nichts gesendet: Die Verschlüsselung erfordert eine sichere (HTTPS-)Verbindung."},

	// --- upload queue: cancel / retry / failure reasons ---
	"js.cancel":    {"en": "Cancel", "de": "Abbrechen"},
	"js.retry":     {"en": "Retry", "de": "Erneut versuchen"},
	"js.cancelled": {"en": "Cancelled", "de": "Abgebrochen"},
	"js.reason_cancelled": {"en": "Cancelled before the upload finished. Nothing was stored.",
		"de": "Vor Abschluss des Uploads abgebrochen. Es wurde nichts gespeichert."},
	"js.reason_network": {"en": "The connection was interrupted before the upload finished. Nothing was stored.",
		"de": "Die Verbindung wurde vor Abschluss des Uploads unterbrochen. Es wurde nichts gespeichert."},
	"js.reason_login": {"en": "Your session expired. Sign in again, then retry the upload.",
		"de": "Deine Sitzung ist abgelaufen. Melde dich erneut an und versuche den Upload noch einmal."},
	"js.reason_http": {"en": "The server rejected the upload (HTTP %s).",
		"de": "Der Server hat den Upload abgelehnt (HTTP %s)."},
	"js.reason_encrypt": {"en": "Encryption failed in this browser: %s",
		"de": "Die Verschlüsselung ist in diesem Browser fehlgeschlagen: %s"},

	// --- batch strings used by app.js ---
	"js.batch_link":         {"en": "Share link for all files", "de": "Freigabe-Link für alle Dateien"},
	"js.batch_count":        {"en": "%s in this link", "de": "%s in diesem Link"},
	"js.batch_new":          {"en": "Start a new link", "de": "Neuen Link starten"},
	"js.batch_download":     {"en": "Download", "de": "Herunterladen"},
	"js.batch_preview":      {"en": "Preview", "de": "Vorschau"},
	"js.batch_hide_preview": {"en": "Hide preview", "de": "Vorschau ausblenden"},
	"js.batch_preview_failed": {"en": "%s could not be previewed — its contents do not match its type.",
		"de": "%s konnte nicht in der Vorschau angezeigt werden — der Inhalt passt nicht zum Dateityp."},
	"js.batch_empty":    {"en": "This share has no files.", "de": "Diese Freigabe enthält keine Dateien."},
	"js.batch_zipping":  {"en": "Packing ZIP…", "de": "ZIP wird gepackt…"},
	"js.batch_fetching": {"en": "Downloading %s…", "de": "%s wird heruntergeladen…"},
	"js.batch_zip_too_large": {"en": "This batch is too large to zip in the browser (4 GiB limit). Download the files individually instead.",
		"de": "Dieser Stapel ist zu groß, um im Browser gezippt zu werden (4-GiB-Grenze). Lade die Dateien stattdessen einzeln herunter."},
	"js.batch_zip_name": {"en": "shared-files.zip", "de": "geteilte-dateien.zip"},
	"js.batch_options_locked": {"en": "Expiry, password and download limit apply to the whole link and were set with the first file. Start a new link to change them.",
		"de": "Ablauf, Passwort und Download-Limit gelten für den gesamten Link und wurden mit der ersten Datei festgelegt. Starte einen neuen Link, um sie zu ändern."},
	"js.batch_failed": {"en": "Could not load this share.", "de": "Diese Freigabe konnte nicht geladen werden."},

	// --- batch share (one link, many files) ---
	"batch.title":          {"en": "Shared files", "de": "Geteilte Dateien"},
	"batch.kicker":         {"en": "Someone shared these files with you", "de": "Jemand hat diese Dateien mit dir geteilt"},
	"batch.heading":        {"en": "Shared files", "de": "Geteilte Dateien"},
	"batch.n_files":        {"en": "%d files", "de": "%d Dateien"},
	"batch.one_file":       {"en": "1 file", "de": "1 Datei"},
	"batch.locked_summary": {"en": "Password protected", "de": "Passwortgeschützt"},
	"batch.pw_hint": {"en": "Enter the password to list and download these files.",
		"de": "Gib das Passwort ein, um diese Dateien zu sehen und herunterzuladen."},
	// The limit counts file downloads, not link opens: pulling a 5-file batch
	// spends 5, whether one at a time or via the zip.
	"batch.downloads_left": {"en": "%d of %d file downloads left", "de": "Noch %d von %d Dateidownloads"},
	"batch.download_all":   {"en": "Download all as ZIP", "de": "Alle als ZIP herunterladen"},
	"files.batch":          {"en": "In a batch", "de": "Im Stapel"},
	"files.batch_tip": {"en": "Shared together with other files under one link",
		"de": "Zusammen mit anderen Dateien unter einem Link geteilt"},

	// --- files / history page ---
	"files.heading":       {"en": "My files", "de": "Meine Dateien"},
	"files.sub":           {"en": "Everything shared on this instance, newest first.", "de": "Alles, was auf dieser Instanz geteilt wurde — Neuestes zuerst."},
	"files.search":        {"en": "Filter by name, type or uploader…", "de": "Nach Name, Typ oder Uploader filtern…"},
	"files.stat_count":    {"en": "Active files", "de": "Aktive Dateien"},
	"files.stat_size":     {"en": "Total size", "de": "Gesamtgröße"},
	"files.stat_dl":       {"en": "Downloads", "de": "Downloads"},
	"files.empty":         {"en": "No files yet — head over to Upload and share something.", "de": "Noch keine Dateien — geh zu „Hochladen“ und teile etwas."},
	"files.open":          {"en": "Open", "de": "Öffnen"},
	"files.delete":        {"en": "Delete", "de": "Löschen"},
	"files.protected":     {"en": "protected", "de": "geschützt"},
	"files.expires_in":    {"en": "expires in %s", "de": "läuft ab in %s"},
	"files.expires_never": {"en": "never expires", "de": "läuft nie ab"},
	"files.dl_of":         {"en": "%d/%d downloads", "de": "%d/%d Downloads"},
	"files.dl_count":      {"en": "%d downloads", "de": "%d Downloads"},
	"files.dl_one":        {"en": "1 download", "de": "1 Download"},
	"files.by":            {"en": "by %s", "de": "von %s"},
	"files.archived":      {"en": "expired", "de": "abgelaufen"},
	"files.qr":            {"en": "Show QR code", "de": "QR-Code anzeigen"},
	"files.keyed":         {"en": "key in link", "de": "Schlüssel im Link"},
	"files.keyed_tip":     {"en": "The decryption key is only part of the original share link — the server doesn't store it. Copy the link right after uploading.", "de": "Der Entschlüsselungsschlüssel ist nur Teil des ursprünglichen Freigabe-Links — der Server speichert ihn nicht. Kopiere den Link direkt nach dem Hochladen."},

	// --- relative time ---
	"time.expired": {"en": "expired", "de": "abgelaufen"},
	"time.min":     {"en": "%d min", "de": "%d Min."},
	"time.hours":   {"en": "%d h", "de": "%d Std."},
	"time.days":    {"en": "%d days", "de": "%d Tagen"},
	"time.day":     {"en": "1 day", "de": "1 Tag"},

	// --- download landing page ---
	"dl.wants_to_share": {"en": "Someone shared a file with you", "de": "Jemand hat eine Datei mit dir geteilt"},
	"dl.size":           {"en": "Size", "de": "Größe"},
	"dl.type":           {"en": "Type", "de": "Typ"},
	"dl.uploaded":       {"en": "Shared on", "de": "Geteilt am"},
	"dl.expires":        {"en": "Link expires", "de": "Link läuft ab"},
	"dl.never":          {"en": "Never", "de": "Nie"},
	"dl.downloads_left": {"en": "%d of %d downloads left", "de": "%d von %d Downloads übrig"},
	"dl.button":         {"en": "Download file", "de": "Datei herunterladen"},
	"dl.pw_required":    {"en": "This file is password-protected.", "de": "Diese Datei ist passwortgeschützt."},
	"dl.pw_hint":        {"en": "Enter the password you received from the sender to see the file.", "de": "Gib das Passwort ein, das du vom Absender erhalten hast, um die Datei zu sehen."},
	"dl.password":       {"en": "Password", "de": "Passwort"},
	"dl.unlock":         {"en": "Unlock", "de": "Entsperren"},
	"dl.wrong_pw":       {"en": "Wrong password — please try again.", "de": "Falsches Passwort — bitte erneut versuchen."},
	"dl.too_many":       {"en": "Too many failed attempts. Please wait a few minutes and try again.", "de": "Zu viele Fehlversuche. Bitte warte ein paar Minuten und versuche es erneut."},
	"dl.key_missing":    {"en": "This link is incomplete — the decryption key (the part after #) is missing. Ask the sender for the full link.", "de": "Dieser Link ist unvollständig — der Entschlüsselungsschlüssel (der Teil nach #) fehlt. Bitte den Absender um den vollständigen Link."},
	"dl.e2e":            {"en": "End-to-end encrypted", "de": "Ende-zu-Ende-verschlüsselt"},
	"dl.js_required":    {"en": "JavaScript is required to open this encrypted link.", "de": "Zum Öffnen dieses verschlüsselten Links ist JavaScript erforderlich."},
	"dl.no_preview":     {"en": "No preview available for this file type.", "de": "Für diesen Dateityp ist keine Vorschau verfügbar."},
	"dl.preview":        {"en": "Preview", "de": "Vorschau"},
	"dl.gone_title":     {"en": "Link unavailable", "de": "Link nicht verfügbar"},
	"dl.gone_expired":   {"en": "This link has expired and the file is no longer available.", "de": "Dieser Link ist abgelaufen und die Datei ist nicht mehr verfügbar."},
	"dl.gone_limit":     {"en": "This link has reached its download limit.", "de": "Dieser Link hat sein Download-Limit erreicht."},
	"dl.not_found":      {"en": "This link does not exist or the file was removed.", "de": "Dieser Link existiert nicht oder die Datei wurde entfernt."},
	"dl.footer":         {"en": "Shared via %s", "de": "Geteilt über %s"},

	// --- login ---
	"login.heading":     {"en": "Sign in", "de": "Anmelden"},
	"login.sub":         {"en": "Sign in to share files.", "de": "Melde dich an, um Dateien zu teilen."},
	"login.username":    {"en": "Username", "de": "Benutzername"},
	"login.password":    {"en": "Password", "de": "Passwort"},
	"login.submit":      {"en": "Sign in", "de": "Anmelden"},
	"login.or":          {"en": "or", "de": "oder"},
	"login.oidc":        {"en": "Continue with Zitadel", "de": "Weiter mit Zitadel"},
	"login.err_empty":   {"en": "Enter your username and password.", "de": "Bitte Benutzername und Passwort eingeben."},
	"login.err_invalid": {"en": "Invalid username or password.", "de": "Benutzername oder Passwort ist falsch."},
	"login.too_many":    {"en": "Too many failed attempts. Please wait a few minutes and try again.", "de": "Zu viele Fehlversuche. Bitte warte ein paar Minuten und versuche es erneut."},

	// --- account ---
	"account.heading":   {"en": "Your account", "de": "Dein Konto"},
	"account.username":  {"en": "Username", "de": "Benutzername"},
	"account.email":     {"en": "Email", "de": "E-Mail"},
	"account.role":      {"en": "Role", "de": "Rolle"},
	"account.methods":   {"en": "Sign-in methods", "de": "Anmeldemethoden"},
	"account.method_pw": {"en": "password", "de": "Passwort"},
	"role.member":       {"en": "Member", "de": "Mitglied"},
	"role.admin":        {"en": "Admin", "de": "Admin"},
	"role.super":        {"en": "Super admin", "de": "Super-Admin"},
	"account.change_pw": {"en": "Change password", "de": "Passwort ändern"},
	"account.set_pw":    {"en": "Set password", "de": "Passwort festlegen"},
	"account.current":   {"en": "Current password", "de": "Aktuelles Passwort"},
	"account.new":       {"en": "New password (min. 8 characters)", "de": "Neues Passwort (mind. 8 Zeichen)"},
	"account.confirm":   {"en": "Confirm new password", "de": "Neues Passwort bestätigen"},
	"account.update":    {"en": "Update password", "de": "Passwort aktualisieren"},
	"msg.pw_short":      {"en": "New password must be at least 8 characters.", "de": "Das neue Passwort muss mindestens 8 Zeichen lang sein."},
	"msg.pw_mismatch":   {"en": "Passwords do not match.", "de": "Die Passwörter stimmen nicht überein."},
	"msg.pw_wrong":      {"en": "Current password is incorrect.", "de": "Das aktuelle Passwort ist falsch."},
	"msg.pw_updated":    {"en": "Password updated.", "de": "Passwort aktualisiert."},

	// --- admin users ---
	"users.heading":        {"en": "Users", "de": "Benutzer"},
	"users.sub":            {"en": "Manage who can sign in and share files.", "de": "Verwalte, wer sich anmelden und Dateien teilen darf."},
	"users.new":            {"en": "+ New local user", "de": "+ Neuer lokaler Benutzer"},
	"users.username":       {"en": "Username", "de": "Benutzername"},
	"users.email_opt":      {"en": "Email (optional)", "de": "E-Mail (optional)"},
	"users.password8":      {"en": "Password (min. 8)", "de": "Passwort (mind. 8)"},
	"users.is_admin":       {"en": "Admin", "de": "Admin"},
	"users.create":         {"en": "Create user", "de": "Benutzer anlegen"},
	"users.col_email":      {"en": "Email", "de": "E-Mail"},
	"users.col_methods":    {"en": "Methods", "de": "Methoden"},
	"users.col_role":       {"en": "Role", "de": "Rolle"},
	"users.col_created":    {"en": "Created", "de": "Erstellt"},
	"users.col_actions":    {"en": "Actions", "de": "Aktionen"},
	"users.no_login":       {"en": "no login", "de": "kein Login"},
	"users.member":         {"en": "member", "de": "Mitglied"},
	"users.reset_pw":       {"en": "Reset password", "de": "Passwort zurücksetzen"},
	"users.new_pw_ph":      {"en": "new password (min. 8)", "de": "neues Passwort (mind. 8)"},
	"users.save":           {"en": "Save", "de": "Speichern"},
	"users.revoke":         {"en": "Revoke admin", "de": "Admin entziehen"},
	"users.make_admin":     {"en": "Make admin", "de": "Zum Admin machen"},
	"users.delete":         {"en": "Delete", "de": "Löschen"},
	"users.t_super_revoke": {"en": "Super-admin rights can't be revoked", "de": "Super-Admin-Rechte können nicht entzogen werden"},
	"users.t_self_revoke":  {"en": "You can't revoke your own admin rights", "de": "Du kannst dir deine Admin-Rechte nicht selbst entziehen"},
	"users.t_super_delete": {"en": "Super-admin can't be deleted", "de": "Der Super-Admin kann nicht gelöscht werden"},
	"users.t_super_pw":     {"en": "Only a super-admin can reset a super-admin's password", "de": "Nur ein Super-Admin kann das Passwort eines Super-Admins zurücksetzen"},
	"users.t_self_delete":  {"en": "You can't delete yourself", "de": "Du kannst dich nicht selbst löschen"},
	"users.confirm_delete": {"en": "Delete user “%s”?", "de": "Benutzer „%s“ löschen?"},
	"msg.user_required":    {"en": "Username is required.", "de": "Benutzername ist erforderlich."},
	"msg.user_pw_short":    {"en": "Password must be at least 8 characters.", "de": "Das Passwort muss mindestens 8 Zeichen lang sein."},
	"msg.user_exists":      {"en": "A user with that username already exists.", "de": "Ein Benutzer mit diesem Namen existiert bereits."},
	"msg.user_created":     {"en": "Created user %s.", "de": "Benutzer %s angelegt."},
	"msg.pw_reset":         {"en": "Password reset.", "de": "Passwort zurückgesetzt."},
	"msg.super_pw":         {"en": "Only a super-admin can reset a super-admin's password.", "de": "Nur ein Super-Admin kann das Passwort eines Super-Admins zurücksetzen."},
	"msg.super_revoke":     {"en": "The super-admin's admin rights can't be revoked.", "de": "Die Admin-Rechte des Super-Admins können nicht entzogen werden."},
	"msg.self_revoke":      {"en": "You can't revoke your own admin rights.", "de": "Du kannst dir deine Admin-Rechte nicht selbst entziehen."},
	"msg.last_admin":       {"en": "Can't revoke the last admin.", "de": "Der letzte Admin kann nicht entzogen werden."},
	"msg.admin_granted":    {"en": "Admin rights granted.", "de": "Admin-Rechte erteilt."},
	"msg.admin_revoked":    {"en": "Admin rights revoked.", "de": "Admin-Rechte entzogen."},
	"msg.self_delete":      {"en": "You can't delete yourself. Ask another admin.", "de": "Du kannst dich nicht selbst löschen. Bitte einen anderen Admin darum."},
	"msg.super_delete":     {"en": "The super-admin can't be deleted.", "de": "Der Super-Admin kann nicht gelöscht werden."},
	"msg.last_admin_del":   {"en": "Can't delete the last admin.", "de": "Der letzte Admin kann nicht gelöscht werden."},
	"msg.user_deleted":     {"en": "User deleted.", "de": "Benutzer gelöscht."},

	// --- admin settings ---
	"settings.heading":      {"en": "Settings", "de": "Einstellungen"},
	"settings.sub":          {"en": "Instance-wide configuration.", "de": "Instanzweite Konfiguration."},
	"settings.oidc":         {"en": "Single sign-on (Zitadel OIDC)", "de": "Single Sign-on (Zitadel OIDC)"},
	"settings.active":       {"en": "active", "de": "aktiv"},
	"settings.inactive":     {"en": "not active", "de": "nicht aktiv"},
	"settings.howto":        {"en": "How to add Zitadel as OIDC provider", "de": "So richtest du Zitadel als OIDC-Provider ein"},
	"settings.enable":       {"en": "Enable OIDC login", "de": "OIDC-Login aktivieren"},
	"settings.issuer":       {"en": "Issuer URL", "de": "Issuer-URL"},
	"settings.issuer_h":     {"en": "The Zitadel instance base URL — no trailing slash.", "de": "Basis-URL der Zitadel-Instanz — ohne Slash am Ende."},
	"settings.client_id":    {"en": "Client ID", "de": "Client-ID"},
	"settings.secret":       {"en": "Client Secret", "de": "Client-Secret"},
	"settings.secret_keep":  {"en": "(leave blank to keep unchanged)", "de": "(leer lassen, um es zu behalten)"},
	"settings.secret_paste": {"en": "(paste the secret from Zitadel)", "de": "(Secret aus Zitadel einfügen)"},
	"settings.secret_h":     {"en": "Only sent when non-empty. Not displayed after save.", "de": "Wird nur bei Eingabe übertragen. Nach dem Speichern nicht mehr sichtbar."},
	"settings.redirect":     {"en": "Redirect URL", "de": "Redirect-URL"},
	"settings.redirect_h":   {"en": "Must byte-exactly match the URI registered in Zitadel.", "de": "Muss byte-genau mit der in Zitadel hinterlegten URI übereinstimmen."},
	"settings.domain":       {"en": "Allowed org primary domain", "de": "Erlaubte Org-Primärdomain"},
	"settings.domain_h":     {"en": "Leave blank to accept any org. When set, sent as scope urn:zitadel:iam:org:domain:primary:<domain> and cross-checked against the ID-token primary_domain claim.", "de": "Leer lassen, um jede Org zu akzeptieren. Wenn gesetzt, wird der Scope urn:zitadel:iam:org:domain:primary:<domain> gesendet und der primary_domain-Claim des ID-Tokens gegengeprüft."},
	"settings.save":         {"en": "Save & apply", "de": "Speichern & anwenden"},
	"msg.oidc_required":     {"en": "Issuer, Client ID, Client Secret and Redirect URL are required when OIDC is enabled.", "de": "Issuer, Client-ID, Client-Secret und Redirect-URL sind erforderlich, wenn OIDC aktiviert ist."},
	"msg.oidc_unreachable":  {"en": "Couldn't reach the OIDC provider with these settings: %s", "de": "Der OIDC-Provider ist mit diesen Einstellungen nicht erreichbar: %s"},
	"msg.oidc_saved":        {"en": "OIDC settings saved and applied.", "de": "OIDC-Einstellungen gespeichert und angewendet."},

	// settings walkthrough steps
	"howto.1": {"en": "Log in to the Zitadel Console at %s as an org admin.", "de": "Melde dich in der Zitadel-Konsole unter %s als Org-Admin an."},
	"howto.2": {"en": "Open (or create) a Project to hold this app, then New → Application.", "de": "Öffne (oder erstelle) ein Projekt für diese App, dann Neu → Applikation."},
	"howto.3": {"en": "Choose Web. Auth flow: Code (Authorization Code). Auth method: Basic (confidential client with secret). Leave PKCE enabled (default).", "de": "Wähle Web. Auth-Flow: Code (Authorization Code). Auth-Methode: Basic (vertraulicher Client mit Secret). PKCE aktiviert lassen (Standard)."},
	"howto.4": {"en": "Redirect URI:", "de": "Redirect-URI:"},
	"howto.5": {"en": "Post-logout redirect (optional):", "de": "Post-Logout-Redirect (optional):"},
	"howto.6": {"en": "Finish the wizard, then in the app's Token Settings enable “User Info Inside ID Token” so the org's primary_domain claim reaches this app.", "de": "Schließe den Assistenten ab und aktiviere in den Token-Einstellungen der App „User Info Inside ID Token“, damit der primary_domain-Claim der Org diese App erreicht."},
	"howto.7": {"en": "Copy the Client ID and generate a Client Secret — you can only see it once.", "de": "Kopiere die Client-ID und erzeuge ein Client-Secret — es wird nur einmal angezeigt."},
	"howto.8": {"en": "Fill the form below with those values, set the allowed org domain, check “Enable OIDC login” and save.", "de": "Trage die Werte unten ein, setze die erlaubte Org-Domain, aktiviere „OIDC-Login aktivieren“ und speichere."},
	"howto.9": {"en": "The “Continue with Zitadel” button appears on the sign-in page. Zitadel enforces the org restriction at authorization time; this app also verifies the primary_domain claim on callback.", "de": "Der Button „Weiter mit Zitadel“ erscheint auf der Anmeldeseite. Zitadel erzwingt die Org-Beschränkung bereits bei der Autorisierung; diese App prüft zusätzlich den primary_domain-Claim beim Callback."},

	// --- oidc denied ---
	"denied.heading": {"en": "Sign-in denied", "de": "Anmeldung abgelehnt"},
	"denied.msg":     {"en": "Your Zitadel organization is not allowed on this instance.", "de": "Deine Zitadel-Organisation ist auf dieser Instanz nicht zugelassen."},
	"denied.allowed": {"en": "Allowed", "de": "Erlaubt"},
	"denied.yours":   {"en": "Yours", "de": "Deine"},
	"denied.hint":    {"en": "If you have another Zitadel account that belongs to the allowed organization, sign in with that one. Otherwise contact an admin.", "de": "Wenn du ein anderes Zitadel-Konto in der erlaubten Organisation hast, melde dich damit an. Andernfalls wende dich an einen Admin."},
	"denied.retry":   {"en": "Try a different Zitadel account", "de": "Mit anderem Zitadel-Konto versuchen"},
	"denied.back":    {"en": "Back to sign-in", "de": "Zurück zur Anmeldung"},

	// --- generic ---
	"generic.error": {"en": "Something went wrong.", "de": "Etwas ist schiefgelaufen."},
}

// tr resolves a translation key for a language, with fmt.Sprintf args.
func tr(lang, key string, args ...any) string {
	entry, ok := translations[key]
	if !ok {
		return key
	}
	s, ok := entry[lang]
	if !ok || s == "" {
		s = entry["en"]
	}
	if len(args) > 0 {
		return fmt.Sprintf(s, args...)
	}
	return s
}

// langFromRequest picks the UI language: cookie first, then Accept-Language.
func langFromRequest(r *http.Request) string {
	if c, err := r.Cookie(langCookieName); err == nil {
		if isSupportedLang(c.Value) {
			return c.Value
		}
	}
	accept := strings.ToLower(r.Header.Get("Accept-Language"))
	for _, part := range strings.Split(accept, ",") {
		code := strings.TrimSpace(strings.SplitN(part, ";", 2)[0])
		if len(code) >= 2 {
			code = code[:2]
		}
		if isSupportedLang(code) {
			return code
		}
	}
	return "en"
}

func isSupportedLang(l string) bool {
	for _, s := range supportedLangs {
		if s == l {
			return true
		}
	}
	return false
}

// a.tr translates using the request's language.
func (a *App) tr(r *http.Request, key string, args ...any) string {
	return tr(langFromRequest(r), key, args...)
}

// handleLang sets the language cookie and redirects back.
func (a *App) handleLang(w http.ResponseWriter, r *http.Request) {
	to := r.URL.Query().Get("to")
	if !isSupportedLang(to) {
		to = "en"
	}
	next := r.URL.Query().Get("next")
	if !isSafeNext(next) {
		next = "/"
	}
	http.SetCookie(w, &http.Cookie{
		Name:     langCookieName,
		Value:    to,
		Path:     "/",
		Expires:  time.Now().Add(365 * 24 * time.Hour),
		Secure:   a.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// humanUntil renders a localized relative duration until t.
func humanUntil(lang string, t time.Time) string {
	d := time.Until(t)
	switch {
	case d < 0:
		return tr(lang, "time.expired")
	case d < time.Hour:
		n := int(d.Minutes())
		if n < 1 {
			n = 1
		}
		return tr(lang, "time.min", n)
	case d < 24*time.Hour:
		return tr(lang, "time.hours", int(d.Hours()))
	case d < 48*time.Hour:
		return tr(lang, "time.day")
	default:
		return tr(lang, "time.days", int(d.Hours()/24))
	}
}

// jsStrings returns the strings needed by app.js for a language.
func jsStrings(lang string) map[string]string {
	keys := []string{
		"js.done", "js.failed", "js.too_large", "js.login", "js.network",
		"js.copy", "js.copied", "js.toast_copied", "js.toast_copyerr",
		"js.confirm_delete", "js.protected", "js.no_results",
		"js.quota", "js.rate_limited", "js.qr_title",
		"js.e2e_encrypting", "js.e2e_decrypting", "js.e2e_downloading",
		"js.e2e_deriving", "js.e2e_failed", "js.e2e_wrong_pw", "js.e2e_unsupported",
		"js.e2e_unavailable", "js.e2e_insecure",
		"js.cancel", "js.retry", "js.cancelled",
		"js.reason_cancelled", "js.reason_network", "js.reason_login",
		"js.reason_http", "js.reason_encrypt",
		"js.batch_link", "js.batch_count", "js.batch_new", "js.batch_download",
		"js.batch_preview", "js.batch_hide_preview", "js.batch_preview_failed",
		"js.batch_empty", "js.batch_zipping", "js.batch_fetching",
		"js.batch_zip_too_large", "js.batch_zip_name", "js.batch_options_locked",
		"js.batch_failed",
		"batch.n_files", "batch.one_file",
	}
	out := make(map[string]string, len(keys))
	for _, k := range keys {
		out[strings.TrimPrefix(k, "js.")] = tr(lang, k)
	}
	return out
}
