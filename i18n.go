package main

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const langCookieName = "pyxis_lang"

var supportedLangs = []string{"en", "de"}

// translations maps key -> lang -> string. English is the fallback.
var translations = map[string]map[string]string{
	// --- app / nav ---
	"app.name":          {"en": "Pyxis", "de": "Pyxis"},
	"app.tagline":       {"en": "Private file sharing", "de": "Privates Dateiteilen"},
	"nav.section.share": {"en": "Share", "de": "Teilen"},
	"nav.upload":        {"en": "Upload", "de": "Hochladen"},
	"nav.files":         {"en": "My files", "de": "Meine Dateien"},
	"nav.section.admin": {"en": "Administration", "de": "Verwaltung"},
	"nav.allfiles":      {"en": "All files", "de": "Alle Dateien"},
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
	"title.allfiles": {"en": "All files", "de": "Alle Dateien"},
	"title.users":    {"en": "Users", "de": "Benutzer"},
	"title.settings": {"en": "Settings", "de": "Einstellungen"},
	"title.download": {"en": "Shared file", "de": "Geteilte Datei"},

	// --- upload page ---
	"upload.heading": {"en": "Share files", "de": "Dateien teilen"},
	"upload.sub":     {"en": "Set the terms of the link first, then add the files it should cover.", "de": "Erst die Bedingungen des Links festlegen, dann die Dateien hinzufügen, die er umfassen soll."},
	"upload.drop":    {"en": "Drop files here or", "de": "Dateien hier ablegen oder"},
	"upload.browse":  {"en": "browse", "de": "durchsuchen"},
	"upload.hint":    {"en": "Multiple files supported · up to %s each", "de": "Mehrere Dateien möglich · bis zu %s pro Datei"},
	"upload.paste":   {"en": "Paste from clipboard", "de": "Aus Zwischenablage einfügen"},
	"upload.paste_hint": {
		"en": "A screenshot or a copied file works too — press Ctrl+V (⌘V on a Mac) anywhere on this page.",
		"de": "Ein Screenshot oder eine kopierte Datei geht auch — irgendwo auf dieser Seite Strg+V (⌘V am Mac) drücken."},
	"upload.options": {"en": "Options for this batch", "de": "Optionen für diese Übertragung"},

	// --- the two upload steps ---
	"upload.step1": {"en": "Step 1 · Share settings", "de": "Schritt 1 · Freigabe-Einstellungen"},
	"upload.step1_sub": {"en": "These terms belong to the link, not to a file, and they are fixed once the first file lands.",
		"de": "Diese Bedingungen gehören zum Link, nicht zu einer Datei — mit der ersten Datei stehen sie fest."},
	"upload.step2": {"en": "Step 2 · Files", "de": "Schritt 2 · Dateien"},
	"upload.step2_locked": {"en": "Settle the settings above first — the link's terms cannot be chosen after the fact.",
		"de": "Zuerst die Einstellungen oben festlegen — die Bedingungen des Links lassen sich nachträglich nicht mehr wählen."},
	"upload.step2_open": {"en": "Drop everything that belongs under one link.", "de": "Alles ablegen, was unter einen Link gehört."},
	"upload.confirm":    {"en": "Continue to files", "de": "Weiter zu den Dateien"},
	"upload.confirm_hint": {"en": "You can still come back and change these until the first file is uploaded.",
		"de": "Bis zur ersten hochgeladenen Datei kannst du hierher zurück und alles ändern."},
	"upload.step_edit":   {"en": "Change settings", "de": "Einstellungen ändern"},
	"upload.step_set":    {"en": "settled", "de": "festgelegt"},
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
	"upload.single_use":  {"en": "Single-Use", "de": "Einmalig"},
	"upload.single_use_h": {
		"en": "Expires after 1 hour, one download only.",
		"de": "Läuft nach 1 Stunde ab, nur ein Download."},
	"upload.queue":    {"en": "Uploads in this session", "de": "Uploads in dieser Sitzung"},
	"upload.view_all": {"en": "View all files →", "de": "Alle Dateien ansehen →"},
	"upload.e2e":      {"en": "Files are encrypted in your browser before upload — the server only ever stores ciphertext. Without a password the key lives in the share link, so copy it right away: it can't be recovered later.", "de": "Dateien werden vor dem Hochladen in deinem Browser verschlüsselt — der Server speichert nur Chiffretext. Ohne Passwort steckt der Schlüssel im Freigabe-Link: kopiere ihn sofort, er lässt sich später nicht wiederherstellen."},

	// --- js strings (shared) ---
	"js.done":              {"en": "Done", "de": "Fertig"},
	"js.failed":            {"en": "Failed", "de": "Fehlgeschlagen"},
	"js.too_large":         {"en": "File too large", "de": "Datei zu groß"},
	"js.login":             {"en": "Sign-in required", "de": "Anmeldung erforderlich"},
	"js.network":           {"en": "Network error", "de": "Netzwerkfehler"},
	"js.retrying":          {"en": "Retrying…", "de": "Neuer Versuch…"},
	"js.file_gone":         {"en": "File unreadable", "de": "Datei nicht lesbar"},
	"js.copy":              {"en": "Copy link", "de": "Link kopieren"},
	"js.copied":            {"en": "Copied!", "de": "Kopiert!"},
	"js.toast_copied":      {"en": "Link copied to clipboard", "de": "Link in die Zwischenablage kopiert"},
	"js.toast_copyerr":     {"en": "Copy failed — check clipboard permissions", "de": "Kopieren fehlgeschlagen — Zwischenablage-Berechtigung prüfen"},
	"js.confirm_delete":    {"en": "Delete “%s”? The link stops working immediately.", "de": "„%s“ löschen? Der Link funktioniert danach sofort nicht mehr."},
	"js.protected":         {"en": "password-protected", "de": "passwortgeschützt"},
	"js.no_results":        {"en": "No files match your search.", "de": "Keine Dateien entsprechen deiner Suche."},
	"js.quota":             {"en": "Storage limit reached", "de": "Speicherlimit erreicht"},
	"js.pasted":            {"en": "Added %s from the clipboard", "de": "%s aus der Zwischenablage hinzugefügt"},
	"js.paste_empty":       {"en": "Nothing to paste — the clipboard holds no image or file", "de": "Nichts einzufügen — die Zwischenablage enthält kein Bild und keine Datei"},
	"js.paste_denied":      {"en": "Clipboard access denied — press Ctrl+V instead", "de": "Zugriff auf die Zwischenablage verweigert — stattdessen Strg+V drücken"},
	"js.paste_unsupported": {"en": "This browser only pastes with Ctrl+V", "de": "Dieser Browser fügt nur mit Strg+V ein"},
	"js.rate_limited":      {"en": "Too many attempts", "de": "Zu viele Versuche"},
	"js.qr_title":          {"en": "Scan to open the share link", "de": "Scannen, um den Freigabe-Link zu öffnen"},
	"js.e2e_encrypting":    {"en": "Encrypting…", "de": "Verschlüsseln…"},
	"js.e2e_decrypting":    {"en": "Decrypting…", "de": "Entschlüsseln…"},
	"js.e2e_downloading":   {"en": "Downloading…", "de": "Herunterladen…"},
	"js.e2e_deriving":      {"en": "Deriving key…", "de": "Schlüssel ableiten…"},
	"js.e2e_failed":        {"en": "Decryption failed", "de": "Entschlüsselung fehlgeschlagen"},
	"js.e2e_wrong_pw":      {"en": "Wrong password — please try again.", "de": "Falsches Passwort — bitte erneut versuchen."},
	"js.e2e_unsupported":   {"en": "This browser cannot decrypt the file (WebCrypto unavailable over an insecure connection).", "de": "Dieser Browser kann die Datei nicht entschlüsseln (WebCrypto ist über eine unsichere Verbindung nicht verfügbar)."},
	"js.e2e_unavailable":   {"en": "Encryption unavailable — upload refused", "de": "Verschlüsselung nicht verfügbar — Upload abgelehnt"},
	"js.e2e_insecure":      {"en": "Nothing was sent: encryption requires a secure (HTTPS) connection.", "de": "Es wurde nichts gesendet: Die Verschlüsselung erfordert eine sichere (HTTPS-)Verbindung."},

	// --- file list multi-select ---
	"js.selected": {"en": "%s selected", "de": "%s ausgewählt"},
	"js.confirm_delete_many": {"en": "Delete %s selected files? Their links stop working immediately.",
		"de": "%s ausgewählte Dateien löschen? Ihre Links funktionieren danach sofort nicht mehr."},

	// --- "Preview all" gallery ---
	"js.preview_all":   {"en": "Preview all", "de": "Alle ansehen"},
	"js.gallery_prev":  {"en": "Previous file", "de": "Vorherige Datei"},
	"js.gallery_next":  {"en": "Next file", "de": "Nächste Datei"},
	"js.gallery_close": {"en": "Close", "de": "Schließen"},
	"js.gallery_show":  {"en": "Show %s", "de": "%s anzeigen"},
	"js.gallery_hint":  {"en": "Use ← and → to move through the files.", "de": "Mit ← und → zwischen den Dateien wechseln."},
	"js.gallery_nothing": {"en": "Nothing in this share can be previewed.",
		"de": "In dieser Freigabe lässt sich nichts in der Vorschau anzeigen."},
	"js.gallery_prefetch": {"en": "Files up to %s are loaded as soon as this opens; larger ones load when you reach them.",
		"de": "Dateien bis %s werden beim Öffnen geladen, größere erst, wenn du sie erreichst."},
	// A fetch is what the limit counts, and the gallery now spends one on every
	// small file the moment it opens, so say so before that happens.
	"js.gallery_limit_note": {"en": "Every file loaded here counts against this link's download limit.",
		"de": "Jede hier geladene Datei zählt auf das Download-Limit dieses Links."},

	// --- a preview the browser cannot play ---
	// Not every codec survives the trip: an iPhone .mov is usually HEVC, and a
	// Windows browser without that decoder either refuses the file outright or
	// plays its sound over a black rectangle. Say which codec it was, because
	// that is the one thing that tells the recipient what to open it with.
	"js.preview_codec": {"en": "Your browser can't play this video — it uses %s. Download it to watch it in a player.",
		"de": "Dein Browser kann dieses Video nicht abspielen — es verwendet %s. Lade es herunter und öffne es in einem Player."},
	"js.preview_unplayable": {"en": "Your browser can't play this file. Download it to open it in a player.",
		"de": "Dein Browser kann diese Datei nicht abspielen. Lade sie herunter und öffne sie in einem Player."},

	// --- click-to-enlarge, on every image preview ---
	"js.zoom_in":  {"en": "Enlarge", "de": "Vergrößern"},
	"js.zoom_out": {"en": "Fit to view", "de": "Einpassen"},
	// Shown in the enlarged view while the picture is still fitted; once it is
	// zoomed in, the same spot reads out the zoom level instead.
	"js.zoom_hint": {"en": "Scroll or pinch to zoom", "de": "Zum Zoomen scrollen oder aufziehen"},

	// --- integrity of the decrypted result ---
	"js.e2e_legacy": {"en": "This link uses an older format: the contents are authenticated, but the file's length and name are not. It was shared before the current format existed.",
		"de": "Dieser Link nutzt ein älteres Format: Der Inhalt ist authentifiziert, Länge und Name der Datei jedoch nicht. Er wurde vor dem aktuellen Format erstellt."},
	"js.e2e_name_changed": {"en": "This page announced the file as “%s”, but the sender named it “%s”. The verified name is used.",
		"de": "Diese Seite hat die Datei als „%s“ angekündigt, der Absender hat sie aber „%s“ genannt. Verwendet wird der verifizierte Name."},

	// --- upload queue: cancel / retry / failure reasons ---
	"js.cancel":    {"en": "Cancel", "de": "Abbrechen"},
	"js.retry":     {"en": "Retry", "de": "Erneut versuchen"},
	"js.cancelled": {"en": "Cancelled", "de": "Abgebrochen"},
	"js.queued":    {"en": "Waiting…", "de": "Wartet…"},
	"js.reason_cancelled": {"en": "Cancelled before the upload finished. Nothing was stored.",
		"de": "Vor Abschluss des Uploads abgebrochen. Es wurde nichts gespeichert."},
	"js.reason_network": {"en": "The connection was interrupted before the upload finished. Nothing was stored.",
		"de": "Die Verbindung wurde vor Abschluss des Uploads unterbrochen. Es wurde nichts gespeichert."},
	"js.reason_login": {"en": "Your session expired. Sign in again, then retry the upload.",
		"de": "Deine Sitzung ist abgelaufen. Melde dich erneut an und versuche den Upload noch einmal."},
	"js.reason_http": {"en": "The server rejected the upload (HTTP %s).",
		"de": "Der Server hat den Upload abgelehnt (HTTP %s)."},
	"js.reason_too_large": {"en": "This file is %s. The maximum is %s. Nothing was uploaded.",
		"de": "Diese Datei ist %s groß. Das Maximum sind %s. Es wurde nichts hochgeladen."},
	"js.reason_encrypt": {"en": "Encryption failed in this browser: %s",
		"de": "Die Verschlüsselung ist in diesem Browser fehlgeschlagen: %s"},
	"js.reason_retrying": {"en": "The connection was interrupted. Retrying automatically (attempt %s of %s) — nothing was stored yet and there is nothing you need to do.",
		"de": "Die Verbindung wurde unterbrochen. Es wird automatisch erneut versucht (Versuch %s von %s) — es wurde noch nichts gespeichert und du musst nichts tun."},
	// The browser's own words for this are "The object cannot be found here",
	// which names neither the file nor anything to do about it. On iPhone and
	// iPad it almost always means one thing: the file is still in iCloud and
	// was not fetched to the device in time.
	"js.reason_file_gone": {"en": "The browser lost access to this file before it could be encrypted. On iPhone and iPad this happens when the file is only stored in iCloud: open it once in the Files app so it is downloaded to the device, then add it here again.",
		"de": "Der Browser hat den Zugriff auf diese Datei verloren, bevor sie verschlüsselt werden konnte. Auf iPhone und iPad passiert das, wenn die Datei nur in iCloud liegt: Öffne sie einmal in der Dateien-App, damit sie auf das Gerät geladen wird, und füge sie dann erneut hinzu."},
	"js.reason_roster": {"en": "Uploaded, but the signed file list could not be updated — recipients will see this file flagged as unverified.",
		"de": "Hochgeladen, aber die signierte Dateiliste konnte nicht aktualisiert werden — Empfänger sehen diese Datei als nicht verifiziert markiert."},

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

	// --- roster verification (which files this link really contains) ---
	"js.batch_legacy": {"en": "This link predates signed file lists: each file's contents are authenticated, but which files belong to the link is not.",
		"de": "Dieser Link stammt aus der Zeit vor signierten Dateilisten: Der Inhalt jeder Datei ist authentifiziert, die Zugehörigkeit der Dateien zum Link jedoch nicht."},
	"js.batch_no_roster": {"en": "The signed file list is missing or does not match this link, so it cannot be confirmed which files belong here. Each file's contents are still verified on download.",
		"de": "Die signierte Dateiliste fehlt oder passt nicht zu diesem Link, daher lässt sich nicht bestätigen, welche Dateien dazugehören. Der Inhalt jeder Datei wird beim Herunterladen weiterhin verifiziert."},
	"js.batch_unverified": {"en": "%s file(s) here are not in the sender's signed list and are excluded from “Download all”.",
		"de": "%s Datei(en) stehen nicht auf der signierten Liste des Absenders und sind von „Alle herunterladen“ ausgenommen."},
	"js.batch_missing": {"en": "%s file(s) the sender listed are not being offered: %s.",
		"de": "%s vom Absender gelistete Datei(en) werden nicht angeboten: %s."},
	"js.batch_reordered": {"en": "The files were not offered in the order the sender sealed them; the original order has been restored.",
		"de": "Die Dateien wurden nicht in der vom Absender signierten Reihenfolge angeboten; die ursprüngliche Reihenfolge wurde wiederhergestellt."},
	"js.batch_row_unverified": {"en": "unverified", "de": "nicht verifiziert"},
	"js.batch_row_unverified_hint": {"en": "This file is not on the sender's signed list. Its contents are still authenticated, but it may not have been part of this share.",
		"de": "Diese Datei steht nicht auf der signierten Liste des Absenders. Ihr Inhalt ist weiterhin authentifiziert, sie war aber möglicherweise nicht Teil dieser Freigabe."},

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
	"batch.preview_all":    {"en": "Preview all", "de": "Alle ansehen"},
	"files.batch":          {"en": "In a batch", "de": "Im Stapel"},
	"files.batch_tip": {"en": "Shared together with other files under one link",
		"de": "Zusammen mit anderen Dateien unter einem Link geteilt"},

	// --- files / history page ---
	"files.heading":     {"en": "My files", "de": "Meine Dateien"},
	"files.sub":         {"en": "Everything you have shared, newest first.", "de": "Alles, was du geteilt hast — Neuestes zuerst."},
	"files.all_heading": {"en": "All files", "de": "Alle Dateien"},
	"files.all_sub": {"en": "Every account's shares on this instance, newest first. Your own are on My files.",
		"de": "Die Freigaben aller Konten auf dieser Instanz — Neuestes zuerst. Deine eigenen stehen unter „Meine Dateien“."},
	"files.search":        {"en": "Filter by name, type or uploader…", "de": "Nach Name, Typ oder Uploader filtern…"},
	"files.stat_count":    {"en": "Active files", "de": "Aktive Dateien"},
	"files.stat_size":     {"en": "Total size", "de": "Gesamtgröße"},
	"files.stat_dl":       {"en": "Downloads", "de": "Downloads"},
	"files.empty":         {"en": "No files yet — head over to Upload and share something.", "de": "Noch keine Dateien — geh zu „Hochladen“ und teile etwas."},
	"files.all_empty":     {"en": "Nobody on this instance has an active share right now.", "de": "Derzeit hat niemand auf dieser Instanz eine aktive Freigabe."},
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

	// --- sealed names ---
	"dl.name_sealed": {"en": "Encrypted file name", "de": "Verschlüsselter Dateiname"},
	"js.name_sealed": {"en": "Name unavailable", "de": "Name nicht verfügbar"},
	"js.name_unsealable": {"en": "This file's name could not be opened with the key in this link.",
		"de": "Der Dateiname ließ sich mit dem Schlüssel aus diesem Link nicht öffnen."},
	"files.name_sealed": {"en": "Encrypted file name", "de": "Verschlüsselter Dateiname"},
	"files.name_sealed_tip": {"en": "The name is encrypted under the key in the share link, which this page does not have. Open the link to see it.",
		"de": "Der Name ist mit dem Schlüssel aus dem Freigabe-Link verschlüsselt, den diese Seite nicht hat. Öffne den Link, um ihn zu sehen."},
	"files.name_remembered": {"en": "remembered by this browser", "de": "von diesem Browser gemerkt"},

	// --- batch grouping in the file list ---
	"files.batch_of":     {"en": "%d files in one share", "de": "%d Dateien in einer Freigabe"},
	"files.expand_all":   {"en": "Expand all", "de": "Alle ausklappen"},
	"files.collapse_all": {"en": "Collapse all", "de": "Alle einklappen"},
	"files.toggle_group": {"en": "Show or hide the files in this share", "de": "Dateien dieser Freigabe ein- oder ausblenden"},
	"files.select_batch": {"en": "Select every file in this share", "de": "Alle Dateien dieser Freigabe auswählen"},

	// --- file list multi-select ---
	"files.select_all":      {"en": "Select all", "de": "Alle auswählen"},
	"files.select_file":     {"en": "Select “%s”", "de": "„%s“ auswählen"},
	"files.delete_selected": {"en": "Delete selected", "de": "Auswahl löschen"},
	"files.none_selected":   {"en": "Nothing selected", "de": "Nichts ausgewählt"},

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
	"dl.pw_hint":        {"en": "Enter the password you received from the sender to see the file.", "de": "Gib das Passwort ein, das du vom Absender erhalten hast, um die Datei zu sehen."},
	"dl.password":       {"en": "Password", "de": "Passwort"},
	"dl.unlock":         {"en": "Unlock", "de": "Entsperren"},
	"dl.key_missing":    {"en": "This link is incomplete — the decryption key (the part after #) is missing. Ask the sender for the full link.", "de": "Dieser Link ist unvollständig — der Entschlüsselungsschlüssel (der Teil nach #) fehlt. Bitte den Absender um den vollständigen Link."},
	"dl.e2e":            {"en": "End-to-end encrypted", "de": "Ende-zu-Ende-verschlüsselt"},
	"dl.js_required":    {"en": "JavaScript is required to open this encrypted link.", "de": "Zum Öffnen dieses verschlüsselten Links ist JavaScript erforderlich."},
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
	"account.new":       {"en": "New password (min. 12 characters)", "de": "Neues Passwort (mind. 12 Zeichen)"},
	"account.confirm":   {"en": "Confirm new password", "de": "Neues Passwort bestätigen"},
	"account.update":    {"en": "Update password", "de": "Passwort aktualisieren"},
	"account.stepup_hint": {"en": "This account signs in through your identity provider. To add a password — a credential that keeps working after that provider revokes your access — confirm who you are there first.",
		"de": "Dieses Konto meldet sich über deinen Identitätsanbieter an. Um ein Passwort hinzuzufügen — eine Anmeldeinformation, die auch nach einem Entzug des Zugriffs beim Anbieter weiter funktioniert — bestätige dort zuerst deine Identität."},
	"account.stepup_button": {"en": "Confirm identity to set a password",
		"de": "Identität bestätigen, um ein Passwort festzulegen"},
	"msg.stepup_required": {"en": "Confirm your identity with your identity provider before setting a password.",
		"de": "Bestätige deine Identität bei deinem Identitätsanbieter, bevor du ein Passwort festlegst."},
	"msg.pw_short":    {"en": "New password must be at least 12 characters.", "de": "Das neue Passwort muss mindestens 12 Zeichen lang sein."},
	"msg.pw_mismatch": {"en": "Passwords do not match.", "de": "Die Passwörter stimmen nicht überein."},
	"msg.pw_wrong":    {"en": "Current password is incorrect.", "de": "Das aktuelle Passwort ist falsch."},
	"msg.pw_updated":  {"en": "Password updated.", "de": "Passwort aktualisiert."},

	// --- admin users ---
	"users.heading":        {"en": "Users", "de": "Benutzer"},
	"users.sub":            {"en": "Manage who can sign in and share files.", "de": "Verwalte, wer sich anmelden und Dateien teilen darf."},
	"users.new":            {"en": "+ New local user", "de": "+ Neuer lokaler Benutzer"},
	"users.username":       {"en": "Username", "de": "Benutzername"},
	"users.email_opt":      {"en": "Email (optional)", "de": "E-Mail (optional)"},
	"users.password8":      {"en": "Password (min. 12)", "de": "Passwort (mind. 12)"},
	"users.is_admin":       {"en": "Admin", "de": "Admin"},
	"users.create":         {"en": "Create user", "de": "Benutzer anlegen"},
	"users.col_email":      {"en": "Email", "de": "E-Mail"},
	"users.col_methods":    {"en": "Methods", "de": "Methoden"},
	"users.col_role":       {"en": "Role", "de": "Rolle"},
	"users.col_created":    {"en": "Created", "de": "Erstellt"},
	"users.col_quota":      {"en": "Usage / quota", "de": "Belegung / Kontingent"},
	"users.col_actions":    {"en": "Actions", "de": "Aktionen"},
	"users.no_login":       {"en": "no login", "de": "kein Login"},
	"users.member":         {"en": "member", "de": "Mitglied"},
	"users.reset_pw":       {"en": "Reset password", "de": "Passwort zurücksetzen"},
	"users.new_pw_ph":      {"en": "new password (min. 12)", "de": "neues Passwort (mind. 12)"},
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
	"users.quota":          {"en": "Quota", "de": "Kontingent"},
	"quota.your_storage":   {"en": "Your storage", "de": "Dein Speicher"},
	"quota.unlimited":      {"en": "unlimited", "de": "unbegrenzt"},
	"quota.files":          {"en": "files", "de": "Dateien"},
	"quota.custom":         {"en": "custom", "de": "individuell"},
	"users.quota_bytes_ph": {"en": "storage, blank = default", "de": "Speicher, leer = Standard"},
	"users.quota_files_ph": {"en": "files, blank = default", "de": "Dateien, leer = Standard"},
	"users.t_quota_admin":  {"en": "Admins have no quota unless you set one here", "de": "Admins haben kein Kontingent, sofern hier keines gesetzt wird"},
	"users.max_upload":     {"en": "max per file:", "de": "max. pro Datei:"},
	"users.max_upload_ph":  {"en": "per file, blank = default", "de": "pro Datei, leer = Standard"},
	// Short field labels for the limits editor. They are hidden on a wide
	// screen, where the three inputs sit side by side under one heading and the
	// placeholders say which is which; stacked on a phone the placeholders are
	// gone the moment a field holds a value, and two of them read "1 GiB".
	"users.f_storage":    {"en": "Storage", "de": "Speicher"},
	"users.f_files":      {"en": "Files", "de": "Dateien"},
	"users.f_max_upload": {"en": "Max per file", "de": "Max. pro Datei"},
	"msg.user_required":  {"en": "Username is required.", "de": "Benutzername ist erforderlich."},
	"msg.user_pw_short":  {"en": "Password must be at least 12 characters.", "de": "Das Passwort muss mindestens 12 Zeichen lang sein."},
	"msg.user_exists":    {"en": "A user with that username already exists.", "de": "Ein Benutzer mit diesem Namen existiert bereits."},
	"msg.user_created":   {"en": "Created user %s.", "de": "Benutzer %s angelegt."},
	"msg.pw_reset":       {"en": "Password reset.", "de": "Passwort zurückgesetzt."},
	"msg.super_pw":       {"en": "Only a super-admin can reset a super-admin's password.", "de": "Nur ein Super-Admin kann das Passwort eines Super-Admins zurücksetzen."},
	"msg.super_revoke":   {"en": "The super-admin's admin rights can't be revoked.", "de": "Die Admin-Rechte des Super-Admins können nicht entzogen werden."},
	"msg.self_revoke":    {"en": "You can't revoke your own admin rights.", "de": "Du kannst dir deine Admin-Rechte nicht selbst entziehen."},
	"msg.last_admin":     {"en": "Can't revoke the last admin.", "de": "Der letzte Admin kann nicht entzogen werden."},
	"msg.admin_granted":  {"en": "Admin rights granted.", "de": "Admin-Rechte erteilt."},
	"msg.admin_revoked":  {"en": "Admin rights revoked.", "de": "Admin-Rechte entzogen."},
	"msg.self_delete":    {"en": "You can't delete yourself. Ask another admin.", "de": "Du kannst dich nicht selbst löschen. Bitte einen anderen Admin darum."},
	"msg.super_delete":   {"en": "The super-admin can't be deleted.", "de": "Der Super-Admin kann nicht gelöscht werden."},
	"msg.last_admin_del": {"en": "Can't delete the last admin.", "de": "Der letzte Admin kann nicht gelöscht werden."},
	"msg.user_deleted":   {"en": "User deleted.", "de": "Benutzer gelöscht."},
	"msg.quota_saved":    {"en": "Quota updated for %s.", "de": "Kontingent für %s aktualisiert."},
	"msg.quota_bad_size": {"en": "Enter a size such as 20G, 500M or 2 GiB — or 0 for unlimited.",
		"de": "Gib eine Größe wie 20G, 500M oder 2 GiB ein — oder 0 für unbegrenzt."},
	"msg.quota_bad_count": {"en": "The file limit must be a whole number, 0 for unlimited.",
		"de": "Die Dateigrenze muss eine ganze Zahl sein, 0 für unbegrenzt."},
	"msg.quota_default_saved": {"en": "Default quota saved.", "de": "Standard-Kontingent gespeichert."},
	"msg.upload_bad_size": {"en": "Enter a size such as 512M, 2G or 1 GiB. The upload limit cannot be 0 — that would refuse every file.",
		"de": "Gib eine Größe wie 512M, 2G oder 1 GiB ein. Das Upload-Limit kann nicht 0 sein — damit wäre jede Datei abgelehnt."},
	"msg.upload_saved": {"en": "Upload limit saved: %s per file.", "de": "Upload-Limit gespeichert: %s pro Datei."},

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
	"settings.quota":        {"en": "Storage quotas", "de": "Speicherkontingente"},
	"settings.quota_note": {
		"en": "The default applies to every user without a quota of their own. Set one for an individual user on the Users page — that always wins, including for admins, who are otherwise unlimited.",
		"de": "Der Standard gilt für alle Benutzer ohne eigenes Kontingent. Ein individuelles Kontingent wird auf der Benutzer-Seite gesetzt und hat immer Vorrang — auch bei Admins, die sonst unbegrenzt sind."},
	"settings.quota_bytes": {"en": "Storage per user", "de": "Speicher pro Benutzer"},
	"settings.quota_bytes_h": {
		"en": "A size such as 20G, 500M or 2 GiB. Units are binary. 0 means unlimited.",
		"de": "Eine Größe wie 20G, 500M oder 2 GiB. Einheiten sind binär. 0 bedeutet unbegrenzt."},
	"settings.quota_files": {"en": "Files per user", "de": "Dateien pro Benutzer"},
	"settings.quota_files_h": {
		"en": "Maximum number of active files. 0 means unlimited.",
		"de": "Maximale Anzahl aktiver Dateien. 0 bedeutet unbegrenzt."},
	"settings.quota_save": {"en": "Save quotas", "de": "Kontingente speichern"},
	"settings.upload":     {"en": "Upload limit", "de": "Upload-Limit"},
	"settings.upload_note": {
		"en": "The largest single file anyone may upload. Unlike the storage quota this applies to admins too, because it bounds one request — the browser encrypts the whole file before sending it, and the server holds it while it arrives. Give an individual account a different ceiling on the Users page.",
		"de": "Die größte einzelne Datei, die jemand hochladen darf. Anders als das Speicherkontingent gilt dies auch für Admins, denn es begrenzt eine einzelne Anfrage — der Browser verschlüsselt die ganze Datei vor dem Senden, und der Server hält sie, während sie eintrifft. Ein abweichendes Limit für ein einzelnes Konto wird auf der Benutzer-Seite gesetzt."},
	"settings.upload_bytes": {"en": "Maximum file size", "de": "Maximale Dateigröße"},
	"settings.upload_bytes_h": {
		"en": "A size such as 512M, 2G or 1 GiB. Units are binary. There is no \"unlimited\": free disk space and the browser's own memory still apply.",
		"de": "Eine Größe wie 512M, 2G oder 1 GiB. Einheiten sind binär. Es gibt kein „unbegrenzt“: freier Speicherplatz und der Arbeitsspeicher des Browsers bleiben maßgeblich."},
	"settings.upload_save": {"en": "Save upload limit", "de": "Upload-Limit speichern"},
	"msg.oidc_required":    {"en": "Issuer, Client ID, Client Secret and Redirect URL are required when OIDC is enabled.", "de": "Issuer, Client-ID, Client-Secret und Redirect-URL sind erforderlich, wenn OIDC aktiviert ist."},
	"msg.oidc_unreachable": {"en": "Couldn't reach the OIDC provider with these settings: %s", "de": "Der OIDC-Provider ist mit diesen Einstellungen nicht erreichbar: %s"},
	"msg.oidc_saved":       {"en": "OIDC settings saved and applied.", "de": "OIDC-Einstellungen gespeichert und angewendet."},

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

	// --- drops: the owner's side ---
	"nav.drops":   {"en": "Receive files", "de": "Dateien empfangen"},
	"title.drops": {"en": "Receive files", "de": "Dateien empfangen"},

	"drops.title":   {"en": "Receive files", "de": "Dateien empfangen"},
	"drops.heading": {"en": "Receive files", "de": "Dateien empfangen"},
	"drops.sub": {
		"en": "A drop is a link that only accepts files. Everything sent to it is encrypted to a key that exists in your private link and nowhere else — not on this server.",
		"de": "Ein Briefkasten ist ein Link, der ausschließlich Dateien annimmt. Alles, was dort ankommt, wird auf einen Schlüssel verschlüsselt, den es nur in deinem privaten Link gibt — nicht auf diesem Server."},
	"drops.new":               {"en": "New drop", "de": "Neuer Briefkasten"},
	"drops.create":            {"en": "Create drop", "de": "Briefkasten anlegen"},
	"drops.label":             {"en": "Name", "de": "Name"},
	"drops.label_ph":          {"en": "What is this drop for?", "de": "Wofür ist dieser Briefkasten?"},
	"drops.note":              {"en": "Note for senders", "de": "Hinweis für Absender"},
	"drops.note_ph":           {"en": "Shown on the upload page, unencrypted.", "de": "Wird auf der Upload-Seite angezeigt, unverschlüsselt."},
	"drops.note_hint":         {"en": "Senders read this before any key exchange, so the server can read it too. Keep it free of anything private.", "de": "Absender lesen das vor jedem Schlüsselaustausch, also kann der Server es ebenfalls lesen. Nichts Privates hineinschreiben."},
	"drops.expiry":            {"en": "Accepts files until", "de": "Nimmt Dateien an bis"},
	"drops.presets":           {"en": "How much may arrive", "de": "Wie viel ankommen darf"},
	"drops.preset_one":        {"en": "One file only", "de": "Nur eine Datei"},
	"drops.preset_one_h":      {"en": "One sender, one file, then the drop closes itself.", "de": "Ein Absender, eine Datei, danach schließt sich der Briefkasten selbst."},
	"drops.preset_delivery":   {"en": "One delivery", "de": "Eine Lieferung"},
	"drops.preset_delivery_h": {"en": "One sender, as many files as your limits allow.", "de": "Ein Absender, so viele Dateien wie deine Grenzen erlauben."},
	"drops.preset_open":       {"en": "Open drop box", "de": "Offener Briefkasten"},
	"drops.preset_open_h":     {"en": "Several senders, each with their own delivery.", "de": "Mehrere Absender, jeder mit einer eigenen Lieferung."},
	"drops.limits":            {"en": "Limits", "de": "Grenzen"},
	"drops.max_files":         {"en": "Files in total", "de": "Dateien insgesamt"},
	"drops.max_per_sub":       {"en": "Files per delivery", "de": "Dateien pro Lieferung"},
	"drops.max_subs":          {"en": "Deliveries", "de": "Lieferungen"},
	"drops.max_file_size":     {"en": "Largest single file", "de": "Größte Einzeldatei"},
	"drops.max_total":         {"en": "Total size", "de": "Gesamtgröße"},
	"drops.unlimited_ph":      {"en": "no limit", "de": "unbegrenzt"},
	"drops.mb":                {"en": "MB", "de": "MB"},
	"drops.ceiling_hint":      {"en": "Your own upload limit is %s and always applies. Everything sent here counts against your storage quota.", "de": "Dein eigenes Upload-Limit von %s gilt immer. Alles, was hier ankommt, zählt gegen dein Speicherkontingent."},
	"drops.password":          {"en": "Password for senders", "de": "Passwort für Absender"},
	"drops.password_ph":       {"en": "optional", "de": "optional"},
	"drops.password_hint":     {"en": "A second gate on the public link. It does not encrypt anything — the KEM already does that — it just stops a forwarded link being used by everyone.", "de": "Eine zweite Schranke für den öffentlichen Link. Sie verschlüsselt nichts — das macht bereits der KEM — sie verhindert nur, dass ein weitergeleiteter Link von allen benutzt wird."},

	"drops.links_heading":  {"en": "Two links, once", "de": "Zwei Links, einmalig"},
	"drops.public_link":    {"en": "Public link — give this out", "de": "Öffentlicher Link — diesen weitergeben"},
	"drops.public_hint":    {"en": "Anyone with it can send you files. It cannot read them.", "de": "Wer ihn hat, kann dir Dateien schicken. Lesen kann er sie nicht."},
	"drops.private_link":   {"en": "Private link — keep this", "de": "Privater Link — diesen behalten"},
	"drops.private_hint":   {"en": "The only way to read what arrives. It is not stored anywhere: if you lose it, everything sent to this drop is lost, for everyone.", "de": "Der einzige Weg, das Angekommene zu lesen. Er wird nirgends gespeichert: Geht er verloren, ist alles in diesem Briefkasten unwiederbringlich weg — für alle."},
	"drops.saved_confirm":  {"en": "I have saved the private link", "de": "Ich habe den privaten Link gesichert"},
	"drops.list":           {"en": "Your drops", "de": "Deine Briefkästen"},
	"drops.empty":          {"en": "No drops yet.", "de": "Noch keine Briefkästen."},
	"drops.received":       {"en": "%d file(s) · %s", "de": "%d Datei(en) · %s"},
	"drops.deliveries":     {"en": "%d delivery(ies)", "de": "%d Lieferung(en)"},
	"drops.open_inbox":     {"en": "Open with your private link", "de": "Mit privatem Link öffnen"},
	"drops.inbox_hint":     {"en": "This page has no key, so it cannot show you names or contents — only that something arrived.", "de": "Diese Seite hat keinen Schlüssel und kann daher weder Namen noch Inhalte zeigen — nur, dass etwas angekommen ist."},
	"drops.closed":         {"en": "closed", "de": "geschlossen"},
	"drops.accepting":      {"en": "accepting", "de": "nimmt an"},
	"drops.close":          {"en": "Close", "de": "Schließen"},
	"drops.close_hint":     {"en": "Stop accepting files. What already arrived stays.", "de": "Keine Dateien mehr annehmen. Bereits Angekommenes bleibt."},
	"drops.delete":         {"en": "Delete", "de": "Löschen"},
	"drops.confirm_close":  {"en": "Close this drop? It will stop accepting files.", "de": "Diesen Briefkasten schließen? Er nimmt dann keine Dateien mehr an."},
	"drops.confirm_delete": {"en": "Delete this drop and everything sent to it? This cannot be undone.", "de": "Diesen Briefkasten und alles darin löschen? Das lässt sich nicht rückgängig machen."},
	"drops.pq_badge":       {"en": "post-quantum", "de": "Post-Quantum"},
	"drops.pq_hint": {
		"en": "Files are sealed with X-Wing (ML-KEM-768 + X25519). The keypair is generated in this tab; the server stores the public half sealed and never sees the private one.",
		"de": "Dateien werden mit X-Wing (ML-KEM-768 + X25519) versiegelt. Das Schlüsselpaar entsteht in diesem Tab; der Server speichert die öffentliche Hälfte versiegelt und sieht die private nie."},

	// --- drops: the public upload page ---
	"drop.title":        {"en": "Send files", "de": "Dateien senden"},
	"drop.heading":      {"en": "Send files", "de": "Dateien senden"},
	"drop.sub":          {"en": "Your files are encrypted in this tab before they are sent. Only the person who gave you this link can read them.", "de": "Deine Dateien werden in diesem Tab verschlüsselt, bevor sie gesendet werden. Nur wer dir diesen Link gegeben hat, kann sie lesen."},
	"drop.note_from":    {"en": "From the recipient", "de": "Vom Empfänger"},
	"drop.closed":       {"en": "This drop is no longer accepting files.", "de": "Dieser Briefkasten nimmt keine Dateien mehr an."},
	"drop.complete":     {"en": "This drop already has everything it was waiting for.", "de": "Dieser Briefkasten hat bereits alles, worauf er gewartet hat."},
	"drop.one_file":     {"en": "This drop accepts a single file.", "de": "Dieser Briefkasten nimmt genau eine Datei an."},
	"drop.n_files":      {"en": "This drop accepts %d files.", "de": "Dieser Briefkasten nimmt %d Dateien an."},
	"drop.files_left":   {"en": "%d still fit.", "de": "%d passen noch."},
	"drop.max_file":     {"en": "Up to %s per file.", "de": "Bis zu %s pro Datei."},
	"drop.about_you":    {"en": "Who is sending", "de": "Wer sendet"},
	"drop.sender":       {"en": "Your name", "de": "Dein Name"},
	"drop.sender_ph":    {"en": "optional", "de": "optional"},
	"drop.message":      {"en": "Message", "de": "Nachricht"},
	"drop.message_ph":   {"en": "optional — sealed with the files", "de": "optional — wird mit den Dateien versiegelt"},
	"drop.message_hint": {"en": "Encrypted like the files. The recipient sees it beside them, and it says only what you type here — nothing verifies who you are.", "de": "Wird wie die Dateien verschlüsselt. Der Empfänger sieht sie neben den Dateien, und sie sagt nur, was du hier eintippst — deine Identität wird nicht geprüft."},
	"drop.no_read_back": {"en": "You will not be able to open these files again from this page. Encryption here only goes one way.", "de": "Du kannst diese Dateien von dieser Seite aus nicht wieder öffnen. Die Verschlüsselung hier funktioniert nur in eine Richtung."},
	"drop.pw_hint":      {"en": "This drop is password protected. Ask the recipient for it.", "de": "Dieser Briefkasten ist passwortgeschützt. Frag den Empfänger danach."},
	"drop.expires":      {"en": "Accepts files until", "de": "Nimmt Dateien an bis"},
	"drop.sent":         {"en": "Sent", "de": "Gesendet"},
	"drop.sent_hint":    {"en": "Delivered and sealed. You can close this tab.", "de": "Zugestellt und versiegelt. Du kannst diesen Tab schließen."},

	// --- drops: the inbox ---
	"inbox.title":   {"en": "Received files", "de": "Empfangene Dateien"},
	"inbox.heading": {"en": "Received files", "de": "Empfangene Dateien"},
	"inbox.kicker":  {"en": "Your drop", "de": "Dein Briefkasten"},
	"inbox.empty":   {"en": "Nothing has been sent to this drop yet.", "de": "An diesen Briefkasten wurde noch nichts gesendet."},
	"inbox.summary": {"en": "%d file(s) in %d delivery(ies)", "de": "%d Datei(en) in %d Lieferung(en)"},
	"inbox.created": {"en": "Drop created", "de": "Briefkasten angelegt"},
	"inbox.closed":  {"en": "No longer accepting files", "de": "Nimmt keine Dateien mehr an"},

	// --- drops: strings app.js needs ---
	"js.drop_public_link":   {"en": "Public link — give this out", "de": "Öffentlicher Link — diesen weitergeben"},
	"js.drop_private_link":  {"en": "Private link — keep this", "de": "Privater Link — diesen behalten"},
	"js.drop_creating":      {"en": "Generating a post-quantum keypair…", "de": "Post-Quantum-Schlüsselpaar wird erzeugt…"},
	"js.drop_created":       {"en": "Drop created", "de": "Briefkasten angelegt"},
	"js.drop_create_failed": {"en": "The drop could not be created.", "de": "Der Briefkasten konnte nicht angelegt werden."},
	"js.drop_sealing":       {"en": "Sealing to the recipient's key…", "de": "Wird auf den Schlüssel des Empfängers versiegelt…"},
	"js.drop_sending":       {"en": "Sending", "de": "Senden"},
	"js.drop_sent":          {"en": "Sent", "de": "Gesendet"},
	"js.drop_send":          {"en": "Send files", "de": "Dateien senden"},
	"js.drop_key_bad": {
		"en": "This drop's key does not match its link. Do not send anything: either the link is damaged, or the key you were served is not the recipient's.",
		"de": "Der Schlüssel dieses Briefkastens passt nicht zum Link. Sende nichts: Entweder ist der Link beschädigt, oder der ausgelieferte Schlüssel gehört nicht dem Empfänger."},
	"js.drop_kem_missing":        {"en": "This browser cannot do the post-quantum key exchange this drop needs.", "de": "Dieser Browser beherrscht den Post-Quantum-Schlüsselaustausch nicht, den dieser Briefkasten braucht."},
	"js.drop_full":               {"en": "This drop is full.", "de": "Dieser Briefkasten ist voll."},
	"js.drop_file_limit":         {"en": "This drop accepts %s file(s) — the rest were not added.", "de": "Dieser Briefkasten nimmt %s Datei(en) an — der Rest wurde nicht hinzugefügt."},
	"js.drop_closed":             {"en": "This drop is closed.", "de": "Dieser Briefkasten ist geschlossen."},
	"js.inbox_failed":            {"en": "The inbox could not be opened with this link.", "de": "Der Posteingang ließ sich mit diesem Link nicht öffnen."},
	"js.inbox_empty":             {"en": "Nothing has been sent to this drop yet.", "de": "An diesen Briefkasten wurde noch nichts gesendet."},
	"js.inbox_delivery":          {"en": "Delivery %s", "de": "Lieferung %s"},
	"js.inbox_from":              {"en": "from %s", "de": "von %s"},
	"js.inbox_anonymous":         {"en": "no sender given", "de": "kein Absender angegeben"},
	"js.inbox_note_sealed":       {"en": "The sender's note could not be opened.", "de": "Die Notiz des Absenders ließ sich nicht öffnen."},
	"js.inbox_unverified_sender": {"en": "Sender details are what the sender typed. Nothing verifies them.", "de": "Absenderangaben sind das, was der Absender eingetippt hat. Nichts überprüft sie."},
	"js.inbox_download_all":      {"en": "Download everything", "de": "Alles herunterladen"},

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
	return negotiateLang(r.Header.Get("Accept-Language"))
}

// negotiateLang picks the best supported language from an Accept-Language
// header, falling back to English.
//
// The q-value decides, not the header order: RFC 9110 does not require the
// list to be sorted by preference, so "fr, en;q=0.3, de;q=0.9" asks for German
// ahead of English even though English appears first. q=0 means "not
// acceptable" and is skipped rather than matched. Ties fall to whichever came
// first, which is the order browsers actually send.
//
// Only the primary subtag matters here: "de-AT", "de-CH" and "de" all select
// German, because that is as far as the catalogue distinguishes.
func negotiateLang(header string) string {
	best, bestQ := "en", -1.0
	for _, part := range strings.Split(strings.ToLower(header), ",") {
		tag, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		q := 1.0
		for _, p := range strings.Split(params, ";") {
			k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
			if !ok || strings.TrimSpace(k) != "q" {
				continue
			}
			if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
				q = f
			}
		}
		if q <= 0 {
			continue // explicitly rejected
		}
		if base, _, _ := strings.Cut(tag, "-"); isSupportedLang(base) && q > bestQ {
			best, bestQ = base, q
		}
	}
	return best
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
		"js.confirm_delete", "js.confirm_delete_many", "js.selected",
		"js.protected", "js.no_results",
		"js.quota", "js.rate_limited", "js.qr_title",
		"js.pasted", "js.paste_empty", "js.paste_denied", "js.paste_unsupported",
		"js.e2e_encrypting", "js.e2e_decrypting", "js.e2e_downloading",
		"js.e2e_deriving", "js.e2e_failed", "js.e2e_wrong_pw", "js.e2e_unsupported",
		"js.e2e_unavailable", "js.e2e_insecure",
		"js.e2e_legacy", "js.e2e_name_changed",
		"js.cancel", "js.retry", "js.cancelled", "js.queued",
		"js.reason_cancelled", "js.reason_network", "js.reason_login",
		"js.reason_http", "js.reason_encrypt", "js.reason_too_large", "js.reason_roster",
		"js.retrying", "js.file_gone", "js.reason_retrying", "js.reason_file_gone",
		"js.batch_link", "js.batch_count", "js.batch_new", "js.batch_download",
		"js.batch_preview", "js.batch_hide_preview", "js.batch_preview_failed",
		"js.batch_empty", "js.batch_zipping", "js.batch_fetching",
		"js.batch_zip_too_large", "js.batch_zip_name", "js.batch_options_locked",
		"js.batch_failed",
		"js.batch_legacy", "js.batch_no_roster", "js.batch_unverified", "js.batch_missing",
		"js.batch_row_unverified", "js.batch_row_unverified_hint", "js.batch_reordered",
		"js.preview_all", "js.gallery_prev", "js.gallery_next", "js.gallery_close",
		"js.gallery_show", "js.gallery_hint", "js.gallery_nothing",
		"js.gallery_prefetch", "js.gallery_limit_note",
		"js.zoom_in", "js.zoom_out", "js.zoom_hint",
		"js.preview_codec", "js.preview_unplayable",
		"batch.n_files", "batch.one_file",
		// The step-2 subtitle flips between these two as the gate opens.
		"upload.step2_locked", "upload.step2_open",
		"js.name_sealed", "js.name_unsealable",
		"files.name_sealed", "files.name_remembered",
		// Drops: the create page, the public upload page and the inbox.
		"js.drop_public_link", "js.drop_private_link", "js.drop_creating",
		"js.drop_created", "js.drop_create_failed", "js.drop_sealing",
		"js.drop_sending", "js.drop_sent", "js.drop_send",
		"js.drop_key_bad", "js.drop_kem_missing", "js.drop_full",
		"js.drop_file_limit", "js.drop_closed",
		"js.inbox_failed", "js.inbox_empty", "js.inbox_delivery", "js.inbox_from",
		"js.inbox_anonymous", "js.inbox_note_sealed", "js.inbox_unverified_sender",
		"js.inbox_download_all",
	}
	out := make(map[string]string, len(keys))
	for _, k := range keys {
		out[strings.TrimPrefix(k, "js.")] = tr(lang, k)
	}
	return out
}
