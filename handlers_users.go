package main

import (
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// minPasswordLen is a length floor, not a policy: it exists to stop the
// obviously hopeless. Twelve characters rather than eight because eight is now
// within reach of offline guessing even against a memory-hard hash, and every
// local password here can also be an administrator's.
const minPasswordLen = 12

// --- self-service /account ------------------------------------------------

func (a *App) handleAccount(w http.ResponseWriter, r *http.Request) {
	a.renderAccount(w, r, http.StatusOK, "", "")
}

// needsPasswordStepUp reports whether this user must re-authenticate with the
// identity provider before a local password can be set.
//
// The case that matters is an SSO-only account: it has no local credential, so
// nothing about the request proves anything beyond possession of a session
// cookie. Letting that establish a permanent password turns a stolen session —
// a transient thing that expires and can be revoked — into standing access that
// survives revocation at the provider. An account that already has a password
// is not affected: it proves itself with that password instead.
func needsPasswordStepUp(u *User) bool {
	return !u.HasPassword && u.HasOIDC() && !u.ReauthFresh()
}

func (a *App) renderAccount(w http.ResponseWriter, r *http.Request, status int, errMsg, okMsg string) {
	// The quota panel that used to live here is now the shell's quota bar, so
	// it is on this page too — renderStatus fills in Usage for every page.
	user := userFromContext(r.Context())
	a.renderStatus(w, r, status, "account.html", map[string]any{
		"Title":          a.tr(r, "title.account") + " · Pyxis",
		"Active":         "account",
		"Error":          errMsg,
		"Success":        okMsg,
		"StepUpRequired": user != nil && needsPasswordStepUp(user),
		"MinPasswordLen": minPasswordLen,
	})
}

func (a *App) handleAccountPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user := userFromContext(r.Context())
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	current := r.PostFormValue("current_password")
	next := r.PostFormValue("new_password")
	confirm := r.PostFormValue("confirm_password")

	if len(next) < minPasswordLen {
		a.renderAccount(w, r, http.StatusBadRequest,
			a.tr(r, "msg.pw_short"), "")
		return
	}
	if next != confirm {
		a.renderAccount(w, r, http.StatusBadRequest,
			a.tr(r, "msg.pw_mismatch"), "")
		return
	}
	if user.HasPassword {
		_, hash, err := a.findUserByUsername(r.Context(), user.Username)
		if err != nil || !checkPassword(hash, current) {
			a.renderAccount(w, r, http.StatusUnauthorized,
				a.tr(r, "msg.pw_wrong"), "")
			return
		}
	} else if needsPasswordStepUp(user) {
		// The form is not offered in this state, so reaching here is a direct
		// POST. Refuse it and point at the step-up rather than accepting a new
		// permanent credential on the strength of a session cookie alone.
		a.renderAccount(w, r, http.StatusForbidden, a.tr(r, "msg.stepup_required"), "")
		return
	}
	if err := a.updatePassword(r.Context(), user.ID, next); err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	// Revoke every other session: a password change is often a response to a
	// suspected compromise, and stolen session cookies must die with it.
	if err := a.deleteUserSessions(r.Context(), user.ID, readSessionCookie(r)); err != nil {
		log.Printf("revoke sessions after password change: %v", err)
	}
	// Spend the step-up. It authorised this one change; leaving it standing
	// would let the rest of its window authorise another.
	if err := a.clearSessionReauth(r.Context(), user.ID); err != nil {
		log.Printf("clear step-up after password change: %v", err)
	}
	log.Printf("password changed: %s", user.Username)
	a.renderAccount(w, r, http.StatusOK, "", a.tr(r, "msg.pw_updated"))
}

// --- admin /admin/users ---------------------------------------------------

func (a *App) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return a.requireUser(func(w http.ResponseWriter, r *http.Request) {
		u := userFromContext(r.Context())
		if !u.IsAdmin {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

func (a *App) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	a.renderAdminUsers(w, r, http.StatusOK, "", "")
}

func (a *App) renderAdminUsers(w http.ResponseWriter, r *http.Request, status int, errMsg, okMsg string) {
	users, err := a.listUsers(r.Context())
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	me := userFromContext(r.Context())
	def := a.getQuotaDefaults()
	for i := range users {
		u := &users[i]
		u.EffQuota = applyQuotaDefaults(u.IsAdmin, u.QuotaBytes, u.QuotaFiles, def)
		u.Custom = u.QuotaBytes != nil || u.QuotaFiles != nil
		if u.QuotaBytes != nil {
			u.QuotaBytesInput = sizeInput(*u.QuotaBytes)
		}
		if u.QuotaFiles != nil {
			u.QuotaFilesInput = strconv.FormatInt(*u.QuotaFiles, 10)
		}
	}
	a.renderStatus(w, r, status, "admin_users.html", map[string]any{
		"Title":     a.tr(r, "title.users") + " · Pyxis",
		"Active":    "users",
		"Users":     users,
		"MeID":      me.ID.String(),
		"MeIsSuper": me.IsSuperAdmin,
		"Error":     errMsg,
		"Success":   okMsg,
	})
}

// handleAdminSetQuota stores a per-user override. Either field may be left
// blank, which clears that column and puts the user back on the instance
// default — the only way to express "inherit" once a limit has been set.
func (a *App) handleAdminSetQuota(w http.ResponseWriter, r *http.Request) {
	id, ok := parseAdminUserID(w, r, "/quota")
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	bytes, err := parseQuotaOverride(r.PostFormValue("bytes"), parseSize)
	if err != nil {
		a.renderAdminUsers(w, r, http.StatusBadRequest, a.tr(r, "msg.quota_bad_size"), "")
		return
	}
	files, err := parseQuotaOverride(r.PostFormValue("files"), parseCount)
	if err != nil {
		a.renderAdminUsers(w, r, http.StatusBadRequest, a.tr(r, "msg.quota_bad_count"), "")
		return
	}

	var username string
	if err := a.db.QueryRow(r.Context(),
		`SELECT username FROM users WHERE id = $1`, id.String()).Scan(&username); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	if err := a.setUserQuota(r.Context(), id, bytes, files); err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	log.Printf("admin set quota for %s: bytes=%s files=%s",
		username, quotaLogValue(bytes), quotaLogValue(files))
	a.renderAdminUsers(w, r, http.StatusOK, "", a.tr(r, "msg.quota_saved", username))
}

// parseQuotaOverride maps a form field to an override pointer: blank means
// "inherit the default" (NULL), anything else is parsed by parse.
func parseQuotaOverride(raw string, parse func(string) (int64, error)) (*int64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	n, err := parse(raw)
	if err != nil {
		return nil, err
	}
	return &n, nil
}

var errBadCount = errors.New("not a file count")

func parseCount(s string) (int64, error) {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || n < 0 {
		return 0, errBadCount
	}
	return n, nil
}

func quotaLogValue(n *int64) string {
	if n == nil {
		return "default"
	}
	return strconv.FormatInt(*n, 10)
}

func (a *App) handleAdminCreateUser(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.PostFormValue("username"))
	email := strings.TrimSpace(r.PostFormValue("email"))
	password := r.PostFormValue("password")
	isAdmin := r.PostFormValue("is_admin") == "on"

	if username == "" {
		a.renderAdminUsers(w, r, http.StatusBadRequest, a.tr(r, "msg.user_required"), "")
		return
	}
	if len(password) < minPasswordLen {
		a.renderAdminUsers(w, r, http.StatusBadRequest,
			a.tr(r, "msg.user_pw_short"), "")
		return
	}
	if _, _, err := a.findUserByUsername(r.Context(), username); err == nil {
		a.renderAdminUsers(w, r, http.StatusBadRequest,
			a.tr(r, "msg.user_exists"), "")
		return
	} else if !errors.Is(err, pgx.ErrNoRows) {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	u, err := a.createLocalUser(r.Context(), username, email, password, isAdmin)
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	log.Printf("admin created user: %s (admin=%v)", u.Username, u.IsAdmin)
	a.renderAdminUsers(w, r, http.StatusOK, "", a.tr(r, "msg.user_created", u.Username))
}

func (a *App) handleAdminResetPassword(w http.ResponseWriter, r *http.Request) {
	id, ok := parseAdminUserID(w, r, "/password")
	if !ok {
		return
	}
	// Resetting a password takes over the account. The super-admin is
	// protected from demotion and deletion by ordinary admins; without this
	// guard, a credential reset would be a trivial way around both.
	me := userFromContext(r.Context())
	var targetIsSuper bool
	if err := a.db.QueryRow(r.Context(),
		`SELECT is_super_admin FROM users WHERE id = $1`, id.String()).Scan(&targetIsSuper); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	if targetIsSuper && !me.IsSuperAdmin {
		a.renderAdminUsers(w, r, http.StatusForbidden, a.tr(r, "msg.super_pw"), "")
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	newPassword := r.PostFormValue("password")
	if len(newPassword) < minPasswordLen {
		a.renderAdminUsers(w, r, http.StatusBadRequest,
			a.tr(r, "msg.user_pw_short"), "")
		return
	}
	if err := a.updatePassword(r.Context(), id, newPassword); err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	if err := a.deleteUserSessions(r.Context(), id, ""); err != nil {
		log.Printf("revoke sessions after admin reset: %v", err)
	}
	log.Printf("admin reset password for user id=%s", id)
	a.renderAdminUsers(w, r, http.StatusOK, "", a.tr(r, "msg.pw_reset"))
}

func (a *App) handleAdminToggleAdmin(w http.ResponseWriter, r *http.Request) {
	id, ok := parseAdminUserID(w, r, "/admin")
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	target := r.PostFormValue("value") == "on"
	me := userFromContext(r.Context())

	// Read target user's super_admin flag first so guards can honor it.
	var targetIsSuper bool
	if err := a.db.QueryRow(r.Context(),
		`SELECT is_super_admin FROM users WHERE id = $1`, id.String()).Scan(&targetIsSuper); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	if !target && targetIsSuper {
		a.renderAdminUsers(w, r, http.StatusBadRequest,
			a.tr(r, "msg.super_revoke"), "")
		return
	}
	if !target && id == me.ID {
		a.renderAdminUsers(w, r, http.StatusBadRequest,
			a.tr(r, "msg.self_revoke"), "")
		return
	}
	if !target {
		n, err := a.countAdmins(r.Context())
		if err != nil {
			httpError(w, err, http.StatusInternalServerError)
			return
		}
		if n <= 1 {
			a.renderAdminUsers(w, r, http.StatusBadRequest,
				a.tr(r, "msg.last_admin"), "")
			return
		}
	}
	if err := a.setAdminFlag(r.Context(), id, target); err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	// Privilege changes invalidate existing sessions so the new role takes
	// effect on a fresh, deliberate sign-in.
	if err := a.deleteUserSessions(r.Context(), id, ""); err != nil {
		log.Printf("revoke sessions after privilege change: %v", err)
	}
	verb := "revoked"
	msgKey := "msg.admin_revoked"
	if target {
		verb = "granted"
		msgKey = "msg.admin_granted"
	}
	log.Printf("admin %s admin rights for user id=%s", verb, id)
	a.renderAdminUsers(w, r, http.StatusOK, "", a.tr(r, msgKey))
}

func (a *App) handleAdminDeleteUser(w http.ResponseWriter, r *http.Request) {
	id, ok := parseAdminUserID(w, r, "/delete")
	if !ok {
		return
	}
	me := userFromContext(r.Context())
	if id == me.ID {
		a.renderAdminUsers(w, r, http.StatusBadRequest,
			a.tr(r, "msg.self_delete"), "")
		return
	}
	var (
		isAdmin      bool
		isSuperAdmin bool
	)
	if err := a.db.QueryRow(r.Context(),
		`SELECT is_admin, is_super_admin FROM users WHERE id = $1`, id.String()).
		Scan(&isAdmin, &isSuperAdmin); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	if isSuperAdmin {
		a.renderAdminUsers(w, r, http.StatusBadRequest,
			a.tr(r, "msg.super_delete"), "")
		return
	}
	if isAdmin {
		n, err := a.countAdmins(r.Context())
		if err != nil {
			httpError(w, err, http.StatusInternalServerError)
			return
		}
		if n <= 1 {
			a.renderAdminUsers(w, r, http.StatusBadRequest,
				a.tr(r, "msg.last_admin_del"), "")
			return
		}
	}
	if err := a.deleteUser(r.Context(), id); err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	log.Printf("admin deleted user id=%s", id)
	a.renderAdminUsers(w, r, http.StatusOK, "", a.tr(r, "msg.user_deleted"))
}

// parseAdminUserID pulls the UUID from /admin/users/<uuid><suffix>. Writes an
// error response and returns ok=false if parsing fails.
func parseAdminUserID(w http.ResponseWriter, r *http.Request, suffix string) (uuid.UUID, bool) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return uuid.Nil, false
	}
	path := strings.TrimPrefix(r.URL.Path, "/admin/users/")
	path = strings.TrimSuffix(path, suffix)
	id, err := uuid.Parse(path)
	if err != nil {
		http.NotFound(w, r)
		return uuid.Nil, false
	}
	return id, true
}
