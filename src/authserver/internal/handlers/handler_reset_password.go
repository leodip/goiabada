package handlers

import (
	"crypto/subtle"
	"database/sql"
	"log/slog"
	"net/http"
	"time"

	"github.com/gorilla/sessions"
	"github.com/pkg/errors"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/i18n"
	core_middleware "github.com/leodip/goiabada/core/middleware"
	"github.com/leodip/goiabada/core/models"
)

// forgotPasswordCodeLifetime bounds how long a password reset code stays usable
// after it is issued by HandleForgotPasswordPost.
const forgotPasswordCodeLifetime = 5 * time.Minute

// The reasons a reset request is refused, as recorded in the audit entry.
//
// The whole vocabulary changed with #112, because the states the handler can distinguish
// changed. It used to emit missing_code_or_email, unknown_email, no_code_issued,
// code_mismatch and code_expired, all read off ?email= and ?code=. The link now carries the
// code alone, the code is validated once on the first hop, and every later step arrives on a
// URL with no query at all, so four of those five are no longer determinable and naming them
// would have the entry assert causes the handler cannot know.
//
// Four more live on LinkMarkerRejection (marker_missing, marker_wrong_flow, marker_expired,
// and continuation_in_flight), which is what GetLinkMarker and SaveLinkMarker return, so the
// handler records what the helper decided rather than re-deriving it from the same state.
const (
	// auditReasonUnknownCode is a code that resolves to no outstanding reset. Emitted on
	// the first hop only, which after this change is the only request where an
	// attacker-controlled credential arrives at all, and so the only place a burst of bad
	// codes is visible.
	auditReasonUnknownCode = "unknown_code"
	// auditReasonCodeExpired is the code's own 5-minute lifetime having passed. The one
	// name carried over from the old vocabulary, with exactly its old meaning, so no
	// existing log reader is misled by it.
	auditReasonCodeExpired = "code_expired"
	// auditReasonCodeNoLongerOutstanding is a marker whose code hash no longer resolves to
	// a user. It does NOT specifically mean replay: the reset may have completed, a newer
	// code may have been issued, an unrelated password change may have cleared it, or the
	// user row may be gone. All are answered identically.
	auditReasonCodeNoLongerOutstanding = "code_no_longer_outstanding"
	// auditReasonClaimLost is the conditional password write matching no row, which is the
	// same imprecision one step later: a concurrent submission won, or the code stopped
	// being outstanding between the lookup and the write.
	auditReasonClaimLost = "claim_lost"
	// auditReasonContinuationMismatch is a submitted form naming a continuation other than
	// the one the session now holds, which is what refuses a page rendered for one account
	// from acting on another. Determinable and distinct from every other rejection, so it
	// gets its own name rather than being folded into one of them.
	auditReasonContinuationMismatch = "continuation_mismatch"
)

// continuationIdField is the hidden form field carrying the continuation id, and its name
// is duplicated in reset_password.html because a template cannot read a Go constant. A
// rename in one place alone renders a form whose every submission is refused, which the
// integration cases catch: they read the field out of the rendered page rather than
// building the form themselves.
const continuationIdField = "continuationId"

// errResetPasswordClaimLost is returned out of the RevokeUserAuthStateTx callback when the
// conditional password write claims no row. It is not a server fault: it rolls the whole
// transaction back, including the revocation sweep, and the handler then takes the ordinary
// indistinguishable rejection path rather than a 500.
var errResetPasswordClaimLost = errors.New("the forgot password code was no longer outstanding when the password write claimed it")

// isForgotPasswordCodeExpired reports whether the reset code issued to this user
// is past its lifetime.
//
// Consulted on the FIRST hop, where the emailed code arrives. The two steps after the
// redirect deliberately do not re-apply it: they are bounded by the marker's own window,
// which starts when the code was validated, so a user who clicked at 4:59 still has five
// minutes to type a password (#112 decision 7). Worst-case total exposure is therefore the
// code's 5 minutes plus the marker's 5, and what refuses a request after that is the marker
// expiring and the code hash no longer being outstanding.
//
// A user with no code issued has a zero ForgotPasswordCodeIssuedAt and is
// therefore treated as expired, which fails closed.
func isForgotPasswordCodeExpired(user *models.User) bool {
	return user.ForgotPasswordCodeIssuedAt.Time.Add(forgotPasswordCodeLifetime).Before(time.Now().UTC())
}

// forgotPasswordCodeMatches compares a supplied reset code against the stored one
// in constant time, the same way client secrets are compared in
// validators.ValidateTokenRequest. A plain string comparison stops at the first
// differing byte, which in principle leaks how much of a guessed code was right.
//
// Still the authority even though the row is now found by an unsalted SHA-256 of the same
// code: the index locates a candidate row, and this decides whether the code presented is
// really the one stored. An index match that this rejects is answered as an unknown code.
//
// This is not constant time with respect to length: inputs of differing lengths
// are rejected immediately. Reset codes are fixed length, so that difference
// carries nothing useful.
func forgotPasswordCodeMatches(storedCode string, suppliedCode string) bool {
	return subtle.ConstantTimeCompare([]byte(storedCode), []byte(suppliedCode)) == 1
}

// continuationMatches reports whether a submitted form belongs to the continuation the
// session currently holds.
//
// This is what binds a rendered page to the account whose link authorized it, and it is
// needed on top of SaveLinkMarker's first-writer-wins rule because that rule governs
// writes and this refusal is about a page that is already on screen. A marker may be
// replaced legitimately once it expires, so a form rendered at t=0 and submitted at
// t=5min would otherwise act on whatever marker the session holds by then (#112).
//
// An empty stored id is refused rather than matched against an empty submission: only a
// marker written by an older binary can carry one, and treating "" as equal to "" would
// make such a marker accept a form that names no continuation at all.
func continuationMatches(markerContinuationId string, submitted string) bool {
	if markerContinuationId == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(markerContinuationId), []byte(submitted)) == 1
}

// renderResetPasswordCodeInvalid renders the reset form in its "invalid or
// expired" state.
//
// Every condition attributable to the link goes through here: an unknown or expired code, or
// another continuation already in flight, on the first hop, and a missing, expired or
// wrong-flow marker, a code hash that no longer resolves, a form naming a continuation the
// session no longer holds, or a lost claim on the two steps after it. Because they all produce the same
// response, the endpoint cannot be used to work out which of them happened, and in
// particular cannot be used to discover whether an email address has an account.
//
// httpStatus is applied only when non-zero. The GET passes zero so that simply
// viewing a dead link keeps rendering with the 200 it has always used: the page
// itself was served successfully, and reset links are fetched by mail scanners
// and link previewers that treat a 4xx as a broken link. The POST passes 400,
// because there a submission was genuinely refused.
//
// Genuine server faults must NOT come here. A stored code that will not decrypt,
// a database failure, or a session store that cannot be read, stays an
// InternalServerError so it keeps its stack trace and keeps alerting.
func renderResetPasswordCodeInvalid(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request, httpStatus int) {
	bind := map[string]interface{}{
		"codeInvalidOrExpired": true,
	}
	if httpStatus != 0 {
		bind["_httpStatus"] = httpStatus
	}

	if err := httpHelper.RenderTemplate(w, r, "/layouts/auth_layout.html", "/reset_password.html", bind); err != nil {
		httpHelper.InternalServerError(w, r, err)
	}
}

// auditFailedResetPasswordCode records a refused reset request.
//
// The response is identical for every reason (see renderResetPasswordCodeInvalid),
// so this audit entry is the only place the actual cause is visible. That is
// deliberate: the detail is available to an administrator, who needs it to spot
// probing, and withheld from the caller, who would otherwise learn whether an
// address has an account.
//
// It records the client IP rather than the address, because there is no longer an address
// anywhere in the request to record and putting one back would undo half of what #112 and
// #201 removed. userId is written only when the lookup actually resolved a user; on the
// other branches the key is absent rather than zero, since a payload naming user 0 asserts a
// row that does not exist.
//
// The IP is truncated for the same reason the address used to be: MiddlewareRealIP resolves
// it from a forwarded header in a proxied deployment, so this function is still a sink for a
// value that originates outside the process.
func auditFailedResetPasswordCode(auditLogger AuditLogger, r *http.Request, userId int64, reason string) {
	const maxAuditedValueLength = 100

	clientIP := core_middleware.GetClientIPFromRequest(r)
	if len(clientIP) > maxAuditedValueLength {
		clientIP = clientIP[:maxAuditedValueLength]
	}

	details := map[string]interface{}{
		"ip":     clientIP,
		"reason": reason,
	}
	if userId != 0 {
		details["userId"] = userId
	}

	auditLogger.Log(constants.AuditFailedResetPasswordCode, details)
}

// rejectResetPassword audits the cause and renders the one indistinguishable response. The
// branches are kept separate only so the audit entry can name the reason.
func rejectResetPassword(httpHelper HttpHelper, auditLogger AuditLogger, w http.ResponseWriter,
	r *http.Request, userId int64, reason string, httpStatus int) {

	auditFailedResetPasswordCode(auditLogger, r, userId, reason)
	renderResetPasswordCodeInvalid(httpHelper, w, r, httpStatus)
}

// resolveResetPasswordMarker is what both steps after the redirect run before anything else:
// read the session marker, then re-resolve the code hash it names.
//
// Re-resolving is not belt and braces, it is the whole security boundary of the clean steps.
// The session is a client-side encrypted cookie (sessionstore.NewChunkedCookieStore), so
// clearing the marker replaces the browser's copy and cannot invalidate one an attacker
// captured. A marker trusted on its own would therefore outlive the password write, a newly
// issued code and every other password change, where today the write NULLs the code and a
// replayed link simply fails. Resolving the hash is what keeps that true (#112).
//
// Returns (nil, nil) when the request was refused, having already audited and responded.
func resolveResetPasswordMarker(httpHelper HttpHelper, httpSession sessions.Store,
	database data.Database, auditLogger AuditLogger, w http.ResponseWriter, r *http.Request,
	httpStatus int) (*LinkMarker, *models.User) {

	marker, rejection, err := GetLinkMarker(httpSession, r, LinkMarkerFlowResetPassword)
	if err != nil {
		httpHelper.InternalServerError(w, r, err)
		return nil, nil
	}
	if rejection != "" {
		// No userId: a rejected marker was not resolved against any row, and the id it
		// carries is a label rather than something this request established.
		rejectResetPassword(httpHelper, auditLogger, w, r, 0, string(rejection), httpStatus)
		return nil, nil
	}

	user, err := database.GetUserByForgotPasswordCodeHash(nil, marker.CodeHash)
	if err != nil {
		httpHelper.InternalServerError(w, r, err)
		return nil, nil
	}
	if user == nil {
		rejectResetPassword(httpHelper, auditLogger, w, r, 0, auditReasonCodeNoLongerOutstanding, httpStatus)
		return nil, nil
	}

	return marker, user
}

// HandleResetPasswordGet serves both halves of the reset link's journey.
//
// A request carrying ?code= is the emailed link being followed: it validates the code, marks
// the session and answers 303 to the same path with no query, so the credential does not
// remain in the address bar, in browser history, or in the Referer of anything the page then
// loads (#201, absorbed by #112 decision 1). A request with no query is that redirect
// landing, and renders the form from the marker alone.
//
// The link deliberately does NOT carry the address any more, which is what removes #112's
// defect class: a '+' or a '%xx' in an address was mangled by form-urlencoded query parsing
// and those users could never reset a password. The code's alphabet is entirely RFC 3986
// unreserved, so there is no encoding step left to get wrong.
func HandleResetPasswordGet(
	httpHelper HttpHelper,
	httpSession sessions.Store,
	database data.Database,
	auditLogger AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		if code := r.URL.Query().Get("code"); len(code) > 0 {
			handleResetPasswordLinkFollowed(httpHelper, httpSession, database, auditLogger, w, r, code)
			return
		}

		marker, user := resolveResetPasswordMarker(httpHelper, httpSession, database, auditLogger, w, r, 0)
		if user == nil {
			return
		}

		// The form carries the continuation id back, which is what ties this rendering to
		// the marker that produced it once the session moves on.
		bind := map[string]interface{}{
			"continuationId": marker.ContinuationId,
		}

		err := httpHelper.RenderTemplate(w, r, "/layouts/auth_layout.html", "/reset_password.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

// handleResetPasswordLinkFollowed is the first hop: the emailed link, carrying the code.
//
// It validates but does not consume the code (#112 decision 7). A mail scanner or link
// previewer that prefetches the URL therefore writes a marker into its own throwaway cookie
// jar and leaves the code usable for the real user; consuming here would let any prefetching
// gateway burn the code before the user ever saw the message.
func handleResetPasswordLinkFollowed(httpHelper HttpHelper, httpSession sessions.Store,
	database data.Database, auditLogger AuditLogger, w http.ResponseWriter, r *http.Request,
	code string) {

	codeHash, err := hashutil.HashString(code)
	if err != nil {
		httpHelper.InternalServerError(w, r, err)
		return
	}

	user, err := database.GetUserByForgotPasswordCodeHash(nil, codeHash)
	if err != nil {
		httpHelper.InternalServerError(w, r, err)
		return
	}

	// A code matching no row, and a row carrying a hash but no encrypted code, are answered
	// exactly as a wrong code is.
	if user == nil || len(user.ForgotPasswordCodeEncrypted) == 0 {
		rejectResetPassword(httpHelper, auditLogger, w, r, 0, auditReasonUnknownCode, 0)
		return
	}

	storedCode, err := encryption.DecryptData(user.ForgotPasswordCodeEncrypted)
	if err != nil {
		httpHelper.InternalServerError(w, r, errors.Wrap(err, "unable to decrypt forgot password code"))
		return
	}

	// The index found a candidate; this decides. No userId is audited on this branch: the
	// row matched a hash the supplied code does not reproduce, so nothing about it is
	// established as the subject of the request.
	if !forgotPasswordCodeMatches(storedCode, code) {
		rejectResetPassword(httpHelper, auditLogger, w, r, 0, auditReasonUnknownCode, 0)
		return
	}

	if isForgotPasswordCodeExpired(user) {
		rejectResetPassword(httpHelper, auditLogger, w, r, user.Id, auditReasonCodeExpired, 0)
		return
	}

	// The marker names the code hash, not only the user: see resolveResetPasswordMarker for
	// why a marker naming a durable id alone would be weaker than the flow it replaces.
	rejection, err := SaveLinkMarker(httpSession, w, r, LinkMarkerFlowResetPassword, user.Id, codeHash)
	if err != nil {
		httpHelper.InternalServerError(w, r, err)
		return
	}

	// A second, different reset link followed while one is still live. The first
	// continuation keeps the session and this one is refused, because one session holds one
	// marker and the form does not name the marker that rendered it: replacing here would
	// let a form already on screen write its password into this account instead. The userId
	// is this link's, which resolved; the account holding the live marker is not named.
	//
	// Audited rather than silently rendered, because a burst of these is what someone
	// pinning a victim's session looks like, and this response is otherwise identical to
	// every other refusal. Status zero, like the other first-hop rejections: the page was
	// served, it is the link that was refused.
	if rejection != "" {
		rejectResetPassword(httpHelper, auditLogger, w, r, user.Id, string(rejection), 0)
		return
	}

	// 303 rather than 302, so the browser is required to follow with a GET regardless of
	// what this request was, and the code is gone from the request target from here on.
	http.Redirect(w, r, ResetPasswordPath, http.StatusSeeOther)
}

func HandleResetPasswordPost(
	httpHelper HttpHelper,
	httpSession sessions.Store,
	database data.Database,
	passwordValidator PasswordValidator,
	auditLogger AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		renderError := func(message string) {
			bind := map[string]interface{}{
				"error": message,
				// Echoed from the submission rather than read from the marker, because
				// these rejections happen before the marker is resolved. A mistyped
				// confirmation must not cost the user their continuation, and echoing is
				// safe: the value authorizes nothing until it is checked against the
				// marker on the next submission.
				"continuationId": r.FormValue(continuationIdField),
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/auth_layout.html", "/reset_password.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		password := r.FormValue("password")
		passwordConfirmation := r.FormValue("passwordConfirmation")

		// i18n surface: A — browser-flow form rerender.
		if len(password) == 0 {
			renderError(i18n.NewLocalizedError(i18n.ErrCodeHandlerPasswordRequired, nil).Localize(r.Context()))
			return
		}

		if password != passwordConfirmation {
			renderError(i18n.NewLocalizedError(i18n.ErrCodeHandlerPasswordConfirmationMismatch, nil).Localize(r.Context()))
			return
		}

		err := passwordValidator.ValidatePassword(r.Context(), password)
		if err != nil {
			// i18n surface: A — browser-flow form rerender.
			if locErr, ok := err.(*i18n.LocalizedError); ok {
				renderError(locErr.Localize(r.Context()))
			} else {
				renderError(err.Error())
			}
			return
		}

		// The credential comes from the session marker, not the query: template/reset-form
		// has an empty action, so this POST re-submits to the clean URL the first hop
		// redirected to, and there is nothing in it to read.
		marker, user := resolveResetPasswordMarker(httpHelper, httpSession, database, auditLogger,
			w, r, http.StatusBadRequest)
		if user == nil {
			return
		}

		// The form names the marker that rendered it, and this refuses a form rendered for
		// one account from writing into another. Reachable whenever the session's marker
		// changed between the rendering and the submit: the previous marker expired and a
		// newer link took the slot, the reset that rendered this form already completed and
		// cleared it, or two first hops left the browser at once and the later Set-Cookie
		// won. SaveLinkMarker cannot cover any of those, because they act after the write.
		//
		// The userId audited is the marker's, which resolved: it names the account this
		// submission would have written into, which is the useful half of the entry.
		if !continuationMatches(marker.ContinuationId, r.FormValue(continuationIdField)) {
			rejectResetPassword(httpHelper, auditLogger, w, r, user.Id,
				auditReasonContinuationMismatch, http.StatusBadRequest)
			return
		}

		passwordHash, err := hashutil.HashPassword(password)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		// The write claims the code hash in the same conditional UPDATE that sets the
		// password, so a marker replayed after the reset completes, after a newer code is
		// issued, or after any other password change matches no row. Two concurrent copies
		// of one marker produce exactly one winner, for the reason MarkCodeAsUsed and
		// TryConsumeUserOTPStep record: a read followed by an unconditional write lets both
		// believe they made the transition.
		//
		// Narrow rather than a full-row UpdateUser: this handler holds a user model loaded
		// before the password was validated, so writing every column back would undo a
		// concurrent admin disable (#106 decision 14).
		//
		// Reset revokes everything, with no exceptSid: whoever is resetting a forgotten
		// password is not necessarily the person holding the live sessions, which is the
		// stolen-laptop case this issue exists for.
		result, err := RevokeUserAuthStateTx(database, user.Id, "", func(tx *sql.Tx) error {
			claimed, err := database.TryConsumeForgotPasswordCode(tx, user.Id, marker.CodeHash, passwordHash)
			if err != nil {
				return err
			}
			if !claimed {
				// Rolls the revocation sweep back with it: a reset that did not write a
				// password must not terminate the user's sessions either.
				return errResetPasswordClaimLost
			}
			return nil
		})
		if errors.Is(err, errResetPasswordClaimLost) {
			rejectResetPassword(httpHelper, auditLogger, w, r, user.Id, auditReasonClaimLost,
				http.StatusBadRequest)
			return
		}
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		// After commit, per decision 5. This is also the first audit event this handler emits
		// on SUCCESS: until now it logged only failures (auditFailedResetPasswordCode).
		LogRevokedUserAuthState(auditLogger, user.Id, RevocationReasonPasswordReset, "", result)

		// Hygiene, and not the thing that makes the marker single-use: the claim above is.
		// A failure here is logged rather than answered with a 500, because the password has
		// already changed and telling the caller the reset failed would be false. The stale
		// marker it leaves behind resolves to nothing on its next use.
		if err := ClearLinkMarker(httpSession, w, r); err != nil {
			slog.Error("unable to clear the reset password link marker after a completed reset",
				"userId", user.Id, "error", err)
		}

		bind := map[string]interface{}{
			"passwordReset":       true,
			"adminConsoleBaseUrl": config.GetAdminConsole().BaseURL,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/auth_layout.html", "/reset_password.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}
