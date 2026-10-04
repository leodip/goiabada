package accounthandlers

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/sessionstore"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/emaillinks"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/usercreation"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/i18n"
)

// The reasons an activation link is refused, as recorded in the audit entry. They are the reset
// flow's names for the same states, so one audit query reads both emailed-link flows. The marker's
// own rejections (marker_missing, marker_wrong_flow, marker_expired, continuation_in_flight) pass
// through as emaillinks decided them, as they do on the reset side (#425).
const (
	// activationReasonUnknownCode is a code that resolves to no pre-registration, or to one whose
	// stored code it does not reproduce. The first hop only, where the credential arrives.
	activationReasonUnknownCode = "unknown_code"
	// activationReasonCodeExpired is the code's own lifetime having passed.
	activationReasonCodeExpired = "code_expired"
	// activationReasonCodeNoLongerOutstanding is a marker whose code hash no longer resolves: the
	// activation completed, the code expired and was deleted, or the row is otherwise gone.
	activationReasonCodeNoLongerOutstanding = "code_no_longer_outstanding"
	// activationReasonContinuationMismatch is a submitted form naming a continuation other than
	// the one the session holds, so a page rendered for one pending registration cannot activate
	// another. The reset flow's name for the same refusal.
	activationReasonContinuationMismatch = "continuation_mismatch"
	// activationReasonAddressTaken is a pending registration whose address has meanwhile gained
	// an account: an administrator created it, registration without verification ran for it, or
	// another pending registration for it activated first. Checked at the form and again at its
	// POST, and also what an insert that loses the race on the unique email index is (#207
	// decision 10). The pending registration is deleted with it, since it can never complete.
	activationReasonAddressTaken = "address_taken"
)

// refuseActivationLink is every activation refusal: one audit entry naming the reason, then the
// one rendering, at 200 on a GET and 400 on the POST.
//
// 200 and not a 4xx on a GET, for the reason renderResetPasswordCodeInvalid gives: activation links
// are fetched by mail scanners and link previewers that treat a 4xx as a broken link, and the page
// itself was served. The POST passes 400, because there a submission was genuinely refused, as the
// reset form's POST answers its own. The response is otherwise the same for every reason, so the
// entry is the only place the cause is visible. An unknown code used to answer the 500 page with an error-level stack,
// which paged an operator for a user clicking an old link (#425 decision 5).
//
// Audited rather than logged, as a refused reset link is, so an administrator sees probing of
// activation links where they see it for reset links; a Warn record reached the console alone
// until #435. preRegistrationId is written only when the lookup resolved a pre-registration the
// code matched; on the other branches the key is absent rather than zero, since a payload naming
// row 0 asserts a row that does not exist.
//
// Genuine server faults must NOT come here: a stored code that will not decrypt, a database
// failure and a session store that cannot be read stay InternalServerError.
func refuseActivationLink(pageRenderer PageRenderer, auditLogger AuditLogger, w http.ResponseWriter,
	r *http.Request, preRegistrationId int64, reason string, httpStatus int) {

	details := map[string]interface{}{
		"ip":     auditedClientIP(r),
		"reason": reason,
	}
	if preRegistrationId != 0 {
		details["preRegistrationId"] = preRegistrationId
	}

	auditLogger.Log(r.Context(), audit.EventFailedAccountActivationCode, details)
	renderActivationLinkExpired(pageRenderer, w, r, httpStatus)
}

// renderActivationLinkExpired renders the "this link is no longer usable, register again"
// state of the activation result page. Reached only through refuseActivationLink.
//
// Every refusal attributable to the link comes here. On the two steps after the redirect: no
// marker, a marker left by the reset flow, an expired marker, a marker whose code hash no longer
// resolves to a pre-registration, and an address that has meanwhile gained an account; on the
// POST, also a form naming another continuation. A hash that no longer resolves is what refuses a
// marker whose code has since been consumed, which clearing the session does not answer even now
// that clearing it reaches every copy (#266). On the first hop: an unknown code, a code its row's
// stored code does not match, an expired code, and a link followed while another continuation is
// still live.
//
// It is an existing rendering rather than a new state on purpose: the page already tells the
// reader to register again, which is the right instruction for every one of them (#112), an
// address with an account included, since registering again leads to the notice that it has one.
//
// httpStatus is applied only when non-zero, as renderResetPasswordCodeInvalid applies it.
func renderActivationLinkExpired(pageRenderer PageRenderer, w http.ResponseWriter, r *http.Request, httpStatus int) {
	bind := map[string]interface{}{
		"linkHasExpired": true,
	}
	if httpStatus != 0 {
		bind["_httpStatus"] = httpStatus
	}

	if err := pageRenderer.RenderTemplate(w, r, "/layouts/auth_layout.html", "/account_register_activation_result.html", bind); err != nil {
		pageRenderer.InternalServerError(w, r, err)
	}
}

// accountActivateDatabase is what the self-registration activation pages need: the pre-
// registration they consume, and the account its address may have gained meanwhile.
type accountActivateDatabase interface {
	DeletePreRegistration(ctx context.Context, tx *sql.Tx, preRegistrationId int64) error
	GetPreRegistrationByVerificationCodeHash(ctx context.Context, tx *sql.Tx, codeHash string) (*record.PreRegistration, error)
	GetUserByEmail(ctx context.Context, tx *sql.Tx, email string) (*record.User, error)
}

// HandleActivateGet serves both halves of the activation link's journey that a GET reaches.
//
// A request carrying ?code= is the emailed link being followed: it validates the code, marks
// the session and answers 303 to the same path with no query, so the credential does not
// remain in the address bar, in browser history, or in the Referer of anything the page then
// loads (#201, absorbed by #112 decision 1). A request with no query is that redirect landing,
// and renders the "choose your password" form from the marker alone.
//
// The link deliberately does NOT carry the address any more, which is what removes #112's
// defect class: a '+' or a '%xx' in an address was mangled by form-urlencoded query parsing,
// so the pre-registration was never found and those users could not register at all. The
// code's alphabet is entirely RFC 3986 unreserved, so there is no encoding step left to get
// wrong.
//
// Neither hop creates the account, and this handler is given no UserCreator to do it with: only
// the form's POST does, HandleActivatePost (#207 decision 1). The account used to be created on
// the clean GET, so a mail scanner or link previewer that fetched the link created it with no
// click, with the password whoever registered the address had chosen. RFC 9110 section 9.2.1 asks
// that a safe method change nothing the client did not ask for, and that resource owners not
// expose unsafe actions to prefetching or automatic link analysis; now a fetch renders a form, and
// whoever proves control of the mailbox chooses the password.
//
// Both hops refuse while self-registration is off, the way the register pages do: a link mailed
// while registration was on must not create an account after an administrator has turned it off
// (#425 decision 6).
func HandleActivateGet(
	pageRenderer PageRenderer,
	httpSession sessionstore.Store,
	database accountActivateDatabase,
	auditLogger AuditLogger,
	dataCipher *encryption.DataCipher,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			pageRenderer.InternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}
		if !settings.SelfRegistrationEnabled {
			refuseSelfRegistrationDisabled(pageRenderer, w, r)
			return
		}

		if code := r.URL.Query().Get("code"); len(code) > 0 {
			handleActivationLinkFollowed(pageRenderer, httpSession, database, auditLogger, dataCipher, w, r, code)
			return
		}

		marker, preRegistration := resolveActivationMarker(pageRenderer, httpSession, database, auditLogger, w, r, 0)
		if preRegistration == nil {
			return
		}

		// The form carries the continuation id back, which is what ties this rendering to the
		// marker that produced it once the session moves on, as the reset form's does.
		bind := map[string]interface{}{
			"email":          preRegistration.Email,
			"continuationId": marker.ContinuationId,
		}

		err := pageRenderer.RenderTemplate(w, r, "/layouts/auth_layout.html", "/account_activate_password.html", bind)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
		}
	}
}

// handleActivationLinkFollowed is the first hop: the emailed link, carrying the code.
//
// It validates but does not consume the code (#112 decision 7). A mail scanner that prefetches
// the URL writes a marker into its own throwaway cookie jar and leaves the code usable for the
// real user.
func handleActivationLinkFollowed(pageRenderer PageRenderer, httpSession sessionstore.Store,
	database accountActivateDatabase, auditLogger AuditLogger, dataCipher *encryption.DataCipher,
	w http.ResponseWriter, r *http.Request, code string) {

	codeHash := hashutil.HashString(code)

	preRegistration, err := database.GetPreRegistrationByVerificationCodeHash(r.Context(), nil, codeHash)
	if err != nil {
		pageRenderer.InternalServerError(w, r, err)
		return
	}

	// An unknown code is also a consumed one: the activation deletes the row, so a link clicked
	// twice lands here.
	if preRegistration == nil {
		refuseActivationLink(pageRenderer, auditLogger, w, r, 0, activationReasonUnknownCode, 0)
		return
	}

	verificationCode, err := dataCipher.Decrypt(preRegistration.VerificationCodeEncrypted)
	if err != nil {
		pageRenderer.InternalServerError(w, r, errs.Wrap(err, "unable to decrypt verification code"))
		return
	}

	// The index found a candidate; this decides, in constant time, with the comparison the reset
	// flow's code check uses, so no code comparison in either emailed-link flow stops at the first
	// differing byte (#207 decision 12). Reachable only through a SHA-256 collision now that the
	// row is located by hash, and kept so the comparison stays load-bearing rather than
	// decorative. Answered as an unknown code, as the reset twin answers its own mismatch, and
	// with no preRegistrationId for the reason it gives: nothing about the row is established.
	if !emailedCodeMatches(verificationCode, code) {
		refuseActivationLink(pageRenderer, auditLogger, w, r, 0, activationReasonUnknownCode, 0)
		return
	}

	if isVerificationCodeExpired(preRegistration) {
		// The code has expired: delete the pre-registration and ask the user to register again.
		if deletePreRegistrationErr := database.DeletePreRegistration(r.Context(), nil, preRegistration.Id); deletePreRegistrationErr != nil {
			pageRenderer.InternalServerError(w, r, deletePreRegistrationErr)
			return
		}

		refuseActivationLink(pageRenderer, auditLogger, w, r, preRegistration.Id, activationReasonCodeExpired, 0)
		return
	}

	// The marker names the code hash, not only the pre-registration id: a marker naming a
	// durable id alone would still resolve after the row was deleted, where the hash stops
	// resolving the moment the activation completes. See resolveActivationMarker.
	rejection, err := emaillinks.SaveLinkMarker(httpSession, w, r, emaillinks.LinkMarkerFlowAccountActivate,
		preRegistration.Id, codeHash)
	if err != nil {
		pageRenderer.InternalServerError(w, r, err)
		return
	}

	// A second, different link followed while one is still live, of either flow. The first
	// continuation keeps the session and this one is refused: replacing here would let the form
	// the first link rendered, or the redirect already in flight, activate this registration
	// instead of the one that authorized it. Audited as the reset side audits the same refusal,
	// naming this link's pre-registration, which resolved; the one holding the live marker is not
	// named.
	if rejection != "" {
		refuseActivationLink(pageRenderer, auditLogger, w, r, preRegistration.Id, string(rejection), 0)
		return
	}

	// 303 rather than 302, so the browser is required to follow with a GET regardless of what
	// this request was, and the code is gone from the request target from here on.
	http.Redirect(w, r, emaillinks.AccountActivatePath, http.StatusSeeOther)
}

// isVerificationCodeExpired reports whether the activation code issued for this
// pre-registration is past its lifetime. A row with no issued-at is treated as expired, which
// fails closed.
func isVerificationCodeExpired(preRegistration *record.PreRegistration) bool {
	return preRegistration.VerificationCodeIssuedAt.Time.Add(emaillinks.ActivationCodeLifetime).Before(time.Now().UTC())
}

// resolveActivationMarker is what both steps after the redirect run before anything else: read
// the session marker, re-resolve the code hash it names, and check the address has no account.
//
// Re-resolving the marker's code hash is what refuses a replayed marker, for the reason
// resolveResetPasswordMarker gives on the reset side: DeletePreRegistration removes the row the
// hash names in the same request that creates the account, so a second attempt resolves to
// nothing. Clearing the session now reaches every copy of the marker, since the session is a
// database row rather than a browser cookie, so this is defence in depth rather than the whole
// boundary it was written as (#112, #266).
//
// The address check comes before the password is looked at, so an address that has meanwhile
// gained an account is refused whatever was typed into the form rather than answered with another
// form to fill in, as the reset flow refuses a disabled account (#207 decision 10).
//
// Returns (nil, nil) when the request was refused, having already audited and responded.
func resolveActivationMarker(pageRenderer PageRenderer, httpSession sessionstore.Store,
	database accountActivateDatabase, auditLogger AuditLogger, w http.ResponseWriter, r *http.Request,
	httpStatus int) (*emaillinks.LinkMarker, *record.PreRegistration) {

	marker, rejection, err := emaillinks.GetLinkMarker(httpSession, r, emaillinks.LinkMarkerFlowAccountActivate)
	if err != nil {
		pageRenderer.InternalServerError(w, r, err)
		return nil, nil
	}
	if rejection != "" {
		// No preRegistrationId: a rejected marker was not resolved against any row, and the id
		// it carries is a label rather than something this request established.
		refuseActivationLink(pageRenderer, auditLogger, w, r, 0, string(rejection), httpStatus)
		return nil, nil
	}

	// The resolved row is the authority for which registration this is, not marker.Id: the
	// marker travels in a cookie, so the id it carries is a label rather than something this
	// request established.
	preRegistration, err := database.GetPreRegistrationByVerificationCodeHash(r.Context(), nil, marker.CodeHash)
	if err != nil {
		pageRenderer.InternalServerError(w, r, err)
		return nil, nil
	}
	if preRegistration == nil {
		refuseActivationLink(pageRenderer, auditLogger, w, r, 0, activationReasonCodeNoLongerOutstanding, httpStatus)
		return nil, nil
	}

	user, err := database.GetUserByEmail(r.Context(), nil, preRegistration.Email)
	if err != nil {
		pageRenderer.InternalServerError(w, r, err)
		return nil, nil
	}
	if user != nil {
		refuseActivationAddressTaken(pageRenderer, database, auditLogger, w, r, preRegistration.Id, httpStatus)
		return nil, nil
	}

	return marker, preRegistration
}

// refuseActivationAddressTaken refuses a pending registration whose address already has an
// account, and deletes it, since it can never complete: registering again then reaches whatever
// registration tells an address that has an account (#207 decision 10). A delete that fails is a
// server fault, answered as one, as the expired code's delete on the first hop is.
func refuseActivationAddressTaken(pageRenderer PageRenderer, database accountActivateDatabase,
	auditLogger AuditLogger, w http.ResponseWriter, r *http.Request, preRegistrationId int64, httpStatus int) {

	if err := database.DeletePreRegistration(r.Context(), nil, preRegistrationId); err != nil {
		pageRenderer.InternalServerError(w, r, err)
		return
	}

	refuseActivationLink(pageRenderer, auditLogger, w, r, preRegistrationId, activationReasonAddressTaken, httpStatus)
}

// HandleActivatePost is the "choose your password" form's submission, and the one request that
// creates the account: with the password typed here, the address marked verified, and the pending
// registration consumed (#207 decision 1).
//
// It refuses as the reset form's POST does. The marker is resolved first, so a refused link is
// refused whatever was typed, at 400 with the one refusal page; a missing password, a
// confirmation that differs, or a password the configured policy refuses redraws the form with the
// reason; a form naming a continuation other than the one the session holds is refused as
// continuation_mismatch, so a page rendered for one pending registration cannot activate another.
//
// Of two concurrent submissions of one activation, or of two pending registrations for one
// address, exactly one creates the account: the other loses on the unique index on users.email,
// which the data layer reports as data.ErrUniqueViolation, and is refused as address_taken like
// an address the lookup found taken. It used to answer the 500 page with an error-level stack.
func HandleActivatePost(
	pageRenderer PageRenderer,
	httpSession sessionstore.Store,
	database accountActivateDatabase,
	userCreator UserCreator,
	passwordValidator PasswordValidator,
	auditLogger AuditLogger,
	adminConsoleBaseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			pageRenderer.InternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}
		if !settings.SelfRegistrationEnabled {
			refuseSelfRegistrationDisabled(pageRenderer, w, r)
			return
		}

		// The credential comes from the session marker, not the query: the form has an empty
		// action, so this POST re-submits to the clean URL the first hop redirected to.
		marker, preRegistration := resolveActivationMarker(pageRenderer, httpSession, database, auditLogger,
			w, r, http.StatusBadRequest)
		if preRegistration == nil {
			return
		}

		renderError := func(message string) {
			bind := map[string]interface{}{
				"email": preRegistration.Email,
				"error": message,
				// Echoed from the submission rather than read from the marker, because these
				// rejections happen before the continuation is checked against it, as the reset
				// form echoes it: a mistyped confirmation must not cost the continuation.
				"continuationId": r.PostFormValue(continuationIdField),
			}

			err := pageRenderer.RenderTemplate(w, r, "/layouts/auth_layout.html", "/account_activate_password.html", bind)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
			}
		}

		// r.PostFormValue rather than r.FormValue throughout, the continuation id included: r.Form
		// merges the URL query behind the body, so /account/activate?password=... would set a
		// password from a request target, where it reaches the browser's history, the Referer of
		// anything the page loads, and the access log of every proxy in front of the deployment
		// (#202).
		password := r.PostFormValue("password")
		passwordConfirmation := r.PostFormValue("passwordConfirmation")

		// i18n surface: A — browser-flow form rerender.
		if len(password) == 0 {
			renderError(i18n.NewLocalizedError(i18n.ErrCodeHandlerPasswordRequired, nil).Localize(r.Context()))
			return
		}

		if password != passwordConfirmation {
			renderError(i18n.NewLocalizedError(i18n.ErrCodeHandlerPasswordConfirmationMismatch, nil).Localize(r.Context()))
			return
		}

		err := passwordValidator.ValidatePassword(settings.PasswordPolicy, password)
		if err != nil {
			// i18n surface: A — browser-flow form rerender.
			var locErr *i18n.LocalizedError
			if errors.As(err, &locErr) {
				renderError(locErr.Localize(r.Context()))
			} else {
				renderError(err.Error())
			}
			return
		}

		// The form names the marker that rendered it. Reachable whenever the session's marker
		// changed between the rendering and the submit, which the reset POST describes. The
		// pending registration audited is the marker's, which resolved.
		if !continuationMatches(marker.ContinuationId, r.PostFormValue(continuationIdField)) {
			refuseActivationLink(pageRenderer, auditLogger, w, r, preRegistration.Id,
				activationReasonContinuationMismatch, http.StatusBadRequest)
			return
		}

		passwordHash, err := passwordhash.Hash(password)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}

		createdUser, err := userCreator.CreateUser(r.Context(), &usercreation.Input{
			Email:         preRegistration.Email,
			EmailVerified: true,
			PasswordHash:  passwordHash,
		})
		if errors.Is(err, data.ErrUniqueViolation) {
			refuseActivationAddressTaken(pageRenderer, database, auditLogger, w, r, preRegistration.Id, http.StatusBadRequest)
			return
		}
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}

		auditLogger.Log(r.Context(), audit.EventCreatedUser, map[string]interface{}{
			"email": createdUser.Email,
		})

		// What makes the marker one-shot: after this the hash it names resolves to nothing, so a
		// replayed copy lands on the refusal page. Two copies racing before either gets here are
		// bounded instead by the UNIQUE index on users.email, which refuses the second insert, so
		// exactly one account exists either way.
		err = database.DeletePreRegistration(r.Context(), nil, preRegistration.Id)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}

		auditLogger.Log(r.Context(), audit.EventActivatedAccount, map[string]interface{}{
			"email": createdUser.Email,
		})

		// Hygiene, and not the thing that makes the marker single-use: the deletion above is. A
		// failure here is logged rather than answered with a 500, because the account has already
		// been created and telling the caller the activation failed would be false.
		if clearLinkMarkerErr := emaillinks.ClearLinkMarker(httpSession, w, r); clearLinkMarkerErr != nil {
			slog.ErrorContext(r.Context(), "unable to clear the account activation link marker after a completed activation",
				"email", createdUser.Email, "error", clearLinkMarkerErr)
		}

		bind := map[string]interface{}{
			"adminConsoleBaseUrl": adminConsoleBaseURL,
		}

		err = pageRenderer.RenderTemplate(w, r, "/layouts/auth_layout.html", "/account_register_activation_result.html", bind)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
		}
	}
}
