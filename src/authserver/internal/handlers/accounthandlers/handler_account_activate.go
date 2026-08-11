package accounthandlers

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gorilla/sessions"
	"github.com/pkg/errors"

	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/user"
)

// verificationCodeLifetime bounds how long an activation code stays usable after
// HandleAccountRegisterPost issues it.
//
// Consulted on the FIRST hop only, where the emailed code arrives. The clean hop after the
// redirect is bounded by the marker's own window instead, which starts when the code was
// validated, so someone clicking at 4:59 is not dropped between the two requests. That is the
// same rule the reset flow states in isForgotPasswordCodeExpired (#112 decision 7).
const verificationCodeLifetime = 5 * time.Minute

// renderActivationLinkExpired renders the "this link is no longer usable, register again"
// state of the activation result page.
//
// Every marker-attributable refusal on the clean hop comes here: no marker, a marker left by
// the reset flow, an expired marker, and a marker whose code hash no longer resolves to a
// pre-registration. That last one is what refuses a replayed marker, since the session is a
// client-side encrypted cookie and clearing it cannot invalidate a copy somebody kept.
//
// It is an existing rendering rather than a new state on purpose: the page already tells the
// reader to register again, which is the right instruction for all four (#112).
func renderActivationLinkExpired(httpHelper handlers.HttpHelper, w http.ResponseWriter, r *http.Request) {
	bind := map[string]interface{}{
		"linkHasExpired": true,
	}

	if err := httpHelper.RenderTemplate(w, r, "/layouts/auth_layout.html", "/account_register_activation_result.html", bind); err != nil {
		httpHelper.InternalServerError(w, r, err)
	}
}

// HandleAccountActivateGet serves both halves of the activation link's journey.
//
// A request carrying ?code= is the emailed link being followed: it validates the code, marks
// the session and answers 303 to the same path with no query, so the credential does not
// remain in the address bar, in browser history, or in the Referer of anything the page then
// loads (#201, absorbed by #112 decision 1). A request with no query is that redirect landing,
// and completes the activation from the marker alone.
//
// The link deliberately does NOT carry the address any more, which is what removes #112's
// defect class: a '+' or a '%xx' in an address was mangled by form-urlencoded query parsing,
// so the pre-registration was never found and those users could not register at all. The
// code's alphabet is entirely RFC 3986 unreserved, so there is no encoding step left to get
// wrong.
//
// The account is still created during a GET, which decision 3 considered and kept: a link
// previewer that fetches the URL therefore completes the registration. After this change it
// consumes the redirect and the account is created on the clean GET instead, which is the same
// outcome by one more hop.
func HandleAccountActivateGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	database data.Database,
	userCreator handlers.UserCreator,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		if code := r.URL.Query().Get("code"); len(code) > 0 {
			handleActivationLinkFollowed(httpHelper, httpSession, database, w, r, code)
			return
		}

		handleActivationCleanHop(httpHelper, httpSession, database, userCreator, auditLogger, w, r)
	}
}

// handleActivationLinkFollowed is the first hop: the emailed link, carrying the code.
//
// It validates but does not consume the code (#112 decision 7). A mail scanner that prefetches
// the URL writes a marker into its own throwaway cookie jar and leaves the code usable for the
// real user.
func handleActivationLinkFollowed(httpHelper handlers.HttpHelper, httpSession sessions.Store,
	database data.Database, w http.ResponseWriter, r *http.Request, code string) {

	codeHash, err := hashutil.HashString(code)
	if err != nil {
		httpHelper.InternalServerError(w, r, err)
		return
	}

	preRegistration, err := database.GetPreRegistrationByVerificationCodeHash(nil, codeHash)
	if err != nil {
		httpHelper.InternalServerError(w, r, err)
		return
	}

	if preRegistration == nil {
		httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("could not find pre registration")))
		return
	}

	verificationCode, err := encryption.DecryptData(preRegistration.VerificationCodeEncrypted)
	if err != nil {
		httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("unable to decrypt verification code")))
		return
	}

	// The index found a candidate; this decides. Reachable only through a SHA-256 collision now
	// that the row is located by hash, and kept so the comparison stays load-bearing rather than
	// decorative. The address comes from the resolved row, since the request no longer has one.
	if verificationCode != code {
		httpHelper.InternalServerError(w, r, errors.WithStack(fmt.Errorf("email %v is trying to activate the account with the wrong code", preRegistration.Email)))
		return
	}

	if isVerificationCodeExpired(preRegistration) {
		// The code has expired: delete the pre-registration and ask the user to register again.
		if err := database.DeletePreRegistration(nil, preRegistration.Id); err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		renderActivationLinkExpired(httpHelper, w, r)
		return
	}

	// The marker names the code hash, not only the pre-registration id: a marker naming a
	// durable id alone would still resolve after the row was deleted, where the hash stops
	// resolving the moment the activation completes. See handleActivationCleanHop.
	if err := handlers.SaveLinkMarker(httpSession, w, r, handlers.LinkMarkerFlowAccountActivate,
		preRegistration.Id, codeHash); err != nil {
		httpHelper.InternalServerError(w, r, err)
		return
	}

	// 303 rather than 302, so the browser is required to follow with a GET regardless of what
	// this request was, and the code is gone from the request target from here on.
	http.Redirect(w, r, handlers.AccountActivatePath, http.StatusSeeOther)
}

// isVerificationCodeExpired reports whether the activation code issued for this
// pre-registration is past its lifetime. A row with no issued-at is treated as expired, which
// fails closed.
func isVerificationCodeExpired(preRegistration *models.PreRegistration) bool {
	return preRegistration.VerificationCodeIssuedAt.Time.Add(verificationCodeLifetime).Before(time.Now().UTC())
}

// handleActivationCleanHop is the redirect landing: no query at all, the marker alone.
//
// Re-resolving the marker's code hash is the whole security boundary here, for the reason
// resolveResetPasswordMarker gives on the reset side. The session is a client-side encrypted
// cookie, so clearing the marker replaces the browser's copy and cannot invalidate one an
// attacker captured; what refuses that copy is DeletePreRegistration having removed the row
// the hash names, which happens in the same request that creates the account.
func handleActivationCleanHop(httpHelper handlers.HttpHelper, httpSession sessions.Store,
	database data.Database, userCreator handlers.UserCreator, auditLogger handlers.AuditLogger,
	w http.ResponseWriter, r *http.Request) {

	marker, rejection, err := handlers.GetLinkMarker(httpSession, r, handlers.LinkMarkerFlowAccountActivate)
	if err != nil {
		httpHelper.InternalServerError(w, r, err)
		return
	}
	if rejection != "" {
		renderActivationLinkExpired(httpHelper, w, r)
		return
	}

	// The resolved row is the authority for which registration this is, not marker.Id: the
	// marker travels in a cookie, so the id it carries is a label rather than something this
	// request established.
	preRegistration, err := database.GetPreRegistrationByVerificationCodeHash(nil, marker.CodeHash)
	if err != nil {
		httpHelper.InternalServerError(w, r, err)
		return
	}
	if preRegistration == nil {
		renderActivationLinkExpired(httpHelper, w, r)
		return
	}

	createdUser, err := userCreator.CreateUser(&user.CreateUserInput{
		Email:         preRegistration.Email,
		EmailVerified: true,
		PasswordHash:  preRegistration.PasswordHash,
	})
	if err != nil {
		httpHelper.InternalServerError(w, r, err)
		return
	}

	auditLogger.Log(constants.AuditCreatedUser, map[string]interface{}{
		"email": createdUser.Email,
	})

	// What makes the marker one-shot: after this the hash it names resolves to nothing, so a
	// replayed copy of the cookie lands on the expired rendering. Two copies racing before
	// either gets here are bounded instead by the UNIQUE index on users.email, which refuses
	// the second insert, so exactly one account exists either way.
	err = database.DeletePreRegistration(nil, preRegistration.Id)
	if err != nil {
		httpHelper.InternalServerError(w, r, err)
		return
	}

	auditLogger.Log(constants.AuditActivatedAccount, map[string]interface{}{
		"email": createdUser.Email,
	})

	// Hygiene, and not the thing that makes the marker single-use: the deletion above is. A
	// failure here is logged rather than answered with a 500, because the account has already
	// been created and telling the caller the activation failed would be false.
	if err := handlers.ClearLinkMarker(httpSession, w, r); err != nil {
		slog.Error("unable to clear the account activation link marker after a completed activation",
			"email", createdUser.Email, "error", err)
	}

	bind := map[string]interface{}{
		"adminConsoleBaseUrl": config.GetAdminConsole().BaseURL,
	}

	err = httpHelper.RenderTemplate(w, r, "/layouts/auth_layout.html", "/account_register_activation_result.html", bind)
	if err != nil {
		httpHelper.InternalServerError(w, r, err)
	}
}
