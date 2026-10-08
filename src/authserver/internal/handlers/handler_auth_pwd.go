package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/i18n"
)

// authPwdDatabase is what the password hop needs: the client and the user being authenticated.
//
// It embeds the client display port because the screen renders through getClientDisplayInfo.
//
// No session lookup: the GET used to read the browser's session to prefill the email field, but
// GetUserSessionBySessionIdentifier never loads the session's User, so the address was always
// empty. It was removed rather than repaired, because prefilling an ended session's address is
// what a shared machine should not do (#248, #436).
type authPwdDatabase interface {
	clientDisplayDatabase

	GetClientByClientIdentifier(ctx context.Context, tx *sql.Tx, clientIdentifier string) (*record.Client, error)
	GetUserByEmail(ctx context.Context, tx *sql.Tx, email string) (*record.User, error)
}

func HandleAuthPwdGet(
	pageRenderer PageRenderer,
	ceremonyStore CeremonyStore,
	database authPwdDatabase,
	auditLogger AuditLogger,
	adminConsoleBaseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		authContext, ok := loadAuthContext(pageRenderer, ceremonyStore, auditLogger, w, r, adminConsoleBaseURL)
		if !ok {
			return
		}

		if !requireAuthState(pageRenderer, w, r, authContext, ceremony.AuthStateLevel1Password) {
			return
		}

		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			pageRenderer.InternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}

		// Fetch client to get display settings
		client, err := database.GetClientByClientIdentifier(r.Context(), nil, authContext.ClientId)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
		if client == nil {
			pageRenderer.InternalServerError(w, r, errs.New("client not found"))
			return
		}

		displayInfo := getClientDisplayInfo(r.Context(), database, client)

		bind := map[string]interface{}{
			"error": nil,
			// The rendered form says which ceremony rendered it, and HandleAuthPwdPost refuses a
			// submission naming any other one. Without it, a password typed into this form after a
			// second /auth/authorize replaced the auth context would finish that other request's
			// authorization instead, and where that client requires no consent the code is issued
			// without the user seeing any screen at all (#79).
			"ceremonyId":              authContext.CeremonyId,
			"smtpEnabled":             settings.SMTPEnabled,
			"layoutShowClientSection": displayInfo.ShowSection,
			"layoutClientName":        displayInfo.ClientName,
			"layoutHasClientLogo":     displayInfo.HasLogo,
			"layoutClientLogoUrl":     displayInfo.LogoURL,
			"layoutClientDescription": displayInfo.Description,
			"layoutClientWebsiteUrl":  displayInfo.WebsiteURL,
		}

		err = pageRenderer.RenderTemplate(w, r, "/layouts/auth_layout.html", "/auth_pwd.html", bind)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAuthPwdPost(
	pageRenderer PageRenderer,
	ceremonyStore CeremonyStore,
	database authPwdDatabase,
	auditLogger AuditLogger,
	credentialFailures CredentialFailureRecorder,
	baseURL string,
	adminConsoleBaseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// loadAuthContext refuses a submission naming another ceremony before the AuthState check, so
		// a login form left open in another tab gets the 400 mismatch page rather than the 500 that
		// a replaced context's state would produce, and before anything reads the credentials: a
		// submission naming a ceremony that is no longer current is answered without ever looking up
		// a user or verifying a password, so a stale form cannot authenticate anybody for anything
		// (#79).
		authContext, ok := loadAuthContext(pageRenderer, ceremonyStore, auditLogger, w, r, adminConsoleBaseURL)
		if !ok {
			return
		}

		if !requireAuthState(pageRenderer, w, r, authContext, ceremony.AuthStateLevel1Password) {
			return
		}

		// Normalized to exactly what the rate limiter's account key does, and to what every
		// write path stores. Two things depend on the spelling matching: the limiter and the
		// account it protects must agree about which account a request is, or a case variant
		// buys a fresh bucket; and mysql and mssql compare email case-insensitively while
		// postgres and sqlite do not, so without this a stored bob@x.com typed as Bob@x.com
		// signs in on two engines and is refused on the other two (#219).
		email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))

		// r.PostFormValue rather than r.FormValue, matching the ceremony id read above so both
		// reads in this function agree about what a submission is: r.Form merges the URL query
		// behind the body, so /auth/pwd?password=... would authenticate, and a credential in a
		// request target reaches the browser's history, the Referer of anything the page loads,
		// and the access log of every proxy in front of the deployment (#202).
		password := r.PostFormValue("password")

		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			pageRenderer.InternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}

		// Fetch client to get display settings
		client, err := database.GetClientByClientIdentifier(r.Context(), nil, authContext.ClientId)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
		if client == nil {
			pageRenderer.InternalServerError(w, r, errs.New("client not found"))
			return
		}

		displayInfo := getClientDisplayInfo(r.Context(), database, client)

		// renderError closes over r so a subsequent locale refinement
		// is picked up by the closure on its next invocation.
		renderError := func(le *i18n.LocalizedError) {
			bind := map[string]interface{}{
				"error": le.Localize(r.Context()),
				// The re-rendered form has to carry the id too, or a single mistyped password
				// would end the ceremony: the retry would name no ceremony and be refused.
				"ceremonyId":              authContext.CeremonyId,
				"smtpEnabled":             settings.SMTPEnabled,
				"email":                   email,
				"layoutShowClientSection": displayInfo.ShowSection,
				"layoutClientName":        displayInfo.ClientName,
				"layoutHasClientLogo":     displayInfo.HasLogo,
				"layoutClientLogoUrl":     displayInfo.LogoURL,
				"layoutClientDescription": displayInfo.Description,
				"layoutClientWebsiteUrl":  displayInfo.WebsiteURL,
			}

			err = pageRenderer.RenderTemplate(w, r, "/layouts/auth_layout.html", "/auth_pwd.html", bind)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
			}
		}

		// Already trimmed above. password is not: a space can be part of one.
		if len(email) == 0 {
			renderError(i18n.NewLocalizedError(i18n.ErrCodeLoginEmailRequired, nil))
			return
		}

		if len(strings.TrimSpace(password)) == 0 {
			renderError(i18n.NewLocalizedError(i18n.ErrCodeLoginPasswordRequired, nil))
			return
		}

		user, err := database.GetUserByEmail(r.Context(), nil, email)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}

		// The address typed into the form is recorded only as its digest, of the address as the
		// lookup above normalized it: the form collects whatever anyone types, an attacker's
		// address list or a password pasted into the wrong field, and the audit table would
		// otherwise keep every one of them in plain text (#522 decision 10).
		emailDigest := hashutil.HashString(email)

		// "Authentication failed." stays on the request's existing locale
		// (we don't yet know whether this email belongs to a real user —
		// switching to user.Locale here would side-channel disclose whether
		// the account exists).
		authFailed := i18n.NewLocalizedError(i18n.ErrCodeLoginAuthFailed, nil)

		if user == nil {
			// Timing-safe user enumeration protection: perform a dummy bcrypt comparison
			// even when the user doesn't exist. This ensures the response time is similar
			// to when a user exists but the password is wrong, preventing attackers from
			// determining whether an email exists based on response timing differences.
			passwordhash.Verify(passwordhash.DummyHash, password)

			// A guess against an address that names no account is still a guess, and
			// charging it is also what keeps this branch from being a cheaper way to
			// enumerate addresses than the branch below.
			credentialFailures.RecordCredentialFailure(r)
			auditLogger.Log(r.Context(), audit.EventAuthFailedPwd, map[string]interface{}{
				"email_digest": emailDigest,
			})
			renderError(authFailed)
			return
		}

		if !passwordhash.Verify(user.PasswordHash, password) {
			credentialFailures.RecordCredentialFailure(r)
			// The account the guess was against, which the audit log's readers can already
			// see; nothing here reaches the visitor, who is answered as for an unknown address.
			auditLogger.Log(r.Context(), audit.EventAuthFailedPwd, map[string]interface{}{
				"email_digest": emailDigest,
				"user_id":      user.Id,
			})
			renderError(authFailed)
			return
		}

		// Password verified — surfacing user-specific errors (account disabled,
		// downstream flow messages) in user.Locale is now safe and correct.
		// Skipped when explicit request or in-flight UI locales are in play.
		r = r.WithContext(i18n.WithLocale(r.Context(), false, user.Locale))

		// Deliberately not a credential failure: the password was right, so there is
		// nothing here for the rate limiter to bound. The same holds for the missing-email
		// and missing-password renders above, which verify nothing at all. Charging those
		// would let anyone spend an account's failure budget without ever guessing (#219).
		if !user.Enabled {
			auditLogger.Log(r.Context(), audit.EventUserDisabled, map[string]interface{}{
				"user_id": user.Id,
			})
			renderError(i18n.NewLocalizedError(i18n.ErrCodeLoginAccountDisabled, nil))
			return
		}

		// from this point the user is considered authenticated with pwd

		auditLogger.Log(r.Context(), audit.EventAuthSuccessPwd, map[string]interface{}{
			"user_id": user.Id,
		})

		authContext.RecordPasswordVerified(user, time.Now())

		// Rotate the browser session's identifier here, the instant a credential is
		// accepted, and not only at /auth/completed where the user session is minted.
		//
		// Everything between those two points writes into the row the arriving identifier
		// names, and the pages in between are plain GETs gated on nothing but the recorded
		// AuthState: /auth/level1completed admits level1_password_completed and
		// /auth/completed admits authentication_completed, neither comparing anything about
		// the browser making the request, because the session is deliberately not bound to
		// IP or User-Agent. So an attacker who planted an identifier and polls those two
		// paths while this password is being checked can reach /auth/completed before the
		// victim's own redirect does, and be handed the session minted for the victim.
		// Replacing the identifier the moment the password is accepted leaves that race
		// nothing to race for. Undo this and the race is back, silently, with every
		// existing test still green (#266).
		//
		// Before the save, never after. Rotation writes the session's CURRENT contents
		// under the new identifier, so rotating first means the row carries the state this
		// ceremony had before the password was accepted. A failure between the two then
		// leaves a fresh identifier on a session that is not yet password-completed, which
		// is the harmless direction; saving first and failing to rotate would leave the
		// planted identifier naming a row that IS password-completed, which is exactly the
		// state the attacker needs. Same ordering, and the same reason, as the step-up arm
		// in handler_auth_completed.
		if regenerateSessionErr := ceremonyStore.RegenerateSession(w, r); regenerateSessionErr != nil {
			pageRenderer.InternalServerError(w, r, regenerateSessionErr)
			return
		}

		err = ceremonyStore.SaveAuthContext(w, r, authContext)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
		http.Redirect(w, r, ceremonyStepURL(baseURL, "/auth/level1completed", authContext), http.StatusFound)
	}
}
