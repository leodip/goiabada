package handlers

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
)

func HandleAuthPwdGet(
	httpHelper HttpHelper,
	authHelper AuthHelper,
	database data.Database,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		authContext, err := authHelper.GetAuthContext(r)
		if err != nil {
			if errDetail, ok := err.(*customerrors.ErrorDetail); ok && errDetail.IsError(customerrors.ErrNoAuthContext) {
				var profileUrl = GetProfileURL()
				slog.Warn(fmt.Sprintf("auth context is missing, redirecting to %v", profileUrl))
				http.Redirect(w, r, profileUrl, http.StatusFound)
			} else {
				httpHelper.InternalServerError(w, r, err)
			}
			return
		}

		requiredState := oauth.AuthStateLevel1Password
		if authContext.AuthState != requiredState {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("authContext.AuthState is not "+requiredState)))
			return
		}

		sessionIdentifier := ""
		if r.Context().Value(constants.ContextKeySessionIdentifier) != nil {
			sessionIdentifier = r.Context().Value(constants.ContextKeySessionIdentifier).(string)
		}

		// try to get email from session
		email := ""
		if len(sessionIdentifier) > 0 {
			userSession, err := database.GetUserSessionBySessionIdentifier(nil, sessionIdentifier)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			if userSession != nil {
				email = userSession.User.Email
			}
		}

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

		// Fetch client to get display settings
		client, err := database.GetClientByClientIdentifier(nil, authContext.ClientId)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if client == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("client not found")))
			return
		}

		displayInfo := getClientDisplayInfo(database, client)

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
		if len(email) > 0 {
			bind["email"] = email
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/auth_layout.html", "/auth_pwd.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAuthPwdPost(
	httpHelper HttpHelper,
	authHelper AuthHelper,
	database data.Database,
	auditLogger AuditLogger,
	credentialFailures CredentialFailureRecorder,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		authContext, err := authHelper.GetAuthContext(r)
		if err != nil {
			if errDetail, ok := err.(*customerrors.ErrorDetail); ok && errDetail.IsError(customerrors.ErrNoAuthContext) {
				var profileUrl = GetProfileURL()
				slog.Warn(fmt.Sprintf("auth context is missing, redirecting to %v", profileUrl))
				http.Redirect(w, r, profileUrl, http.StatusFound)
			} else {
				httpHelper.InternalServerError(w, r, err)
			}
			return
		}

		// Before the AuthState check, so a login form left open in another tab gets the 400
		// mismatch page rather than the 500 that a replaced context's state would produce. And
		// before anything reads the credentials: a submission naming a ceremony that is no longer
		// current is answered without ever looking up a user or verifying a password, so a stale
		// form cannot authenticate anybody for anything (#79).
		//
		// r.PostFormValue rather than r.FormValue: this form posts to action="", so r.Form would
		// let /auth/pwd?ceremonyId=... supply the id, and only the submitted body is a submission.
		if !ceremonyMatches(authContext.CeremonyId, r.PostFormValue(ceremonyIdField)) {
			rejectCeremonyMismatch(httpHelper, auditLogger, w, r, authContext)
			return
		}

		requiredState := oauth.AuthStateLevel1Password
		if authContext.AuthState != requiredState {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("authContext.AuthState is not "+requiredState)))
			return
		}

		// Normalized to exactly what the rate limiter's account key does, and to what every
		// write path stores. Two things depend on the spelling matching: the limiter and the
		// account it protects must agree about which account a request is, or a case variant
		// buys a fresh bucket; and mysql and mssql compare email case-insensitively while
		// postgres and sqlite do not, so without this a stored bob@x.com typed as Bob@x.com
		// signs in on two engines and is refused on the other two (#219).
		email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
		password := r.FormValue("password")

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

		// Fetch client to get display settings
		client, err := database.GetClientByClientIdentifier(nil, authContext.ClientId)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if client == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("client not found")))
			return
		}

		displayInfo := getClientDisplayInfo(database, client)

		// renderError closes over r so a subsequent r = i18n.RefineLocalizerWithUser
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

			err = httpHelper.RenderTemplate(w, r, "/layouts/auth_layout.html", "/auth_pwd.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
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

		user, err := database.GetUserByEmail(nil, email)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

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
			hashutil.VerifyPasswordHash(hashutil.DummyPasswordHash, password)

			// A guess against an address that names no account is still a guess, and
			// charging it is also what keeps this branch from being a cheaper way to
			// enumerate addresses than the branch below.
			credentialFailures.RecordCredentialFailure(r)
			auditLogger.Log(constants.AuditAuthFailedPwd, map[string]interface{}{
				"email": email,
			})
			renderError(authFailed)
			return
		}

		if !hashutil.VerifyPasswordHash(user.PasswordHash, password) {
			credentialFailures.RecordCredentialFailure(r)
			auditLogger.Log(constants.AuditAuthFailedPwd, map[string]interface{}{
				"email": email,
			})
			renderError(authFailed)
			return
		}

		// Password verified — surfacing user-specific errors (account disabled,
		// downstream flow messages) in user.Locale is now safe and correct.
		// Skipped when explicit ?ui_locales / AuthContext.UILocales is in play.
		r = i18n.RefineLocalizerWithUser(r, user)

		// Deliberately not a credential failure: the password was right, so there is
		// nothing here for the rate limiter to bound. The same holds for the missing-email
		// and missing-password renders above, which verify nothing at all. Charging those
		// would let anyone spend an account's failure budget without ever guessing (#219).
		if !user.Enabled {
			auditLogger.Log(constants.AuditUserDisabled, map[string]interface{}{
				"userId": user.Id,
			})
			renderError(i18n.NewLocalizedError(i18n.ErrCodeLoginAccountDisabled, nil))
			return
		}

		// from this point the user is considered authenticated with pwd

		auditLogger.Log(constants.AuditAuthSuccessPwd, map[string]interface{}{
			"userId": user.Id,
		})

		authContext.UserId = user.Id
		// Capture the generation the credentials were verified against. If a credential
		// change lands while the rest of this ceremony completes, the code it eventually
		// issues carries this older value and is rejected at redemption, which is the
		// intended direction (#106 decision 11 rule 1).
		authContext.AuthStateGeneration = user.AuthStateGeneration
		authContext.AddAuthMethod(enums.AuthMethodPassword.String())
		// Mark that real authentication occurred — used by handler_auth_completed
		// to decide whether to refresh the session's AuthTime.
		utcNow := time.Now().UTC()
		authContext.AuthenticatedAt = &utcNow
		// This ceremony performed level 1, so it may create a session even when the one it
		// started on has gone. This is the only writer of the field, deliberately: the OTP
		// handler also sets AuthenticatedAt, and level 2 alone must not stand in for level 1
		// at the gate in handler_auth_completed (#129 decisions 6 and 15).
		authContext.Level1AuthCompleted = true
		authContext.AuthState = oauth.AuthStateLevel1PasswordCompleted
		err = authHelper.SaveAuthContext(w, r, authContext)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		http.Redirect(w, r, config.GetAuthServer().BaseURL+"/auth/level1completed", http.StatusFound)
	}
}
