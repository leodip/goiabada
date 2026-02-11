package handlers

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/hashutil"
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
			"error":                   nil,
			"smtpEnabled":             settings.SMTPEnabled,
			"csrfField":               csrf.TemplateField(r),
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

		email := r.FormValue("email")
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

		renderError := func(message string) {
			bind := map[string]interface{}{
				"error":                   message,
				"smtpEnabled":             settings.SMTPEnabled,
				"email":                   email,
				"csrfField":               csrf.TemplateField(r),
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

		if len(strings.TrimSpace(email)) == 0 {
			renderError("Email is required.")
			return
		}

		if len(strings.TrimSpace(password)) == 0 {
			renderError("Password is required.")
			return
		}

		user, err := database.GetUserByEmail(nil, email)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		authFailedMessage := "Authentication failed."
		if user == nil {
			// Timing-safe user enumeration protection: perform a dummy bcrypt comparison
			// even when the user doesn't exist. This ensures the response time is similar
			// to when a user exists but the password is wrong, preventing attackers from
			// determining whether an email exists based on response timing differences.
			hashutil.VerifyPasswordHash(hashutil.DummyPasswordHash, password)

			auditLogger.Log(constants.AuditAuthFailedPwd, map[string]interface{}{
				"email": email,
			})
			renderError(authFailedMessage)
			return
		}

		if !hashutil.VerifyPasswordHash(user.PasswordHash, password) {
			auditLogger.Log(constants.AuditAuthFailedPwd, map[string]interface{}{
				"email": email,
			})
			renderError(authFailedMessage)
			return
		}

		if !user.Enabled {
			auditLogger.Log(constants.AuditUserDisabled, map[string]interface{}{
				"userId": user.Id,
			})
			renderError("Your user account is disabled.")
			return
		}

		// from this point the user is considered authenticated with pwd

		auditLogger.Log(constants.AuditAuthSuccessPwd, map[string]interface{}{
			"userId": user.Id,
		})

		authContext.UserId = user.Id
		authContext.AddAuthMethod(enums.AuthMethodPassword.String())
		// Mark that real authentication occurred — used by handler_auth_completed
		// to decide whether to refresh the session's AuthTime.
		utcNow := time.Now().UTC()
		authContext.AuthenticatedAt = &utcNow
		authContext.AuthState = oauth.AuthStateLevel1PasswordCompleted
		err = authHelper.SaveAuthContext(w, r, authContext)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		http.Redirect(w, r, config.GetAuthServer().BaseURL+"/auth/level1completed", http.StatusFound)
	}
}
