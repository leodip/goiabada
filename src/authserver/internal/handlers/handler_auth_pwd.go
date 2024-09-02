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
)

func HandleAuthPwdGet(
	httpHelper HttpHelper,
	authHelper AuthHelper,
	database data.Database,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		_, err := authHelper.GetAuthContext(r)
		if err != nil {
			if errDetail, ok := err.(*customerrors.ErrorDetail); ok && errDetail.GetCode() == "no_auth_context" {
				slog.Warn("no auth context, redirecting to " + config.Get().BaseURL + "/account/profile")
				http.Redirect(w, r, config.GetAdminConsole().BaseURL+"/account/profile", http.StatusFound)
			} else {
				httpHelper.InternalServerError(w, r, err)
			}
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

		bind := map[string]interface{}{
			"error":       nil,
			"smtpEnabled": settings.SMTPEnabled,
			"csrfField":   csrf.TemplateField(r),
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
	userSessionManager UserSessionManager,
	database data.Database,
	auditLogger AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		authContext, err := authHelper.GetAuthContext(r)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		email := r.FormValue("email")
		password := r.FormValue("password")

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

		renderError := func(message string) {
			bind := map[string]interface{}{
				"error":       message,
				"smtpEnabled": settings.SMTPEnabled,
				"email":       email,
				"csrfField":   csrf.TemplateField(r),
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

		// from this point the user is considered authenticated with pwd

		auditLogger.Log(constants.AuditAuthSuccessPwd, map[string]interface{}{
			"userId": user.Id,
		})

		if !user.Enabled {
			auditLogger.Log(constants.AuditUserDisabled, map[string]interface{}{
				"userId": user.Id,
			})
			renderError("Your account is disabled.")
			return
		}

		sessionIdentifier := ""
		if r.Context().Value(constants.ContextKeySessionIdentifier) != nil {
			sessionIdentifier = r.Context().Value(constants.ContextKeySessionIdentifier).(string)
		}

		userSession, err := database.GetUserSessionBySessionIdentifier(nil, sessionIdentifier)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		err = database.UserSessionLoadUser(nil, userSession)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		client, err := database.GetClientByClientIdentifier(nil, authContext.ClientId)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if client == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New(fmt.Sprintf("client %v not found", authContext.ClientId))))
			return
		}

		requestedAcrValues := authContext.ParseRequestedAcrValues()
		targetAcrLevel := client.DefaultAcrLevel

		if len(requestedAcrValues) > 0 {
			targetAcrLevel = requestedAcrValues[0]
		}

		hasValidUserSession := userSessionManager.HasValidUserSession(r.Context(), userSession, authContext.ParseRequestedMaxAge())
		if hasValidUserSession {

			requiresOTPAuth := userSessionManager.RequiresOTPAuth(r.Context(), client, userSession, targetAcrLevel)
			if requiresOTPAuth {
				authContext.UserId = user.Id
				err = authHelper.SaveAuthContext(w, r, authContext)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}
				http.Redirect(w, r, config.Get().BaseURL+"/auth/otp", http.StatusFound)
				return
			}

		}

		// if the client accepts AcrLevel1 that means only the password is sufficient to authenticate
		// no need to check anything else

		if targetAcrLevel != enums.AcrLevel1 {

			// optional: the system will offer OTP auth if it's enabled for the user
			optional2fa := targetAcrLevel == enums.AcrLevel2 && user.OTPEnabled

			// mandatory: if target acr is level 3, we'll force an OTP auth
			mandatory2fa := targetAcrLevel == enums.AcrLevel3

			if optional2fa || mandatory2fa {
				authContext.UserId = user.Id
				err = authHelper.SaveAuthContext(w, r, authContext)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}
				http.Redirect(w, r, config.Get().BaseURL+"/auth/otp", http.StatusFound)
				return
			}
		}

		// user is fully authenticated

		// start new session

		_, err = userSessionManager.StartNewUserSession(w, r, user.Id, client.Id, enums.AuthMethodPassword.String(), targetAcrLevel.String())
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		auditLogger.Log(constants.AuditStartedNewUserSesson, map[string]interface{}{
			"userId":   user.Id,
			"clientId": client.Id,
		})

		// redirect to consent
		authContext.UserId = user.Id
		err = authContext.SetAcrLevel(targetAcrLevel, userSession)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		authContext.AuthMethods = enums.AuthMethodPassword.String()
		authContext.AuthTime = time.Now().UTC()
		authContext.AuthCompleted = true
		err = authHelper.SaveAuthContext(w, r, authContext)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, config.Get().BaseURL+"/auth/consent", http.StatusFound)
	}
}
