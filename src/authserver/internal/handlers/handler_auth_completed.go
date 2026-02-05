package handlers

import (
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/oidc"
	"github.com/pkg/errors"
)

func HandleAuthCompletedGet(
	httpHelper HttpHelper,
	authHelper AuthHelper,
	userSessionManager UserSessionManager,
	database data.Database,
	templateFS fs.FS,
	auditLogger AuditLogger,
	permissionChecker PermissionChecker,
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

		requiredState := oauth.AuthStateAuthenticationCompleted
		if authContext.AuthState != requiredState {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("authContext.AuthState is not "+requiredState)))
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

		targetAcrLevel := authContext.GetTargetAcrLevel(client.DefaultAcrLevel)
		hasValidUserSession := userSessionManager.HasValidUserSession(r.Context(), userSession, authContext.ParseRequestedMaxAge())
		if hasValidUserSession {
			// Bump session with current auth context's methods and target ACR level.
			// This handles step-up authentication: if the user had a level1 session but just
			// completed OTP for a level2 client, the session's AuthMethods and AcrLevel
			// will be upgraded to reflect the stronger authentication that was performed.
			_, err = userSessionManager.BumpUserSession(r, sessionIdentifier, client.Id,
				authContext.AuthMethods, targetAcrLevel.String())
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			auditLogger.Log(constants.AuditBumpedUserSession, map[string]interface{}{
				"userId":   authContext.UserId,
				"clientId": client.Id,
			})
		} else {
			// start new session
			_, err = userSessionManager.StartNewUserSession(
				w, r, authContext.UserId, client.Id, authContext.AuthMethods, targetAcrLevel.String())
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			auditLogger.Log(constants.AuditStartedNewUserSesson, map[string]interface{}{
				"userId":   authContext.UserId,
				"clientId": client.Id,
			})
		}

		// set the acr level in the auth context
		err = authContext.SetAcrLevel(targetAcrLevel, userSession)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		user, err := database.GetUserById(nil, authContext.UserId)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if user == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("user not found")))
			return
		}

		if !user.Enabled {
			auditLogger.Log(constants.AuditUserDisabled, map[string]interface{}{
				"userId": user.Id,
			})
			err := redirToClientWithError(w, r, templateFS, "access_denied", "The user account is disabled.",
				authContext.ResponseMode, authContext.RedirectURI, authContext.State, authContext.ResponseType)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			err = authHelper.ClearAuthContext(w, r)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			return
		}

		// we need to check if consent is required

		// we'll first find out what is the effective scope,
		// by filtering out the scopes where the user is not authorized
		effectiveScope, err := permissionChecker.FilterOutScopesWhereUserIsNotAuthorized(authContext.Scope, user)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		// in the auth context replace the scope with the effective scope
		authContext.SetScope(effectiveScope)
		if len(authContext.Scope) == 0 {
			err = redirToClientWithError(w, r, templateFS, "access_denied", "The user is not authorized to access any of the requested scopes", authContext.ResponseMode,
				authContext.RedirectURI, authContext.State, authContext.ResponseType)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}

			err = authHelper.ClearAuthContext(w, r)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			return
		}

		// Handle prompt=consent: force consent screen regardless of existing consent or client settings
		if authContext.HasPromptValue("consent") {
			authContext.AuthState = oauth.AuthStateRequiresConsent
			err = authHelper.SaveAuthContext(w, r, authContext)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, config.GetAuthServer().BaseURL+"/auth/consent", http.StatusFound)
			return
		}

		// we must redirect to consent if the client requires it or if there's an offline_access scope
		if client.ConsentRequired || authContext.HasScope(oidc.OfflineAccessScope) {
			authContext.AuthState = oauth.AuthStateRequiresConsent

			err = authHelper.SaveAuthContext(w, r, authContext)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, config.GetAuthServer().BaseURL+"/auth/consent", http.StatusFound)
			return
		}

		// if there's no need for consent, we're ready to issue the code
		authContext.AuthState = oauth.AuthStateReadyToIssueCode
		err = authHelper.SaveAuthContext(w, r, authContext)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		http.Redirect(w, r, config.GetAuthServer().BaseURL+"/auth/issue", http.StatusFound)
	}
}
