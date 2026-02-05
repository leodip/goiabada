package handlers

import (
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/oidc"
	"github.com/leodip/goiabada/core/validators"
)

func HandleAuthorizeGet(
	httpHelper HttpHelper,
	authHelper AuthHelper,
	userSessionManager UserSessionManager,
	database data.Database,
	templateFS fs.FS,
	authorizeValidator AuthorizeValidator,
	auditLogger AuditLogger,
	permissionChecker PermissionChecker,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		requestId := middleware.GetReqID(r.Context())

		authContext := oauth.AuthContext{
			AuthState:                     oauth.AuthStateInitial,
			ClientId:                      r.URL.Query().Get("client_id"),
			RedirectURI:                   r.URL.Query().Get("redirect_uri"),
			ResponseType:                  r.URL.Query().Get("response_type"),
			CodeChallengeMethod:           r.URL.Query().Get("code_challenge_method"),
			CodeChallenge:                 r.URL.Query().Get("code_challenge"),
			ResponseMode:                  r.URL.Query().Get("response_mode"),
			MaxAge:                        r.URL.Query().Get("max_age"),
			AcrValuesFromAuthorizeRequest: r.URL.Query().Get("acr_values"),
			State:                         r.URL.Query().Get("state"),
			Nonce:                         r.URL.Query().Get("nonce"),
			UserAgent:                     r.UserAgent(),
			IpAddress:                     r.RemoteAddr,
		}
		authContext.SetScope(r.URL.Query().Get("scope"))

		err := authHelper.SaveAuthContext(w, r, &authContext)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		renderErrorUi := func(message string) {
			bind := map[string]interface{}{
				"title": "Unable to authorize",
				"error": message,
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/no_menu_layout.html", "/auth_error.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		err = authorizeValidator.ValidateClientAndRedirectURI(&validators.ValidateClientAndRedirectURIInput{
			RequestId:    requestId,
			ClientId:     authContext.ClientId,
			RedirectURI:  authContext.RedirectURI,
			ResponseType: authContext.ResponseType,
		})

		if err != nil {
			valError, ok := err.(*customerrors.ErrorDetail)
			if ok {
				renderErrorUi(valError.GetDescription())
				return
			} else {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		redirToClientWithError := func(validationError *customerrors.ErrorDetail) {
			err := redirToClientWithError(w, r, templateFS, validationError.GetCode(), validationError.GetDescription(),
				r.URL.Query().Get("response_mode"), r.URL.Query().Get("redirect_uri"), r.URL.Query().Get("state"),
				r.URL.Query().Get("response_type"))
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}

			err = authHelper.ClearAuthContext(w, r)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		// Load client and settings to determine PKCE requirement
		client, err := database.GetClientByClientIdentifier(nil, authContext.ClientId)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if client == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New(fmt.Sprintf("client %v not found", authContext.ClientId))))
			return
		}

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
		pkceRequired := client.IsPKCERequired(settings.PKCERequired)
		implicitGrantEnabled := client.IsImplicitGrantEnabled(settings.ImplicitFlowEnabled)

		err = authorizeValidator.ValidateRequest(&validators.ValidateRequestInput{
			ResponseType:         authContext.ResponseType,
			CodeChallengeMethod:  authContext.CodeChallengeMethod,
			CodeChallenge:        authContext.CodeChallenge,
			ResponseMode:         authContext.ResponseMode,
			PKCERequired:         pkceRequired,
			ImplicitGrantEnabled: implicitGrantEnabled,
			Scope:                authContext.Scope,
			Nonce:                authContext.Nonce,
		})

		if err != nil {
			valError, ok := err.(*customerrors.ErrorDetail)
			if ok {
				redirToClientWithError(valError)
				return
			} else {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		err = authorizeValidator.ValidateScopes(authContext.Scope)

		if err != nil {
			valError, ok := err.(*customerrors.ErrorDetail)
			if ok {
				redirToClientWithError(valError)
				return
			} else {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		// Validate and normalize the prompt parameter
		normalizedPrompt, err := authorizeValidator.ValidatePrompt(r.URL.Query().Get("prompt"))
		if err != nil {
			valError, ok := err.(*customerrors.ErrorDetail)
			if ok {
				redirToClientWithError(valError)
				return
			} else {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}
		authContext.Prompt = normalizedPrompt

		sessionIdentifier := ""
		if r.Context().Value(constants.ContextKeySessionIdentifier) != nil {
			sessionIdentifier = r.Context().Value(constants.ContextKeySessionIdentifier).(string)
		}

		// Handle prompt=none: silent authentication without any UI
		if authContext.HasPromptValue("none") {
			handlePromptNone(w, r, httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker, &authContext, client, sessionIdentifier)
			return
		}

		// Handle prompt=login: force re-authentication, skip session entirely
		if authContext.HasPromptValue("login") {
			authContext.AuthState = oauth.AuthStateRequiresLevel1
			err = authHelper.SaveAuthContext(w, r, &authContext)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, config.GetAuthServer().BaseURL+"/auth/level1", http.StatusFound)
			return
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

		hasValidUserSession := userSessionManager.HasValidUserSession(r.Context(), userSession, authContext.ParseRequestedMaxAge())
		if hasValidUserSession {

			// is the account still enabled?

			if !userSession.User.Enabled {

				// the user account has been disabled
				// we should log this event and return an error to the client
				auditLogger.Log(constants.AuditUserDisabled, map[string]interface{}{
					"userId": userSession.UserId,
				})

				redirToClientWithError(customerrors.NewErrorDetailWithHttpStatusCode("access_denied", "The user account is disabled.", http.StatusBadRequest))
				return
			}

			// if the user has a valid session, that means they already completed level1 auth
			// so we can send them to level1 completed handler, where further checks will be made

			authContext.UserId = userSession.UserId
			authContext.AcrLevel = userSession.AcrLevel
			authContext.AuthMethods = userSession.AuthMethods
			authContext.AuthState = oauth.AuthStateLevel1ExistingSession
			err = authHelper.SaveAuthContext(w, r, &authContext)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, config.GetAuthServer().BaseURL+"/auth/level1completed", http.StatusFound)
			return
		}

		// no valid session, requires level 1 auth
		authContext.AuthState = oauth.AuthStateRequiresLevel1
		err = authHelper.SaveAuthContext(w, r, &authContext)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		http.Redirect(w, r, config.GetAuthServer().BaseURL+"/auth/level1", http.StatusFound)
	}
}

// handlePromptNone handles the OIDC prompt=none flow for silent authentication.
// It performs all necessary checks without displaying any UI and either:
// - Returns an error to the client if silent auth is not possible
// - Issues a code silently if all conditions are met
func handlePromptNone(w http.ResponseWriter, r *http.Request, httpHelper HttpHelper, authHelper AuthHelper, userSessionManager UserSessionManager, database data.Database, templateFS fs.FS, auditLogger AuditLogger, permissionChecker PermissionChecker, authContext *oauth.AuthContext, client *models.Client, sessionIdentifier string) {
	// Helper to redirect with error and clear auth context
	redirectWithError := func(errorCode string, errorDescription string) {
		err := redirToClientWithError(w, r, templateFS, errorCode, errorDescription,
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
	}

	// 1. Check session exists
	userSession, err := database.GetUserSessionBySessionIdentifier(nil, sessionIdentifier)
	if err != nil {
		httpHelper.InternalServerError(w, r, err)
		return
	}

	if userSession == nil {
		redirectWithError(constants.ErrorLoginRequired, "User authentication is required")
		return
	}

	// Load user for the session
	err = database.UserSessionLoadUser(nil, userSession)
	if err != nil {
		httpHelper.InternalServerError(w, r, err)
		return
	}

	// 2. Check session time-based validity (idle timeout, max lifetime, max_age)
	hasValidSession := userSessionManager.HasValidUserSession(r.Context(), userSession, authContext.ParseRequestedMaxAge())
	if !hasValidSession {
		// Determine if it's max_age that caused the failure
		if authContext.ParseRequestedMaxAge() != nil {
			// Check if session would be valid without max_age
			if userSessionManager.HasValidUserSession(r.Context(), userSession, nil) {
				redirectWithError(constants.ErrorLoginRequired, "Session age exceeds max_age")
				return
			}
		}
		redirectWithError(constants.ErrorLoginRequired, "User session has expired")
		return
	}

	// 3. Check user is enabled
	if !userSession.User.Enabled {
		auditLogger.Log(constants.AuditUserDisabled, map[string]interface{}{
			"userId": userSession.UserId,
		})
		redirectWithError("access_denied", "The user account is disabled")
		return
	}

	// 4. Check ACR requirements
	targetAcrLevel := authContext.GetTargetAcrLevel(client.DefaultAcrLevel)
	sessionAcrLevel, err := enums.AcrLevelFromString(userSession.AcrLevel)
	if err != nil {
		// Unknown session ACR, treat as insufficient
		redirectWithError(constants.ErrorInteractionRequired, "Higher authentication level required")
		return
	}

	// If target ACR is higher than session ACR, we need step-up (interaction required)
	if targetAcrLevel.IsHigherThan(sessionAcrLevel) {
		redirectWithError(constants.ErrorInteractionRequired, "Higher authentication level required")
		return
	}

	// 5. Check OTP requirements for level2
	// For level2_mandatory: user MUST have OTP enabled
	// For level2_optional: if user has OTP but session doesn't have OTP method, need step-up
	if targetAcrLevel == enums.AcrLevel2Mandatory {
		if !userSession.User.OTPEnabled {
			redirectWithError(constants.ErrorInteractionRequired, "Additional authentication setup required")
			return
		}
	}

	// 6. Check if Level2AuthConfigHasChanged flag is set (user changed OTP settings)
	if userSession.Level2AuthConfigHasChanged {
		// Only matters if target requires level2
		if targetAcrLevel == enums.AcrLevel2Optional || targetAcrLevel == enums.AcrLevel2Mandatory {
			redirectWithError(constants.ErrorInteractionRequired, "Authentication configuration has changed")
			return
		}
	}

	// 7. Compute effective scopes (filter by user permissions)
	user := &userSession.User
	effectiveScope, err := permissionChecker.FilterOutScopesWhereUserIsNotAuthorized(authContext.Scope, user)
	if err != nil {
		httpHelper.InternalServerError(w, r, err)
		return
	}

	if len(strings.TrimSpace(effectiveScope)) == 0 {
		redirectWithError("access_denied", "The user is not authorized to access any of the requested scopes")
		return
	}

	// 8. Check consent requirements
	if client.ConsentRequired || strings.Contains(effectiveScope, oidc.OfflineAccessScope) {
		consent, err := database.GetConsentByUserIdAndClientId(nil, user.Id, client.Id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		if consent == nil {
			redirectWithError(constants.ErrorConsentRequired, "User consent is required")
			return
		}

		// Check if existing consent covers all effective scopes
		effectiveScopes := strings.Fields(effectiveScope)
		for _, scope := range effectiveScopes {
			if !consent.HasScope(scope) {
				redirectWithError(constants.ErrorConsentRequired, "Additional consent is required")
				return
			}
		}
	}

	// All checks passed - proceed with silent code issuance

	// Set auth context for code issuance
	authContext.UserId = userSession.UserId
	authContext.AuthMethods = userSession.AuthMethods
	authContext.AcrLevel = userSession.AcrLevel
	authContext.SetScope(effectiveScope)

	// Preserve the original session's auth_time for the token
	if userSession.AuthTime.IsZero() {
		// Fallback for legacy sessions without AuthTime
		authContext.AuthenticatedAt = &userSession.Started
	} else {
		authContext.AuthenticatedAt = &userSession.AuthTime
	}

	// Set ACR level (takes max of target and session ACR)
	err = authContext.SetAcrLevel(targetAcrLevel, userSession)
	if err != nil {
		httpHelper.InternalServerError(w, r, err)
		return
	}

	// Bump the user session to update LastAccessed time
	_, err = userSessionManager.BumpUserSession(r, sessionIdentifier, client.Id,
		authContext.AuthMethods, authContext.AcrLevel)
	if err != nil {
		httpHelper.InternalServerError(w, r, err)
		return
	}

	auditLogger.Log(constants.AuditBumpedUserSession, map[string]interface{}{
		"userId":   authContext.UserId,
		"clientId": client.Id,
	})

	// Ready to issue code
	authContext.AuthState = oauth.AuthStateReadyToIssueCode
	err = authHelper.SaveAuthContext(w, r, authContext)
	if err != nil {
		httpHelper.InternalServerError(w, r, err)
		return
	}

	http.Redirect(w, r, config.GetAuthServer().BaseURL+"/auth/issue", http.StatusFound)
}

func redirToClientWithError(w http.ResponseWriter, r *http.Request, templateFS fs.FS, code string,
	description string, responseMode string, redirectURI string, state string, responseType string) error {

	// Per RFC 6749 4.2.2.1 and OIDC Core 3.2.2.5: implicit flow errors MUST be returned in fragment
	// Determine if this is an implicit flow by checking response_type
	rtInfo := oauth.ParseResponseType(responseType)
	isImplicitFlow := rtInfo.IsImplicitFlow()

	// For implicit flow, default to fragment response mode
	effectiveResponseMode := responseMode
	if isImplicitFlow && effectiveResponseMode == "" {
		effectiveResponseMode = "fragment"
	}

	if effectiveResponseMode == "fragment" {
		values := url.Values{}
		values.Add("error", code)
		values.Add("error_description", description)
		if len(strings.TrimSpace(state)) > 0 {
			values.Add("state", state)
		}
		http.Redirect(w, r, redirectURI+"#"+values.Encode(), http.StatusFound)
		return nil
	}

	if effectiveResponseMode == "form_post" {
		m := make(map[string]interface{})
		m["redirectURI"] = redirectURI
		m["error"] = code
		m["error_description"] = description
		if len(strings.TrimSpace(state)) > 0 {
			m["state"] = state
		}

		t, err := template.ParseFS(templateFS, "form_post.html")
		if err != nil {
			return errors.Wrap(err, "unable to parse template")
		}
		err = t.Execute(w, m)
		if err != nil {
			return errors.Wrap(err, "unable to execute template")
		}
		return nil
	}

	// default to query
	redirUrl, err := url.ParseRequestURI(redirectURI)
	if err != nil {
		return errors.Wrap(err, "unable to parse redirect URI")
	}
	values := redirUrl.Query()
	values.Add("error", code)
	values.Add("error_description", description)
	if len(strings.TrimSpace(state)) > 0 {
		values.Add("state", state)
	}
	redirUrl.RawQuery = values.Encode()

	http.Redirect(w, r, redirUrl.String(), http.StatusFound)
	return nil
}
