package handlers

import (
	"bytes"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
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
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/oidc"
	"github.com/leodip/goiabada/core/stringutil"
	"github.com/leodip/goiabada/core/validators"
)

// validateIdTokenHint parses and validates the id_token_hint parameter.
// Per OIDC Core 1.0 Section 3.1.2.2:
// - MUST validate the server was the issuer
// - SHOULD accept expired tokens (withExpirationCheck=false)
// Returns the sub claim from the hint, or empty string if no hint provided.
// Returns error if hint is malformed or not issued by this server.
func validateIdTokenHint(idTokenHint string, tokenParser TokenParser, settings *models.Settings) (string, error) {
	if idTokenHint == "" {
		return "", nil
	}

	// Defensive check: tokenParser should never be nil in production wiring, but guard against future refactors
	if tokenParser == nil {
		return "", errors.WithStack(errors.New("tokenParser is nil"))
	}

	// Parse JWT: verify signature, skip expiration (spec: SHOULD accept expired)
	jwtToken, err := tokenParser.DecodeAndValidateTokenString(idTokenHint, nil, false)
	if err != nil {
		return "", customerrors.NewErrorDetailWithHttpStatusCode(
			"invalid_request",
			"The id_token_hint is invalid.",
			http.StatusBadRequest)
	}

	// MUST validate issuer (Section 3.1.2.2)
	// Use safe type assertion — a malformed iss claim (e.g. iss: 123) must not panic.
	iss, ok := jwtToken.Claims["iss"].(string)
	if !ok || iss != settings.Issuer {
		return "", customerrors.NewErrorDetailWithHttpStatusCode(
			"invalid_request",
			"The id_token_hint was not issued by this server.",
			http.StatusBadRequest)
	}

	// Extract sub claim
	// Use safe type assertion — a malformed sub claim (e.g. sub: 123) must not panic.
	sub, ok := jwtToken.Claims["sub"].(string)
	if !ok || sub == "" {
		return "", customerrors.NewErrorDetailWithHttpStatusCode(
			"invalid_request",
			"The id_token_hint does not contain a valid sub claim.",
			http.StatusBadRequest)
	}

	return sub, nil
}

func HandleAuthorizeGet(
	httpHelper HttpHelper,
	authHelper AuthHelper,
	userSessionManager UserSessionManager,
	database data.Database,
	templateFS fs.FS,
	authorizeValidator AuthorizeValidator,
	auditLogger AuditLogger,
	permissionChecker PermissionChecker,
	tokenParser TokenParser,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		requestId := middleware.GetReqID(r.Context())

		// The ceremony id is minted here and nowhere else, because this is the only place an
		// auth context is created. Every form this ceremony renders carries it and every POST
		// checks it, so a page left open in another tab cannot act on the authorization
		// request that replaced it (#79).
		ceremonyId := stringutil.GenerateSecurityRandomString(ceremonyIdLength)
		if ceremonyId == "" {
			// GenerateSecurityRandomString answers "" when the system CSPRNG is unavailable.
			// Saving that would put an empty id in the context, which every bound POST refuses,
			// so the ceremony would render its forms and then reject each one. Failing here is
			// the same outcome with a stack trace attached, as SaveLinkMarker does (#112).
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("unable to generate an auth ceremony id")))
			return
		}

		authContext := oauth.AuthContext{
			AuthState:                     oauth.AuthStateInitial,
			CeremonyId:                    ceremonyId,
			ClientId:                      r.FormValue("client_id"),
			RedirectURI:                   r.FormValue("redirect_uri"),
			ResponseType:                  r.FormValue("response_type"),
			CodeChallengeMethod:           r.FormValue("code_challenge_method"),
			CodeChallenge:                 r.FormValue("code_challenge"),
			ResponseMode:                  r.FormValue("response_mode"),
			MaxAge:                        r.FormValue("max_age"),
			AcrValuesFromAuthorizeRequest: r.FormValue("acr_values"),
			State:                         r.FormValue("state"),
			Nonce:                         r.FormValue("nonce"),
			UserAgent:                     r.UserAgent(),
			IpAddress:                     r.RemoteAddr,
		}
		authContext.SetScope(r.FormValue("scope"))

		// Capture OIDC ui_locales (RFC §3.1.2.1) into AuthContext so the
		// RP's stated preference survives every subsequent step of the
		// multi-step auth flow (/auth/pwd → /auth/otp → /auth/consent →
		// /auth/issue). Sanitize first — BCP 47 shape filter, capped at
		// 10 tags / 256 bytes — so we don't bloat the session cookie or
		// accept attacker-controlled junk. r.FormValue covers both query
		// (GET) and form body (POST).
		if uiLocales := i18n.SanitizeUILocales(r.FormValue("ui_locales")); len(uiLocales) > 0 {
			authContext.UILocales = uiLocales
			// The global locale middleware ran on this request but only sees
			// the query string. If the value came from the form body
			// (typical POST authorize), refine the current request's
			// localizer now so any browser-visible response on this request
			// (error pages, the level1 password page) renders in the chosen
			// locale.
			r = i18n.RefineLocalizerWithUILocales(r, uiLocales)
		}

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

		// The client is loaded here rather than after the unsupported-parameter check below,
		// because the closure declared next dispatches an error redirect and every error redirect
		// now carries the client it is answering: RFC 9700 4.11.2 hands the trust decision to the
		// server and names the source of the redirect URI as one of its inputs, so the redirect
		// has to know which client asked for it. A closure declared above this load cannot
		// reference the variable at all, which is why the load moved rather than the closure
		// (#108).
		//
		// Nothing is lost by the move: ValidateClientAndRedirectURI ran directly above and returns
		// an error unless the client exists and is enabled, so the only way this finds nothing is a
		// client deleted between the two lookups, which answered 500 before the move as well.
		client, err := database.GetClientByClientIdentifier(nil, authContext.ClientId)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if client == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New(fmt.Sprintf("client %v not found", authContext.ClientId))))
			return
		}

		redirToClientWithError := func(validationError *customerrors.ErrorDetail) {
			// The clear goes FIRST. ClearAuthContext persists the deletion through a Set-Cookie
			// on w, and redirToClientWithError commits the response in every response mode, so
			// clearing afterwards leaves the header on a response already written and the
			// browser keeps an auth context it can replay (#141).
			err := authHelper.ClearAuthContext(w, r)
			if err != nil {
				// The clear failed, so Save wrote no cookie and the browser still holds the
				// auth context. The client is owed an error response regardless: its redirect
				// URI was validated upstream, so OIDC Core 1.0 3.1.2.2 with 3.1.2.6 applies,
				// and RFC 6749 4.1.2.1 mints server_error for exactly this condition (#141).
				slog.Error("failed to clear the auth context, answering the client with server_error",
					"error", err)
				// Read from the request rather than from authContext: this closure runs before the
				// second SaveAuthContext below, and two of its call sites run before the context
				// has been populated with the validated values at all.
				err = redirToClientWithError(w, r, templateFS, redirectErrorInput{
					client:       client,
					code:         "server_error",
					description:  "Internal server error",
					responseMode: r.FormValue("response_mode"),
					redirectURI:  r.FormValue("redirect_uri"),
					state:        r.FormValue("state"),
					responseType: r.FormValue("response_type"),
				})
				if err != nil {
					// Nowhere left to send the client, so the 500 is the last resort here.
					httpHelper.InternalServerError(w, r, err)
				}
				return
			}

			err = redirToClientWithError(w, r, templateFS, redirectErrorInput{
				client:       client,
				code:         validationError.GetCode(),
				description:  validationError.GetDescription(),
				responseMode: r.FormValue("response_mode"),
				redirectURI:  r.FormValue("redirect_uri"),
				state:        r.FormValue("state"),
				responseType: r.FormValue("response_type"),
			})
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		err = authorizeValidator.ValidateUnsupportedRequestParameters(&validators.ValidateUnsupportedRequestParametersInput{
			HasRequest:    r.Form.Has("request"),
			HasRequestURI: r.Form.Has("request_uri"),
		})
		if err != nil {
			valError, ok := err.(*customerrors.ErrorDetail)
			if ok {
				redirToClientWithError(valError)
				return
			}
			httpHelper.InternalServerError(w, r, err)
			return
		}

		// The client was loaded above the error-redirect closure, which needs it. Settings still
		// come from the request context here, where the PKCE requirement is decided.
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
		normalizedPrompt, err := authorizeValidator.ValidatePrompt(r.FormValue("prompt"))
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

		// Validate id_token_hint if present (OIDC Core 1.0 Section 3.1.2.1/3.1.2.2)
		idTokenHint := r.FormValue("id_token_hint")
		hintSub, err := validateIdTokenHint(idTokenHint, tokenParser, settings)
		if err != nil {
			// id_token_hint validation errors are redirected to client
			valError, ok := err.(*customerrors.ErrorDetail)
			if ok {
				redirToClientWithError(valError)
				return
			}
			httpHelper.InternalServerError(w, r, err)
			return
		}
		authContext.IdTokenHintSub = hintSub

		// Save AuthContext with the validated hint sub for use in downstream handlers
		err = authHelper.SaveAuthContext(w, r, &authContext)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

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

			// Check id_token_hint sub matching for SSO session reuse (OIDC Core 3.1.2.1)
			// If hint identifies a different user, force re-authentication instead of SSO
			if authContext.IdTokenHintSub != "" && userSession.User.Subject.String() != authContext.IdTokenHintSub {
				// Treat as no valid session — force re-authentication
				authContext.AuthState = oauth.AuthStateRequiresLevel1
				err = authHelper.SaveAuthContext(w, r, &authContext)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}
				http.Redirect(w, r, config.GetAuthServer().BaseURL+"/auth/level1", http.StatusFound)
				return
			}

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
			// Inherited from the SESSION, never read from the user. This path never reaches
			// the password handler, and reading the user's current generation here would
			// launder an old session into a newer generation (#106 decision 11(d)).
			authContext.AuthStateGeneration = userSession.AuthStateGeneration
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
	// Helper to clear the auth context and then redirect with error
	redirectWithError := func(errorCode string, errorDescription string) {
		// The clear goes FIRST. ClearAuthContext persists the deletion through a Set-Cookie on
		// w, and redirToClientWithError commits the response in every response mode, so
		// clearing afterwards leaves the header on a response already written and the browser
		// keeps an auth context it can replay (#141).
		err := authHelper.ClearAuthContext(w, r)
		if err != nil {
			// The clear failed, so Save wrote no cookie and the browser still holds the auth
			// context. The client is owed an error response regardless: its redirect URI was
			// validated upstream, so OIDC Core 1.0 3.1.2.2 with 3.1.2.6 applies, and RFC 6749
			// 4.1.2.1 mints server_error for exactly this condition (#141). A silent-renewal
			// iframe reads that as "retry later" rather than "start an interactive login",
			// which on a genuine server fault is the accurate instruction of the two.
			slog.Error("failed to clear the auth context, answering the client with server_error",
				"error", err)
			err = redirToClientWithError(w, r, templateFS,
				redirectErrorFromAuthContext(authContext, client, "server_error", "Internal server error"))
			if err != nil {
				// Nowhere left to send the client, so the 500 is the last resort here.
				httpHelper.InternalServerError(w, r, err)
			}
			return
		}

		err = redirToClientWithError(w, r, templateFS,
			redirectErrorFromAuthContext(authContext, client, errorCode, errorDescription))
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

	// 3a. Check id_token_hint sub matching (OIDC Core 3.1.2.1)
	// "MUST NOT reply with an ID Token for a different user"
	if authContext.IdTokenHintSub != "" {
		if userSession.User.Subject.String() != authContext.IdTokenHintSub {
			redirectWithError(constants.ErrorLoginRequired,
				"The current session user does not match the id_token_hint")
			return
		}
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
	// Same rule as the interactive SSO path above: the generation comes from the session
	// being reused, not from the user (#106 decision 11(d)).
	authContext.AuthStateGeneration = userSession.AuthStateGeneration
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

// redirectErrorInput carries what an error response to a client is built from. It is a struct
// rather than a longer parameter list because the redirect now has to know which client it is
// answering as well as what to say: RFC 9700 4.11.2 hands the "is this redirection URI trusted"
// decision to the server and names the source of the redirect URI among its inputs, and a
// ten-argument call repeated across sixteen sites is not something anyone can read (#108).
type redirectErrorInput struct {
	// client is the client being answered, or nil when the handler could not resolve it before
	// the error arose. Nil means "provenance unknown", never "there is no client": the trust
	// decision is about where the redirect URI came from, so an unresolved client is the
	// untrusted case rather than an exempt one.
	client *models.Client

	code         string
	description  string
	responseMode string
	redirectURI  string
	state        string
	responseType string
}

// redirectErrorFromAuthContext builds the input for an error redirect whose response parameters
// come from the stored ceremony, which is where fourteen of the sixteen take them from. The two
// inside HandleAuthorizeGet's own closure run before the context holds the validated values and
// read the request instead.
func redirectErrorFromAuthContext(authContext *oauth.AuthContext, client *models.Client,
	code string, description string) redirectErrorInput {

	return redirectErrorInput{
		client:       client,
		code:         code,
		description:  description,
		responseMode: authContext.ResponseMode,
		redirectURI:  authContext.RedirectURI,
		state:        authContext.State,
		responseType: authContext.ResponseType,
	}
}

// clientProvenance loads the client behind a ceremony for the sole benefit of the trust decision in
// redirToClientWithError, at the handlers that reach an error redirect without having loaded one.
//
// It answers nil instead of an error on purpose. Every caller is already on its way to returning an
// error response to the client, so a lookup that fails must not turn a refusal that works today
// into a 500; and unresolved provenance is the untrusted case, which errs towards withholding a
// redirect rather than towards performing one (#108).
func clientProvenance(database data.Database, clientIdentifier string) *models.Client {
	client, err := database.GetClientByClientIdentifier(nil, clientIdentifier)
	if err != nil {
		slog.Error("unable to load the client while answering it with an error, treating its provenance as unresolved",
			"clientIdentifier", clientIdentifier, "error", err)
		return nil
	}
	return client
}

func redirToClientWithError(w http.ResponseWriter, r *http.Request,
	templateFS fs.FS, input redirectErrorInput) error {

	// Per RFC 6749 4.2.2.1 and OIDC Core 3.2.2.5: implicit flow errors MUST be returned in fragment
	// Determine if this is an implicit flow by checking response_type
	rtInfo := oauth.ParseResponseType(input.responseType)
	isImplicitFlow := rtInfo.IsImplicitFlow()

	// For implicit flow, default to fragment response mode
	effectiveResponseMode := input.responseMode
	if isImplicitFlow && effectiveResponseMode == "" {
		effectiveResponseMode = "fragment"
	}

	if effectiveResponseMode == "fragment" {
		values := url.Values{}
		values.Add("error", input.code)
		values.Add("error_description", input.description)
		if len(strings.TrimSpace(input.state)) > 0 {
			values.Add("state", input.state)
		}
		http.Redirect(w, r, input.redirectURI+"#"+values.Encode(), http.StatusFound)
		return nil
	}

	if effectiveResponseMode == "form_post" {
		m := make(map[string]interface{})
		m["redirectURI"] = input.redirectURI
		m["error"] = input.code
		m["error_description"] = input.description
		if len(strings.TrimSpace(input.state)) > 0 {
			m["state"] = input.state
		}

		t, err := template.ParseFS(templateFS, "form_post.html")
		if err != nil {
			return errors.Wrap(err, "unable to parse template")
		}

		// Render into a buffer, not straight to w. Execute writes as it walks the template, so a
		// template that parses and then fails part way through would leave a partial body and an
		// implicit 200 already on the wire. Every caller answers an error from here with
		// httpHelper.InternalServerError as its last resort, and a WriteHeader after the response
		// is committed changes nothing, so the client would be told 200 for a page that was never
		// finished. form_post.html is operator supplied whenever GOIABADA_AUTHSERVER_TEMPLATEDIR
		// is set, so this is reachable in a real deployment rather than only in tests. Buffering
		// keeps the response uncommitted until there is a whole page to send (#141).
		var rendered bytes.Buffer
		err = t.Execute(&rendered, m)
		if err != nil {
			return errors.Wrap(err, "unable to execute template")
		}
		_, err = w.Write(rendered.Bytes())
		if err != nil {
			// The connection itself failed. Nothing can be recovered from here, including the
			// caller's 500, but the error is still worth reporting rather than swallowing.
			return errors.Wrap(err, "unable to write the form_post response")
		}
		return nil
	}

	// default to query
	redirUrl, err := url.ParseRequestURI(input.redirectURI)
	if err != nil {
		return errors.Wrap(err, "unable to parse redirect URI")
	}
	values := redirUrl.Query()
	values.Add("error", input.code)
	values.Add("error_description", input.description)
	if len(strings.TrimSpace(input.state)) > 0 {
		values.Add("state", input.state)
	}
	redirUrl.RawQuery = values.Encode()

	http.Redirect(w, r, redirUrl.String(), http.StatusFound)
	return nil
}
