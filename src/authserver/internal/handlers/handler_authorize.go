package handlers

import (
	"bytes"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"slices"
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
	"github.com/leodip/goiabada/core/urlutil"
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

		// The refusal page, which is how this handler answers anything it must not send to the
		// client. The status is a parameter because the two conditions that reach it differ on it:
		// a bad client_id or redirect_uri has always answered 200, and an unsupported
		// response_mode is answered 400 because OIDC Core 3.1.2.6 names that code (#213).
		renderErrorUi := func(message string, httpStatus int) {
			bind := map[string]interface{}{
				"title":       i18n.T(r.Context(), "auth_error.unable_to_authorize.title"),
				"error":       message,
				"_httpStatus": httpStatus,
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
			// Localized, unlike every other error this handler answers, because this one is
			// rendered rather than redirected: RFC 6749 4.1.2.1 forbids sending a bad client_id
			// or redirect_uri anywhere, so the page is the whole answer and OIDC Core requires
			// an OP to honour ui_locales for the user interface. The localizer on r was already
			// refined from ui_locales above. Anything that is not a LocalizedError is a database
			// failure from inside the validator, which answered 500 before this change too
			// (#213 decision 9).
			localizedErr, ok := err.(*i18n.LocalizedError)
			if ok {
				renderErrorUi(localizedErr.Localize(r.Context()), http.StatusOK)
				return
			} else {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		// An unsupported response_mode is answered here, above every validation that answers by
		// redirect, because it is the one failure that cannot be answered by redirect at all.
		//
		// OpenID Connect Core 1.0 section 3.1.2.6 closes with an explicit exception to the rule
		// that returns errors to the redirect URI: "If the Response Mode value is not supported,
		// the Authorization Server returns an HTTP response code of 400 (Bad Request) without
		// Error Response parameters, since understanding the Response Mode is necessary to know
		// how to return those parameters." So the check precedes all five, not just the one that
		// would have caught it: whichever error a request carries, this server cannot encode it in
		// a mechanism it does not implement, and falling through to the query default would answer
		// in a mode the client did not ask for and may not read.
		//
		// Applied to every authorization request rather than only to an OIDC Authentication
		// Request. The sentence's reasoning does not turn on the scope, and OAuth 2.0 Multiple
		// Response Type Encoding Practices section 2.1, which defines response_mode, states no
		// behaviour for an unsupported value, so extending it contradicts nothing (#213
		// decision 11).
		//
		// ValidateRequest's other response_mode rule is deliberately left where it is: an implicit
		// request asking for query or form_post is asking for a mode this server understands and
		// simply may not use for tokens, so that error can be, and is, delivered as a redirect the
		// client can parse.
		if !validators.IsSupportedResponseMode(authContext.ResponseMode) {
			renderErrorUi(i18n.T(r.Context(), "auth_error.unsupported_response_mode.message"),
				http.StatusBadRequest)
			return
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

		sessionIdentifier := ""
		if r.Context().Value(constants.ContextKeySessionIdentifier) != nil {
			sessionIdentifier = r.Context().Value(constants.ContextKeySessionIdentifier).(string)
		}

		// The session row behind this browser, loaded at most once and only if somebody asks. The
		// predicate below asks, and so does the ordinary path at the bottom of the handler, and
		// between them there must be exactly one query: this handler used to reach the lookup only
		// after prompt=none and prompt=login had already returned, so an eager load here would add
		// a query to every prompt=login request and a second one to every prompt=none request,
		// which does its own lookup inside handlePromptNone.
		//
		// A lookup that fails records the error and answers false. False is not "no session" here,
		// it is "no answer", so every caller checks sessionLoadErr and answers 500 rather than
		// acting on it: treating an unreadable session as an absent one would turn a database
		// fault into a login prompt for somebody who is already signed in (#213).
		var (
			userSession     *models.UserSession
			sessionLookedUp bool
			sessionIsValid  bool
			sessionLoadErr  error
		)
		hasValidUserSession := func() bool {
			if sessionLookedUp {
				return sessionIsValid
			}
			sessionLookedUp = true

			userSession, sessionLoadErr = database.GetUserSessionBySessionIdentifier(nil, sessionIdentifier)
			if sessionLoadErr != nil {
				return false
			}

			sessionIsValid = userSessionManager.HasValidUserSession(r.Context(), userSession,
				authContext.ParseRequestedMaxAge())
			return sessionIsValid
		}

		// Silence and forced re-authentication are read from the RAW parameter rather than from
		// authContext.Prompt, because a prompt the validator rejects is never assigned there, and
		// OIDC Core 3.1.2.3 forbids interacting with a request that "contains the prompt parameter
		// with the value none" whether or not the rest of the value parsed. So "none login", which
		// ValidatePrompt refuses below, is still a silent request and must not be shown a login
		// page. Case-sensitively, and on whitespace-separated tokens, because OIDC prompt values
		// are case-sensitive: "NONE" and "Login" carry no recognised token and are interactive
		// (#213 decision 5).
		rawPrompt := strings.Fields(r.FormValue("prompt"))
		requestsSilence := slices.Contains(rawPrompt, "none")
		requestsLogin := slices.Contains(rawPrompt, "login")

		// Whether the five validations below answer the client straight away or park their error
		// and send the visitor to log in first.
		//
		// RFC 9700 4.11.2: "The authorization server MUST always authenticate the user first and,
		// with the exception of the silent authentication use case, prompt the user for credentials
		// when needed, before redirecting the user." Without this, one link sent to a logged-out
		// browser makes this server redirect it to a host the client chose, which is attack 1 in
		// that section verbatim.
		//
		// The rule the three clauses come from: authentication is required before a REDIRECT, and
		// only before a redirect. Where the answer is a page it is rendered at once.
		//
		//   - requestsSilence: OIDC Core 3.1.2.3 says the server "MUST NOT interact with the
		//     End-User" when prompt=none, which is the exception RFC 9700 names.
		//   - !redirectWillBeEmitted: no redirect leaves this server, so the requirement that
		//     governs redirects has nothing to say and the visitor reaches the same refusal page
		//     with or without a login (#108's and #122's guards, decision 8).
		//   - !requestsLogin && hasValidUserSession(): a session holder has authenticated already,
		//     unless the client asked not to be answered on the strength of one (decision 4).
		//
		// The two clauses that read nothing are evaluated first so the one that does is reached
		// only when it decides something: || short-circuits, and what redirectWillBeEmitted does
		// is read, so skipping it changes no state and the value is identical to the order §4
		// wrote. Only the queries differ. It stopped being side-effect free when it gained the
		// registration gate (#241 decision 11), and the ordering argument rests on the read being
		// a read rather than on the predicate being pure.
		//
		// The answer is remembered, in the shape hasValidUserSession above already uses, because
		// this request has a second reader: the emitter. Two live reads of a table an administrator
		// can change mid-request are two answers that need not agree, and a no here is what makes
		// answering the client at once safe, so it is carried to the emitter as a floor rather than
		// recomputed there. redirectAlreadyWithheld is where it lands and why.
		var (
			emissionLookedUp bool
			emissionAllowed  bool
		)
		redirectWouldBeEmitted := func() bool {
			if emissionLookedUp {
				return emissionAllowed
			}
			emissionLookedUp = true

			emissionAllowed = redirectWillBeEmitted(database, client, authContext.RedirectURI,
				authContext.ResponseType, "authorize")
			return emissionAllowed
		}

		answerClientNow := requestsSilence ||
			!redirectWouldBeEmitted() ||
			(!requestsLogin && hasValidUserSession())

		if sessionLoadErr != nil {
			httpHelper.InternalServerError(w, r, sessionLoadErr)
			return
		}

		// answerClientImmediately answers the client with an error now, whoever is at the browser.
		//
		// Read from the request rather than from authContext: this closure runs before the
		// second SaveAuthContext below, and two of its call sites run before the context
		// has been populated with the validated values at all. answerClientWithError then
		// clears the context before answering, and derives its own server_error fallback
		// from this same request-sourced input (#141).
		answerClientImmediately := func(validationError *customerrors.ErrorDetail) {
			input := redirectErrorFromRequest(r, client,
				validationError.GetCode(), validationError.GetDescription())

			// Carry a refusal this request has already been given, and only a refusal. The
			// predicate may not have run at all, on a silent request, where the first clause of
			// answerClientNow short-circuits it; that is "nothing has refused yet" and the emitter
			// asks for itself.
			input.redirectAlreadyWithheld = emissionLookedUp && !emissionAllowed

			answerClientWithError(w, r, database, httpHelper, authHelper, templateFS, input)
		}

		// answerValidationError answers one of the five validations that run before this handler
		// knows who is at the browser. It is separate from answerClientImmediately, rather than
		// being the only closure with the disabled-account path folded into it, because that path
		// must never defer: a disabled user sent to the login page cannot complete it, so the
		// access_denied its client is owed would never be delivered at all.
		//
		// These five descriptions stay English and are deliberately NOT localized, unlike the
		// seven above that render the refusal page. They become an error_description, which RFC
		// 6749 4.1.2.1 confines to "%x20-21 / %x23-5B / %x5D-7E" and describes as "used to assist
		// the client developer in understanding the error that occurred": the audience is the
		// integrator reading a redirect, not the visitor, and the character set excludes pt-BR
		// anyway. Translating one would not ship non-ASCII, because
		// customerrors.ConformErrorDescription enforces that set at both the parking site below
		// and the emitter, so an accented sentence would reach the client as a row of question
		// marks instead. That is the failure a translation here buys (#213 decision 9).
		answerValidationError := func(validationError *customerrors.ErrorDetail) {
			if answerClientNow {
				answerClientImmediately(validationError)
				return
			}

			// Park the error and go and authenticate. It is carried on the auth context, which
			// securecookie encrypts and HMACs, so it is not a value the visitor can choose, and
			// it is delivered at /auth/level1completed once level 1 credentials are verified.
			//
			// The description is conformed HERE and not only at the emitter. RFC 6749 Appendix
			// A.8's character set is enforced in redirToClientWithError as well, and that filter
			// is idempotent so the two paths stay byte-identical, but a bound applied at emission
			// does nothing for a string already parked in the session: descriptions interpolate
			// request text, so an unbounded one would be carried by every request of the
			// ceremony that parked it. The bound itself is ConformErrorDescription's own
			// maxErrorDescriptionBytes; it used to be attributed to the 50-chunk cap of the
			// cookie store, which no longer exists (#213 decision 10, #266).
			authContext.DeferredErrorCode = validationError.GetCode()
			authContext.DeferredErrorDescription =
				customerrors.ConformErrorDescription(validationError.GetDescription())
			authContext.AuthState = oauth.AuthStateRequiresLevel1

			err := authHelper.SaveAuthContext(w, r, &authContext)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, config.GetAuthServer().BaseURL+"/auth/level1", http.StatusFound)
		}

		err = authorizeValidator.ValidateUnsupportedRequestParameters(&validators.ValidateUnsupportedRequestParametersInput{
			HasRequest:    r.Form.Has("request"),
			HasRequestURI: r.Form.Has("request_uri"),
		})
		if err != nil {
			valError, ok := err.(*customerrors.ErrorDetail)
			if ok {
				answerValidationError(valError)
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
				answerValidationError(valError)
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
				answerValidationError(valError)
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
				answerValidationError(valError)
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
				answerValidationError(valError)
				return
			}
			httpHelper.InternalServerError(w, r, err)
			return
		}
		authContext.IdTokenHintSub = hintSub

		// The authentication level this ceremony must reach is fixed HERE, at the one point the
		// request has been accepted and before any handler acts on it, and every later handler
		// reads the snapshot instead of the client's row. /auth/level1completed, /auth/level2 and
		// /auth/completed each reload the client and would otherwise recompute the target from
		// whatever default_acr_level says by the time they run, so an administrator editing that
		// row mid-ceremony would retroactively change what the ceremony was required to do:
		// raising it after the step-up decision has been taken stamps an acr naming a second
		// factor that was never performed, and lowering it takes /auth/level2's target outside
		// its switch and answers 500. This is also the last point before handlePromptNone below
		// reads the target (#240).
		authContext.SetTargetAcrLevel(client.DefaultAcrLevel)

		// Save AuthContext with the validated hint sub and the target ACR snapshot, for use in
		// downstream handlers
		err = authHelper.SaveAuthContext(w, r, &authContext)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
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

		// The same lookup the predicate at the top of the handler may already have performed, and
		// the closure returns its cached answer when it did. It has not when a clause above the
		// session clause carried the predicate on its own, which is why this is a call and not a
		// read of a variable.
		sessionIsValidForSSO := hasValidUserSession()
		if sessionLoadErr != nil {
			httpHelper.InternalServerError(w, r, sessionLoadErr)
			return
		}

		// The user behind the session is loaded here, and not inside the closure, because the
		// predicate needs only the session's own timestamps and this is the first point anything
		// reads userSession.User. UserSessionLoadUser answers nil for a nil session.
		err = database.UserSessionLoadUser(nil, userSession)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		if sessionIsValidForSSO {

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

				// Answered at once, never deferred: this path has a valid session, so somebody is
				// already authenticated, and a disabled user sent to the login page could not
				// complete it anyway (#213).
				answerClientImmediately(customerrors.NewErrorDetailWithHttpStatusCode("access_denied", "The user account is disabled.", http.StatusBadRequest))
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
	// Helper to clear the auth context and then redirect with error. The clear-then-answer
	// sequence and its server_error fallback live in answerClientWithError, which derives that
	// fallback from the input handed to it, so this path keeps answering from the stored ceremony
	// exactly as it did when the sequence was written out here (#141).
	//
	// On the silent path the fallback is worth naming: a silent-renewal iframe reads server_error
	// as "retry later" rather than "start an interactive login", which on a genuine server fault
	// is the accurate instruction of the two.
	redirectWithError := func(errorCode string, errorDescription string) {
		answerClientWithError(w, r, database, httpHelper, authHelper, templateFS,
			redirectErrorFromAuthContext(authContext, client, errorCode, errorDescription))
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

	// 6. The user's authenticator has changed since this session last answered the level 2
	// question. userSession.User is already loaded on this path, for Enabled and OTPEnabled
	// above, so the comparison costs no query.
	//
	// A reader only: it refuses and promotes nothing, because no interaction happened. That
	// is what makes an identical second prompt=none request get the identical answer, where
	// the boolean this replaced would have been a one-shot signal had either reader cleared
	// it here (#242 decision 1).
	if userSession.OtpConfigGeneration != userSession.User.OtpConfigGeneration {
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

	// redirectAlreadyWithheld records that redirectWillBeEmitted has ALREADY answered no for this
	// request, so the emitter must not ask again and get a different answer. It is a floor, never a
	// ceiling: false means "nothing has refused yet", not "a redirect is permitted", and the
	// emitter still runs the live gates on top of it.
	//
	// The gate began reading the database (#241 decision 11), which made it non-monotonic across
	// the two readers one authorization request has. HandleAuthorizeGet asks it before routing, to
	// decide whether a validation failure may be answered at once or has to be parked behind a
	// login: a refusal there makes answerClientNow true, on the reasoning that no redirect leaves
	// this server so RFC 9700 4.11.2 has nothing to govern. The emitter then asks again. When the
	// first answer was a transient registration-read failure, or the callback was re-added between
	// the two reads, the second answer can be yes, and the refusal that made answering at once safe
	// has been discarded: a logged-out browser holding one crafted link is redirected to the
	// client's host on a request this server refused, which is attack 1 of RFC 9700 4.11.2 verbatim
	// and the exact harm the deferral machinery exists to prevent (#213, #241).
	//
	// So a later read may narrow yes to no, which is a removal taking effect, and may never widen
	// no to yes.
	redirectAlreadyWithheld bool
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

// redirectErrorFromRequest builds the input for an error redirect whose response parameters come
// from the HTTP request rather than from the stored ceremony. It is the twin of
// redirectErrorFromAuthContext, and it exists because HandleAuthorizeGet answers errors that arise
// before the context holds the validated values: two of its sites run before the second
// SaveAuthContext, so the request is the only source that has them.
func redirectErrorFromRequest(r *http.Request, client *models.Client,
	code string, description string) redirectErrorInput {

	return redirectErrorInput{
		client:       client,
		code:         code,
		description:  description,
		responseMode: r.FormValue("response_mode"),
		redirectURI:  r.FormValue("redirect_uri"),
		state:        r.FormValue("state"),
		responseType: r.FormValue("response_type"),
	}
}

// answerClientWithError clears the auth context and then answers the client with an error, which
// is the sequence every error response from an authorization ceremony owes.
//
// The clear goes FIRST. ClearAuthContext persists the deletion through a Set-Cookie on w, and
// redirToClientWithError commits the response in every response mode, so clearing afterwards
// leaves the header on a response already written and the browser keeps an auth context it can
// replay (#141).
//
// On a failed clear the client is owed an error response regardless: its redirect URI was
// validated upstream, so OIDC Core 1.0 3.1.2.2 with 3.1.2.6 applies, and RFC 6749 4.1.2.1 mints
// server_error for exactly this condition (#141). The fallback is the caller's own input with its
// code and description swapped, so each call site keeps the parameter source it built the input
// from and neither has to restate it.
func answerClientWithError(w http.ResponseWriter, r *http.Request, database data.Database,
	httpHelper HttpHelper, authHelper AuthHelper, templateFS fs.FS, input redirectErrorInput) {

	err := authHelper.ClearAuthContext(w, r)
	if err != nil {
		// The clear failed, so Save wrote no cookie and the browser still holds the auth context.
		slog.Error("failed to clear the auth context, answering the client with server_error",
			"error", err)

		fallback := input
		fallback.code = "server_error"
		fallback.description = "Internal server error"

		err = redirToClientWithError(w, r, database, httpHelper, templateFS, fallback)
		if err != nil {
			// Nowhere left to send the client, so the 500 is the last resort here.
			httpHelper.InternalServerError(w, r, err)
		}
		return
	}

	err = redirToClientWithError(w, r, database, httpHelper, templateFS, input)
	if err != nil {
		httpHelper.InternalServerError(w, r, err)
		return
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

// redirectWillBeEmitted answers whether an error response to this client would actually leave the
// server as a redirect, or whether it would be withheld and replaced by the refusal interstitial.
// It is the three gates below, asked as one question, so the callers that need the answer BEFORE
// building a response and the emitter that enforces it at the last moment cannot drift apart.
//
// site names the caller for the log line inside checkRedirectURIEmittable, which records where a
// refusal happened and deliberately never records the URI itself (#159).
//
// Gate 3. RFC 9700 4.11.2: an attacker who registers a client anonymously can use this server's own
// error redirect to deliver a victim to a host they control, either by getting the user to
// decline (attack 2) or by sending a deliberately invalid request (attack 1). The RFC leaves
// "trusted" to the server and names the source of the redirect URI among its inputs, so a
// client that registered itself is the untrusted case and an administrator-registered one,
// whose redirect URI a human vetted, is not. An unresolved client is untrusted too: the
// question is where the redirect URI came from, and "we could not find out" is not an answer
// that justifies using it.
//
// A silent request is NOT exempt, and an earlier version of this guard had it the other way
// round. RFC 9700 4.11.2 lists three attacks, and the third is the exemption written out:
// "Intentionally send a valid silent authentication request (prompt=none) with client_id and
// redirect_uri controlled by the attacker. In this case, the authorization server will
// automatically redirect the user agent to the phishing site." It needs neither a session nor
// any victim interaction, which makes it the cheapest of the three rather than a corner. The
// exception clause in the same section, "with the exception of the silent authentication use
// case", sits inside the requirement to prompt for credentials, not inside the "MUST take
// precautions to prevent these threats" that governs the list attack 3 is in.
//
// OIDC Core 3.1.2.1 is not violated by rendering the interstitial instead: it forbids displaying
// "any authentication or consent user interface pages", and that page asks for neither. What it
// costs is real and was accepted knowingly: a self-registered client's silent renewal stops
// receiving a readable consent_required and has to fall back to an interactive authorization
// (#108, decision 15).
//
// Gate 4, the last resort, and a separate statement from the gate above rather than a third
// clause on it: that one weighs where the redirect URI came from, this one weighs whether the
// string can name the host it appears to. An administrator-registered client passes the
// provenance test and can still hold a row stored before these rules existed, which is the case
// the gate above cannot cover and this one does. Unreachable once the authorization endpoint has
// refused the URI, and kept so that a test enforces it (#122).
//
// The registration gate, last of the three and the only one that reads anything. The two above
// weigh the redirect URI as it was stored when the ceremony began; this one weighs it against what
// the client has registered right now. An authorization ceremony can sit on the consent screen for
// as long as a person takes to read it, and an administrator who deletes a callback in that window
// expects the deletion to reach the sign-in already running. Without this gate it reaches only what
// /auth/issue mints: six other places answer the client from a ceremony in progress, every one of
// them an error redirect, and every one of them navigates the browser to the URI stored at the
// start. Delivering one to a host the operator has just disowned is RFC 9700 section 4.11.2's harm
// whichever of the seven sites produced it, which is why the check lives in the one predicate they
// share rather than at each of them: a registration test copied to every site is the shape a later
// edit gets out of step (#241 decision 11).
//
// The flag to RedirectURIIsRegistered is computed from the response type, by the same token-sequence
// test validators.ValidateClientAndRedirectURI and /auth/issue apply, so exactly one token equal to
// "code" buys loopback port flexibility and every implicit response stays strict. An earlier version
// of this gate passed false unconditionally, reasoning that flexibility exists for a native app's
// ephemeral port on a code request and an error redirect carries no code. That reasoning asks the
// wrong question. This gate weighs whether the destination is one the client still has registered,
// and RFC 8252 section 7.3 settles what "registered" means for a loopback URI: "The authorization
// server MUST allow any port to be specified at the time of the request for loopback IP redirect
// URIs, to accommodate clients that obtain an available ephemeral port from the operating system at
// the time of the request." So http://127.0.0.1:49152/cb IS covered by a registered
// http://127.0.0.1/cb on a code request, and calling it unregistered here withholds an error the
// client is owed: RFC 6749 section 4.1.2.1 confines the MUST NOT redirect to a request that "fails
// due to a missing, invalid, or mismatching redirection URI", and for every other failure "the
// authorization server informs the client by adding the following parameters to the query component
// of the redirection URI". Passing false made a native app's consent cancellation, deferred
// validation error and scope refusal vanish into this server's interstitial with nothing on the
// wire, which is a hang rather than an error it can report.
//
// Strictness is not free here, which is why it is not the default: this gate can only refuse, so an
// over-strict answer is a delivery failure with no security to show for it. The relaxation admits
// nothing new either. The same flexible rule already ran over the same URI at /auth/authorize, on
// the same ceremony, so a destination this arm now accepts is one the front door accepted, and a
// loopback IP literal names the browser's own machine, which is not a host somebody else controls.
// Each caller supplies the flag from what it knows, per urlutil's package contract (#41), and what
// this caller knows is the response type the ceremony carries (#241).
//
// A failed load answers no, matching clientProvenance above and for the reason that function
// states: every caller is already on its way to returning an error response, so a lookup that fails
// must not turn a refusal that works today into a 500, and an unresolved registration is the
// untrusted case rather than an exempt one.
//
// This predicate is asked twice within one authorization request, and the second answer may not be
// more permissive than the first: see redirectErrorInput.redirectAlreadyWithheld, which carries the
// first refusal into the emitter.
func redirectWillBeEmitted(database data.Database, client *models.Client, redirectURI string,
	responseType string, site string) bool {

	if client == nil || client.CreatedViaDCR {
		return false
	}

	if err := checkRedirectURIEmittable(site, redirectURI); err != nil {
		return false
	}

	redirectURIs, err := database.GetRedirectURIsByClientId(nil, client.Id)
	if err != nil {
		// The client identifier is a bounded stored value and is safe to log; the URI is not,
		// matching checkRedirectURIEmittable, which records where a refusal happened and
		// deliberately never records the value (#159).
		slog.Error("unable to load the client's redirect URIs while answering it with an error, withholding the redirect",
			"clientIdentifier", client.ClientIdentifier, "site", site, "error", err)
		return false
	}

	registered := make([]string, 0, len(redirectURIs))
	for _, uri := range redirectURIs {
		registered = append(registered, uri.URI)
	}

	// Read off the token sequence rather than off ParseResponseType's booleans, for the reason
	// stated at validators.ValidateClientAndRedirectURI: the parser ignores unrecognised values
	// and collapses duplicates, so "code code" and "code foo" are true for HasCode && !HasToken
	// && !HasIdToken and must not buy an arbitrary loopback port.
	responseTypes := strings.Fields(responseType)
	allowLoopbackPortFlexibility := len(responseTypes) == 1 && responseTypes[0] == "code"

	if !urlutil.RedirectURIIsRegistered(registered, redirectURI, allowLoopbackPortFlexibility) {
		slog.Warn("the redirect URI this client would be answered at is no longer registered on it, so the redirect is withheld",
			"clientIdentifier", client.ClientIdentifier, "site", site)
		return false
	}

	return true
}

func redirToClientWithError(w http.ResponseWriter, r *http.Request, database data.Database,
	httpHelper HttpHelper, templateFS fs.FS, input redirectErrorInput) error {

	// All three gates, asked through the one predicate so this emitter and the callers that ask the
	// same question before building a response cannot answer it differently. The reasoning for each
	// gate travels with redirectWillBeEmitted (#108, #122, #241).
	//
	// redirectAlreadyWithheld is read FIRST and short-circuits the live gates, so a caller that has
	// already been told no cannot have that refusal overturned by a second read of a registration
	// table that has changed, or recovered, since. The predicate is a database read now, so the two
	// answers one request gets are not guaranteed to agree, and only one direction of disagreement
	// is safe: see the field's own comment.
	//
	// The call sits above the response-mode dispatch so it covers query, fragment and form_post
	// alike, and it can only ever withhold a redirect: nothing below it is reached, no state is
	// written and no route is added, so there is nothing here for an attacker to drive. The
	// interstitial names the destination and the authorization stops, rather than this server
	// forwarding a browser to a host of somebody else's choosing on a request it just refused.
	if input.redirectAlreadyWithheld ||
		!redirectWillBeEmitted(database, input.client, input.redirectURI, input.responseType,
			"redirToClientWithError") {
		return renderRedirectBlocked(httpHelper, w, r, input)
	}

	// The description becomes an error_description on the wire from here down, so it is conformed to
	// RFC 6749 Appendix A.8's NQSCHAR once, here, and every branch below reads the conformed value.
	// Descriptions interpolate request text, so an emoji or a Cyrillic word in a rejected scope
	// otherwise puts a byte the RFC forbids into a protocol parameter (#213).
	//
	// This function rather than answerClientWithError, which wraps it: the three response modes below
	// build the parameter in two different places, the params slice that query and fragment share and
	// the form_post bind map, and a wrapper cannot cover a caller that reaches this emitter without
	// going through it.
	//
	// Below the redirect guard, deliberately. renderRedirectBlocked above puts the description on an
	// HTML page, which is a user interface and not a protocol parameter, so the interstitial keeps the
	// text as the validator wrote it and only what actually leaves as a redirect is filtered.
	description := customerrors.ConformErrorDescription(input.description)

	// Per RFC 6749 4.2.2.1 and OIDC Core 3.2.2.5: implicit flow errors MUST be returned in fragment
	// Determine if this is an implicit flow by checking response_type
	rtInfo := oauth.ParseResponseType(input.responseType)
	isImplicitFlow := rtInfo.IsImplicitFlow()

	// For implicit flow, default to fragment response mode
	effectiveResponseMode := input.responseMode
	if isImplicitFlow && effectiveResponseMode == "" {
		effectiveResponseMode = "fragment"
	}

	// The error response's parameters, in the order they reach the client, built once for all three
	// response modes because all three answer with the same three fields.
	//
	// state is appended on its value being non-empty and nothing else. There is no TrimSpace, and
	// no separate "was the parameter present" flag either, because at this endpoint the two
	// questions have one answer: RFC 6749 section 3.1 says "Parameters sent without a value MUST be
	// treated as if they were omitted from the request", so "?state=" and "?state" are requests
	// that carried no state. Appendix A.5 then defines the response element as "state = 1*VSCHAR",
	// which admits no empty value in the response either. Space is %x20 and so is VSCHAR, which is
	// why a whitespace-only state is a real state and is echoed byte for byte: trimming it away was
	// this server substituting its own judgement for "the exact value received from the client"
	// (RFC 6749 4.1.2.1). Undoing this and reinstating a trim would put that back (#146).
	//
	// The end_session_endpoint deliberately does NOT work this way: see buildPostLogoutRedirect,
	// where a supplied-but-empty state does come back as "state=". RP-Initiated Logout 1.0 carries
	// no valueless-parameter rule, so the two endpoints differ because their specifications do.
	params := []responseParam{
		{"error", input.code},
		{"error_description", description},
	}
	if input.state != "" {
		params = append(params, responseParam{"state", input.state})
	}

	if effectiveResponseMode == "fragment" {
		// A fragment is built by appending rather than through writeResponseParams: the redirect
		// URI cannot carry a fragment of its own (RFC 6749 3.1.2 forbids it and
		// checkRedirectURIEmittable refuses one above), so there is no registered field list here
		// to preserve or replace. Its query, if it registered one, is left exactly as it stands.
		http.Redirect(w, r, input.redirectURI+"#"+encodeResponseParams(params), http.StatusFound)
		return nil
	}

	if effectiveResponseMode == "form_post" {
		m := make(map[string]interface{})
		m["redirectURI"] = input.redirectURI
		m["error"] = input.code
		m["error_description"] = description
		// The same rule as the params slice above, stated again because this branch answers through
		// a bind map rather than through a field list, and all three branches should say what they
		// emit in the same terms. What the client actually receives is then decided by
		// form_post.html, whose {{if .state}} omits the input entirely.
		//
		// This guard was written as unobservable and is not. {{.state}} and {{if .state}} do answer
		// identically for an absent key and a key holding "", which is as far as the first reading
		// went, but a template that enumerates the map tells them apart: range yields the key only
		// when it is present, and len counts it. form_post.html is operator supplied whenever
		// GOIABADA_AUTHSERVER_TEMPLATEDIR is set, so that is a real reader rather than a contrived
		// one, and TestFormPostBindMapOmitsAnAbsentState pins both emitters on it (#146).
		if input.state != "" {
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
		// OAuth 2.0 Form Post Response Mode section 2: "Because the Authorization Response is
		// intended to be used only once, the Authorization Server MUST instruct the User Agent (and
		// any intermediaries) not to store or reuse the content of the response." The page holds
		// the client's state, and on the success path its twin holds an authorization code, so a
		// cached or reused copy is a replayable response sitting in an intermediary. This pair is
		// what the rest of this codebase already writes for a no-store response (#146).
		//
		// Set here rather than before Execute deliberately: a render that fails must leave the
		// response completely untouched, so that the caller's last-resort InternalServerError owns
		// every header as well as the status. Moving these two above the Execute would leave a 500
		// carrying the headers of a form_post page that was never sent (#141).
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")

		_, err = w.Write(rendered.Bytes())
		if err != nil {
			// The connection itself failed. Nothing can be recovered from here, including the
			// caller's 500, but the error is still worth reporting rather than swallowing.
			return errors.Wrap(err, "unable to write the form_post response")
		}
		return nil
	}

	// default to query
	//
	// writeResponseParams, not Query() then Encode(). Seeding url.Values from the registered URI's
	// own query and calling Add on top is what emitted two state parameters to a client that had
	// registered "?state=fixed", leaving its CSRF check to be made against a value it never
	// generated, which is the defect this change exists to remove. Re-encoding also silently
	// rewrote the registered query in five separate ways, against RFC 6749 3.1.2's "MUST be
	// retained". Both are the shared helper's to prevent, and its comment carries the detail (#146).
	//
	// authorizationResponseParamNames, so a registered "code" is dropped from an error response as
	// well: without it a client registering "?code=stale" was refused with
	// "?code=stale&error=access_denied&...", a response carrying an authorization code and an error
	// at once. The reserved set is filtered whether or not this response emits the name, which is
	// what makes that true (#146).
	location, err := writeResponseParams(input.redirectURI, params, authorizationResponseParamNames)
	if err != nil {
		return errors.Wrap(err, "unable to build the error redirect")
	}

	http.Redirect(w, r, location, http.StatusFound)
	return nil
}
