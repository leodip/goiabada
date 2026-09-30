package handlers

import (
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/go-chi/chi/v5/middleware"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	authserver_middleware "github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/urlutil"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/stringutil"
)

// validateIdTokenHint parses and validates the id_token_hint parameter.
// Per OIDC Core 1.0 Section 3.1.2.2:
// - MUST validate the server was the issuer
// - SHOULD accept expired tokens (withExpirationCheck=false)
// Returns the sub claim from the hint, or empty string if no hint provided.
// Returns error if hint is malformed or not issued by this server.
func validateIdTokenHint(ctx context.Context, idTokenHint string, tokenParser TokenParser, settings *models.Settings) (string, error) {
	if idTokenHint == "" {
		return "", nil
	}

	// Defensive check: tokenParser should never be nil in production wiring, but guard against future refactors
	if tokenParser == nil {
		return "", errs.New("tokenParser is nil")
	}

	// Parse JWT: verify signature, skip expiration (spec: SHOULD accept expired)
	jwtToken, err := tokenParser.DecodeAndValidateTokenString(ctx, idTokenHint, false)
	// OIDC Core 1.0 section 3.1.2.1 defines the hint as an ID Token, and the signature does not
	// say which kind of token this is: access and refresh tokens are signed with the same key and
	// carry iss and sub too. The typ denylist is the one logout applies; a refused kind is
	// answered as a hint that does not parse, so the answer says nothing about which it was (#401).
	if err != nil || nonIdTokenTypValues[jwtToken.GetStringClaim("typ")] {
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

// authorizeDatabase is what the authorization endpoint needs: the client and its redirect URIs,
// the consent already given, and the session a browser may arrive with.
type authorizeDatabase interface {
	GetClientByClientIdentifier(ctx context.Context, tx *sql.Tx, clientIdentifier string) (*models.Client, error)
	GetConsentByUserIdAndClientId(ctx context.Context, tx *sql.Tx, userId int64, clientId int64) (*models.UserConsent, error)
	GetRedirectURIsByClientId(ctx context.Context, tx *sql.Tx, clientId int64) ([]models.RedirectURI, error)
	GetUserSessionBySessionIdentifier(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (*models.UserSession, error)
	UserSessionLoadUser(ctx context.Context, tx *sql.Tx, userSession *models.UserSession) error
}

func HandleAuthorizeGet(
	pageRenderer PageRenderer,
	ceremonyStore CeremonyStore,
	userSessionManager UserSessionManager,
	database authorizeDatabase,
	templateFS fs.FS,
	authorizeValidator AuthorizeValidator,
	auditLogger AuditLogger,
	permissionChecker PermissionChecker,
	tokenParser TokenParser,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		requestId := middleware.GetReqID(r.Context())

		// The refusal page, which is how this handler answers anything it must not send to the
		// client. The status is a parameter because the conditions that reach it differ on it: a bad
		// client_id or redirect_uri has always answered 200, while an unsupported response_mode is
		// answered 400 because OIDC Core 3.1.2.6 names that code (#213), and a request that cannot be
		// parsed or repeats a delivery parameter is 400 as the malformed request it is (#228).
		renderErrorUi := func(message string, httpStatus int) {
			bind := map[string]interface{}{
				"title":       i18n.T(r.Context(), "auth_error.unable_to_authorize.title"),
				"error":       message,
				"_httpStatus": httpStatus,
			}

			renderTemplateErr := pageRenderer.RenderTemplate(w, r, "/layouts/no_menu_layout.html", "/auth_error.html", bind)
			if renderTemplateErr != nil {
				pageRenderer.InternalServerError(w, r, renderTemplateErr)
			}
		}

		// A request that does not parse is answered on the page and never by redirect: a malformed
		// escape drops the field it sits in, so the client_id or redirect_uri the redirect would be
		// built from may be one the client never sent. Before #228 the failure was ignored and the
		// request went on without that field.
		params, err := authorizeParameters(r)
		if err != nil {
			renderErrorUi(i18n.T(r.Context(), "auth_error.malformed_request.message"), http.StatusBadRequest)
			return
		}

		// RFC 6749 4.1.2 returns state as "the exact value received from the client". Two differing
		// copies leave no such value, so the ceremony carries none and the invalid_request that
		// refuses the request below reaches the client without one, #146's rule that state is
		// emitted only when there is exactly one value to emit (#228).
		state := params.Get("state")
		if protocolvalidation.ConflictingParameter(params, []string{"state"}) != "" {
			state = ""
		}

		// The ceremony id is minted here and nowhere else, because this is the only place an
		// auth context is created. Every form this ceremony renders carries it and every POST
		// checks it, so a page left open in another tab cannot act on the authorization
		// request that replaced it (#79).
		ceremonyId := stringutil.GenerateSecurityRandomString(ceremonyIdLength)

		// The literal carries no AuthState, and nothing below saves it until an exit has assigned
		// one. A request refused for its client, redirect URI or response mode therefore writes no
		// record, so a sign-in in progress in the same browser survives a malformed link (#436).
		authContext := ceremony.AuthContext{
			CeremonyId:                    ceremonyId,
			ClientId:                      params.Get("client_id"),
			RedirectURI:                   params.Get("redirect_uri"),
			ResponseType:                  params.Get("response_type"),
			CodeChallengeMethod:           params.Get("code_challenge_method"),
			CodeChallenge:                 params.Get("code_challenge"),
			ResponseMode:                  params.Get("response_mode"),
			MaxAge:                        params.Get("max_age"),
			AcrValuesFromAuthorizeRequest: params.Get("acr_values"),
			State:                         state,
			Nonce:                         params.Get("nonce"),
			UserAgent:                     r.UserAgent(),
			IpAddress:                     authserver_middleware.GetClientIPFromRequest(r),
		}
		// The scope the client asked for, normalized, is what the validator judges below; the scope
		// stored is what the response type can honour of it. They differ only when offline_access is
		// asked for a response type that returns no code, which OIDC Core 11 says to ignore, and
		// validating the request rather than the stored value keeps a request for offline_access
		// alone refused as that, on every response type (#244).
		requestedScope := oidc.NormalizeScope(params.Get("scope"))
		authContext.SetScope(protocolvalidation.ParseResponseType(authContext.ResponseType).ScopeHonoured(requestedScope))
		// The scope as asked for, before any hop narrows Scope to what a user holds. A restart
		// restores Scope from it, so it is written here and nowhere else (#436). It is the honoured
		// scope, so a restart cannot bring offline_access back onto an implicit ceremony.
		authContext.RequestedScope = authContext.Scope

		// Capture OIDC ui_locales (RFC §3.1.2.1) into AuthContext so the
		// RP's stated preference survives every subsequent step of the
		// multi-step auth flow (/auth/pwd → /auth/otp → /auth/consent →
		// /auth/issue). Sanitize first — BCP 47 shape filter, capped at
		// 10 tags / 256 bytes — so we don't bloat the server-side session
		// store this context lives in, which #266 moved out of the cookie,
		// or accept attacker-controlled junk. params covers both query
		// (GET) and form body (POST).
		if uiLocales := i18n.SanitizeUILocales(params.Get("ui_locales")); len(uiLocales) > 0 {
			authContext.UILocales = uiLocales
			// The global locale middleware ran on this request but only sees
			// the query string. If the value came from the form body
			// (typical POST authorize), refine the current request's
			// localizer now so any browser-visible response on this request
			// (error pages, the level1 password page) renders in the chosen
			// locale.
			r = r.WithContext(i18n.WithLocale(r.Context(), true, uiLocales...))
		}

		// The parameters that decide where an answer goes and how it is encoded are checked for
		// repeats first, above everything that could redirect: with two client_ids, redirect_uris,
		// response_types or response_modes there is no single answer to "where does this response
		// go, and in what form", so it goes nowhere and the page answers instead. RFC 6749 4.1.2.1
		// already keeps a bad client_id or redirect_uri off the client for the same reason (#228).
		if name := protocolvalidation.ConflictingParameter(params, authorizeDeliveryParameters); name != "" {
			renderErrorUi(i18n.T(r.Context(), "auth_error.conflicting_parameter.message",
				map[string]any{"parameter": name}), http.StatusBadRequest)
			return
		}

		err = authorizeValidator.ValidateClientAndRedirectURI(r.Context(), &protocolvalidation.ValidateClientAndRedirectURIInput{
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
			var localizedErr *i18n.LocalizedError
			if errors.As(err, &localizedErr) {
				renderErrorUi(localizedErr.Localize(r.Context()), http.StatusOK)
				return
			} else {
				pageRenderer.InternalServerError(w, r, err)
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
		if !protocolvalidation.IsSupportedResponseMode(authContext.ResponseMode) {
			renderErrorUi(i18n.T(r.Context(), "auth_error.unsupported_response_mode.message"),
				http.StatusBadRequest)
			return
		}

		// The client is loaded here, above every answer that can redirect, because every error
		// redirect carries the client it is answering: RFC 9700 4.11.2 hands the trust decision to
		// the server and names the source of the redirect URI as one of its inputs, so the redirect
		// has to know which client asked for it (#108).
		//
		// ValidateClientAndRedirectURI ran directly above and returns an error unless the client
		// exists and is enabled, so the only way this finds nothing is a client deleted between the
		// two lookups, which is answered 500.
		client, err := database.GetClientByClientIdentifier(r.Context(), nil, authContext.ClientId)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
		if client == nil {
			pageRenderer.InternalServerError(w, r, errs.Errorf("client %v not found", authContext.ClientId))
			return
		}

		sessionIdentifier, _ := reqctx.SessionIdentifierFrom(r.Context())

		// Settings are read here, above the session predicate, because the predicate needs the two
		// session lifetimes, and the PKCE and implicit-flow decisions below read them too.
		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			pageRenderer.InternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}

		// The client's max_age as the session predicate applies it. A malformed value is refused
		// by ValidateRequest below with invalid_request, and until then it constrains nothing: it
		// is nil here, so whether the browser holds a valid session is decided as if the client
		// had sent none, which is what makes a session holder answered at once rather than sent to
		// log in for a request that will be refused anyway (#243).
		requestedMaxAge, _ := oidc.ParseMaxAge(authContext.MaxAge)

		// Silence and forced re-authentication are read from the RAW parameter rather than from
		// authContext.Prompt, because a prompt the validator rejects is never assigned there, and
		// OIDC Core 3.1.2.3 forbids interacting with a request that "contains the prompt parameter
		// with the value none" whether or not the rest of the value parsed. So "none login", which
		// ValidatePrompt refuses below, is still a silent request and must not be shown a login
		// page. Case-sensitively, and on whitespace-separated tokens, because OIDC prompt values
		// are case-sensitive: "NONE" and "Login" carry no recognised token and are interactive
		// (#213 decision 5).
		//
		// Every copy is read, not the first: a prompt sent twice with different values is refused
		// below, and a copy asking for none still means nobody may be shown a login page before that
		// refusal reaches the client. One copy, or identical copies, read as they always did (#228).
		rawPrompt := oauth.SplitSpaceDelimited(strings.Join(params["prompt"], " "))
		facts := authorizeRouteFacts{
			requestsSilence: slices.Contains(rawPrompt, "none"),
			requestsLogin:   slices.Contains(rawPrompt, "login"),
		}

		var (
			userSession *models.UserSession
			refusal     *customerrors.ErrorDetail
		)

		// The loads. decideAuthorizeRoute names the next fact it needs, or the route once it needs
		// none, and each fact is loaded here once and only when asked for. That is what keeps the
		// reads what they were: a prompt=none request never reads the session here, because
		// handlePromptNone does its own lookup; a prompt=login request never reads it at all; and a
		// session read that fails answers 500 before any validation runs, rather than being taken
		// for "no session" and turning a database fault into a login prompt for somebody already
		// signed in (#213).
		route, need := decideAuthorizeRoute(facts)
		for need != authorizeFactNone {
			switch need {
			case authorizeFactRedirectEmission:
				// Remembered on the facts, because this request has a second reader: the emitter.
				// Two live reads of a table an administrator can change mid-request are two answers
				// that need not agree, and a no here is what makes answering the client at once
				// safe, so it is carried to the emitter as a floor rather than recomputed there.
				// redirectAlreadyWithheld is where it lands and why.
				emitted := redirectWillBeEmitted(r.Context(), database, client, authContext.RedirectURI,
					authContext.ResponseType, "authorize")
				facts.redirectEmitted = &emitted

			case authorizeFactSessionValidity:
				userSession, err = database.GetUserSessionBySessionIdentifier(r.Context(), nil, sessionIdentifier)
				if err != nil {
					pageRenderer.InternalServerError(w, r, err)
					return
				}
				valid := userSessionManager.HasValidUserSession(userSession,
					settings.UserSessionIdleTimeoutInSeconds, settings.UserSessionMaxLifetimeInSeconds, requestedMaxAge)
				facts.sessionValid = &valid

			case authorizeFactValidation:
				validation, validationErr := validateAuthorizeRequest(r.Context(), authorizeValidator, tokenParser,
					settings, params, &protocolvalidation.ValidateRequestInput{
						ResponseType:         authContext.ResponseType,
						CodeChallengeMethod:  authContext.CodeChallengeMethod,
						CodeChallenge:        authContext.CodeChallenge,
						ResponseMode:         authContext.ResponseMode,
						PKCERequired:         client.IsPKCERequired(settings.PKCERequired),
						ImplicitGrantEnabled: client.IsImplicitGrantEnabled(settings.ImplicitFlowEnabled),
						Scope:                requestedScope,
						Nonce:                authContext.Nonce,
						State:                authContext.State,
						MaxAge:               authContext.MaxAge,
					})
				if validationErr != nil {
					pageRenderer.InternalServerError(w, r, validationErr)
					return
				}
				refusal = validation.refusal
				authContext.Prompt = validation.prompt
				authContext.IdTokenHintSub = validation.hintSubject
				if refusal == nil {
					// The authentication level this ceremony must reach is fixed HERE, at the one
					// point the request has been accepted and before any handler acts on it, and
					// every later handler reads the snapshot instead of the client's row.
					// /auth/level1completed, /auth/level2 and /auth/completed each reload the client
					// and would otherwise recompute the target from whatever default_acr_level says
					// by the time they run, so an administrator editing that row mid-ceremony would
					// retroactively change what the ceremony was required to do: raising it after
					// the step-up decision has been taken stamps an acr naming a second factor that
					// was never performed, and lowering it takes /auth/level2's target outside its
					// switch and answers 500. This is also the last point before handlePromptNone
					// reads the target (#240).
					authContext.SetTargetAcrLevel(client.DefaultAcrLevel)
				}
				facts.validated = true
				facts.refused = refusal != nil
				facts.promptNone = authContext.HasPromptValue("none")
				facts.promptLogin = authContext.HasPromptValue("login")
				facts.hintSubject = authContext.IdTokenHintSub

			case authorizeFactSessionUser:
				// Loaded only here, because the session predicate needs only the session's own
				// timestamps and this is the first point anything reads userSession.User.
				// UserSessionLoadUser answers nil for a nil session.
				err = database.UserSessionLoadUser(r.Context(), nil, userSession)
				if err != nil {
					pageRenderer.InternalServerError(w, r, err)
					return
				}
				facts.sessionUserLoaded = true
				if userSession != nil {
					facts.sessionUserSubject = userSession.User.Subject
					facts.sessionUserEnabled = userSession.User.Enabled
				}
			}
			route, need = decideAuthorizeRoute(facts)
		}

		// answerClientImmediately answers the client with an error now, whoever is at the browser.
		// answerClientWithError clears the context before answering, and derives its own
		// server_error fallback from this same input (#141).
		answerClientImmediately := func(errorDetail *customerrors.ErrorDetail) {
			input := redirectErrorFromAuthContext(&authContext, client,
				errorDetail.GetCode(), errorDetail.GetDescription())

			// Carry a refusal this request has already been given, and only a refusal. The
			// predicate is not read at all on a silent request; that is "nothing has refused yet"
			// and the emitter asks for itself.
			input.redirectAlreadyWithheld = facts.redirectEmitted != nil && !*facts.redirectEmitted

			answerClientWithError(w, r, database, pageRenderer, ceremonyStore, templateFS, input)
		}

		saveAndRedirect := func(path string) {
			err := ceremonyStore.SaveAuthContext(w, r, &authContext)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, baseURL+path, http.StatusFound)
		}

		switch route {
		case authorizeRouteAnswerNow:
			answerClientImmediately(refusal)

		case authorizeRoutePark:
			// Park the error and go and authenticate. It is carried on the auth context, which the
			// session store seals with an AEAD, so it is not a value the visitor can choose, and it
			// is delivered at /auth/level1completed once level 1 credentials are verified.
			// ParkDeferredError conforms and bounds the description before it is stored.
			authContext.ParkDeferredError(refusal.GetCode(), refusal.GetDescription())
			saveAndRedirect("/auth/level1")

		case authorizeRoutePromptNone:
			handlePromptNone(w, r, pageRenderer, ceremonyStore, userSessionManager, database, templateFS, auditLogger, permissionChecker, &authContext, client, sessionIdentifier, settings, baseURL)

		case authorizeRouteForceLogin, authorizeRouteLevel1:
			authContext.AuthState = ceremony.AuthStateRequiresLevel1
			saveAndRedirect("/auth/level1")

		case authorizeRouteDisabledUser:
			auditLogger.Log(r.Context(), audit.AuditUserDisabled, map[string]interface{}{
				"userId": userSession.UserId,
			})

			// Answered at once, never deferred: this path has a valid session, so somebody is
			// already authenticated, and a disabled user sent to the login page could not complete
			// it anyway (#213).
			answerClientImmediately(customerrors.NewErrorDetailWithHttpStatusCode("access_denied", "The user account is disabled.", http.StatusBadRequest))

		case authorizeRouteSSO:
			// The session already completed level 1, so the ceremony goes to /auth/level1completed,
			// where the step-up checks are made.
			authContext.AdoptSession(userSession)
			authContext.AuthState = ceremony.AuthStateLevel1ExistingSession
			saveAndRedirect("/auth/level1completed")
		}
	}
}

// authorizeDeliveryParameters are the parameters that decide where an authorization response goes
// and how it is encoded. A repeat of one with differing values is answered on the refusal page,
// never by redirect (#228).
var authorizeDeliveryParameters = []string{"client_id", "redirect_uri", "response_type", "response_mode"}

// authorizeRequestParameters are every parameter HandleAuthorizeGet reads a value of, and so every
// one whose copies must agree. TestAuthorizeRequestParameters_EveryReadIsListed holds the list to
// the reads, so a parameter read later cannot be left out of the check. request and request_uri
// are absent because they are refused whatever their value (#228).
var authorizeRequestParameters = []string{
	"client_id", "redirect_uri", "response_type", "response_mode",
	"code_challenge", "code_challenge_method", "max_age", "acr_values", "state", "nonce", "scope",
	"ui_locales", "prompt", "id_token_hint",
}

// authorizeParameters answers the authorization request's parameters, the query and a form body
// merged, as the one source HandleAuthorizeGet reads them from, or the error that stopped them
// parsing. A multipart body is read as r.FormValue reads it, so a body that is simply not multipart
// is no error.
func authorizeParameters(r *http.Request) (url.Values, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	// net/http's defaultMaxMemory, the limit r.FormValue parses with.
	//nolint:gosec // G120: bounded by the server's request-body table, as r.FormValue's own parse was; G120 flags every multipart parse
	if err := r.ParseMultipartForm(32 << 20); err != nil && !errors.Is(err, http.ErrNotMultipart) {
		return nil, err
	}
	return r.Form, nil
}

// authorizeValidation is what validateAuthorizeRequest found: the first refusal, or nil when the
// request was accepted, and the two values the validations produce on the way.
type authorizeValidation struct {
	refusal *customerrors.ErrorDetail
	// prompt is the normalized prompt once ValidatePrompt has accepted it, so a request refused
	// later, for its id_token_hint, still carries it into the parked ceremony.
	prompt string
	// hintSubject is the id_token_hint's sub once the hint has been accepted, "" without a hint.
	hintSubject string
}

// validateAuthorizeRequest runs the validations that answer by redirect, in the order the client is
// told about them: parameters repeated with differing values, unsupported request parameters, the
// request itself, the scopes, the prompt, the id_token_hint. The first refusal stops the rest. An error that is not an ErrorDetail
// is a fault inside a validator and is returned for the 500.
//
// These five descriptions stay English and are deliberately NOT localized, unlike the refusal page
// HandleAuthorizeGet renders. They become an error_description, which RFC 6749 4.1.2.1 confines to
// "%x20-21 / %x23-5B / %x5D-7E" and describes as "used to assist the client developer in
// understanding the error that occurred": the audience is the integrator reading a redirect, not
// the visitor, and the character set excludes pt-BR anyway. Translating one would not ship
// non-ASCII, because customerrors.ConformErrorDescription enforces that set at both the parking
// site and the emitter, so an accented sentence would reach the client as a row of question marks
// instead. That is the failure a translation here buys (#213 decision 9).
func validateAuthorizeRequest(ctx context.Context, authorizeValidator AuthorizeValidator, tokenParser TokenParser,
	settings *models.Settings, params url.Values, request *protocolvalidation.ValidateRequestInput) (authorizeValidation, error) {

	var validation authorizeValidation

	// stop ends the validations on err: an ErrorDetail is the refusal, anything else a fault.
	stop := func(err error) (authorizeValidation, error) {
		var errorDetail *customerrors.ErrorDetail
		if errors.As(err, &errorDetail) {
			validation.refusal = errorDetail
			return validation, nil
		}
		return authorizeValidation{}, err
	}

	// First, because a parameter sent twice with differing values makes every later check read a
	// copy the client may not have meant. The delivery parameters were checked above, before the
	// client was loaded; the rest are refused here, so the refusal reaches the client through the
	// deferral path like the four below (#228).
	err := protocolvalidation.ValidateNoConflictingParameters(params, authorizeRequestParameters)
	if err != nil {
		return stop(err)
	}

	err = authorizeValidator.ValidateUnsupportedRequestParameters(&protocolvalidation.ValidateUnsupportedRequestParametersInput{
		HasRequest:    params.Has("request"),
		HasRequestURI: params.Has("request_uri"),
	})
	if err != nil {
		return stop(err)
	}

	err = authorizeValidator.ValidateRequest(request)
	if err != nil {
		return stop(err)
	}

	err = authorizeValidator.ValidateScopes(ctx, request.Scope)
	if err != nil {
		return stop(err)
	}

	normalizedPrompt, err := authorizeValidator.ValidatePrompt(params.Get("prompt"))
	if err != nil {
		return stop(err)
	}
	validation.prompt = normalizedPrompt

	// OIDC Core 1.0 sections 3.1.2.1 and 3.1.2.2; a refused hint is answered to the client like the
	// four above.
	hintSubject, err := validateIdTokenHint(ctx, params.Get("id_token_hint"), tokenParser, settings)
	if err != nil {
		return stop(err)
	}
	validation.hintSubject = hintSubject

	return validation, nil
}

// authorizeFact is a fact decideAuthorizeRoute needs and has not been given. HandleAuthorizeGet
// loads it and asks again.
type authorizeFact int

const (
	// authorizeFactNone means the route is decided.
	authorizeFactNone authorizeFact = iota
	// authorizeFactRedirectEmission is redirectWillBeEmitted's answer for this request.
	authorizeFactRedirectEmission
	// authorizeFactSessionValidity is whether the browser holds a valid session.
	authorizeFactSessionValidity
	// authorizeFactValidation is validateAuthorizeRequest's result.
	authorizeFactValidation
	// authorizeFactSessionUser is the subject and enabled flag of the session's user.
	authorizeFactSessionUser
)

// authorizeRoute is where /auth/authorize sends an authorization request.
type authorizeRoute int

const (
	// authorizeRouteUndecided is returned beside a fact still to load.
	authorizeRouteUndecided authorizeRoute = iota
	// authorizeRouteAnswerNow answers a refused request's client at once.
	authorizeRouteAnswerNow
	// authorizeRoutePark parks a refused request's error and sends the visitor to log in first.
	authorizeRoutePark
	// authorizeRoutePromptNone goes on to silent authentication.
	authorizeRoutePromptNone
	// authorizeRouteForceLogin sends the visitor to log in whatever session it holds: prompt=login,
	// or an id_token_hint naming another user than the session's.
	authorizeRouteForceLogin
	// authorizeRouteDisabledUser answers access_denied for a valid session whose user is disabled.
	authorizeRouteDisabledUser
	// authorizeRouteSSO reuses the valid session.
	authorizeRouteSSO
	// authorizeRouteLevel1 sends a visitor with no valid session to log in.
	authorizeRouteLevel1
)

// authorizeRouteFacts is what decideAuthorizeRoute decides from. The raw prompt tokens are known
// from the start; every other fact is unknown until HandleAuthorizeGet has loaded it, a nil pointer
// or a false loaded flag.
type authorizeRouteFacts struct {
	// requestsSilence and requestsLogin are the raw prompt parameter's none and login tokens.
	requestsSilence bool
	requestsLogin   bool

	redirectEmitted *bool
	sessionValid    *bool

	// validated is set once validateAuthorizeRequest has run; the four after it are its result.
	validated   bool
	refused     bool
	promptNone  bool
	promptLogin bool
	hintSubject string

	// sessionUserLoaded is set once the session's user has been loaded; the two after it are ""
	// and false when there is no session.
	sessionUserLoaded  bool
	sessionUserSubject string
	sessionUserEnabled bool
}

// decideAuthorizeRoute decides where an authorization request goes, or names the next fact it needs
// to decide that. It asks for each fact at the point the handler has always read it, and only when
// the answer turns on it, so a path makes the reads it always made and no others.
//
// Whether a refused request is answered at once or parked behind a login is the first question,
// asked before the validations run: RFC 9700 4.11.2, "The authorization server MUST always
// authenticate the user first and, with the exception of the silent authentication use case, prompt
// the user for credentials when needed, before redirecting the user." Without it, one link sent to
// a logged-out browser makes this server redirect it to a host the client chose, which is attack 1
// in that section verbatim. Authentication is required before a REDIRECT, and only before a
// redirect, so a refusal is answered at once on any of three clauses:
//
//   - requestsSilence: OIDC Core 3.1.2.3 says the server "MUST NOT interact with the End-User" when
//     prompt=none, which is the exception RFC 9700 names.
//   - a withheld redirect: no redirect leaves this server, so the requirement that governs redirects
//     has nothing to say and the visitor reaches the same refusal page with or without a login
//     (#108's and #122's guards, #213 decision 8).
//   - a valid session without login: a session holder has authenticated already, unless the client
//     asked not to be answered on the strength of one (#213 decision 4).
//
// The clause that reads nothing is asked first, and the session only when the redirect would be
// emitted, so each read is reached only when it decides something. The session read is also the
// one the ordinary path below needs, so a request reads it at most once.
func decideAuthorizeRoute(f authorizeRouteFacts) (authorizeRoute, authorizeFact) {
	if !f.requestsSilence {
		if f.redirectEmitted == nil {
			return authorizeRouteUndecided, authorizeFactRedirectEmission
		}
		if *f.redirectEmitted && !f.requestsLogin && f.sessionValid == nil {
			return authorizeRouteUndecided, authorizeFactSessionValidity
		}
	}

	if !f.validated {
		return authorizeRouteUndecided, authorizeFactValidation
	}

	if f.refused {
		answerNow := f.requestsSilence || !*f.redirectEmitted || (!f.requestsLogin && *f.sessionValid)
		if answerNow {
			return authorizeRouteAnswerNow, authorizeFactNone
		}
		return authorizeRoutePark, authorizeFactNone
	}

	// The validated prompt from here, which for an accepted request holds the same tokens as the raw
	// one.
	if f.promptNone {
		return authorizeRoutePromptNone, authorizeFactNone
	}
	// prompt=login skips the session entirely.
	if f.promptLogin {
		return authorizeRouteForceLogin, authorizeFactNone
	}

	if f.sessionValid == nil {
		return authorizeRouteUndecided, authorizeFactSessionValidity
	}
	if !f.sessionUserLoaded {
		return authorizeRouteUndecided, authorizeFactSessionUser
	}

	if !*f.sessionValid {
		return authorizeRouteLevel1, authorizeFactNone
	}
	// OIDC Core 3.1.2.1: a hint naming a different user than the session's forces
	// re-authentication rather than SSO.
	if f.hintSubject != "" && f.sessionUserSubject != f.hintSubject {
		return authorizeRouteForceLogin, authorizeFactNone
	}
	if !f.sessionUserEnabled {
		return authorizeRouteDisabledUser, authorizeFactNone
	}
	return authorizeRouteSSO, authorizeFactNone
}

// handlePromptNone handles the OIDC prompt=none flow for silent authentication. It performs all
// necessary checks without displaying any UI and either answers the client with an error when
// silent authentication is not possible, or goes on to issue a code silently.
func handlePromptNone(w http.ResponseWriter, r *http.Request, pageRenderer PageRenderer, ceremonyStore CeremonyStore, userSessionManager UserSessionManager, database authorizeDatabase, templateFS fs.FS, auditLogger AuditLogger, permissionChecker PermissionChecker, authContext *ceremony.AuthContext, client *models.Client, sessionIdentifier string, settings *models.Settings, baseURL string) {
	// Helper to clear the auth context and then redirect with error. The clear-then-answer
	// sequence and its server_error fallback live in answerClientWithError, which derives that
	// fallback from the input handed to it, so this path keeps answering from the stored ceremony
	// exactly as it did when the sequence was written out here (#141).
	//
	// On the silent path the fallback is worth naming: a silent-renewal iframe reads server_error
	// as "retry later" rather than "start an interactive login", which on a genuine server fault
	// is the accurate instruction of the two.
	redirectWithError := func(errorCode string, errorDescription string) {
		answerClientWithError(w, r, database, pageRenderer, ceremonyStore, templateFS,
			redirectErrorFromAuthContext(authContext, client, errorCode, errorDescription))
	}

	idleTimeout, maxLifetime := settings.UserSessionIdleTimeoutInSeconds, settings.UserSessionMaxLifetimeInSeconds
	requestedMaxAge := authContext.RequestedMaxAge()
	facts := silentAuthenticationFacts{
		maxAgeRequested: requestedMaxAge != nil,
		hintSubject:     authContext.IdTokenHintSub,
		target:          authContext.GetTargetAcrLevel(client.DefaultAcrLevel),
		consentRequired: client.ConsentRequired,
	}

	// The loads, each made once and only when decideSilentAuthentication asks for it, so a refusal
	// reads nothing past the check that refused.
	answer, need := decideSilentAuthentication(facts)
	for need != silentFactNone {
		switch need {
		case silentFactSession:
			userSession, err := database.GetUserSessionBySessionIdentifier(r.Context(), nil, sessionIdentifier)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
				return
			}
			if userSession != nil {
				err = database.UserSessionLoadUser(r.Context(), nil, userSession)
				if err != nil {
					pageRenderer.InternalServerError(w, r, err)
					return
				}
			}
			facts.sessionLoaded = true
			facts.session = userSession

		case silentFactValidity:
			valid := userSessionManager.HasValidUserSession(facts.session, idleTimeout, maxLifetime, requestedMaxAge)
			facts.sessionValid = &valid

		case silentFactValidityWithoutMaxAge:
			valid := userSessionManager.HasValidUserSession(facts.session, idleTimeout, maxLifetime, nil)
			facts.sessionValidWithoutMaxAge = &valid

		case silentFactEffectiveScope:
			effectiveScope, err := permissionChecker.FilterOutScopesWhereUserIsNotAuthorized(r.Context(),
				authContext.Scope, &facts.session.User)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
				return
			}
			facts.effectiveScope = &effectiveScope

		case silentFactConsent:
			consent, err := database.GetConsentByUserIdAndClientId(r.Context(), nil, facts.session.User.Id, client.Id)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
				return
			}
			facts.consentLoaded = true
			facts.consent = consent
		}
		answer, need = decideSilentAuthentication(facts)
	}

	if answer.errorCode != "" {
		if answer.userDisabled {
			auditLogger.Log(r.Context(), audit.AuditUserDisabled, map[string]interface{}{
				"userId": facts.session.UserId,
			})
		}
		redirectWithError(answer.errorCode, answer.errorDescription)
		return
	}

	// All checks passed: the ceremony reuses the session and goes on to issue a code silently.
	userSession := facts.session
	authContext.AdoptSession(userSession)
	authContext.SetScope(*facts.effectiveScope)

	// Preserve the original session's auth_time for the token
	if userSession.AuthTime.IsZero() {
		// Fallback for legacy sessions without AuthTime
		authContext.AuthenticatedAt = &userSession.Started
	} else {
		authContext.AuthenticatedAt = &userSession.AuthTime
	}

	// Set ACR level (takes max of target and session ACR)
	err := authContext.SetAcrLevel(facts.target, userSession)
	if err != nil {
		pageRenderer.InternalServerError(w, r, err)
		return
	}

	// Bump the user session to update LastAccessed time
	_, err = userSessionManager.BumpUserSession(r.Context(), sessionIdentifier, client.Id,
		authContext.AuthMethods, authContext.AcrLevel, authserver_middleware.GetClientIPFromRequest(r))
	if err != nil {
		pageRenderer.InternalServerError(w, r, err)
		return
	}

	auditLogger.Log(r.Context(), audit.AuditBumpedUserSession, map[string]interface{}{
		"userId":   authContext.UserId,
		"clientId": client.Id,
	})

	// Ready to issue code
	authContext.AuthState = ceremony.AuthStateReadyToIssueCode
	err = ceremonyStore.SaveAuthContext(w, r, authContext)
	if err != nil {
		pageRenderer.InternalServerError(w, r, err)
		return
	}

	http.Redirect(w, r, baseURL+"/auth/issue", http.StatusFound)
}

// silentFact is a fact decideSilentAuthentication needs and has not been given. handlePromptNone
// loads it and asks again.
type silentFact int

const (
	// silentFactNone means the answer is decided.
	silentFactNone silentFact = iota
	// silentFactSession is the browser's session with its user, or none.
	silentFactSession
	// silentFactValidity is whether the session is valid with the request's max_age applied.
	silentFactValidity
	// silentFactValidityWithoutMaxAge is whether it would be valid without max_age.
	silentFactValidityWithoutMaxAge
	// silentFactEffectiveScope is the requested scope narrowed to what the user holds.
	silentFactEffectiveScope
	// silentFactConsent is the user's consent to this client, or none.
	silentFactConsent
)

// silentAuthenticationFacts is what decideSilentAuthentication decides from. The first four are
// known from the ceremony and its client; every other fact is unknown until handlePromptNone has
// loaded it, a nil pointer or a false loaded flag.
type silentAuthenticationFacts struct {
	maxAgeRequested bool
	hintSubject     string
	target          models.AcrLevel
	// consentRequired is the client's ConsentRequired.
	consentRequired bool

	// sessionLoaded is set once the session has been looked up; session is nil when there is none,
	// and otherwise carries its User.
	sessionLoaded             bool
	session                   *models.UserSession
	sessionValid              *bool
	sessionValidWithoutMaxAge *bool
	effectiveScope            *string
	// consentLoaded is set once the consent has been looked up; consent is nil when there is none.
	consentLoaded bool
	consent       *models.UserConsent
}

// silentAuthenticationAnswer is decideSilentAuthentication's answer: an error for the client, or
// an empty errorCode to proceed.
type silentAuthenticationAnswer struct {
	errorCode        string
	errorDescription string
	// userDisabled says the refusal is for a disabled account, which is audited.
	userDisabled bool
}

// decideSilentAuthentication decides whether a prompt=none request can be answered silently, or
// names the next fact it needs to decide that. The checks run in a fixed order and the first that
// fails is the answer, so each fact is asked for only once every check before it has passed:
//
//  1. a session exists;
//  2. it is valid, and when it is not only because of max_age, the answer says so;
//  3. its user is enabled;
//  4. an id_token_hint names that user (OIDC Core 3.1.2.1: "MUST NOT reply with an ID Token for a
//     different user");
//  5. the step-up rule asks for no higher level (an unknown session ACR is insufficient);
//  6. level2_mandatory has an authenticator to satisfy it;
//  7. the user's authenticator has not changed since the session last answered the level 2
//     question, when the target asks it. A reader only: it refuses and promotes nothing, because no
//     interaction happened, which is what makes an identical second prompt=none request get the
//     identical answer (#242 decision 1). Steps 5 and 7 are the step-up rule's two answers, and
//     step 6 sits between them so the order of the refusals is kept;
//  8. the user holds at least one requested scope;
//  9. when the client requires consent or offline_access is asked for, a consent covers every
//     scope.
func decideSilentAuthentication(f silentAuthenticationFacts) (silentAuthenticationAnswer, silentFact) {
	refuse := func(code, description string) (silentAuthenticationAnswer, silentFact) {
		return silentAuthenticationAnswer{errorCode: code, errorDescription: description}, silentFactNone
	}

	if !f.sessionLoaded {
		return silentAuthenticationAnswer{}, silentFactSession
	}
	if f.session == nil {
		return refuse(oidc.ErrorLoginRequired, "User authentication is required")
	}

	if f.sessionValid == nil {
		return silentAuthenticationAnswer{}, silentFactValidity
	}
	if !*f.sessionValid {
		if f.maxAgeRequested {
			if f.sessionValidWithoutMaxAge == nil {
				return silentAuthenticationAnswer{}, silentFactValidityWithoutMaxAge
			}
			if *f.sessionValidWithoutMaxAge {
				return refuse(oidc.ErrorLoginRequired, "Session age exceeds max_age")
			}
		}
		return refuse(oidc.ErrorLoginRequired, "User session has expired")
	}

	user := &f.session.User
	if !user.Enabled {
		return silentAuthenticationAnswer{
			errorCode:        "access_denied",
			errorDescription: "The user account is disabled",
			userDisabled:     true,
		}, silentFactNone
	}

	if f.hintSubject != "" && user.Subject != f.hintSubject {
		return refuse(oidc.ErrorLoginRequired, "The current session user does not match the id_token_hint")
	}

	stepUp, stepUpErr := ceremony.StepUpOwed(f.target, f.session)
	if stepUpErr != nil || stepUp == ceremony.StepUpLevel {
		return refuse(oidc.ErrorInteractionRequired, "Higher authentication level required")
	}
	if f.target == models.AcrLevel2Mandatory && !user.OTPEnabled {
		return refuse(oidc.ErrorInteractionRequired, "Additional authentication setup required")
	}
	if stepUp == ceremony.StepUpOtpConfigChanged {
		return refuse(oidc.ErrorInteractionRequired, "Authentication configuration has changed")
	}

	if f.effectiveScope == nil {
		return silentAuthenticationAnswer{}, silentFactEffectiveScope
	}
	if len(strings.TrimSpace(*f.effectiveScope)) == 0 {
		return refuse("access_denied", "The user is not authorized to access any of the requested scopes")
	}

	if f.consentRequired || oidc.HasOfflineAccessScope(*f.effectiveScope) {
		if !f.consentLoaded {
			return silentAuthenticationAnswer{}, silentFactConsent
		}
		if f.consent == nil {
			return refuse(oidc.ErrorConsentRequired, "User consent is required")
		}
		for _, scope := range oidc.SplitScope(*f.effectiveScope) {
			if !f.consent.HasScope(scope) {
				return refuse(oidc.ErrorConsentRequired, "Additional consent is required")
			}
		}
	}

	return silentAuthenticationAnswer{}, silentFactNone
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
// come from the ceremony, which is where every error redirect takes them from. At /auth/authorize
// that is the literal HandleAuthorizeGet has just built, which holds the four as the request sent
// them before anything is validated, so an error arising there answers what the request carried.
func redirectErrorFromAuthContext(authContext *ceremony.AuthContext, client *models.Client,
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
func answerClientWithError(w http.ResponseWriter, r *http.Request, database authorizeDatabase,
	pageRenderer PageRenderer, ceremonyStore CeremonyStore, templateFS fs.FS, input redirectErrorInput) {

	err := ceremonyStore.ClearAuthContext(w, r)
	if err != nil {
		// The clear failed, so Save wrote no cookie and the browser still holds the auth context.
		slog.ErrorContext(r.Context(), "unable to clear the auth context, answering the client with server_error",
			"error", err)

		fallback := input
		fallback.code = "server_error"
		fallback.description = "Internal server error"

		err = redirToClientWithError(w, r, database, pageRenderer, templateFS, fallback)
		if err != nil {
			// Nowhere left to send the client, so the 500 is the last resort here.
			pageRenderer.InternalServerError(w, r, err)
		}
		return
	}

	err = redirToClientWithError(w, r, database, pageRenderer, templateFS, input)
	if err != nil {
		pageRenderer.InternalServerError(w, r, err)
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
func clientProvenance(ctx context.Context, database authorizeDatabase, clientIdentifier string) *models.Client {
	client, err := database.GetClientByClientIdentifier(ctx, nil, clientIdentifier)
	if err != nil {
		slog.ErrorContext(ctx, "unable to load the client while answering it with an error, treating its provenance as unresolved",
			"client_identifier", clientIdentifier, "error", err)
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
// test protocolvalidation.ValidateClientAndRedirectURI and /auth/issue apply, so exactly one token equal to
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
func redirectWillBeEmitted(ctx context.Context, database authorizeDatabase, client *models.Client, redirectURI string,
	responseType string, site string) bool {

	if client == nil || client.CreatedViaDCR {
		return false
	}

	if err := checkRedirectURIEmittable(ctx, site, redirectURI); err != nil {
		return false
	}

	redirectURIs, err := database.GetRedirectURIsByClientId(ctx, nil, client.Id)
	if err != nil {
		// The client identifier is a bounded stored value and is safe to log; the URI is not,
		// matching checkRedirectURIEmittable, which records where a refusal happened and
		// deliberately never records the value (#159).
		slog.ErrorContext(ctx, "unable to load the client's redirect URIs while answering it with an error, withholding the redirect",
			"client_identifier", client.ClientIdentifier, "site", site, "error", err)
		return false
	}

	registered := make([]string, 0, len(redirectURIs))
	for _, uri := range redirectURIs {
		registered = append(registered, uri.URI)
	}

	// IsCodeOnly, for the reason stated at protocolvalidation.ValidateClientAndRedirectURI: only the
	// exact type "code" buys an arbitrary loopback port, and the parser reports "code code" and
	// "code foo" as what they are (#244).
	allowLoopbackPortFlexibility := protocolvalidation.ParseResponseType(responseType).IsCodeOnly()

	if !urlutil.RedirectURIIsRegistered(registered, redirectURI, allowLoopbackPortFlexibility) {
		slog.WarnContext(ctx, "the redirect URI this client would be answered at is no longer registered on it, so the redirect is withheld",
			"client_identifier", client.ClientIdentifier, "site", site)
		return false
	}

	return true
}

func redirToClientWithError(w http.ResponseWriter, r *http.Request, database authorizeDatabase,
	pageRenderer PageRenderer, templateFS fs.FS, input redirectErrorInput) error {

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
		!redirectWillBeEmitted(r.Context(), database, input.client, input.redirectURI, input.responseType,
			"redirToClientWithError") {
		return renderRedirectBlocked(pageRenderer, w, r, input)
	}

	// The description becomes an error_description on the wire from here down, so it is conformed to
	// RFC 6749 Appendix A.8's NQSCHAR once, here, and every response mode reads the conformed value
	// from the parameter list below. Descriptions interpolate request text, so an emoji or a Cyrillic
	// word in a rejected scope otherwise puts a byte the RFC forbids into a protocol parameter (#213).
	//
	// This function rather than answerClientWithError, which wraps it: a wrapper cannot cover a caller
	// that reaches this emitter without going through it.
	//
	// Below the redirect guard, deliberately. renderRedirectBlocked above puts the description on an
	// HTML page, which is a user interface and not a protocol parameter, so the interstitial keeps the
	// text as the validator wrote it and only what actually leaves as a redirect is filtered.
	description := customerrors.ConformErrorDescription(input.description)

	// Per RFC 6749 4.2.2.1 and OIDC Core 3.2.2.5: implicit flow errors MUST be returned in fragment
	// Determine if this is an implicit flow by checking response_type
	rtInfo := protocolvalidation.ParseResponseType(input.responseType)
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

	return writeAuthorizationResponse(w, r, templateFS, effectiveResponseMode, input.redirectURI, params)
}
