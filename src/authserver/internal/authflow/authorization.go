package authflow

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/url"
	"slices"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/authorizerequest"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/signingkeys"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/oauth"
)

// Every parameter /auth/authorize reads is read in this file, through the url.Values named params:
// TestAuthorizeRequestParameters_EveryReadIsListed and TestAuthorizeParkedParameters_CoverEveryRead
// hold the two lists below to those reads, so a parameter read anywhere else escapes both.

// httpStatusBadRequest is net/http's StatusBadRequest, which this package does not import, for the
// error details the validations below build.
const httpStatusBadRequest = 400

// authorizeDeliveryParameters are the parameters that decide where an authorization response goes
// and how it is encoded. A repeat of one is answered on the refusal page, never by redirect (#228).
var authorizeDeliveryParameters = []string{"client_id", "redirect_uri", "response_type", "response_mode"}

// authorizeRequestParameters are every parameter Authorization.Run reads a value of, and so every
// one that may arrive once. TestAuthorizeRequestParameters_EveryReadIsListed holds the list to the
// reads. request and request_uri are absent because they are refused whatever their value (#228).
var authorizeRequestParameters = []string{
	"client_id", "redirect_uri", "response_type", "response_mode",
	"code_challenge", "code_challenge_method", "max_age", "acr_values", "state", "nonce", "scope",
	"ui_locales", "prompt", "id_token_hint",
}

// AuthorizeDeliveryParameters answers a copy of the parameters whose repeat is answered on the
// refusal page. Exported for the handler tests that send each one twice.
func AuthorizeDeliveryParameters() []string {
	return slices.Clone(authorizeDeliveryParameters)
}

// AuthorizeUILocales is the ui_locales hint an authorization request states, sanitized: BCP 47
// shaped, and capped at 10 tags and 256 bytes, so attacker-chosen junk neither reaches the localizer
// nor bloats the server-side session store the auth context lives in (#266). The handler refines the
// request's localizer to it, and Authorization.Run stores it on the ceremony, so the relying party's
// stated preference (OIDC Core 1.0 section 3.1.2.1) holds on every step after this one.
func AuthorizeUILocales(params url.Values) []string {
	return i18n.SanitizeUILocales(params.Get("ui_locales"))
}

// authorizationDatabase is what Authorization reads: the request a POST parked, the client, and the
// browser's user session with its user. The client's redirect URIs are the client-error
// responder's to read, and what a prompt=none request reads is SilentAuthentication's.
// data.Database satisfies it.
type authorizationDatabase interface {
	authorizerequest.Consuming
	GetClientByClientIdentifier(ctx context.Context, tx *sql.Tx, clientIdentifier string) (*record.Client, error)
	GetUserSessionBySessionIdentifier(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (*record.UserSession, error)
	UserSessionLoadUser(ctx context.Context, tx *sql.Tx, userSession *record.UserSession) error
}

// authorizeAddressValidator is the check that an authorization request names a client and a
// redirect URI an answer may be addressed to. *protocolvalidation.AuthorizeValidator satisfies it.
type authorizeAddressValidator interface {
	ValidateClientAndRedirectURI(ctx context.Context, input *protocolvalidation.ValidateClientAndRedirectURIInput) error
}

// authorizeRequestValidator is every validation of an authorization request.
// *protocolvalidation.AuthorizeValidator satisfies it.
type authorizeRequestValidator interface {
	authorizeAddressValidator
	ValidateUnsupportedRequestParameters(input *protocolvalidation.ValidateUnsupportedRequestParametersInput) error
	ValidateRequest(input *protocolvalidation.ValidateRequestInput) error
	ValidateScopes(ctx context.Context, scope string) error
	ValidatePrompt(prompt string) (string, error)
}

// idTokenHintParser verifies an id_token_hint's signature. *signingkeys.TokenParser satisfies it.
type idTokenHintParser interface {
	DecodeAndValidateTokenString(ctx context.Context, token string, withExpirationCheck bool) (*oauth.JwtToken, error)
}

// redirectEmission answers whether an error response to this client, at this redirect URI, would
// leave the server as a redirect rather than be withheld. site names the caller for the log line.
// handlers.ClientErrorResponder satisfies it: its gates are the same ones that decide when the
// answer is written, so the question asked here and the answer written there cannot drift apart.
type redirectEmission interface {
	RedirectWillBeEmitted(ctx context.Context, client *record.Client, redirectURI string, responseType string,
		site string) bool
}

// authorizeBrowser is the one browser-session write /auth/authorize makes. It starts a ceremony
// beside the ones the browser session holds, pushing out the least recently written when it holds
// ceremony.MaxHeldCeremonies already, and leaves every other alone (#246). A request answered at
// once with an error writes nothing, so it leaves every sign-in in progress alone. The handler's
// per-request adapter satisfies it.
type authorizeBrowser interface {
	AddAuthContext(authContext *ceremony.AuthContext) error
}

// Authorization is GET /auth/authorize: it accepts or refuses an authorization request, starts the
// ceremony that answers it, and routes that ceremony to the login, to the browser's session, or to
// silent authentication. It is the one place an AuthContext is created and the one place a request
// field is written (TestRequestFields_WrittenOnlyAtAuthorize). The route table builds one.
type Authorization struct {
	database             authorizationDatabase
	sessions             sessionValidity
	validator            authorizeRequestValidator
	tokenParser          idTokenHintParser
	redirects            redirectEmission
	auditLogger          auditLogger
	silentAuthentication *SilentAuthentication
}

// NewAuthorization builds the operation over the database, the session validity check, the
// request's validator, the id_token_hint's parser, the client-error responder's emission gate, the
// audit log, and the operation that answers a prompt=none request.
func NewAuthorization(database authorizationDatabase, sessions sessionValidity, validator authorizeRequestValidator,
	tokenParser idTokenHintParser, redirects redirectEmission, auditLogger auditLogger,
	silentAuthentication *SilentAuthentication) *Authorization {

	return &Authorization{database: database, sessions: sessions, validator: validator, tokenParser: tokenParser,
		redirects: redirects, auditLogger: auditLogger, silentAuthentication: silentAuthentication}
}

// AuthorizePageRefusal is a request /auth/authorize answers on its refusal page and never by
// redirect, because the answer has nowhere safe to go or cannot be encoded. The handler chooses the
// message and the status from Reason.
type AuthorizePageRefusal struct {
	Reason AuthorizePageRefusalReason
	// Parameter is the repeated parameter, for AuthorizePageRefusalRepeatedParameter.
	Parameter string
	// ClientRefusal is the validator's refusal of the client_id or redirect_uri, for
	// AuthorizePageRefusalClientOrRedirectURI, localized when the page is rendered.
	ClientRefusal *i18n.LocalizedError
	// ImplicitFlow is whether the request asks for tokens rather than a code, for
	// AuthorizePageRefusalFormPostUnreachable, so the page names the modes that request may use.
	ImplicitFlow bool
}

// AuthorizePageRefusalReason is why a request is answered on the refusal page.
type AuthorizePageRefusalReason int

const (
	// AuthorizePageRefusalUnusableHandle is a request_handle beside another authorization
	// parameter, sent twice, or naming no request a POST parked that is still good (#246).
	AuthorizePageRefusalUnusableHandle AuthorizePageRefusalReason = iota + 1
	// AuthorizePageRefusalRepeatedParameter is a delivery parameter sent more than once (#228).
	AuthorizePageRefusalRepeatedParameter
	// AuthorizePageRefusalClientOrRedirectURI is a client_id or redirect_uri that names nowhere an
	// answer may go (RFC 6749 section 4.1.2.1).
	AuthorizePageRefusalClientOrRedirectURI
	// AuthorizePageRefusalUnsupportedResponseMode is a response_mode this server cannot encode an
	// answer in (OIDC Core 1.0 section 3.1.2.6).
	AuthorizePageRefusalUnsupportedResponseMode
	// AuthorizePageRefusalFormPostUnreachable is response_mode=form_post with a redirect URI whose
	// scheme is neither http nor https, which no form can post to (#121).
	AuthorizePageRefusalFormPostUnreachable
)

// AuthorizeArrival is what HandleAuthorizeGet reads off the HTTP request beside its parameters.
type AuthorizeArrival struct {
	// RequestId is the request's id, which the client and redirect URI check logs under.
	RequestId string
	// SessionIdentifier is the browser session's identifier, "" when the browser holds none.
	SessionIdentifier string
	UserAgent         string
	// IpAddress is the browser's address as the real-IP middleware resolved it.
	IpAddress string
}

// AuthorizationResult is what Authorization.Run did. PageRefusal set means nothing else is: no
// ceremony was started and nothing was written. Otherwise AuthContext is the ceremony this request
// started, and exactly one of ClientRefusal and NextStep is set.
type AuthorizationResult struct {
	// PageRefusal is the refusal page the handler answers with.
	PageRefusal *AuthorizePageRefusal

	// AuthContext is the ceremony this request started, from which the handler builds the error
	// response or the step redirect.
	AuthContext *ceremony.AuthContext

	// ClientRefusal is the error the client is answered with now. The ceremony ends with it: it was
	// never stored, and whatever sign-in the browser holds is left as it was (#246).
	ClientRefusal *ClientError
	// RedirectWithheld says the client-error responder's gates already answered that a redirect
	// to this client would be withheld. The responder takes it as a floor and asks no more
	// permissively when it writes the answer: two live reads of a table an administrator can change
	// mid-request need not agree, and the first no is what made answering at once safe.
	RedirectWithheld bool

	// NextStep is the route the ceremony was saved to go to: /auth/level1, /auth/level1completed or
	// /auth/issue.
	NextStep string
	// SaveErr is the save's failure. The handler redirects to NextStep only when it is nil, and
	// answers 500 otherwise.
	SaveErr error
}

// ResolveParked answers the parameters an authorization request runs from: params as they are when
// they name no request_handle, and what a POST parked (AuthorizationParking) when they do. A GET carrying a
// handle is the second half of a POST, and the ceremony runs from the parked request exactly as it
// would from the same parameters in the query (#246). It answers a refusal when the handle is
// unusable, and an error when the parked request could not be read.
//
// A handle beside any other authorization parameter is refused and never merged: which of the two a
// parameter came from would decide what the ceremony did, and no request this server issues looks
// like that. A handle that is unknown, expired, already consumed or malformed gets one answer, so
// the page says nothing about which it was.
func (o *Authorization) ResolveParked(ctx context.Context, params url.Values) (url.Values, *AuthorizePageRefusal, error) {
	if !params.Has(authorizerequest.HandleParameter) {
		return params, nil, nil
	}

	refusal := &AuthorizePageRefusal{Reason: AuthorizePageRefusalUnusableHandle}

	// A handle sent twice is refused like any other repeated parameter, whether or not the copies
	// agree (#228).
	if protocolvalidation.RepeatedParameter(params, []string{authorizerequest.HandleParameter}) != "" {
		return nil, refusal, nil
	}
	for _, name := range authorizeParkedParameters {
		if params.Has(name) {
			return nil, refusal, nil
		}
	}

	form, found, err := authorizerequest.Consume(ctx, o.database, params.Get(authorizerequest.HandleParameter))
	if err != nil {
		return nil, nil, err
	}
	if !found {
		return nil, refusal, nil
	}
	return form, nil, nil
}

// Run, in order:
//
//  1. Creates the ceremony from params: a new ceremony id, every request field, the scope the
//     response type honours, and the ui_locales hint. Nothing saves it until a route below has
//     given it a state, so a request refused on the page writes nothing and a sign-in in progress
//     in the same browser survives a malformed link (#436).
//  2. Answers on the refusal page a request with a repeated delivery parameter, a client_id or
//     redirect_uri an answer may not be addressed to, or a response_mode this server cannot encode
//     (refuseUnaddressableAuthorizeRequest).
//  3. Loads the client, above every answer that can redirect, since each error redirect carries the
//     client it answers (RFC 9700 section 4.11.2, #108).
//  4. Decides the route (decideAuthorizeRoute), loading each fact it asks for, once: the
//     responder's emission gate, the browser's session and its validity, the validations
//     (validateAuthorizeRequest), and the session's user. Once the request is accepted, the
//     ceremony's target ACR is fixed from the client (SetTargetAcrLevel). A failed read is returned
//     as an error, never taken for "no session".
//  5. Acts on the route:
//     - answer now: records a refusal of administrative scopes and returns ClientRefusal, writing
//     nothing;
//     - park: records a refusal of administrative scopes, parks the error on the ceremony (#213)
//     and saves it in requires_level_1, for /auth/level1;
//     - silence: SilentAuthentication answers the request;
//     - login, forced or for want of a valid session: saves the ceremony in requires_level_1, for
//     /auth/level1;
//     - a disabled user: records user_disabled and returns ClientRefusal with access_denied,
//     writing nothing;
//     - SSO: adopts the session and saves the ceremony in level1_existing_session, for
//     /auth/level1completed.
//
// settings are the request's. params are the ones ResolveParked answered, and ctx carries the
// localizer the handler refined to their ui_locales.
func (o *Authorization) Run(ctx context.Context, browser authorizeBrowser, settings *record.Settings,
	params url.Values, arrival AuthorizeArrival) (AuthorizationResult, error) {

	// RFC 6749 4.1.2 returns state as "the exact value received from the client". A repeated state
	// was not received as one value, whether or not its copies agree, so the ceremony carries none,
	// and the invalid_request that refuses the request reaches the client without one: state is
	// emitted only when exactly one value was received (#146, #228).
	state := params.Get("state")
	if protocolvalidation.RepeatedParameter(params, []string{"state"}) != "" {
		state = ""
	}

	// The ceremony id is minted here and nowhere else. Every form the ceremony renders carries it and
	// every redirect between its steps names it, so a page left open in another tab acts on its own
	// request and on no other the browser holds (#79, #246).
	authContext := &ceremony.AuthContext{
		CeremonyId:                    ceremony.NewId(),
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
		UserAgent:                     arrival.UserAgent,
		IpAddress:                     arrival.IpAddress,
	}
	// requestedScope, the scope asked for and normalized, is what the validations judge; the scope
	// stored is what the response type honours of it. They differ only when offline_access is asked
	// for a response type that returns no code, which OIDC Core 1.0 section 11 says to ignore, and
	// validating the request rather than the stored value keeps a request for offline_access alone
	// refused as that on every response type (#244).
	requestedScope := oidc.NormalizeScope(params.Get("scope"))
	authContext.SetScope(protocolvalidation.ParseResponseType(authContext.ResponseType).ScopeHonoured(requestedScope))
	// The request's scope, which a restart puts Scope back from (#436). It is the honoured scope, so a
	// restart cannot bring offline_access back onto an implicit ceremony.
	authContext.RequestedScope = authContext.Scope
	if uiLocales := AuthorizeUILocales(params); len(uiLocales) > 0 {
		authContext.UILocales = uiLocales
	}

	pageRefusal, err := refuseUnaddressableAuthorizeRequest(ctx, o.validator, arrival.RequestId, params)
	if err != nil {
		return AuthorizationResult{}, err
	}
	if pageRefusal != nil {
		return AuthorizationResult{PageRefusal: pageRefusal}, nil
	}

	// The address check above refuses a client that does not exist or is disabled, so the only way
	// this finds nothing is a client deleted between the two lookups.
	client, err := o.database.GetClientByClientIdentifier(ctx, nil, authContext.ClientId)
	if err != nil {
		return AuthorizationResult{}, err
	}
	if client == nil {
		return AuthorizationResult{}, errs.Errorf("client %v not found", authContext.ClientId)
	}

	// The client's max_age as the session predicate applies it. A malformed value is refused by
	// ValidateRequest with invalid_request, and until then it is nil and constrains nothing, so a
	// session holder is answered at once rather than sent to log in for a request that will be
	// refused anyway (#243).
	requestedMaxAge, _ := oidc.ParseMaxAge(authContext.MaxAge)

	// Silence and forced re-authentication are read from the raw parameter, every copy of it, because
	// a prompt the validator refuses is never assigned to the ceremony, and OIDC Core 1.0 section
	// 3.1.2.3 forbids interacting with a request that "contains the prompt parameter with the value
	// none" whether or not the rest of the value parsed: "none login", refused by ValidatePrompt, is
	// still silent (#213 decision 5, #228). Tokens are case-sensitive and split on spaces alone, so
	// "NONE" asks for nothing and "none<TAB>login" for neither (#244).
	rawPrompt := oauth.SplitSpaceDelimited(strings.Join(params["prompt"], " "))
	facts := authorizeRouteFacts{
		requestsSilence: slices.Contains(rawPrompt, "none"),
		requestsLogin:   slices.Contains(rawPrompt, "login"),
	}

	var (
		userSession *record.UserSession
		refusal     *oauth.ErrorDetail
		// refusedAdministrativeScopes is set when the refusal is for administrative scopes this
		// client may not request, which is recorded where it is answered (#499).
		refusedAdministrativeScopes []string
	)

	route, need := decideAuthorizeRoute(facts)
	for need != authorizeFactNone {
		switch need {
		case authorizeFactRedirectEmission:
			emitted := o.redirects.RedirectWillBeEmitted(ctx, client, authContext.RedirectURI,
				authContext.ResponseType, "authorize")
			facts.redirectEmitted = &emitted

		case authorizeFactSessionValidity:
			userSession, err = o.database.GetUserSessionBySessionIdentifier(ctx, nil, arrival.SessionIdentifier)
			if err != nil {
				return AuthorizationResult{}, err
			}
			valid := o.sessions.HasValidUserSession(userSession,
				settings.UserSessionIdleTimeoutInSeconds, settings.UserSessionMaxLifetimeInSeconds, requestedMaxAge)
			facts.sessionValid = &valid

		case authorizeFactValidation:
			validation, validationErr := validateAuthorizeRequest(ctx, o.validator, o.tokenParser,
				settings, client, params, &protocolvalidation.ValidateRequestInput{
					ResponseType:             authContext.ResponseType,
					CodeChallengeMethod:      authContext.CodeChallengeMethod,
					CodeChallenge:            authContext.CodeChallenge,
					ResponseMode:             authContext.ResponseMode,
					PKCERequired:             client.IsPKCERequired(settings.PKCERequired),
					ImplicitGrantEnabled:     client.IsImplicitGrantEnabled(settings.ImplicitFlowEnabled),
					AuthorizationCodeEnabled: client.AuthorizationCodeEnabled,
					Scope:                    requestedScope,
					Nonce:                    authContext.Nonce,
					State:                    authContext.State,
					MaxAge:                   authContext.MaxAge,
				})
			if validationErr != nil {
				return AuthorizationResult{}, validationErr
			}
			refusal = validation.refusal
			refusedAdministrativeScopes = validation.refusedAdministrativeScopes
			authContext.Prompt = validation.prompt
			authContext.IdTokenHintSub = validation.hintSubject
			if refusal == nil {
				// Fixed once, where the request is accepted: every later step, SilentAuthentication
				// included, reads this snapshot and not the client's row, so an edit to
				// default_acr_level mid-ceremony cannot change what the step-up decided (#240).
				authContext.SetTargetAcrLevel(client.DefaultAcrLevel)
			}
			facts.validated = true
			facts.refused = refusal != nil
			facts.promptNone = authContext.HasPromptValue("none")
			facts.promptLogin = authContext.HasPromptValue("login")
			facts.hintSubject = authContext.IdTokenHintSub

		case authorizeFactSessionUser:
			// The session predicate needs only the session's own timestamps, so its user is loaded
			// here, the first point anything reads it. UserSessionLoadUser answers nil for a nil
			// session.
			err = o.database.UserSessionLoadUser(ctx, nil, userSession)
			if err != nil {
				return AuthorizationResult{}, err
			}
			facts.sessionUserLoaded = true
			if userSession != nil {
				facts.sessionUserSubject = userSession.User.Subject
				facts.sessionUserEnabled = userSession.User.Enabled
			}
		}
		route, need = decideAuthorizeRoute(facts)
	}

	result := AuthorizationResult{AuthContext: authContext}

	// answerClient answers the client with an error now, whoever is at the browser, and stores
	// nothing: a link or redirect that is not even a valid sign-in, sent to this browser from
	// anywhere, must not end the sign-in it holds (#246). A silent request never asked the emission
	// gate, which is "nothing has withheld it yet".
	answerClient := func(code, description string) AuthorizationResult {
		result.ClientRefusal = &ClientError{Client: client, Code: code, Description: description}
		result.RedirectWithheld = facts.redirectEmitted != nil && !*facts.redirectEmitted
		return result
	}
	saveFor := func(nextStep string) AuthorizationResult {
		result.NextStep = nextStep
		result.SaveErr = browser.AddAuthContext(authContext)
		return result
	}

	switch route {
	case authorizeRouteAnswerNow:
		if len(refusedAdministrativeScopes) > 0 {
			// Recorded against the user when the browser holds a valid session, which this route
			// has not read when it answered for silence or a withheld redirect; read here, for this
			// refusal alone.
			if facts.sessionValid == nil {
				userSession, err = o.database.GetUserSessionBySessionIdentifier(ctx, nil, arrival.SessionIdentifier)
				if err != nil {
					return AuthorizationResult{}, err
				}
				valid := o.sessions.HasValidUserSession(userSession,
					settings.UserSessionIdleTimeoutInSeconds, settings.UserSessionMaxLifetimeInSeconds, requestedMaxAge)
				facts.sessionValid = &valid
			}
			if *facts.sessionValid {
				protocolvalidation.LogAdministrativeScopeRefused(ctx, o.auditLogger, client, refusedAdministrativeScopes,
					"authorize", userSession.UserId)
			} else {
				warnAdministrativeScopeRefused(ctx, client, refusedAdministrativeScopes)
			}
		}
		return answerClient(refusal.Code(), refusal.Description()), nil

	case authorizeRoutePark:
		if len(refusedAdministrativeScopes) > 0 {
			warnAdministrativeScopeRefused(ctx, client, refusedAdministrativeScopes)
		}
		// The error rides on the auth context, which the session store seals with an AEAD, so the
		// visitor cannot choose it, and /auth/level1completed delivers it once the password is
		// verified. ParkDeferredError conforms and bounds the description.
		authContext.ParkDeferredError(refusal.Code(), refusal.Description())
		return saveFor("/auth/level1"), nil

	case authorizeRoutePromptNone:
		silent, silentErr := o.silentAuthentication.Run(ctx, browser, settings, authContext, client,
			arrival.SessionIdentifier, arrival.IpAddress)
		if silentErr != nil {
			return AuthorizationResult{}, silentErr
		}
		if silent.Refusal != nil {
			result.ClientRefusal = silent.Refusal
			return result, nil
		}
		result.NextStep = "/auth/issue"
		result.SaveErr = silent.SaveErr
		return result, nil

	case authorizeRouteForceLogin, authorizeRouteLevel1:
		authContext.AuthState = ceremony.AuthStateRequiresLevel1
		return saveFor("/auth/level1"), nil

	case authorizeRouteDisabledUser:
		o.auditLogger.Log(ctx, audit.EventUserDisabled, map[string]interface{}{
			"user_id": userSession.UserId,
		})
		// Answered at once, never parked: the browser holds a valid session, so somebody has
		// authenticated already, and a disabled user sent to the login page could not finish it (#213).
		return answerClient("access_denied", userDisabledDescription), nil

	case authorizeRouteSSO:
		// The session completed level 1 already, so the ceremony goes to /auth/level1completed,
		// which decides the step-up.
		authContext.AdoptSession(userSession)
		authContext.AuthState = ceremony.AuthStateLevel1ExistingSession
		return saveFor("/auth/level1completed"), nil
	}
	return AuthorizationResult{}, errs.Errorf("authorization request reached no route (%v)", route)
}

// refuseUnaddressableAuthorizeRequest answers the refusal page an authorization request is owed
// when the server cannot address an answer to it, or nil when it can. It is the one place that rule
// is written: Authorization.Run asks it before it loads the client, and AuthorizationParking.Run
// before it parks a request, so a request the GET would refuse without a trace costs a POST no row
// either. A failure of the address check that is no refusal is a fault inside the validator,
// returned as an error.
func refuseUnaddressableAuthorizeRequest(ctx context.Context, validator authorizeAddressValidator, requestId string,
	params url.Values) (*AuthorizePageRefusal, error) {

	// Repeats of the parameters that decide where an answer goes and how it is encoded are checked
	// first, above everything that could redirect: a request carrying two of one does not say, in the
	// one form the grammar allows, where its response goes, so it goes nowhere. Copies that agree are
	// no exception (#228).
	if name := protocolvalidation.RepeatedParameter(params, authorizeDeliveryParameters); name != "" {
		return &AuthorizePageRefusal{Reason: AuthorizePageRefusalRepeatedParameter, Parameter: name}, nil
	}

	// RFC 6749 section 4.1.2.1 forbids sending a bad client_id or redirect_uri anywhere, so the page
	// is the whole answer.
	err := validator.ValidateClientAndRedirectURI(ctx, &protocolvalidation.ValidateClientAndRedirectURIInput{
		RequestId:    requestId,
		ClientId:     params.Get("client_id"),
		RedirectURI:  params.Get("redirect_uri"),
		ResponseType: params.Get("response_type"),
	})
	if err != nil {
		var localizedErr *i18n.LocalizedError
		if errors.As(err, &localizedErr) {
			return &AuthorizePageRefusal{Reason: AuthorizePageRefusalClientOrRedirectURI, ClientRefusal: localizedErr}, nil
		}
		return nil, err
	}

	// OIDC Core 1.0 section 3.1.2.6: "If the Response Mode value is not supported, the Authorization
	// Server returns an HTTP response code of 400 (Bad Request) without Error Response parameters,
	// since understanding the Response Mode is necessary to know how to return those parameters." So
	// this precedes every validation that answers by redirect, whichever error the request carries,
	// and applies to every authorization request rather than only to an OIDC Authentication Request:
	// the reasoning does not turn on the scope (#213 decision 11). An implicit request asking for
	// the query names a mode this server understands and may not use for tokens, which ValidateRequest
	// refuses by redirect, in the fragment (#231).
	if !protocolvalidation.IsSupportedResponseMode(params.Get("response_mode")) {
		return &AuthorizePageRefusal{Reason: AuthorizePageRefusalUnsupportedResponseMode}, nil
	}

	// response_mode=form_post answers through an HTML form whose action is the redirect URI, and
	// html/template's URL filter, the one guard standing between a stored javascript: redirect URI
	// and a live form action, rewrites every scheme outside http, https and mailto to "#ZgotmplZ"
	// rather than let the form target it. A private-use scheme such as myapp:// (RFC 8252 section
	// 7.1) therefore got a form that posted the code back to this server, and any error answered in
	// that mode goes the same way, so the request is refused here, for the reason the unsupported
	// mode above is: the server cannot deliver a response in the mode asked for. The template's
	// allowlist stays as it is (#121). The redirect URI was checked above to be registered and
	// absolute, and the parse lower-cases its scheme.
	if params.Get("response_mode") == "form_post" {
		redirectURI, err := url.Parse(params.Get("redirect_uri"))
		if err != nil || (redirectURI.Scheme != "http" && redirectURI.Scheme != "https") {
			return &AuthorizePageRefusal{Reason: AuthorizePageRefusalFormPostUnreachable,
				ImplicitFlow: protocolvalidation.ParseResponseType(params.Get("response_type")).IsImplicitFlow()}, nil
		}
	}

	return nil, nil
}

// authorizeValidation is what validateAuthorizeRequest found: the first refusal, or nil when the
// request was accepted, and the two values the validations produce on the way.
type authorizeValidation struct {
	refusal *oauth.ErrorDetail
	// prompt is the normalized prompt once ValidatePrompt has accepted it, so a request refused
	// later, for its id_token_hint, still carries it into the parked ceremony.
	prompt string
	// hintSubject is the id_token_hint's sub once the hint has been accepted, "" without a hint.
	hintSubject string
	// refusedAdministrativeScopes is the administrative scopes the refusal is for, when the client
	// may not request them, and nil for every other refusal.
	refusedAdministrativeScopes []string
}

// validateAuthorizeRequest runs the validations that answer by redirect, in the order the client is
// told about them: repeated parameters, unsupported request parameters, the request itself, the
// scopes, whether the client may request the administrative scopes among them, the prompt, the
// id_token_hint. The first refusal stops the rest. An error that is not an ErrorDetail is a fault
// inside a validator and is returned for the 500.
//
// These descriptions stay English and are never localized, unlike the refusal page. They become an
// error_description, which RFC 6749 section 4.1.2.1 confines to "%x20-21 / %x23-5B / %x5D-7E" and
// addresses to the client developer, not the visitor. oauth.ConformErrorDescription enforces that
// set where an error is parked and where it is emitted, so a translated sentence would reach the
// client as a row of question marks (#213 decision 9).
func validateAuthorizeRequest(ctx context.Context, validator authorizeRequestValidator, tokenParser idTokenHintParser,
	settings *record.Settings, client *record.Client, params url.Values,
	request *protocolvalidation.ValidateRequestInput) (authorizeValidation, error) {

	var validation authorizeValidation

	// stop ends the validations on err: an ErrorDetail is the refusal, anything else a fault.
	stop := func(err error) (authorizeValidation, error) {
		var errorDetail *oauth.ErrorDetail
		if errors.As(err, &errorDetail) {
			validation.refusal = errorDetail
			return validation, nil
		}
		return authorizeValidation{}, err
	}

	// First, because every later check reads the first copy of a parameter, and a parameter sent
	// twice may have meant the other. The delivery parameters were checked before the client was
	// loaded; the rest are refused here, so the refusal reaches the client like the ones below (#228).
	err := protocolvalidation.ValidateNoRepeatedParameters(params, authorizeRequestParameters)
	if err != nil {
		return stop(err)
	}

	err = validator.ValidateUnsupportedRequestParameters(&protocolvalidation.ValidateUnsupportedRequestParametersInput{
		HasRequest:    params.Has("request"),
		HasRequestURI: params.Has("request_uri"),
	})
	if err != nil {
		return stop(err)
	}

	err = validator.ValidateRequest(request)
	if err != nil {
		return stop(err)
	}

	// The scope as sent, not request.Scope's normalized copy, because its grammar is judged on the
	// spaces the client put in it (#244).
	err = validator.ValidateScopes(ctx, params.Get("scope"))
	if err != nil {
		return stop(err)
	}

	// Once the scopes are known to exist, who asked for them: only a client allowed to request the
	// administrative scopes may obtain one on a user's behalf. A validation like the others, so its
	// refusal reaches the client as theirs does, on the interactive, silent and implicit paths alike
	// (#499 decisions 1 and 7). request.Scope is the scope as asked for, normalized.
	if refused := protocolvalidation.RefusedAdministrativeScopes(client, request.Scope); len(refused) > 0 {
		validation.refusal = protocolvalidation.AdministrativeScopeRefusal(refused)
		validation.refusedAdministrativeScopes = refused
		return validation, nil
	}

	normalizedPrompt, err := validator.ValidatePrompt(params.Get("prompt"))
	if err != nil {
		return stop(err)
	}
	validation.prompt = normalizedPrompt

	hintSubject, err := validateIdTokenHint(ctx, params.Get("id_token_hint"), tokenParser, settings)
	if err != nil {
		return stop(err)
	}
	validation.hintSubject = hintSubject

	return validation, nil
}

// validateIdTokenHint answers the sub of the id_token_hint, "" when there is none, the
// invalid_request that refuses it, or the fault when the parser could not check it. OIDC Core 1.0 section 3.1.2.2 requires the server to verify it
// issued the hint, and says it SHOULD accept an expired one, so the expiry is not checked.
func validateIdTokenHint(ctx context.Context, idTokenHint string, tokenParser idTokenHintParser,
	settings *record.Settings) (string, error) {

	if idTokenHint == "" {
		return "", nil
	}

	if tokenParser == nil {
		return "", errs.New("tokenParser is nil")
	}

	jwtToken, err := tokenParser.DecodeAndValidateTokenString(ctx, idTokenHint, false)
	// A hint the parser could not check, because the signing keys could not be read or decoded,
	// says nothing about the hint: a fault, answered on the server error page rather than telling
	// the client a hint that may be good is invalid (#680).
	if err != nil && !errors.Is(err, signingkeys.ErrTokenRefused) {
		return "", errs.Wrap(err, "unable to check the id_token_hint")
	}
	// OIDC Core 1.0 section 3.1.2.1 defines the hint as an ID Token, and the signature does not say
	// which kind of token this is: access and refresh tokens are signed with the same key and carry
	// iss and sub too. A refused kind is answered as a hint that does not parse, so the answer says
	// nothing about which it was (#401).
	if err != nil || issuance.IsNotIDTokenTyp(jwtToken.StringClaim("typ")) {
		return "", oauth.NewErrorDetailWithHTTPStatus("invalid_request", "The id_token_hint is invalid.",
			httpStatusBadRequest)
	}

	// Safe type assertions: a malformed claim (iss: 123) must not panic.
	iss, ok := jwtToken.Claims["iss"].(string)
	if !ok || iss != settings.Issuer {
		return "", oauth.NewErrorDetailWithHTTPStatus("invalid_request", "The id_token_hint was not issued by this server.",
			httpStatusBadRequest)
	}

	sub, ok := jwtToken.Claims["sub"].(string)
	if !ok || sub == "" {
		return "", oauth.NewErrorDetailWithHTTPStatus("invalid_request", "The id_token_hint does not contain a valid sub claim.",
			httpStatusBadRequest)
	}

	return sub, nil
}

// warnAdministrativeScopeRefused is what a refusal at /auth/authorize leaves when no valid session
// names a user, signed out or parked behind the sign-in: a Warn record and no audit row, because
// that endpoint is unauthenticated and its admission tier bounds one address only while the rate
// limiter switch is on (#504), so a row per request would be audit rows anyone can write at will
// (#499 decision 9). The client identifier and the scopes are bounded stored values, safe to log.
func warnAdministrativeScopeRefused(ctx context.Context, client *record.Client, scopes []string) {
	slog.WarnContext(ctx, "refused an administrative scope the client may not request, with no signed-in user to record it against",
		"client_identifier", client.ClientIdentifier, "scopes", scopes)
}
