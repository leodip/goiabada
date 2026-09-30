package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/urlutil"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
)

// authIssueDatabase is what /auth/issue reads before it issues: the client, its redirect URIs, the
// user and the ambient session. The session row taken before the insert, and the transaction, are
// the code issuer's (#139).
//
// It embeds the authorize port because a refusal here is answered through redirToClientWithError.
type authIssueDatabase interface {
	authorizeDatabase

	ClientLoadRedirectURIs(ctx context.Context, tx *sql.Tx, client *models.Client) error
	GetClientByClientIdentifier(ctx context.Context, tx *sql.Tx, clientIdentifier string) (*models.Client, error)
	GetUserById(ctx context.Context, tx *sql.Tx, userId int64) (*models.User, error)
	GetUserSessionBySessionIdentifier(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (*models.UserSession, error)
}

func HandleIssueGet(
	pageRenderer PageRenderer,
	ceremonyStore CeremonyStore,
	templateFS fs.FS,
	codeIssuer CodeIssuer,
	implicitTokenIssuer ImplicitTokenIssuer,
	database authIssueDatabase,
	auditLogger AuditLogger,
	userSessionManager UserSessionManager,
	permissionChecker PermissionChecker,
	baseURL string,
	adminConsoleBaseURL string,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authContext, ok := loadAuthContext(pageRenderer, ceremonyStore, auditLogger, w, r, adminConsoleBaseURL)
		if !ok {
			return
		}

		if !requireAuthState(pageRenderer, w, r, authContext, ceremony.AuthStateReadyToIssueCode) {
			return
		}

		sessionIdentifier, _ := reqctx.SessionIdentifierFrom(r.Context())

		facts := issuanceFacts{
			redirectURI:              authContext.RedirectURI,
			responseType:             authContext.ResponseType,
			hintSubject:              authContext.IdTokenHintSub,
			authStateGeneration:      authContext.AuthStateGeneration,
			sessionIdentifierPresent: sessionIdentifier != "",
		}

		// What the loads produce beyond the facts, for the acts below.
		var (
			issuingClient  *models.Client
			ambientSession *models.UserSession
			settings       *models.Settings
			scopeField     *string
			effectiveScope string
		)

		// The settings ride on the request's context, and two facts read them: the client's flow
		// switches and the session's timeouts. Read once, and only when one of them is asked for,
		// so a ceremony refused above both answers without them in its context.
		loadSettings := func() bool {
			if settings != nil {
				return true
			}
			s, ok := reqctx.SettingsFrom(r.Context())
			if !ok {
				pageRenderer.InternalServerError(w, r, reqctx.ErrNoSettings)
				return false
			}
			settings = s
			return true
		}

		// The loads, each made once and only when decideIssuance asks for it, so a refusal reads
		// nothing past the check that refused.
		answer, need := decideIssuance(facts)
		for need != issuanceFactNone {
			switch need {
			case issuanceFactRegistration:
				// The client loaded here is the one every act below answers or issues for, so
				// neither the refusals nor issueImplicitGrant load it again.
				client, err := database.GetClientByClientIdentifier(r.Context(), nil, authContext.ClientId)
				if err != nil {
					pageRenderer.InternalServerError(w, r, err)
					return
				}
				registered := []string{}
				if client != nil {
					err = database.ClientLoadRedirectURIs(r.Context(), nil, client)
					if err != nil {
						pageRenderer.InternalServerError(w, r, err)
						return
					}
					for _, redirectURI := range client.RedirectURIs {
						registered = append(registered, redirectURI.URI)
					}
				}
				issuingClient = client
				facts.registrationLoaded = true
				facts.registeredRedirectURIs = registered
				facts.clientEnabled = client != nil && client.Enabled

			case issuanceFactFlows:
				// Only reached for a registered client, which the registration gate has already
				// established is not nil.
				if !loadSettings() {
					return
				}
				facts.flows = &clientFlows{
					implicit: issuingClient.IsImplicitGrantEnabled(settings.ImplicitFlowEnabled),
					code:     issuingClient.AuthorizationCodeEnabled,
				}

			case issuanceFactUser:
				user, err := database.GetUserById(r.Context(), nil, authContext.UserId)
				if err != nil {
					pageRenderer.InternalServerError(w, r, err)
					return
				}
				facts.userLoaded = true
				facts.user = user

			case issuanceFactSession:
				session, err := database.GetUserSessionBySessionIdentifier(r.Context(), nil, sessionIdentifier)
				if err != nil {
					pageRenderer.InternalServerError(w, r, err)
					return
				}
				ambientSession = session
				facts.sessionLoaded = true
				facts.sessionPresent = session != nil
				facts.sessionOwned = authContext.OwnsSession(session)

			case issuanceFactSessionValidity:
				// nil for the requested max age, and that is decision 1 rather than an omission.
				// max_age bounds the age of the AUTHENTICATION, which this ceremony already
				// satisfied at /auth/completed; re-applying it here would turn it into a deadline
				// for reading the consent screen. UserSession.IsValid measures it from the
				// session's AuthTime, so max_age=0 is violated a nanosecond after the credential
				// was accepted and every such ceremony would restart at level 1, mint a fresh
				// session and fail again (#241).
				if !loadSettings() {
					return
				}
				valid := userSessionManager.HasValidUserSession(ambientSession,
					settings.UserSessionIdleTimeoutInSeconds, settings.UserSessionMaxLifetimeInSeconds, nil)
				facts.sessionValid = &valid

			case issuanceFactEffectiveScope:
				// Whichever field the issuer will READ, and never the other one. IssueAuthCodeTx
				// and issueImplicitGrant both prefer ConsentedScope and fall back to Scope when it
				// is empty, so writing an emptied ConsentedScope back would fall through to the
				// full unfiltered request, which is why the empty result refuses instead of
				// writing anything at all (#241 decision 2).
				scopeField = &authContext.Scope
				if authContext.ConsentedScope != "" {
					scopeField = &authContext.ConsentedScope
				}
				scope, err := permissionChecker.FilterOutScopesWhereUserIsNotAuthorized(r.Context(), *scopeField, facts.user)
				if err != nil {
					pageRenderer.InternalServerError(w, r, err)
					return
				}
				effectiveScope = scope
				facts.effectiveScope = &effectiveScope
			}
			answer, need = decideIssuance(facts)
		}

		switch answer.outcome {
		case issuanceRefuseUnregisteredRedirect:
			refuseIssuanceUnregisteredRedirect(w, r, authContext, issuingClient, pageRenderer, ceremonyStore, auditLogger)

		case issuanceRefuseClientDisabled:
			refuseIssuanceClientDisabled(w, r, authContext, pageRenderer, ceremonyStore)

		case issuanceRefuseImplicitDisabled:
			refuseIssuanceFlowDisabled(w, r, protocolvalidation.ImplicitNotAuthorizedErrorMsg, authContext, issuingClient,
				database, pageRenderer, ceremonyStore, templateFS)

		case issuanceRefuseCodeDisabled:
			refuseIssuanceFlowDisabled(w, r, protocolvalidation.AuthorizationCodeNotSupportedErrorMsg, authContext, issuingClient,
				database, pageRenderer, ceremonyStore, templateFS)

		case issuanceRefuseUserDisabled:
			// The same event and the same answer as /auth/completed gives the same condition, arriving
			// later: the account was disabled while the ceremony sat on a step.
			auditLogger.Log(r.Context(), audit.AuditUserDisabled, map[string]interface{}{
				"userId": facts.user.Id,
			})
			answerClientWithError(w, r, database, pageRenderer, ceremonyStore, templateFS,
				redirectErrorFromAuthContext(authContext, issuingClient, "access_denied", userDisabledDescription))

		case issuanceRefuseHintMismatch:
			// An error redirect carries the client it is answering, so its provenance has to be
			// resolved ahead of the dispatch (#108). The registration gate already loaded it and
			// refused a nil, so issuingClient is that client rather than a clientProvenance call
			// of its own.
			answerClientWithError(w, r, database, pageRenderer, ceremonyStore, templateFS,
				redirectErrorFromAuthContext(authContext, issuingClient, oidc.ErrorLoginRequired,
					"The authenticated user does not match the id_token_hint"))

		case issuanceRefuseUnusableSession:
			refuseIssuanceUnusableSession(w, r, answer.sessionShape, authContext, issuingClient, ambientSession,
				sessionIdentifier, pageRenderer, ceremonyStore, templateFS, database, auditLogger, baseURL)

		case issuanceUserMissing:
			pageRenderer.InternalServerError(w, r, errs.Errorf("user %v not found", authContext.UserId))

		case issuanceRefuseScopeDenied:
			slog.WarnContext(r.Context(), "the user holds none of the permissions behind the scopes this ceremony would grant, so nothing is issued",
				"user_id", authContext.UserId,
				"client_identifier", authContext.ClientId)

			auditLogger.Log(r.Context(), audit.AuditIssuanceRefusedScopeDenied, map[string]interface{}{
				"userId":   authContext.UserId,
				"clientId": authContext.ClientId,
			})

			// The wording and the error code are /auth/completed's for the same condition,
			// arriving later: the same removal gets one answer wherever it lands.
			answerClientWithError(w, r, database, pageRenderer, ceremonyStore, templateFS,
				redirectErrorFromAuthContext(authContext, issuingClient, "access_denied",
					"The user is not authorized to access any of the requested scopes"))

		default:
			// A narrowed set is issued rather than refused, which is RFC 6749 section 3.3's "The
			// authorization server MAY fully or partially ignore the scope requested by the
			// client" and what /auth/completed's own filter did with the same removal seconds
			// earlier. The client is told what it actually got: TokenResponse.Scope carries the
			// granted set on the code arm, and issueImplicitTokens appends a scope parameter on the
			// implicit arm (#241 decision 2).
			*scopeField = effectiveScope

			if answer.outcome == issuanceIssueImplicit {
				issueImplicitGrant(w, r, authContext, sessionIdentifier, issuingClient, facts.user, settings, ambientSession,
					pageRenderer, ceremonyStore, templateFS, implicitTokenIssuer, database, auditLogger, baseURL)
				return
			}

			issueAuthorizationCodeGrant(w, r, authContext, sessionIdentifier, issuingClient, ambientSession,
				pageRenderer, ceremonyStore, templateFS, codeIssuer, database, auditLogger, baseURL)
		}
	}
}

// issuanceFact is a fact decideIssuance needs and has not been given. HandleIssueGet loads it and
// asks again.
type issuanceFact int

const (
	// issuanceFactNone means the answer is decided.
	issuanceFactNone issuanceFact = iota
	// issuanceFactRegistration is the client's registered redirect URIs, none for a missing client, and
	// whether it is enabled.
	issuanceFactRegistration
	// issuanceFactFlows is which authorization flows the client may use.
	issuanceFactFlows
	// issuanceFactUser is the ceremony's user, or none.
	issuanceFactUser
	// issuanceFactSession is the session the request's identifier names, or none.
	issuanceFactSession
	// issuanceFactSessionValidity is whether that session is valid, max_age not applied.
	issuanceFactSessionValidity
	// issuanceFactEffectiveScope is the scope to be issued narrowed to what the user holds.
	issuanceFactEffectiveScope
)

// issuanceOutcome is what /auth/issue does with a ceremony.
type issuanceOutcome int

const (
	// issuanceUndecided is returned beside a fact still to load.
	issuanceUndecided issuanceOutcome = iota
	// issuanceRefuseUnregisteredRedirect renders the refusal page: the redirect URI is no longer
	// registered on the client.
	issuanceRefuseUnregisteredRedirect
	// issuanceRefuseClientDisabled renders the refusal page /auth/authorize renders for a disabled client.
	issuanceRefuseClientDisabled
	// issuanceRefuseImplicitDisabled answers unauthorized_client: the ceremony is an implicit one and the
	// client may no longer use the implicit grant.
	issuanceRefuseImplicitDisabled
	// issuanceRefuseCodeDisabled answers unauthorized_client: the ceremony is a code one and the client
	// may no longer use the authorization code flow.
	issuanceRefuseCodeDisabled
	// issuanceRefuseHintMismatch answers login_required: the user is not the id_token_hint's.
	issuanceRefuseHintMismatch
	// issuanceRefuseUnusableSession is refuseIssuanceUnusableSession, for sessionShape.
	issuanceRefuseUnusableSession
	// issuanceUserMissing answers 500: the ceremony's user no longer exists.
	issuanceUserMissing
	// issuanceRefuseUserDisabled answers access_denied: the ceremony's user has been disabled.
	issuanceRefuseUserDisabled
	// issuanceRefuseScopeDenied answers access_denied: the user holds none of the scopes.
	issuanceRefuseScopeDenied
	// issuanceIssueImplicit issues tokens for an implicit response type.
	issuanceIssueImplicit
	// issuanceIssueCode issues an authorization code.
	issuanceIssueCode
)

// issuanceAnswer is decideIssuance's answer.
type issuanceAnswer struct {
	outcome issuanceOutcome
	// sessionShape names the condition an issuanceRefuseUnusableSession answers.
	sessionShape sessionRefusalShape
}

// clientFlows is which authorization flows a client may use, each as the token endpoint would read
// it: the implicit grant through the client's override or else the global switch, the authorization
// code flow through the client's own flag.
type clientFlows struct {
	implicit bool
	code     bool
}

// issuanceFacts is what decideIssuance decides from. The first five are known from the ceremony
// and the request; every other fact is unknown until HandleIssueGet has loaded it, a nil pointer or
// a false loaded flag.
type issuanceFacts struct {
	redirectURI  string
	responseType string
	hintSubject  string
	// authStateGeneration is the generation the ceremony authenticated at, as its context holds it.
	authStateGeneration int64
	// sessionIdentifierPresent says the request resolved a session identifier.
	sessionIdentifierPresent bool

	registrationLoaded     bool
	registeredRedirectURIs []string
	// clientEnabled is the client's enabled flag, false for a missing client, and is known with the
	// registration.
	clientEnabled bool
	// flows is nil until the client's flows have been loaded.
	flows *clientFlows
	// userLoaded is set once the user has been looked up; user is nil when there is none.
	userLoaded bool
	user       *models.User
	// sessionLoaded is set once the session has been looked up; the two after it are false when
	// there is none. sessionOwned is AuthContext.OwnsSession's answer for it.
	sessionLoaded  bool
	sessionPresent bool
	sessionOwned   bool
	sessionValid   *bool
	effectiveScope *string
}

// decideIssuance decides what /auth/issue does with a ceremony ready to issue, or names the next
// fact it needs to decide that. The checks run in a fixed order and the first that fails is the
// answer, so each fact is asked for only once every check before it has passed:
//
//  1. The redirect URI this ceremony would be answered at is STILL registered on the client. It was
//     matched once, at /auth/authorize, and the consent screen has no bound on how long it holds a
//     ceremony still, so an operator who deleted a callback while it sat there has an expectation
//     this check is what meets (#241). It is first because every refusal after it answers the
//     client by redirect, and delivering one to a callback the operator has just pulled navigates a
//     browser to that host on a request this server refused, which is the RFC 9700 section 4.11.2
//     harm the check exists to prevent. A missing client has no registrations at all, so the
//     question is answered rather than errored. Loopback port flexibility is the caller's gate to
//     compute, per urlutil's package contract (#41), and this is
//     validator.ValidateClientAndRedirectURI's own test applied to the stored response type:
//     IsCodeOnly, true for the exact type "code", so "code code" and "code foo", which a ceremony
//     stored before #244 can hold, do not buy an arbitrary loopback port.
//  2. The client is still enabled, and still allowed the flow this ceremony is for. Both were
//     checked at /auth/authorize, and the ceremony may have sat on a step for as long as the user
//     left it, so an operator who disabled the client or switched the flow off in that time has an
//     expectation these checks meet (#197). They sit right after the registration because they need
//     neither the hint, the session nor the user, and so a refusal reads nothing more. A disabled
//     client is the page /auth/authorize renders for one and never a redirect, because it is the
//     client itself that is refused; a flow switched off is unauthorized_client by redirect, as the
//     token endpoint answers it. The implicit grant is read through the client's override and else
//     the global switch, as everywhere it is asked.
//  3. An id_token_hint names the ceremony's user. OIDC Core 3.1.2.2: "The Authorization Server MUST
//     NOT reply with an ID Token or Access Token for a different user, even if they have an active
//     session with the Authorization Server." A user who no longer exists is not the hint's either.
//  4. The ceremony may bind a grant to the browser's session: it exists, is the ceremony user's, and
//     is valid. A ceremony must not bind a grant to a session that no longer exists (#129 decision
//     6, second half): the session was alive at /auth/completed, and if it was ended while the user
//     sat on the consent screen, the grant minted here is brand new and no marker written by the
//     termination can reach it. An EMPTY identifier is the shape that case arrives in, because
//     MiddlewareSessionIdentifier puts the identifier in the request context ONLY when the row
//     exists; a non-empty one whose row is gone is the narrower race of a termination committing
//     after the middleware's read. Neither is inert: grantIsOffline treats an empty session
//     identifier as an offline grant, so a code issued here would yield an Offline refresh token
//     that outlives the terminated session. Ownership is #133's: user A's cookie can survive user
//     B's prompt=login or id_token_hint ceremony, and binding B's grant to A's session governs B's
//     access by A's lifetimes. Validity is #241's: /auth/completed applied the timeouts once, and a
//     session that timed out on the consent screen still resolves and is still owned, while the
//     authorization_code grant checks ownership and not validity, so only the FIRST refresh would
//     fail. The check sits ABOVE the response-type dispatch, for both flows: a third-party
//     resource server validating an already-signed token has no way to compare the session's owner
//     against its subject (#133). An implicit ceremony with no identifier at all was exempt from it
//     until #197, on the reasoning that it issues no refresh token and there was nothing to
//     cross-bind to; but the tokens it signs name no session, so no termination could ever end
//     them, and the code flow already refuses the same ceremony. It is the gone shape now, answered
//     as the code flow answers it. The implicit flow's issuer takes the session row again inside its
//     own transaction, which is what closes the gap between this read and the signing.
//  5. The user still exists (a 500 if not), is still enabled, and the credential the ceremony
//     authenticated with is still current. A disabled account is access_denied, and is audited as
//     /auth/completed audits it. The credential is current when the ceremony's generation is the
//     user's, the comparison the token endpoint makes at redemption: a password change or a
//     revocation moves the user's on, and a ceremony at any other value would be issued a code that
//     endpoint refuses, or tokens signed under a credential that is no longer current. It is
//     restarted at level 1 instead, or told login_required when the request forbids UI, as a
//     session that is gone is (#197, #106).
//  6. The user holds at least one of the scopes to be issued, re-filtered against the LIVE
//     permissions immediately before anything is minted. /auth/completed's filter is the only other
//     live check, and nothing downstream catches a removal: the authorization_code grant never
//     consults the permission checker, so without this a brand-new grant is the one thing minted
//     without a live check (#241). It is below the binding check so a ceremony about to be
//     restarted pays none of it.
func decideIssuance(f issuanceFacts) (issuanceAnswer, issuanceFact) {
	decided := func(outcome issuanceOutcome) (issuanceAnswer, issuanceFact) {
		return issuanceAnswer{outcome: outcome}, issuanceFactNone
	}

	if !f.registrationLoaded {
		return issuanceAnswer{}, issuanceFactRegistration
	}
	rtInfo := protocolvalidation.ParseResponseType(f.responseType)
	allowLoopbackPortFlexibility := rtInfo.IsCodeOnly()
	if !urlutil.RedirectURIIsRegistered(f.registeredRedirectURIs, f.redirectURI, allowLoopbackPortFlexibility) {
		return decided(issuanceRefuseUnregisteredRedirect)
	}

	if !f.clientEnabled {
		return decided(issuanceRefuseClientDisabled)
	}
	isImplicitFlow := rtInfo.IsImplicitFlow()
	if f.flows == nil {
		return issuanceAnswer{}, issuanceFactFlows
	}
	if isImplicitFlow && !f.flows.implicit {
		return decided(issuanceRefuseImplicitDisabled)
	}
	if !isImplicitFlow && !f.flows.code {
		return decided(issuanceRefuseCodeDisabled)
	}

	if f.hintSubject != "" {
		if !f.userLoaded {
			return issuanceAnswer{}, issuanceFactUser
		}
		if f.user == nil || f.user.Subject != f.hintSubject {
			return decided(issuanceRefuseHintMismatch)
		}
	}

	if f.sessionIdentifierPresent && !f.sessionLoaded {
		return issuanceAnswer{}, issuanceFactSession
	}
	if f.sessionValid == nil {
		return issuanceAnswer{}, issuanceFactSessionValidity
	}
	mayBind := f.sessionOwned && *f.sessionValid
	if !mayBind {
		// The three shapes are mutually exclusive by construction: a row that is absent cannot be
		// foreign, and a foreign one is refused on ownership before its clock is read.
		shape := sessionGone
		switch {
		case f.sessionPresent && !f.sessionOwned:
			shape = sessionForeign
		case f.sessionPresent && !*f.sessionValid:
			shape = sessionExpired
		}
		return issuanceAnswer{outcome: issuanceRefuseUnusableSession, sessionShape: shape}, issuanceFactNone
	}

	if !f.userLoaded {
		return issuanceAnswer{}, issuanceFactUser
	}
	if f.user == nil {
		return decided(issuanceUserMissing)
	}
	if !f.user.Enabled {
		return decided(issuanceRefuseUserDisabled)
	}
	if f.user.AuthStateGeneration != f.authStateGeneration {
		return issuanceAnswer{outcome: issuanceRefuseUnusableSession, sessionShape: sessionGenerationStale}, issuanceFactNone
	}

	if f.effectiveScope == nil {
		return issuanceAnswer{}, issuanceFactEffectiveScope
	}
	if *f.effectiveScope == "" {
		return decided(issuanceRefuseScopeDenied)
	}

	if isImplicitFlow {
		return decided(issuanceIssueImplicit)
	}
	return decided(issuanceIssueCode)
}

// refuseIssuanceUnregisteredRedirect answers a ceremony whose redirect URI is no longer registered
// on its client: nothing is issued and nothing is emitted, and the refusal page is rendered here.
func refuseIssuanceUnregisteredRedirect(
	w http.ResponseWriter,
	r *http.Request,
	authContext *ceremony.AuthContext,
	issuingClient *models.Client,
	pageRenderer PageRenderer,
	ceremonyStore CeremonyStore,
	auditLogger AuditLogger,
) {
	// The client identifier is a bounded stored value and is safe to log; the URI is not logged,
	// matching the authorization endpoint's refusal, since the operator reads the offending value
	// off the client's page.
	slog.WarnContext(r.Context(), "the redirect URI this ceremony would be answered at is no longer registered on the client, so nothing is issued and nothing is emitted",
		"client_identifier", authContext.ClientId)

	auditLogger.Log(r.Context(), audit.AuditIssuanceRefusedRedirectURI, map[string]interface{}{
		"userId":   authContext.UserId,
		"clientId": authContext.ClientId,
	})

	// The clear goes FIRST, the order every refusal in this handler uses: ClearAuthContext persists
	// the deletion through a Set-Cookie on w, and the render below commits the response, so
	// clearing afterwards leaves the header on a response already written (#141).
	err := ceremonyStore.ClearAuthContext(w, r)
	if err != nil {
		// This is the ONE refusal in the file whose fallback is not "answer the client with
		// server_error", and so the one that does not go through answerClientWithError. Answering
		// this client is precisely what the gate exists to prevent, and an error redirect is a
		// response to the deregistered URI just as a code would be. So the page is rendered
		// regardless and the browser keeps a replayable auth context, which is the lesser of the
		// two: a replay arrives back at this same gate and is refused again for as long as the
		// registration is gone.
		slog.ErrorContext(r.Context(), "unable to clear the auth context while withholding a redirect to a deregistered URI, rendering the refusal anyway",
			"error", err)
	}

	// Rendered locally, never redirected: this URI must receive nothing, an error response
	// included. auth_redirect_blocked.html is the page redirToClientWithError already withholds a
	// redirect through, so one condition keeps one page wherever it fires (#241 decision 4, as
	// amended by decision 11).
	//
	// Built directly rather than through redirectErrorFromAuthContext, which fills in an error
	// code, a description, a state and a response mode: this page carries none of them, and naming
	// the two fields it does read says so. A nil client is rendered without a name.
	err = renderRedirectBlocked(pageRenderer, w, r, redirectErrorInput{
		client:      issuingClient,
		redirectURI: authContext.RedirectURI,
	})
	if err != nil {
		pageRenderer.InternalServerError(w, r, err)
	}
}

// refuseIssuanceClientDisabled answers a ceremony whose client was disabled after it started:
// nothing is issued and nothing is emitted, and the refusal page /auth/authorize renders for a
// disabled client is rendered here, in the visitor's locale and with the status that page has
// there. It is a page and never a redirect because it is the client that is refused, and answering
// the client is what disabling it stops (#197).
func refuseIssuanceClientDisabled(
	w http.ResponseWriter,
	r *http.Request,
	authContext *ceremony.AuthContext,
	pageRenderer PageRenderer,
	ceremonyStore CeremonyStore,
) {
	slog.WarnContext(r.Context(), "the client this ceremony is issuing for has been disabled, so nothing is issued and nothing is emitted",
		"client_identifier", authContext.ClientId)

	// The clear goes FIRST, the order every refusal in this handler uses (#141). Its failure does not
	// change the answer, for the reason refuseIssuanceUnregisteredRedirect gives: the page reaches no
	// client, and a replay of the context that stays behind comes back to this gate and is refused
	// again for as long as the client stays disabled.
	err := ceremonyStore.ClearAuthContext(w, r)
	if err != nil {
		slog.ErrorContext(r.Context(), "unable to clear the auth context while refusing a disabled client, rendering the refusal anyway",
			"error", err)
	}

	message := i18n.NewLocalizedError(i18n.ErrCodeAuthorizeClientDisabled, nil).Localize(r.Context())
	renderAuthorizeRefusal(pageRenderer, w, r, message, http.StatusOK)
}

// refuseIssuanceFlowDisabled answers a ceremony whose client was switched off for the flow the
// ceremony is for: unauthorized_client, by redirect, through answerClientWithError. The description
// is the one the authorize and token endpoints give for the same condition, so it reads alike
// wherever it is found (#197).
func refuseIssuanceFlowDisabled(
	w http.ResponseWriter,
	r *http.Request,
	description string,
	authContext *ceremony.AuthContext,
	issuingClient *models.Client,
	database authIssueDatabase,
	pageRenderer PageRenderer,
	ceremonyStore CeremonyStore,
	templateFS fs.FS,
) {
	slog.WarnContext(r.Context(), "the client is no longer allowed the flow this ceremony is for, so nothing is issued",
		"client_identifier", authContext.ClientId,
		"response_type", authContext.ResponseType)

	answerClientWithError(w, r, database, pageRenderer, ceremonyStore, templateFS,
		redirectErrorFromAuthContext(authContext, issuingClient, "unauthorized_client", description))
}

// issueAuthorizationCodeGrant is the authorization code branch: it issues the code, bound to the
// session, and delivers it to the client.
func issueAuthorizationCodeGrant(
	w http.ResponseWriter,
	r *http.Request,
	authContext *ceremony.AuthContext,
	sessionIdentifier string,
	issuingClient *models.Client,
	ambientSession *models.UserSession,
	pageRenderer PageRenderer,
	ceremonyStore CeremonyStore,
	templateFS fs.FS,
	codeIssuer CodeIssuer,
	database authIssueDatabase,
	auditLogger AuditLogger,
	baseURL string,
) {
	createCodeInput := newCreateCodeInput(authContext, sessionIdentifier)

	// The session row and the insert share one transaction the issuer opens, which is what orders
	// this ceremony against a termination of that session (#139); the liveness read in
	// decideIssuance cannot do it alone. It is opened here, on the authorization code branch only,
	// so the row is held across as few statements as possible: the implicit flow mints no code and
	// no refresh token, so it has no durable grant for this to protect (#139 decision 6).
	code, err := codeIssuer.IssueAuthCodeTx(r.Context(), createCodeInput)
	if errors.Is(err, issuance.ErrIssuingSessionGone) || errors.Is(err, issuance.ErrIssuingClientGone) {
		if errors.Is(err, issuance.ErrIssuingClientGone) {
			// The client's registration went away under this ceremony, between the liveness read
			// and the insert. Answered as the session-gone shape rather than as a 500: nothing is
			// wrong with this server, the application the browser was signing in to no longer
			// exists, and the refusal path already knows how to say that once for an interactive
			// ceremony and once for a silent one. redirectWillBeEmitted re-reads the registration
			// on its way out and withholds the redirect, so a deleted client is told on an
			// interstitial rather than by a redirect to an address nobody owns any more (#248 part
			// 5).
			slog.WarnContext(r.Context(), "the client this ceremony is issuing for no longer exists, refusing to issue a code",
				"client_identifier", authContext.ClientId,
				"session_identifier", sessionIdentifier)
		}
		// The gone shape, answered exactly as the liveness read answers it: the browser restarts at
		// level 1 and a prompt=none ceremony is told login_required. The issuer returns either
		// sentinel only after its transaction has rolled back, which the refusal needs: it writes
		// the session store on a nil transaction, and on SQLite that is the connection the
		// transaction was holding (#139).
		refuseIssuanceUnusableSession(w, r, sessionGone, authContext, issuingClient, ambientSession,
			sessionIdentifier, pageRenderer, ceremonyStore, templateFS, database, auditLogger, baseURL)
		return
	}

	// Everything below this line attests to a write, so it waits for the issuer to return, which is
	// after the commit: the rule revocation.TerminateUserSessionTx documents, never attest to a
	// write that could still roll back. A commit that returns an error leaves the code row's fate
	// indeterminate, and the client is answered with a 500 rather than a code.
	if err != nil {
		pageRenderer.InternalServerError(w, r, err)
		return
	}

	auditLogger.Log(r.Context(), audit.AuditCreatedAuthCode, map[string]interface{}{
		"userId":   createCodeInput.UserId,
		"clientId": code.ClientId,
		"codeId":   code.Id,
	})

	// A failed clear leaves the context in ready_to_issue_code, so a reload mints a second code, and
	// that is a retry rather than a second grant. The code row stores only the plaintext's SHA-256
	// (models.Code.Code is db:"-"), and this 500 is answered before issueAuthCode, so the first code
	// reaches nobody and cannot be redeemed; the reload's is the only one delivered, and the
	// worker's code sweep deletes the orphaned row once it is past its grace cutoff. Clearing before
	// minting would strand the user on a transient mint fault where a reload now retries (#248 part
	// 6, #436).
	err = ceremonyStore.ClearAuthContext(w, r)
	if err != nil {
		pageRenderer.InternalServerError(w, r, err)
		return
	}
	err = issueAuthCode(w, r, templateFS, code, authContext.ResponseMode)
	if err != nil {
		pageRenderer.InternalServerError(w, r, err)
	}
}

// newCreateCodeInput copies the fields an authorization code is written from off the ceremony,
// with the session the code binds to. Issuance names only these, so it depends on no ceremony
// state it does not read (#437).
func newCreateCodeInput(authContext *ceremony.AuthContext, sessionIdentifier string) *issuance.CreateCodeInput {
	return &issuance.CreateCodeInput{
		ClientId:            authContext.ClientId,
		RedirectURI:         authContext.RedirectURI,
		ResponseMode:        authContext.ResponseMode,
		Scope:               authContext.Scope,
		ConsentedScope:      authContext.ConsentedScope,
		CodeChallenge:       authContext.CodeChallenge,
		CodeChallengeMethod: authContext.CodeChallengeMethod,
		State:               authContext.State,
		Nonce:               authContext.Nonce,
		UserAgent:           authContext.UserAgent,
		IpAddress:           authContext.IpAddress,
		UserId:              authContext.UserId,
		AcrLevel:            authContext.AcrLevel,
		AuthMethods:         authContext.AuthMethods,
		AuthenticatedAt:     authContext.AuthenticatedAt,
		AuthStateGeneration: authContext.AuthStateGeneration,
		SessionIdentifier:   sessionIdentifier,
	}
}

// sessionRefusalShape names which of the four conditions refuseIssuanceUnusableSession is answering:
// three on the session backing a ceremony and one on the credential it authenticated with. The
// three session conditions are mutually exclusive by construction: a row that is absent cannot be
// foreign, and a foreign one is refused on ownership before its clock is read. The fourth is
// reached only after the session has passed all three.
type sessionRefusalShape int

const (
	// sessionGone is a session identifier with no row behind it. What removed the row is not
	// asked and cannot be told from here, which is #129's own finding: an explicit termination, a
	// logout in another tab, the idle reaper and the max-lifetime reaper all look identical to
	// the reader (#139 decision 9).
	sessionGone sessionRefusalShape = iota
	// sessionForeign is a row that resolves and belongs to a different user than the ceremony's
	// (#133).
	sessionForeign
	// sessionExpired is a row that resolves, is owned, and is outside its idle timeout or its
	// maximum lifetime (#241).
	sessionExpired
	// sessionGenerationStale is a session that is fine and a credential that is not: the user's
	// authentication generation has moved on since the ceremony authenticated, by a password change
	// or a revocation, so what this ceremony proved is no longer current. Answered like the other
	// three, because whoever signs in next must prove it again (#197, #106).
	sessionGenerationStale
)

// refuseIssuanceUnusableSession is /auth/issue's one answer to "this ceremony cannot bind a grant
// to this session", and it exists as a function because the handler reaches that conclusion at
// several points: the liveness read above the response-type dispatch, the generation check beside
// it, and below the dispatch the acquisition that orders the code insert, or the signing of the
// implicit tokens, against a session termination. Decision 3 of #139 is that one condition gets one
// answer wherever it is learned, and a shared implementation is what makes that checkable rather
// than a claim about blocks that currently agree.
//
// Two outcomes, one predicate. An interactive ceremony is restarted at level 1, and a prompt=none
// ceremony is answered login_required, because a request that forbids UI cannot be sent to a
// password form. No code is minted on either branch.
//
// ambientSession is read only for the two shapes that have a row: the log lines for a foreign or
// an expired session name the user the row belongs to, and the gone shape has nothing to name.
func refuseIssuanceUnusableSession(
	w http.ResponseWriter,
	r *http.Request,
	shape sessionRefusalShape,
	authContext *ceremony.AuthContext,
	issuingClient *models.Client,
	ambientSession *models.UserSession,
	sessionIdentifier string,
	pageRenderer PageRenderer,
	ceremonyStore CeremonyStore,
	templateFS fs.FS,
	database authIssueDatabase,
	auditLogger AuditLogger,
	baseURL string,
) {
	// Only the expired shape audits. The foreign and gone shapes are #133's and #129's refusals,
	// writing no audit row today; this event attests the check #241 added, which is the one an
	// administrator can cause by configuring a timeout, and stretching it over two older
	// conditions would make it useless for answering the question it exists for.
	if shape == sessionExpired {
		auditLogger.Log(r.Context(), audit.AuditIssuanceRefusedSessionInvalid, map[string]interface{}{
			"userId":            authContext.UserId,
			"clientId":          authContext.ClientId,
			"sessionIdentifier": sessionIdentifier,
		})
	}

	// prompt=none is the one ceremony that cannot be restarted: /auth/level1 sends the browser to
	// /auth/pwd, which renders a form, and this request forbids any UI at all (OIDC Core 3.1.2.1,
	// and concepts/prompt-parameter.mdx says the same). Nothing between here and the form reads
	// the prompt, so the client would be handed a login page and no error, and a silent-renewal
	// iframe would wait for its own timeout instead. It gets login_required instead (#129 decision
	// 16), which is what handlePromptNone itself returns when its session lookup finds no row: the
	// condition really is the same one, arriving one redirect hop later, so the client cannot tell
	// the two apart and does not need to. No code is minted on either branch, so the fail-open
	// decision 6 closes stays closed.
	if authContext.HasPromptValue("none") {
		switch shape {
		case sessionForeign:
			slog.WarnContext(r.Context(), "the session in this browser belongs to a different user, returning login_required instead of binding this silent ceremony to it",
				"session_identifier", sessionIdentifier,
				"session_user_id", ambientSession.UserId,
				"ceremony_user_id", authContext.UserId)
		case sessionExpired:
			slog.WarnContext(r.Context(), "the session backing this silent ceremony is no longer within its idle timeout or maximum lifetime, returning login_required instead of issuing a code",
				"session_identifier", sessionIdentifier,
				"session_user_id", ambientSession.UserId)
		case sessionGenerationStale:
			slog.WarnContext(r.Context(), "the user's authentication generation has moved on since this silent ceremony authenticated, returning login_required instead of issuing anything",
				"ceremony_user_id", authContext.UserId)
		default:
			slog.WarnContext(r.Context(), "the session backing this silent ceremony is gone, returning login_required instead of issuing a code",
				"session_identifier", sessionIdentifier)
		}
		// Cleared first, and answered server_error when the clear fails, both in
		// answerClientWithError (#141). A failed clear leaves the auth context either wholly there
		// or wholly gone, never half: the store's row is written before the cookie, so a failure
		// before the row leaves the context intact and one after it leaves it gone server-side
		// while the browser's identifier still names the same cleared row. Neither outcome lets
		// the browser replay a ready_to_issue_code context, so withholding the client's response
		// would buy nothing (#266).
		//
		// Provenance is resolved before the dispatch, for the same reason as at the id_token_hint
		// refusal (#108). The registration gate at the top of the handler loaded the client and
		// refused a nil, so issuingClient is it.
		answerClientWithError(w, r, database, pageRenderer, ceremonyStore, templateFS,
			redirectErrorFromAuthContext(authContext, issuingClient, oidc.ErrorLoginRequired,
				"User authentication is required"))
		return
	}

	switch shape {
	case sessionForeign:
		slog.WarnContext(r.Context(), "the session in this browser belongs to a different user, restarting level 1 instead of binding this ceremony to it",
			"session_identifier", sessionIdentifier,
			"session_user_id", ambientSession.UserId,
			"ceremony_user_id", authContext.UserId)
	case sessionExpired:
		slog.WarnContext(r.Context(), "the session backing this ceremony is no longer within its idle timeout or maximum lifetime, restarting level 1 instead of issuing a code",
			"session_identifier", sessionIdentifier,
			"session_user_id", ambientSession.UserId)
	case sessionGenerationStale:
		slog.WarnContext(r.Context(), "the user's authentication generation has moved on since this ceremony authenticated, restarting level 1 instead of issuing anything",
			"ceremony_user_id", authContext.UserId)
	default:
		slog.WarnContext(r.Context(), "the session backing this ceremony is gone, restarting level 1 instead of issuing a code",
			"session_identifier", sessionIdentifier)
	}
	// Restart route 2. Whoever signs in next may not be the user this attempt authenticated, so
	// their methods, scope and consent are computed afresh from the request (#140, #436).
	authContext.Restart()
	err := ceremonyStore.SaveAuthContext(w, r, authContext)
	if err != nil {
		pageRenderer.InternalServerError(w, r, err)
		return
	}
	http.Redirect(w, r, ceremonyStepURL(baseURL, "/auth/level1", authContext), http.StatusFound)
}

// issueImplicitGrant is the implicit branch: it signs the tokens, bound to the session, and
// delivers them to the client. Per RFC 6749 4.2.2 and OIDC Core 3.2.2.5, tokens are returned in the
// fragment, or posted in a form when the request asked for response_mode=form_post (#231).
//
// It takes the client and the user rather than loading them. HandleIssueGet resolves both above the
// dispatch, the client for the registration gate and the user for the scope re-filter, and both
// gates refuse a nil, so re-reading them here would be two queries for values already in hand
// (#241).
//
// The issuer signs inside a transaction that takes the session row first, as the code issuer does
// (#197), so a session that was ended between the liveness read and the signing is answered
// exactly as the read answers it, and only after the issuer has rolled back: the refusal writes the
// session store on a nil transaction, and on SQLite that is the connection the transaction held
// (#139). Like issueAuthorizationCodeGrant it answers for itself.
func issueImplicitGrant(
	w http.ResponseWriter,
	r *http.Request,
	authContext *ceremony.AuthContext,
	sessionIdentifier string,
	client *models.Client,
	user *models.User,
	settings *models.Settings,
	ambientSession *models.UserSession,
	pageRenderer PageRenderer,
	ceremonyStore CeremonyStore,
	templateFS fs.FS,
	implicitTokenIssuer ImplicitTokenIssuer,
	database authIssueDatabase,
	auditLogger AuditLogger,
	baseURL string,
) {
	// Determine what tokens to issue based on response_type
	rtInfo := protocolvalidation.ParseResponseType(authContext.ResponseType)
	issueAccessToken := rtInfo.HasToken
	issueIdToken := rtInfo.HasIdToken

	// Use provided AuthenticatedAt if set (for prompt=none, preserves session's auth_time),
	// otherwise use current time (normal flow, prompt=login).
	authenticatedAt := time.Now().UTC()
	if authContext.AuthenticatedAt != nil && !authContext.AuthenticatedAt.IsZero() {
		authenticatedAt = *authContext.AuthenticatedAt
	}

	// Determine the scope to use (consented scope if available, otherwise requested scope)
	scope := authContext.Scope
	if authContext.ConsentedScope != "" {
		scope = authContext.ConsentedScope
	}

	// Generate tokens
	implicitInput := &issuance.ImplicitGrantInput{
		Client:            client,
		User:              user,
		Scope:             scope,
		AcrLevel:          authContext.AcrLevel,
		AuthMethods:       authContext.AuthMethods,
		SessionIdentifier: sessionIdentifier,
		Nonce:             authContext.Nonce,
		AuthenticatedAt:   authenticatedAt,

		AuthStateGeneration: authContext.AuthStateGeneration,
	}

	tokenResponse, err := implicitTokenIssuer.IssueImplicitTx(r.Context(), settings, implicitInput, issueAccessToken, issueIdToken)
	if errors.Is(err, issuance.ErrIssuingSessionGone) {
		// The gone shape, answered exactly as the liveness read answers it: the browser restarts at
		// level 1 and a prompt=none ceremony is told login_required. Nothing was signed.
		refuseIssuanceUnusableSession(w, r, sessionGone, authContext, client, ambientSession,
			sessionIdentifier, pageRenderer, ceremonyStore, templateFS, database, auditLogger, baseURL)
		return
	}
	if err != nil {
		pageRenderer.InternalServerError(w, r, err)
		return
	}

	// Everything below this line attests to what was signed, so it waits for the issuer to return,
	// which is after the commit.
	auditLogger.Log(r.Context(), audit.AuditTokenIssuedImplicitResponse, map[string]interface{}{
		"userId":           user.Id,
		"clientId":         client.Id,
		"scope":            scope,
		"responseType":     authContext.ResponseType,
		"issueAccessToken": issueAccessToken,
		"issueIdToken":     issueIdToken,
	})

	// Clear auth context
	err = ceremonyStore.ClearAuthContext(w, r)
	if err != nil {
		pageRenderer.InternalServerError(w, r, err)
		return
	}

	err = issueImplicitTokens(w, r, templateFS, authContext.ResponseMode, authContext.RedirectURI, authContext.State, tokenResponse)
	if err != nil {
		pageRenderer.InternalServerError(w, r, err)
	}
}

// issueImplicitTokens answers the client with tokens: in the fragment of its redirect URI, which is
// what RFC 6749 4.2.2 defines and the default, or in an auto-submitting form when the request asked
// for response_mode=form_post. The mode is implicitResponseMode's, so the query is not reachable
// from here whatever the ceremony holds (#231).
func issueImplicitTokens(
	w http.ResponseWriter,
	r *http.Request,
	templateFS fs.FS,
	responseMode string,
	redirectURI string,
	state string,
	tokenResponse *issuance.ImplicitGrantResponse,
) error {
	// Gate 4, the last resort, ABOVE the response-mode dispatch so that it covers the fragment and
	// form_post alike, as issueAuthCode's does. This flow hands over access and ID tokens rather than
	// a code, so a redirect URI that resolves to a host the operator never registered exfiltrates
	// credentials directly rather than something still to be exchanged, and the form's action is the
	// one place html/template's URL filter passes a scheme-relative value through untouched. Nothing
	// can reach here with such a value once the authorization endpoint has refused it, and the check
	// stays so that the property is enforced by a test rather than claimed by a comment (#122).
	if err := checkRedirectURIEmittable(r.Context(), "issueImplicitTokens", redirectURI); err != nil {
		return err
	}

	// The response's parameters, in the order they reach the client. Each carries the condition it
	// already had; what changed is the construction underneath and the rule for state.
	//
	// state is appended on its value being non-empty and nothing else. There is no TrimSpace: RFC
	// 6749 section 3.1 says "Parameters sent without a value MUST be treated as if they were
	// omitted from the request", so "?state=" and "?state" are requests that carried no state, and
	// Appendix A.5's "state = 1*VSCHAR" admits no empty value in the response either. Space is
	// %x20 and so is VSCHAR, so a whitespace-only state is a value the client chose and section
	// 4.2.2 requires "the exact value received from the client": trimming it away substituted this
	// server's judgement for the client's (#146).
	params := make([]responseParam, 0, 6)

	if tokenResponse.AccessToken != "" {
		params = append(params,
			responseParam{"access_token", tokenResponse.AccessToken},
			responseParam{"token_type", tokenResponse.TokenType},
			responseParam{"expires_in", fmt.Sprintf("%d", tokenResponse.ExpiresIn)},
		)
	}

	if tokenResponse.IdToken != "" {
		params = append(params, responseParam{"id_token", tokenResponse.IdToken})
	}

	if tokenResponse.Scope != "" {
		params = append(params, responseParam{"scope", tokenResponse.Scope})
	}

	if state != "" {
		params = append(params, responseParam{"state", state})
	}

	// Written by writeAuthorizationResponse, whose fragment branch appends rather than going through
	// writeResponseParams: the redirect URI cannot carry a fragment of its own for these fields to
	// collide with, since RFC 6749 3.1.2 forbids one and checkRedirectURIEmittable refuses one just
	// above. Its query, if it registered one, is left exactly as it stands. The form_post branch is
	// the one the authorization code and the error emitter use: OAuth 2.0 Form Post Response Mode
	// section 4 makes it safe for the parameters whose default is the fragment, and it sets
	// Cache-Control: no-store and Pragma: no-cache once the page has rendered, which matters more
	// here than on the code path since the page holds the tokens themselves.
	//
	// Field order is declaration order rather than Encode's alphabetical sort. Nothing depends on
	// it: RFC 6749 4.2.2 defines a set of parameters and not a sequence.
	return writeAuthorizationResponse(w, r, templateFS, implicitResponseMode(responseMode), redirectURI, params)
}

func issueAuthCode(w http.ResponseWriter, r *http.Request, templateFS fs.FS, code *models.Code, responseMode string) error {

	// Gate 4, the last resort, ABOVE the response-mode dispatch so that it covers query, fragment
	// and form_post alike. All three emit the stored value: the first two into a Location header,
	// the third into the action of an auto-submitting form, which html/template's URL filter passes
	// through untouched for a scheme-relative value. Unreachable once the authorization endpoint has
	// refused the URI, and kept so that a test enforces it (#122).
	//
	// The caller answers a non-nil error with a 500, which leaves the code unredeemed rather than
	// delivered to the wrong host; it expires in 60 seconds.
	if err := checkRedirectURIEmittable(r.Context(), "issueAuthCode", code.RedirectURI); err != nil {
		return err
	}

	// The response's parameters, in the order they reach the client, built once for all three
	// response modes because all three answer with the same two fields.
	//
	// state is appended on its value being non-empty and nothing else, the same rule the error
	// emitter states at length: RFC 6749 section 3.1 makes a parameter sent without a value an
	// omitted one, and Appendix A.5's "state = 1*VSCHAR" admits no empty value in the response. A
	// whitespace-only state is a real value, because space is %x20 and so is VSCHAR, and section
	// 4.1.2 requires "the exact value received from the client", so the TrimSpace that used to drop
	// it is gone (#146).
	params := []responseParam{{"code", code.Code}}
	if code.State != "" {
		params = append(params, responseParam{"state", code.State})
	}

	// An empty response mode is the query, the default for response_type=code (OAuth 2.0 Multiple
	// Response Type Encoding Practices 2.1).
	return writeAuthorizationResponse(w, r, templateFS, responseMode, code.RedirectURI, params)
}
