package authflow

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/otpcredential"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// issuanceDatabase is what Issuance reads before it issues: the client with its redirect URIs, the
// user and the browser's session. The session row taken before the write, and the transaction, are
// the issuers' (#139). *data.Database satisfies it.
type issuanceDatabase interface {
	ClientLoadRedirectURIs(ctx context.Context, tx *sql.Tx, client *record.Client) error
	GetClientByClientIdentifier(ctx context.Context, tx *sql.Tx, clientIdentifier string) (*record.Client, error)
	GetUserById(ctx context.Context, tx *sql.Tx, userId int64) (*record.User, error)
	GetUserSessionBySessionIdentifier(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (*record.UserSession, error)
}

// codeIssuer writes an authorization code in a transaction of its own, which takes the session row
// before the insert (#139) and asks the ceremony's claim to a one-time code again under the user's
// row (#542). *issuance.CodeIssuer satisfies it.
type codeIssuer interface {
	IssueAuthCodeTx(ctx context.Context, input *issuance.CreateCodeInput) (*record.Code, error)
}

// implicitTokenIssuer signs the implicit grant's tokens in a transaction that takes the session row
// first (#197) and asks the claim to a one-time code again, as the code issuer does.
// *issuance.TokenIssuer satisfies it.
type implicitTokenIssuer interface {
	IssueImplicitTx(ctx context.Context, settings *record.Settings, input *issuance.ImplicitGrantInput,
		issueAccessToken bool, issueIdToken bool) (*issuance.ImplicitGrantResponse, error)
}

// issuedTokens counts the tokens issued by grant type. *tokenmetrics.Recorder satisfies it.
type issuedTokens interface {
	Issued(grantType oidc.GrantType)
}

// issuanceBrowser is every browser-session write Issuance makes: the restart's save and the clear
// that ends the ceremony. The handler's per-request adapter satisfies it.
type issuanceBrowser interface {
	stepSaver
	ceremonyClearer
}

// Issuance is GET /auth/issue, reached once a ceremony is ready to issue (ready_to_issue_code). It
// checks again what may have changed while the ceremony sat on a step, then issues an authorization
// code or the implicit grant's tokens, bound to the browser's session. The route table builds one.
type Issuance struct {
	database     issuanceDatabase
	codes        codeIssuer
	tokens       implicitTokenIssuer
	sessions     sessionValidity
	scopes       scopeFilter
	auditLogger  auditLogger
	issuedTokens issuedTokens
}

// NewIssuance builds the operation over the database, the two issuers, the session validity check,
// the scope filter, the audit log and the token metrics it uses.
func NewIssuance(database issuanceDatabase, codes codeIssuer, tokens implicitTokenIssuer, sessions sessionValidity,
	scopes scopeFilter, auditLogger auditLogger, issuedTokens issuedTokens) *Issuance {

	return &Issuance{database: database, codes: codes, tokens: tokens, sessions: sessions, scopes: scopes,
		auditLogger: auditLogger, issuedTokens: issuedTokens}
}

// IssuanceResult is what Issuance.Run did. Exactly one of UnregisteredRedirect, ClientDisabled,
// ClientError, NextStep, Code and Tokens is set.
type IssuanceResult struct {
	// UnregisteredRedirect is a redirect URI no longer registered on the client. Nothing may reach it,
	// an error included, so the handler renders the redirect-blocked page naming Client (#241).
	UnregisteredRedirect bool
	// ClientDisabled is a client disabled since /auth/authorize. The handler renders the refusal page
	// /auth/authorize renders for one, never a redirect (#197).
	ClientDisabled bool
	// Client is the ceremony's client as loaded, nil when it no longer exists. Read for the
	// UnregisteredRedirect page.
	Client *record.Client

	// ClientError is the error the client is owed by redirect. The ceremony ends with it: it was
	// cleared.
	ClientError *ClientError

	// NextStep is /auth/level1, set when the ceremony was restarted (restart route 2).
	NextStep string
	// SaveErr is the restart's save failure, ceremony.ErrCeremonyReplaced when the browser session no
	// longer holds the ceremony. The handler redirects to NextStep only when it is nil.
	SaveErr error

	// Code is the authorization code issued and committed, for the handler to deliver.
	Code *record.Code
	// Tokens is the implicit grant's tokens, signed and committed, for the handler to deliver.
	Tokens *issuance.ImplicitGrantResponse

	// ClearErr is the clear's failure, for every result but a restart. On UnregisteredRedirect and
	// ClientDisabled the page is rendered anyway unless it is ceremony.ErrCeremonyReplaced: the page
	// reaches no client, and a replay comes back to the same refusal. On ClientError any other failure
	// answers the client server_error instead (#141). On Code and Tokens any failure withholds them:
	// a replay is a retry, and what was issued reaches nobody.
	ClearErr error
}

// Run, in order:
//
//  1. Decides the ceremony (decideIssuance), loading each fact it asks for once and only when asked:
//     the client with its redirect URIs, its flows, the user, the browser's session and its validity,
//     and the scope narrowed to what the user holds. A failed read, and a user who no longer exists,
//     is returned as an error.
//  2. A refusal is audited where it is audited, then the ceremony is cleared, or restarted at level 1
//     for an unusable session that is not prompt=none (refuseUnusableSession).
//  3. Otherwise the narrowed scope replaces the one the issuer reads, and the code (issueCode) or the
//     implicit tokens (issueImplicit) are issued, audited after the commit, and the ceremony cleared.
//
// settings are the request's; sessionIdentifier is the browser's session identifier, empty when the
// request resolved none.
//
// The handler writes every answer after Run returns, so each clear lands before the response that
// depends on it (#141), and everything issued is committed before the clear and the answer.
func (o *Issuance) Run(ctx context.Context, browser issuanceBrowser, settings *record.Settings,
	authContext *ceremony.AuthContext, sessionIdentifier string) (IssuanceResult, error) {

	facts := issuanceFacts{
		redirectURI:              authContext.RedirectURI,
		responseType:             authContext.ResponseType,
		hintSubject:              authContext.IdTokenHintSub,
		authStateGeneration:      authContext.AuthStateGeneration,
		otpClaim:                 OTPClaimOf(authContext),
		sessionIdentifierPresent: sessionIdentifier != "",
	}

	var (
		client         *record.Client
		ambientSession *record.UserSession
		// scopeField is the field the issuer reads: ConsentedScope when the consent screen wrote one,
		// else Scope. The narrowed scope is written back to it alone (#241 decision 2).
		scopeField     *string
		effectiveScope string
	)

	answer, need := decideIssuance(facts)
	for need != issuanceFactNone {
		switch need {
		case issuanceFactRegistration:
			loaded, err := o.database.GetClientByClientIdentifier(ctx, nil, authContext.ClientId)
			if err != nil {
				return IssuanceResult{}, err
			}
			registered := []string{}
			if loaded != nil {
				err = o.database.ClientLoadRedirectURIs(ctx, nil, loaded)
				if err != nil {
					return IssuanceResult{}, err
				}
				for _, redirectURI := range loaded.RedirectURIs {
					registered = append(registered, redirectURI.URI)
				}
			}
			client = loaded
			facts.registrationLoaded = true
			facts.registeredRedirectURIs = registered
			facts.clientEnabled = client != nil && client.Enabled
			if client != nil {
				facts.refusedAdministrativeScopes = protocolvalidation.RefusedAdministrativeScopes(client,
					issuerScope(authContext))
			}

		case issuanceFactFlows:
			// Asked only for a registered client, which the registration check has established.
			facts.flows = &clientFlows{
				implicit: client.IsImplicitGrantEnabled(settings.ImplicitFlowEnabled),
				code:     client.AuthorizationCodeEnabled,
			}

		case issuanceFactUser:
			user, err := o.database.GetUserById(ctx, nil, authContext.UserId)
			if err != nil {
				return IssuanceResult{}, err
			}
			facts.userLoaded = true
			facts.user = user

		case issuanceFactSession:
			session, err := o.database.GetUserSessionBySessionIdentifier(ctx, nil, sessionIdentifier)
			if err != nil {
				return IssuanceResult{}, err
			}
			ambientSession = session
			facts.sessionLoaded = true
			facts.sessionPresent = session != nil
			facts.sessionOwned = authContext.OwnsSession(session)

		case issuanceFactSessionValidity:
			// No max age: max_age bounds the authentication, which /auth/completed checked. Applied here
			// it would be a deadline for reading the consent screen, and max_age=0 would restart every
			// ceremony forever (#241).
			valid := o.sessions.HasValidUserSession(ambientSession,
				settings.UserSessionIdleTimeoutInSeconds, settings.UserSessionMaxLifetimeInSeconds, nil)
			facts.sessionValid = &valid

		case issuanceFactEffectiveScope:
			scopeField = &authContext.Scope
			if authContext.ConsentedScope != "" {
				scopeField = &authContext.ConsentedScope
			}
			scope, err := o.scopes.FilterOutScopesWhereUserIsNotAuthorized(ctx, *scopeField, facts.user)
			if err != nil {
				return IssuanceResult{}, err
			}
			effectiveScope = scope
			facts.effectiveScope = &effectiveScope
		}
		answer, need = decideIssuance(facts)
	}

	switch answer.outcome {
	case issuanceRefuseUnregisteredRedirect:
		return o.refuseUnregisteredRedirect(ctx, browser, authContext, client), nil

	case issuanceRefuseClientDisabled:
		slog.WarnContext(ctx, "the client this ceremony is issuing for has been disabled, so nothing is issued and nothing is emitted",
			"client_identifier", authContext.ClientId)
		return IssuanceResult{
			ClientDisabled: true,
			ClearErr:       browser.ClearAuthContext(authContext.CeremonyId),
		}, nil

	case issuanceRefuseImplicitDisabled:
		return refuseFlowDisabled(ctx, browser, authContext, client, protocolvalidation.ImplicitNotAuthorizedErrorMsg), nil

	case issuanceRefuseCodeDisabled:
		return refuseFlowDisabled(ctx, browser, authContext, client, protocolvalidation.AuthorizationCodeNotSupportedErrorMsg), nil

	case issuanceRefuseAdministrativeScope:
		// Somebody has authenticated by now, so the refusal is recorded against the ceremony's user
		// (#499 decisions 7 and 9).
		o.auditLogger.Log(ctx, audit.EventAdministrativeScopeRefused,
			administrativeScopeRefusedDetails(client, facts.refusedAdministrativeScopes, "issue", authContext.UserId))
		return answerClient(browser, authContext, client, "invalid_scope",
			protocolvalidation.AdministrativeScopeRefusal(facts.refusedAdministrativeScopes).Description()), nil

	case issuanceRefuseUserDisabled:
		// The event and the answer Completion gives the same condition.
		o.auditLogger.Log(ctx, audit.EventUserDisabled, map[string]interface{}{
			"user_id": facts.user.Id,
		})
		return answerClient(browser, authContext, client, "access_denied", UserDisabledDescription), nil

	case issuanceRefuseHintMismatch:
		return answerClient(browser, authContext, client, oidc.ErrorLoginRequired,
			"The authenticated user does not match the id_token_hint"), nil

	case issuanceRefuseUnusableSession:
		return o.refuseUnusableSession(ctx, browser, answer.sessionShape, authContext, client, ambientSession,
			sessionIdentifier), nil

	case issuanceUserMissing:
		return IssuanceResult{}, errs.Errorf("user %v not found", authContext.UserId)

	case issuanceRefuseScopeDenied:
		slog.WarnContext(ctx, "the user holds none of the permissions behind the scopes this ceremony would grant, so nothing is issued",
			"user_id", authContext.UserId,
			"client_identifier", authContext.ClientId)
		o.auditLogger.Log(ctx, audit.EventIssuanceRefusedScopeDenied, map[string]interface{}{
			"user_id":           authContext.UserId,
			"client_id":         client.Id,
			"client_identifier": authContext.ClientId,
		})
		// Completion's wording and code for the same condition.
		return answerClient(browser, authContext, client, "access_denied",
			"The user is not authorized to access any of the requested scopes"), nil
	}

	// A narrowed set is issued rather than refused (RFC 6749 section 3.3, "The authorization server MAY
	// fully or partially ignore the scope requested by the client"), and the client is told what it
	// got: the code's token response carries the granted scope, and the implicit answer a scope
	// parameter (#241 decision 2).
	*scopeField = effectiveScope

	if answer.outcome == issuanceIssueImplicit {
		return o.issueImplicit(ctx, browser, settings, authContext, client, facts.user, ambientSession, sessionIdentifier)
	}
	return o.issueCode(ctx, browser, authContext, client, ambientSession, sessionIdentifier)
}

// issuerScope is the scope the issuers read: ConsentedScope when the consent screen wrote one, else
// Scope.
func issuerScope(authContext *ceremony.AuthContext) string {
	if authContext.ConsentedScope != "" {
		return authContext.ConsentedScope
	}
	return authContext.Scope
}

// answerClient is a refusal answered to the client by redirect: the ceremony is cleared, and the
// handler answers after the clear (#141). client is the one the registration check loaded, which is
// not nil past that check, so its provenance needs no lookup of its own (#108).
func answerClient(browser ceremonyClearer, authContext *ceremony.AuthContext, client *record.Client,
	code string, description string) IssuanceResult {

	return IssuanceResult{
		ClientError: &ClientError{Client: client, Code: code, Description: description},
		ClearErr:    browser.ClearAuthContext(authContext.CeremonyId),
	}
}

// refuseUnregisteredRedirect answers a ceremony whose redirect URI is no longer registered on its
// client: it is logged, audited and cleared, and the handler renders the redirect-blocked page.
// Nothing is emitted to the URI, an error response included (#241 decision 4). The URI is not logged,
// as at the authorization endpoint: the operator reads it off the client's page.
func (o *Issuance) refuseUnregisteredRedirect(ctx context.Context, browser ceremonyClearer,
	authContext *ceremony.AuthContext, client *record.Client) IssuanceResult {

	slog.WarnContext(ctx, "the redirect URI this ceremony would be answered at is no longer registered on the client, so nothing is issued and nothing is emitted",
		"client_identifier", authContext.ClientId)

	details := map[string]interface{}{
		"user_id":           authContext.UserId,
		"client_identifier": authContext.ClientId,
	}
	// Absent rather than zero for a client that no longer exists: client 0 names no row.
	if client != nil {
		details["client_id"] = client.Id
	}
	o.auditLogger.Log(ctx, audit.EventIssuanceRefusedRedirectURI, details)

	return IssuanceResult{
		UnregisteredRedirect: true,
		Client:               client,
		ClearErr:             browser.ClearAuthContext(authContext.CeremonyId),
	}
}

// refuseFlowDisabled answers a ceremony whose client was switched off for its flow:
// unauthorized_client by redirect, with the description the authorize and token endpoints give for
// the same condition (#197).
func refuseFlowDisabled(ctx context.Context, browser ceremonyClearer, authContext *ceremony.AuthContext,
	client *record.Client, description string) IssuanceResult {

	slog.WarnContext(ctx, "the client is no longer allowed the flow this ceremony is for, so nothing is issued",
		"client_identifier", authContext.ClientId,
		"response_type", authContext.ResponseType)
	return answerClient(browser, authContext, client, "unauthorized_client", description)
}

// refuseUnusableSession is the one answer to "this ceremony cannot bind a grant to this session",
// for every shape and wherever it is learned: by decideIssuance, or by an issuer asking again in its
// transaction (#139 decision 3). Nothing is issued on either branch:
//
//   - prompt=none is answered login_required by redirect after the clear, the answer
//     /auth/authorize gives a silent request with no session: a request that forbids UI cannot be
//     sent to a password form (OIDC Core 1.0 section 3.1.2.1, #129 decision 16).
//   - Any other ceremony is restarted at level 1 (restart route 2): AuthContext.Restart discards the
//     attempt, since whoever signs in next may be someone else, and the ceremony is saved towards
//     /auth/level1 (#140, #436).
//
// Only the expired shape is audited: it is the condition an administrator causes by configuring a
// timeout (#241). ambientSession is read only for the foreign and expired shapes, whose records name
// the user the row belongs to.
func (o *Issuance) refuseUnusableSession(ctx context.Context, browser issuanceBrowser, shape sessionRefusalShape,
	authContext *ceremony.AuthContext, client *record.Client, ambientSession *record.UserSession,
	sessionIdentifier string) IssuanceResult {

	if shape == sessionExpired {
		o.auditLogger.Log(ctx, audit.EventIssuanceRefusedSessionInvalid, map[string]interface{}{
			"user_id":            authContext.UserId,
			"client_id":          client.Id,
			"client_identifier":  authContext.ClientId,
			"session_identifier": sessionIdentifier,
		})
	}

	if authContext.HasPromptValue("none") {
		switch shape {
		case sessionForeign:
			slog.WarnContext(ctx, "the session in this browser belongs to a different user, returning login_required instead of binding this silent ceremony to it",
				"session_identifier", sessionIdentifier,
				"session_user_id", ambientSession.UserId,
				"ceremony_user_id", authContext.UserId)
		case sessionExpired:
			slog.WarnContext(ctx, "the session backing this silent ceremony is no longer within its idle timeout or maximum lifetime, returning login_required instead of issuing a code",
				"session_identifier", sessionIdentifier,
				"session_user_id", ambientSession.UserId)
		case sessionGenerationStale:
			slog.WarnContext(ctx, "the user's authentication generation has moved on since this silent ceremony authenticated, returning login_required instead of issuing anything",
				"ceremony_user_id", authContext.UserId)
		case sessionAuthenticatorRemoved:
			slog.WarnContext(ctx, "this silent ceremony names a one-time code and the user no longer has an authenticator, returning login_required instead of issuing anything",
				"ceremony_user_id", authContext.UserId)
		default:
			slog.WarnContext(ctx, "the session backing this silent ceremony is gone, returning login_required instead of issuing a code",
				"session_identifier", sessionIdentifier)
		}
		return answerClient(browser, authContext, client, oidc.ErrorLoginRequired, "User authentication is required")
	}

	switch shape {
	case sessionForeign:
		slog.WarnContext(ctx, "the session in this browser belongs to a different user, restarting level 1 instead of binding this ceremony to it",
			"session_identifier", sessionIdentifier,
			"session_user_id", ambientSession.UserId,
			"ceremony_user_id", authContext.UserId)
	case sessionExpired:
		slog.WarnContext(ctx, "the session backing this ceremony is no longer within its idle timeout or maximum lifetime, restarting level 1 instead of issuing a code",
			"session_identifier", sessionIdentifier,
			"session_user_id", ambientSession.UserId)
	case sessionGenerationStale:
		slog.WarnContext(ctx, "the user's authentication generation has moved on since this ceremony authenticated, restarting level 1 instead of issuing anything",
			"ceremony_user_id", authContext.UserId)
	case sessionAuthenticatorRemoved:
		slog.WarnContext(ctx, "this ceremony names a one-time code and the user no longer has an authenticator, restarting level 1 instead of issuing anything",
			"ceremony_user_id", authContext.UserId)
	default:
		slog.WarnContext(ctx, "the session backing this ceremony is gone, restarting level 1 instead of issuing a code",
			"session_identifier", sessionIdentifier)
	}
	authContext.Restart()
	return IssuanceResult{NextStep: "/auth/level1", SaveErr: browser.SaveAuthContext(authContext)}
}

// issueCode is the authorization code arm. In order:
//
//  1. Issues the code, bound to the browser's session (IssueAuthCodeTx). The issuer's transaction
//     takes the session row before the insert, which orders the code against a termination of that
//     session (#139), and asks the claim to a one-time code again under the user's row (#542). A
//     session gone, a client gone or an authenticator removed by then is refuseUnusableSession's,
//     answered after the issuer has rolled back; a client gone is the gone shape, and the
//     responder's gates then withhold the redirect to a client that no longer exists (#248 part 5).
//  2. Audits the code, after the commit; any other issuer failure is returned before it.
//  3. Clears the ceremony. A failed clear withholds the code: it is stored only as a digest, so it
//     reaches nobody, and a reload issues another (#248 part 6, #436).
func (o *Issuance) issueCode(ctx context.Context, browser issuanceBrowser, authContext *ceremony.AuthContext,
	client *record.Client, ambientSession *record.UserSession, sessionIdentifier string) (IssuanceResult, error) {

	input := newCreateCodeInput(authContext, sessionIdentifier)
	code, err := o.codes.IssueAuthCodeTx(ctx, input)
	if errors.Is(err, otpcredential.ErrAuthenticatorRemoved) {
		return o.refuseUnusableSession(ctx, browser, sessionAuthenticatorRemoved, authContext, client, ambientSession,
			sessionIdentifier), nil
	}
	if errors.Is(err, issuance.ErrIssuingClientGone) {
		slog.WarnContext(ctx, "the client this ceremony is issuing for no longer exists, refusing to issue a code",
			"client_identifier", authContext.ClientId,
			"session_identifier", sessionIdentifier)
	}
	if errors.Is(err, issuance.ErrIssuingSessionGone) || errors.Is(err, issuance.ErrIssuingClientGone) {
		return o.refuseUnusableSession(ctx, browser, sessionGone, authContext, client, ambientSession,
			sessionIdentifier), nil
	}
	if err != nil {
		return IssuanceResult{}, err
	}

	o.auditLogger.Log(ctx, audit.EventCreatedAuthCode, map[string]interface{}{
		"user_id":   input.UserId,
		"client_id": code.ClientId,
		"code_id":   code.Id,
	})

	return IssuanceResult{Code: code, ClearErr: browser.ClearAuthContext(authContext.CeremonyId)}, nil
}

// newCreateCodeInput copies the fields an authorization code is written from off the ceremony, with
// the session the code binds to. Issuance names only these, so it depends on no ceremony state it
// does not read (#437).
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
		OTPClaim:            OTPClaimOf(authContext),
	}
}

// issueImplicit is the implicit arm, for a response type naming token, id_token or both (RFC 6749
// section 4.2, OIDC Core 1.0 section 3.2). In order:
//
//  1. Refuses a ceremony with no auth time. /auth/completed always sets one from the session it
//     binds to, and an auth_time is never invented for the tokens (#580 decision 5).
//  2. Signs the tokens, bound to the browser's session (IssueImplicitTx), in a transaction that takes
//     the session row first and asks the claim to a one-time code again, as for a code (#197, #542).
//     A session gone or an authenticator removed by then is refuseUnusableSession's, answered after
//     the issuer has rolled back; any other failure is returned.
//  3. Audits the tokens and counts them, after the commit.
//  4. Clears the ceremony. A failed clear withholds the tokens.
//
// client and user are the ones the registration and the user checks loaded, neither nil past them.
func (o *Issuance) issueImplicit(ctx context.Context, browser issuanceBrowser, settings *record.Settings,
	authContext *ceremony.AuthContext, client *record.Client, user *record.User, ambientSession *record.UserSession,
	sessionIdentifier string) (IssuanceResult, error) {

	if authContext.AuthenticatedAt == nil || authContext.AuthenticatedAt.IsZero() {
		return IssuanceResult{}, errs.Errorf("the ceremony for user %v has no auth time to issue the implicit grant with",
			authContext.UserId)
	}

	rtInfo := protocolvalidation.ParseResponseType(authContext.ResponseType)
	issueAccessToken := rtInfo.HasToken
	issueIdToken := rtInfo.HasIdToken
	scope := issuerScope(authContext)

	tokens, err := o.tokens.IssueImplicitTx(ctx, settings, &issuance.ImplicitGrantInput{
		Client:              client,
		User:                user,
		Scope:               scope,
		AcrLevel:            authContext.AcrLevel,
		AuthMethods:         authContext.AuthMethods,
		SessionIdentifier:   sessionIdentifier,
		Nonce:               authContext.Nonce,
		AuthenticatedAt:     *authContext.AuthenticatedAt,
		AuthStateGeneration: authContext.AuthStateGeneration,
		OTPClaim:            OTPClaimOf(authContext),
	}, issueAccessToken, issueIdToken)
	if errors.Is(err, otpcredential.ErrAuthenticatorRemoved) {
		return o.refuseUnusableSession(ctx, browser, sessionAuthenticatorRemoved, authContext, client, ambientSession,
			sessionIdentifier), nil
	}
	if errors.Is(err, issuance.ErrIssuingSessionGone) {
		return o.refuseUnusableSession(ctx, browser, sessionGone, authContext, client, ambientSession,
			sessionIdentifier), nil
	}
	if err != nil {
		return IssuanceResult{}, err
	}

	o.auditLogger.Log(ctx, audit.EventTokenIssuedImplicitResponse, map[string]interface{}{
		"user_id":            user.Id,
		"client_id":          client.Id,
		"scope":              scope,
		"response_type":      authContext.ResponseType,
		"issue_access_token": issueAccessToken,
		"issue_id_token":     issueIdToken,
	})
	o.issuedTokens.Issued(oidc.GrantTypeImplicit)

	return IssuanceResult{Tokens: tokens, ClearErr: browser.ClearAuthContext(authContext.CeremonyId)}, nil
}

// administrativeScopeRefusedDetails is an administrative_scope_refused record's payload: the client
// refused, the administrative scopes it asked for, the checkpoint that refused them, and the user
// they were asked for (#499 decision 9). Authorization and Issuance record it here; handlers declares
// the same payload for the token endpoint, and the audit log's key catalog holds both to the
// documented keys.
func administrativeScopeRefusedDetails(client *record.Client, scopes []string, checkpoint string,
	userId int64) map[string]interface{} {

	return map[string]interface{}{
		"client_id":         client.Id,
		"client_identifier": client.ClientIdentifier,
		"scopes":            scopes,
		"checkpoint":        checkpoint,
		"user_id":           userId,
	}
}
