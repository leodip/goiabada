package authflow

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/otpcredential"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/revocation"
	"github.com/leodip/goiabada/authserver/internal/usersession"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/sessionstore"
)

// UserDisabledDescription is the error_description of the access_denied a ceremony is answered with
// when its user turns out to be disabled. Three steps ask the question, each at the moment it is
// cheapest to: the session shortcut at /auth/authorize, /auth/completed once the credential is
// accepted (Completion), and /auth/issue before anything is minted (#197). They say the same thing,
// so an application reading the description sees one condition wherever it was found.
const UserDisabledDescription = "The user account is disabled."

// completionDatabase is what Completion reads and writes: the browser's session with its user, the
// client, the ceremony's user, the stored consent, and the OTP configuration generation it promotes.
// It embeds revocation.Database because a foreign session is ended through
// revocation.TerminateUserSessionTx. *data.Database satisfies it.
type completionDatabase interface {
	revocation.Database

	GetClientByClientIdentifier(ctx context.Context, tx *sql.Tx, clientIdentifier string) (*record.Client, error)
	GetConsentByUserIdAndClientId(ctx context.Context, tx *sql.Tx, userId int64, clientId int64) (*record.UserConsent, error)
	GetUserById(ctx context.Context, tx *sql.Tx, userId int64) (*record.User, error)
	PromoteUserSessionOtpConfigGeneration(ctx context.Context, tx *sql.Tx, userSessionId int64, generation int64) error
	UserSessionLoadUser(ctx context.Context, tx *sql.Tx, userSession *record.UserSession) error
}

// completionSessions is what Completion asks of the user sessions: whether the browser's is valid,
// whether a bind would be refused as stale, and the reuse arm's bind.
// *usersession.UserSessionManager satisfies it.
type completionSessions interface {
	sessionValidity
	AuthenticationIsStale(ctx context.Context, sessionIdentifier string,
		authentication usersession.Authentication) (bool, error)
	BindUserSession(ctx context.Context, sessionIdentifier string, clientId int64,
		authentication usersession.Authentication, replace bool, ipAddress string) (*record.UserSession, error)
}

// scopeFilter narrows a scope to what the user holds. *permissions.PermissionChecker satisfies it.
type scopeFilter interface {
	FilterOutScopesWhereUserIsNotAuthorized(ctx context.Context, scope string, user *record.User) (string, error)
}

// auditLogger records one security event under the request's context. *audit.AuditLogger
// satisfies it.
type auditLogger interface {
	Log(ctx context.Context, auditEvent string, details map[string]interface{})
}

// completionBrowser is every browser-session write Completion makes. Each lands only while the
// browser session still holds this ceremony, and otherwise answers ceremony.ErrCeremonyReplaced and
// writes nothing (#579). The handler's per-request adapter satisfies it.
type completionBrowser interface {
	stepSaver
	ceremonyClearer
	// RegenerateSession rotates the browser session's identifier, the reuse arm's rotation.
	RegenerateSession(ceremonyId string) error
	// ConfirmCeremony writes nothing: it answers nil while the browser session, read afresh, still
	// holds the ceremony, the create arm's check before it ends or creates anything.
	ConfirmCeremony(ceremonyId string) error
	// StartNewUserSession is the create arm's session start: its transaction, then the rotation that
	// binds the new session to the browser session on condition it still holds this ceremony, and
	// the device cookie. A rotation finding the session gone answers sessionstore.ErrNotFound.
	StartNewUserSession(clientId int64, authentication usersession.Authentication,
		authStateGeneration int64, otpConfigGeneration *int64, ipAddress string, replacing *record.UserSession,
		limits usersession.SessionLimits) (*record.UserSession, []usersession.Removal, error)
}

// Completion is GET /auth/completed, reached once a ceremony's authentication is complete
// (authentication_completed). It binds the ceremony to a user session and sends it on to consent
// or to issuance. The route table builds one.
type Completion struct {
	database    completionDatabase
	sessions    completionSessions
	auditLogger auditLogger
	scopes      scopeFilter
}

// NewCompletion builds the operation over the database, the user sessions, the audit log and the
// scope filter it uses.
func NewCompletion(database completionDatabase, sessions completionSessions, auditLogger auditLogger,
	scopes scopeFilter) *Completion {

	return &Completion{database: database, sessions: sessions, auditLogger: auditLogger, scopes: scopes}
}

// CompletionResult is what Completion.Run did. Exactly one of NextStep, ClientError, Stale and
// Replaced is set.
type CompletionResult struct {
	// NextStep is the route the ceremony was saved to go to: /auth/level1 on a restart, /auth/consent
	// or /auth/issue once bound.
	NextStep string
	// SaveErr is the save's failure, ceremony.ErrCeremonyReplaced when the browser session no longer
	// holds the ceremony. The handler redirects to NextStep only when it is nil.
	SaveErr error

	// ClientError is the access_denied the client is owed, for a disabled user or for a user holding
	// none of the requested scopes. The ceremony ends with it: it was cleared.
	ClientError *ClientError
	// ClearErr is the clear's failure: ceremony.ErrCeremonyReplaced, which answers the "no longer
	// active" page and nothing to the client, or any other, which answers the client server_error in
	// place of ClientError (#141).
	ClearErr error

	// Stale is a bind refused because a newer authentication had already reached the session
	// (usersession.ErrStaleAuthentication, #538). Nothing was bound, rotated or saved, and the handler
	// answers the "no longer active" page.
	Stale bool
	// Replaced is a rotation, a confirmation or the session start finding the browser session no
	// longer holding this ceremony, or gone. Nothing was bound to the browser session, and the
	// handler answers it as any step of a replaced ceremony (#579).
	Replaced bool
}

// Run, in order:
//
//  1. Loads the browser's user session by sessionIdentifier with its user, then the client; a failed
//     read or a client not found is returned as an error.
//  2. Decides the mode (decideCompletion): reuseSession, createSession or restartAtLevel1.
//  3. Unless it restarts, loads the ceremony's user and decides on it before anything is bound
//     (decideBeforeBinding): a missing user is an error, a disabled one is audited and answered
//     access_denied after the ceremony is cleared, and a moved generation or a removed
//     authenticator restarts.
//  4. A restart (restart route 1) discards the attempt (AuthContext.Restart) and saves the ceremony
//     towards /auth/level1.
//  5. Binds: the reuse arm (bindReusedSession) or the create arm (bindNewSession). The write asking
//     decideBeforeBinding's question again and finding the authenticator gone restarts; a stale bind
//     is Stale; a browser session no longer holding this ceremony is Replaced.
//  6. Takes the ceremony's auth time from the bound session, and refuses one with none: such a
//     session cannot be stored (StartNewUserSession refuses a zero instant, migration 000062 ended
//     every older session), and an auth_time is never invented for it (#580 decision 5).
//  7. Sets the ceremony's ACR against the bound session (AuthContext.SetAcrLevel).
//  8. Decides where the bound ceremony goes (DecideAfterBinding), loading what it asks for: the scope
//     narrowed to what the user holds, which replaces the ceremony's, and the stored consent. A user
//     holding none of the scopes is answered access_denied after the clear; otherwise the ceremony is
//     saved towards /auth/consent or /auth/issue.
//
// settings are the request's, for the session's bounds; ipAddress is the browser's, recorded on the
// session it binds to.
//
// The user is decided on before either arm binds, so a refusal or a restart leaves no session row, no
// rotated identifier and no record of a session behind it (#522 decision 6). The restart arm needs no
// user: it binds nothing and the password step reads the user afresh.
func (o *Completion) Run(ctx context.Context, browser completionBrowser, settings *record.Settings,
	authContext *ceremony.AuthContext, sessionIdentifier string, ipAddress string) (CompletionResult, error) {

	userSession, err := o.database.GetUserSessionBySessionIdentifier(ctx, nil, sessionIdentifier)
	if err != nil {
		return CompletionResult{}, err
	}
	err = o.database.UserSessionLoadUser(ctx, nil, userSession)
	if err != nil {
		return CompletionResult{}, err
	}

	client, err := o.database.GetClientByClientIdentifier(ctx, nil, authContext.ClientId)
	if err != nil {
		return CompletionResult{}, err
	}
	if client == nil {
		return CompletionResult{}, errs.Errorf("client %v not found", authContext.ClientId)
	}

	targetAcrLevel := authContext.GetTargetAcrLevel(client.DefaultAcrLevel)
	plan := decideCompletion(completionFacts{
		sessionPresent: userSession != nil,
		sessionValid: o.sessions.HasValidUserSession(userSession, settings.UserSessionIdleTimeoutInSeconds,
			settings.UserSessionMaxLifetimeInSeconds, authContext.RequestedMaxAge()),
		sessionOwned:    authContext.OwnsSession(userSession),
		level1Completed: authContext.Level1AuthCompleted,
		// AuthenticatedAt is set by the password and the OTP steps when a credential is entered, and is
		// nil on an SSO pass. It is no proof of level 1, since OTP alone sets it (#129 decision 15).
		credentialEntered:           authContext.AuthenticatedAt != nil && !authContext.AuthenticatedAt.IsZero(),
		raisesPrivilege:             usersession.WillRaisePrivilege(userSession, authContext.AuthMethods, targetAcrLevel),
		otpConfigGenerationCaptured: authContext.OtpConfigGeneration != nil,
		target:                      targetAcrLevel,
	})

	var user *record.User
	if _, restarts := plan.(restartPlan); !restarts {
		user, err = o.database.GetUserById(ctx, nil, authContext.UserId)
		if err != nil {
			return CompletionResult{}, err
		}

		switch decideBeforeBinding(user, authContext.AuthStateGeneration, OTPClaimOf(authContext)) {
		case beforeBindingUserMissing:
			return CompletionResult{}, errs.New("user not found")
		case beforeBindingUserDisabled:
			o.auditLogger.Log(ctx, audit.EventUserDisabled, map[string]interface{}{
				"user_id": user.Id,
			})
			return CompletionResult{
				ClientError: &ClientError{Client: client, Code: "access_denied", Description: UserDisabledDescription},
				ClearErr:    browser.ClearAuthContext(authContext.CeremonyId),
			}, nil
		case beforeBindingGenerationMoved:
			slog.WarnContext(ctx, "the user's authentication generation has moved on since this ceremony authenticated, restarting level 1 instead of binding a session",
				"ceremony_user_id", authContext.UserId)
			plan = restartAtLevel1()
		case beforeBindingAuthenticatorRemoved:
			slog.WarnContext(ctx, "this ceremony names a one-time code from an authenticator the user no longer has, restarting level 1 instead of binding a session",
				"ceremony_user_id", authContext.UserId)
			plan = restartAtLevel1()
		}
	}

	var boundSession *record.UserSession
	switch mode := plan.(type) {
	case reuseSessionPlan:
		boundSession, err = o.bindReusedSession(ctx, browser, mode, authContext, client, sessionIdentifier,
			targetAcrLevel, ipAddress)
	case createSessionPlan:
		boundSession, err = o.bindNewSession(ctx, browser, mode, authContext, client, userSession, targetAcrLevel,
			ipAddress, usersession.SessionLimits{
				IdleTimeoutInSeconds: settings.UserSessionIdleTimeoutInSeconds,
				MaxLifetimeInSeconds: settings.UserSessionMaxLifetimeInSeconds,
				MaxSessionsPerUser:   settings.MaxUserSessionsPerUser,
			})
	default:
		// restartPlan, the third mode.
		return restartCompletion(browser, authContext), nil
	}
	switch {
	case errors.Is(err, otpcredential.ErrAuthenticatorRemoved):
		// decideBeforeBinding's question, asked again by the write under the user's row lock: an
		// authenticator removed between the two is answered as it would have been there (#542).
		slog.WarnContext(ctx, "this ceremony names a one-time code from an authenticator the user no longer has, restarting level 1 instead of binding a session",
			"ceremony_user_id", authContext.UserId)
		return restartCompletion(browser, authContext), nil
	case errors.Is(err, usersession.ErrStaleAuthentication):
		slog.WarnContext(ctx, "a newer authentication has already reached this session, answering this ceremony as one the browser has replaced",
			"ceremony_user_id", authContext.UserId)
		return CompletionResult{Stale: true}, nil
	case errors.Is(err, ceremony.ErrCeremonyReplaced) || errors.Is(err, sessionstore.ErrNotFound):
		return CompletionResult{Replaced: true}, nil
	case err != nil:
		return CompletionResult{}, err
	}

	if boundSession.AuthTime.IsZero() {
		return CompletionResult{}, errs.Errorf("user session %v has no auth time", boundSession.Id)
	}
	authContext.AuthenticatedAt = &boundSession.AuthTime

	// Against the session this ceremony bound to, never the one the browser arrived with: the ACR is
	// the higher of the two arguments, so the arrived-with session, another user's or this user's
	// expired one, would raise the acr of a token bound to a different session (#133). A ceremony that
	// authenticated afresh has just written its target onto the session, so its ACR is the target
	// (#537).
	err = authContext.SetAcrLevel(targetAcrLevel, boundSession)
	if err != nil {
		return CompletionResult{}, err
	}

	facts := AfterBindingFacts{
		PromptConsent:    authContext.HasPromptValue("consent"),
		ConsentRequired:  client.ConsentRequired,
		ClientIdentifier: client.ClientIdentifier,
	}
	answer, need := DecideAfterBinding(facts)
	for need != AfterBindingFactNone {
		switch need {
		case AfterBindingFactEffectiveScope:
			effectiveScope, filterErr := o.scopes.FilterOutScopesWhereUserIsNotAuthorized(ctx, authContext.Scope, user)
			if filterErr != nil {
				return CompletionResult{}, filterErr
			}
			authContext.SetScope(effectiveScope)
			scope := authContext.Scope
			facts.EffectiveScope = &scope
		case AfterBindingFactConsent:
			consent, consentErr := o.database.GetConsentByUserIdAndClientId(ctx, nil, user.Id, client.Id)
			if consentErr != nil {
				return CompletionResult{}, consentErr
			}
			facts.ConsentLoaded = true
			facts.Consent = consent
		}
		answer, need = DecideAfterBinding(facts)
	}

	switch answer {
	case AfterBindingNoScope:
		return CompletionResult{
			ClientError: &ClientError{Client: client, Code: "access_denied",
				Description: "The user is not authorized to access any of the requested scopes"},
			ClearErr: browser.ClearAuthContext(authContext.CeremonyId),
		}, nil
	case AfterBindingConsent:
		authContext.AuthState = ceremony.AuthStateRequiresConsent
		return CompletionResult{NextStep: "/auth/consent", SaveErr: browser.SaveAuthContext(authContext)}, nil
	default:
		authContext.AuthState = ceremony.AuthStateReadyToIssueCode
		return CompletionResult{NextStep: "/auth/issue", SaveErr: browser.SaveAuthContext(authContext)}, nil
	}
}

// restartCompletion is restart route 1: the attempt is discarded with AuthContext.Restart, so the
// methods and the user carried in from a session that ended do not reach the session the second pass
// creates, and the ceremony is saved towards /auth/level1 (#140, #436).
func restartCompletion(browser stepSaver, authContext *ceremony.AuthContext) CompletionResult {
	authContext.Restart()
	return CompletionResult{NextStep: "/auth/level1", SaveErr: browser.SaveAuthContext(authContext)}
}

// bindReusedSession is the reuse arm: it binds the ceremony to the session the browser arrived with,
// as plan says, and answers the bound row. In order:
//
//  1. When the plan rotates (rotateIdentifier): asks whether the bind would be refused as stale
//     (#538), and refuses here, before rotating, so a stale ceremony rotates nothing; then rotates the
//     browser session's identifier (RegenerateSession).
//  2. Binds (BindUserSession), in one transaction under the session's row, which raises the
//     session's level and methods to this ceremony's or, with replaceAuthentication, writes them over
//     it, and asks again whether the bind is stale and whether the ceremony's code still stands.
//  3. Promotes the OTP configuration generation, when the plan says so.
//  4. Audits the bump.
//
// The rotation comes before the bind, which commits before it returns: rotating after would leave the
// identifier the browser arrived with naming a session already at the higher level, so an identifier
// stolen at level 1 would keep working after the step-up. A failure between the two leaves a fresh
// identifier on a session not yet raised, the safe direction. The rotation lands only while the
// browser session still holds this ceremony (#579).
//
// The auth time handed to the bind is the instant the credential step captured, never the clock read
// here: auth_time is what max_age is measured against, "the last time the End-User was actively
// authenticated by the OP" (OIDC Core 1.0 section 3.1.2.1), and a tab paused after the password and
// resumed hours later must not be told it signed in just now (#252 decision 8).
func (o *Completion) bindReusedSession(ctx context.Context, browser completionBrowser, plan reuseSessionPlan,
	authContext *ceremony.AuthContext, client *record.Client, sessionIdentifier string,
	targetAcrLevel record.AcrLevel, ipAddress string) (*record.UserSession, error) {

	authentication := usersession.Authentication{
		UserId:      authContext.UserId,
		AuthMethods: authContext.AuthMethods,
		AcrLevel:    targetAcrLevel,
		OTPClaim:    OTPClaimOf(authContext),
		// The instant the ceremony adopted the session at, nil for one that authenticated afresh. The
		// bind's ordering rule compares it with the locked row (#538).
		AdoptedAuthTime: authContext.AdoptedSessionAuthTime,
	}
	if plan.refreshAuthTime {
		authentication.AuthTime = authContext.AuthenticatedAt
	}
	if plan.replaceAuthentication {
		authentication.PasswordAuthTime = authContext.PasswordVerifiedAt
	}

	if plan.rotateIdentifier {
		stale, err := o.sessions.AuthenticationIsStale(ctx, sessionIdentifier, authentication)
		if err != nil {
			return nil, err
		}
		if stale {
			return nil, errs.WithStack(usersession.ErrStaleAuthentication)
		}
		if err = browser.RegenerateSession(authContext.CeremonyId); err != nil {
			return nil, err
		}
	}

	boundSession, err := o.sessions.BindUserSession(ctx, sessionIdentifier, client.Id, authentication,
		plan.replaceAuthentication, ipAddress)
	if err != nil {
		return nil, err
	}

	// After the bind, which writes the whole row: otp_config_generation is dont-update, and this
	// narrow write is the only thing that moves it (#242).
	if plan.promoteOtpConfigGeneration {
		err = o.database.PromoteUserSessionOtpConfigGeneration(ctx, nil, boundSession.Id,
			*authContext.OtpConfigGeneration)
		if err != nil {
			return nil, err
		}
		boundSession.OtpConfigGeneration = *authContext.OtpConfigGeneration
	}

	o.auditLogger.Log(ctx, audit.EventBumpedUserSession, map[string]interface{}{
		"user_id":   authContext.UserId,
		"client_id": client.Id,
	})
	return boundSession, nil
}

// bindNewSession is the create arm: it starts a new session for the ceremony and answers it. In
// order:
//
//  1. Confirms the browser session still holds this ceremony (ConfirmCeremony). Everything after
//     this ends or deletes something, and a ceremony the browser abandoned for a newer sign-in must
//     do none of it: it would revoke another user's grants, or delete the session a newer SSO
//     ceremony adopted (#579 decision 4).
//  2. When the plan says the arrived-with session is another user's: terminates it with its codes
//     and refresh tokens (revocation.TerminateUserSessionTx), then audits the handover, the deletion
//     and the termination, in that order and after the commit.
//  3. Starts the new session (StartNewUserSession), replacing the arrived-with one when it is this
//     user's, and audits every session the start removed, whether or not it then failed.
//  4. Audits the new session.
//
// A failed termination is returned before anything is created, with the browser still holding the
// old session: the fail-closed direction.
func (o *Completion) bindNewSession(ctx context.Context, browser completionBrowser, plan createSessionPlan,
	authContext *ceremony.AuthContext, client *record.Client, userSession *record.UserSession,
	targetAcrLevel record.AcrLevel, ipAddress string, limits usersession.SessionLimits) (*record.UserSession, error) {

	if err := browser.ConfirmCeremony(authContext.CeremonyId); err != nil {
		return nil, err
	}

	// The browser changed hands, so the session it carried is ended rather than left orphaned with
	// its refresh tokens working. StartNewUserSession sweeps only the new user's sessions, so it would
	// never reach this one. Both sweeps key on the session identifier, so the previous user's other
	// devices are untouched (#133).
	if plan.terminatesForeignSession() {
		terminationResult, err := revocation.TerminateUserSessionTx(ctx, o.database, userSession)
		if err != nil {
			return nil, err
		}

		// The handover comes first, as the reason for the other two, and attests the ending, not a
		// replacement: started_new_user_session attests that, so its absence after this event shows a
		// handover that did not complete (#133). No event names logged_in_user: the only identity in
		// scope is the cookie's, which is still the user being terminated, and the actor is this
		// event's user_id.
		o.auditLogger.Log(ctx, audit.EventCrossUserSessionReplaced, map[string]interface{}{
			"user_id":                     authContext.UserId,
			"previous_user_id":            userSession.UserId,
			"previous_session_identifier": userSession.SessionIdentifier,
			"client_id":                   client.Id,
		})
		// deleted_user_session beside terminated_user_session, the pair every caller of
		// TerminateUserSessionTx writes (#129 decision 9).
		o.auditLogger.Log(ctx, audit.EventDeletedUserSession, map[string]interface{}{
			"user_session_id": userSession.Id,
			"logged_in_user":  "",
			"reason":          audit.DeletedUserSessionReplacedByOtherUser,
		})
		revocation.LogTerminatedUserSession(ctx, o.auditLogger, userSession, "", terminationResult)
	}

	// The browser's own session, when it is this user's, is the one this sign-in replaces. Nothing it
	// authorized is revoked, the policy for a same-user sign-in (#133, #243). A foreign session was
	// terminated above and is not passed.
	var replacing *record.UserSession
	if plan.replacesOwnSession() {
		replacing = userSession
	}
	// AuthenticatedAt is always set here: decideCompletion takes this arm only with
	// Level1AuthCompleted, and the password step sets both. StartNewUserSession refuses a nil or
	// zero instant rather than invent one (#252 decision 8).
	newSession, removedSessions, err := browser.StartNewUserSession(client.Id, usersession.Authentication{
		UserId:           authContext.UserId,
		AuthMethods:      authContext.AuthMethods,
		AcrLevel:         targetAcrLevel,
		AuthTime:         authContext.AuthenticatedAt,
		PasswordAuthTime: authContext.PasswordVerifiedAt,
		OTPClaim:         OTPClaimOf(authContext),
		// The rotation binding the new session lands only while the browser session still holds this
		// ceremony (#579 decision 4).
		BrowserSessionCondition: ceremony.Held(authContext.CeremonyId),
	}, authContext.AuthStateGeneration, authContext.OtpConfigGeneration, ipAddress, replacing, limits)

	// A removed row is gone once the start's transaction committed, which a failure after the commit
	// does not undo, so each is audited before either answer.
	for _, removal := range removedSessions {
		o.auditLogger.Log(ctx, audit.EventDeletedUserSession, map[string]interface{}{
			"user_session_id": removal.Session.Id,
			"logged_in_user":  "",
			"reason":          removal.Reason,
		})
	}
	if err != nil {
		return nil, err
	}

	o.auditLogger.Log(ctx, audit.EventStartedNewUserSession, map[string]interface{}{
		"user_id":   authContext.UserId,
		"client_id": client.Id,
	})
	return newSession, nil
}

// OTPClaimOf is the ceremony's claim to a one-time code: whether its methods name one, and the
// generation of the authenticator it came from, adopted from the session or recorded when the code
// was entered (#542).
func OTPClaimOf(authContext *ceremony.AuthContext) otpcredential.OTPClaim {
	return otpcredential.OTPClaim{Claimed: authContext.ClaimsOTP(), Generation: authContext.OtpClaimGeneration}
}
