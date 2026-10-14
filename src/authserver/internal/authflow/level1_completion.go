package authflow

import (
	"context"
	"database/sql"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// level1CompletionDatabase is what Level1Completion reads: the browser's user session with its
// user, and the client, for the step-up decision, and the client again for a parked error's
// provenance. data.Database satisfies it.
type level1CompletionDatabase interface {
	GetClientByClientIdentifier(ctx context.Context, tx *sql.Tx, clientIdentifier string) (*record.Client, error)
	GetUserSessionBySessionIdentifier(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (*record.UserSession, error)
	UserSessionLoadUser(ctx context.Context, tx *sql.Tx, userSession *record.UserSession) error
}

// sessionValidity is the check of a user session against the idle timeout, the maximum lifetime and
// the request's max_age. *usersession.Manager satisfies it.
type sessionValidity interface {
	HasValidUserSession(userSession *record.UserSession, idleTimeoutInSeconds int, maxLifetimeInSeconds int,
		requestedMaxAgeInSeconds *int64) bool
}

// level1CompletionBrowser is the two browser-session writes Level1Completion makes: the save of its
// next state, and the clear that ends a ceremony delivering a parked error.
type level1CompletionBrowser interface {
	stepSaver
	ceremonyClearer
}

// Level1Completion is GET /auth/level1completed, reached once level 1 is done, by a verified
// password (level1_password_completed) or by the SSO shortcut (level1_existing_session). The route
// table builds one.
type Level1Completion struct {
	database level1CompletionDatabase
	sessions sessionValidity
}

// NewLevel1Completion builds the operation over the database it reads and the session validity
// check.
func NewLevel1Completion(database level1CompletionDatabase, sessions sessionValidity) *Level1Completion {
	return &Level1Completion{database: database, sessions: sessions}
}

// Level1CompletionResult is what Level1Completion.Run did. Exactly one of NextStep and
// DeferredError is set.
type Level1CompletionResult struct {
	// NextStep is the route the ceremony was saved to go to: /auth/level2 when a step-up is owed,
	// /auth/completed otherwise.
	NextStep string
	// SaveErr is the save's failure, ceremony.ErrCeremonyReplaced when the browser session no longer
	// holds the ceremony. The handler redirects to NextStep only when it is nil.
	SaveErr error

	// DeferredError is the error /auth/authorize parked, which the handler answers the client with.
	// The ceremony ends with it: it was cleared, and no session was created or touched.
	DeferredError *ClientError
	// ClearErr is the clear's failure: ceremony.ErrCeremonyReplaced, which answers the "no longer
	// active" page and nothing to the client, or any other, which answers the client server_error
	// in place of DeferredError (#141).
	ClearErr error
}

// Run, in order:
//
//  1. A parked error: reads the client's provenance (clientProvenance), clears the ceremony and
//     returns DeferredError. Nothing past this is read.
//  2. Loads the browser's user session by sessionIdentifier with its user, then the client; a
//     failed read or a client not found is returned as an error, and nothing is saved.
//  3. Decides whether a step-up is owed (ceremony.StepUpOwed) against the session it may reuse.
//  4. Saves the ceremony in requires_level_2 or in authentication_completed, and returns the route.
//
// settings are the request's, for the session's idle timeout and maximum lifetime.
//
// A parked error is delivered here because RFC 9700 4.11.2 requires the server to "always
// authenticate the user first ... before redirecting the user", and this is the first step reached
// once level 1 is verified. Level 2 is about the ACR of a token, and none is issued on this path, so
// a visitor is not taken through OTP for a request already known to be invalid (#213 decision 2).
// Either accepted state delivers it, although only level1_password_completed can carry one: the SSO
// shortcut is reached only with a valid session, and that request was answered at /auth/authorize.
//
// The session is reused only when all three hold:
//
//   - The ceremony did not verify the password itself (Level1AuthCompleted false). One that did,
//     prompt=login over a valid session, an id_token_hint naming someone else, or a restart, is a
//     new authentication: OIDC Core 1.0 section 3.1.2.3 says the server "MUST reauthenticate the
//     End-User even if the End-User is already authenticated", and section 2 has acr, amr and
//     auth_time describe that one authentication. It owes every factor its target needs, as a
//     sign-in with no session does, so a session's code never counts towards it. Do not undo this:
//     counting it would issue acr level 3 beside amr ["pwd"] and a fresh auth_time (#537).
//   - The session is valid for these settings and the request's max_age.
//   - The session belongs to the user this ceremony authenticated. A browser may hold user A's
//     session while user B signs in, and A's level must not decide B's step-up (#133).
//
// Only the SSO shortcut reuses a session's level: it verified nothing itself and carries the
// session's methods and auth time.
func (o *Level1Completion) Run(ctx context.Context, browser level1CompletionBrowser, settings *record.Settings,
	authContext *ceremony.AuthContext, sessionIdentifier string) (Level1CompletionResult, error) {

	if authContext.DeferredErrorCode != "" {
		client := clientProvenance(ctx, o.database, authContext.ClientId)
		return Level1CompletionResult{
			DeferredError: &ClientError{
				Client:      client,
				Code:        authContext.DeferredErrorCode,
				Description: authContext.DeferredErrorDescription,
			},
			ClearErr: browser.ClearAuthContext(authContext.CeremonyId),
		}, nil
	}

	userSession, err := o.database.GetUserSessionBySessionIdentifier(ctx, nil, sessionIdentifier)
	if err != nil {
		return Level1CompletionResult{}, err
	}
	err = o.database.UserSessionLoadUser(ctx, nil, userSession)
	if err != nil {
		return Level1CompletionResult{}, err
	}

	client, err := o.database.GetClientByClientIdentifier(ctx, nil, authContext.ClientId)
	if err != nil {
		return Level1CompletionResult{}, err
	}
	if client == nil {
		return Level1CompletionResult{}, errs.Errorf("client %v not found", authContext.ClientId)
	}
	targetAcrLevel := authContext.GetTargetAcrLevel(client.DefaultAcrLevel)

	var reusableSession *record.UserSession
	if !authContext.Level1AuthCompleted && o.sessions.HasValidUserSession(userSession,
		settings.UserSessionIdleTimeoutInSeconds, settings.UserSessionMaxLifetimeInSeconds,
		authContext.RequestedMaxAge()) && authContext.OwnsSession(userSession) {
		reusableSession = userSession
	}

	// UserSessionLoadUser populated the session's user, so the rule's OTP configuration comparison
	// costs no query.
	stepUp, err := ceremony.StepUpOwed(targetAcrLevel, reusableSession)
	if err != nil {
		return Level1CompletionResult{}, err
	}

	nextStep := "/auth/completed"
	authContext.AuthState = ceremony.AuthStateAuthenticationCompleted
	if stepUp != ceremony.StepUpNone {
		nextStep = "/auth/level2"
		authContext.AuthState = ceremony.AuthStateRequiresLevel2
	}
	return Level1CompletionResult{
		NextStep: nextStep,
		SaveErr:  browser.SaveAuthContext(authContext),
	}, nil
}
