package handlers

import (
	"context"

	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/usersession"
)

// The interfaces in this file are taken by no handler. Each is the whole of a service the route
// table hands straight to the authflow operations, whose own ports name only the part each
// operation calls, and is declared here so that mockery generates one double of it in
// handlers/mocks. The handler tests build every operation from those doubles, so one expectation
// set on, say, UserSessionManager is what /auth/authorize, /auth/level1completed, /auth/completed
// and /auth/issue all meet. A method added to an authflow port that the concrete service has is
// added here too, or the doubles cannot satisfy that port. OtpSecretGenerator's double also stands
// in for apihandlers' port of the same name, structurally.

// OtpSecretGenerator mints a TOTP enrolment key and its otpauth URL. *otp.KeyGenerator satisfies it.
type OtpSecretGenerator interface {
	GenerateKeyURL(email string, appName string) (string, error)
}

// ImplicitTokenIssuer issues the implicit grant's tokens, signed in a transaction that takes the
// session row first (#197). *issuance.TokenIssuer satisfies it.
type ImplicitTokenIssuer interface {
	IssueImplicitTx(ctx context.Context, settings *record.Settings, input *issuance.ImplicitGrantInput, issueAccessToken bool, issueIdToken bool) (*issuance.ImplicitGrantResponse, error)
}

// AuthorizeValidator validates an authorization request. *protocolvalidation.AuthorizeValidator
// satisfies it.
type AuthorizeValidator interface {
	ValidateScopes(ctx context.Context, scope string) error
	ValidateClientAndRedirectURI(ctx context.Context, input *protocolvalidation.ValidateClientAndRedirectURIInput) error
	ValidateRequest(input *protocolvalidation.ValidateRequestInput) error
	ValidatePrompt(prompt string) (string, error)
	ValidateUnsupportedRequestParameters(input *protocolvalidation.ValidateUnsupportedRequestParametersInput) error
}

// CodeIssuer issues an authorization code in a transaction of its own, which takes the session row
// before the insert (#139). *issuance.CodeIssuer satisfies it.
type CodeIssuer interface {
	IssueAuthCodeTx(ctx context.Context, input *issuance.CreateCodeInput) (*record.Code, error)
}

// UserSessionManager validates, starts, binds and bumps user sessions.
// *usersession.Manager satisfies it.
type UserSessionManager interface {
	// HasValidUserSession answers whether a session is within its idle timeout, its maximum lifetime
	// and the request's max_age.
	HasValidUserSession(userSession *record.UserSession, idleTimeoutInSeconds int, maxLifetimeInSeconds int, requestedMaxAgeInSeconds *int64) bool
	// StartNewUserSession creates the create arm's session in one transaction and answers it with
	// the rows it removed. It writes nothing to the browser: the caller binds the session to the
	// browser session after it returns, and abandons it when that fails.
	StartNewUserSession(ctx context.Context, clientId int64, authentication usersession.Authentication,
		authStateGeneration int64, otpConfigGeneration *int64, device usersession.Device, ipAddress string,
		replacing *record.UserSession, limits usersession.SessionLimits) (*record.UserSession, []usersession.Removal, error)
	// AbandonUserSession deletes a session StartNewUserSession committed when binding it to the
	// browser session failed, and returns cause, joined with the delete's failure if it failed.
	AbandonUserSession(ctx context.Context, userSession *record.UserSession, cause error) error
	// BumpUserSession updates an existing session's last accessed time and client list, and raises
	// its ACR and adds its methods, never lowering either (#537). A non-empty ipAddress replaces the
	// session's recorded address; empty leaves it.
	BumpUserSession(ctx context.Context, sessionIdentifier string, clientId int64,
		authMethods string, acrLevel record.AcrLevel, ipAddress string) (*record.UserSession, error)
	// BindUserSession is BumpUserSession for a completed sign-in: under the session's row lock, it
	// checks the sign-in's one-time code claim on the user, raises the session or, with replace,
	// writes the sign-in's authentication over it, and sets its auth_time (#542).
	BindUserSession(ctx context.Context, sessionIdentifier string, clientId int64,
		authentication usersession.Authentication, replace bool, ipAddress string) (*record.UserSession, error)
	// AuthenticationIsStale answers, without locking or writing, whether BindUserSession would
	// refuse authentication as older than the session's (#538), so the reuse arm can refuse before
	// it rotates the browser session's identifier rather than after.
	AuthenticationIsStale(ctx context.Context, sessionIdentifier string,
		authentication usersession.Authentication) (bool, error)
}

// PermissionChecker narrows a scope to what a user holds. *permissions.Checker satisfies
// it.
type PermissionChecker interface {
	FilterOutScopesWhereUserIsNotAuthorized(ctx context.Context, scope string, user *record.User) (string, error)
}
