package authflow

import (
	"context"
	"database/sql"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// silentAuthenticationDatabase is what SilentAuthentication reads: the browser's user session with
// its user, and the user's consent to the client. data.Database satisfies it.
type silentAuthenticationDatabase interface {
	GetUserSessionBySessionIdentifier(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (*record.UserSession, error)
	UserSessionLoadUser(ctx context.Context, tx *sql.Tx, userSession *record.UserSession) error
	GetConsentByUserIdAndClientId(ctx context.Context, tx *sql.Tx, userId int64, clientId int64) (*record.UserConsent, error)
}

// silentAuthenticationSessions is what SilentAuthentication asks of the user sessions: whether the
// browser's is valid, and the bump of the one it reuses. *usersession.Manager satisfies
// it.
type silentAuthenticationSessions interface {
	sessionValidity
	BumpUserSession(ctx context.Context, sessionIdentifier string, clientId int64,
		authMethods string, acrLevel record.AcrLevel, ipAddress string) (*record.UserSession, error)
}

// SilentAuthentication is GET /auth/authorize for a request carrying prompt=none (OIDC Core 1.0
// section 3.1.2.1), once the request is accepted: it answers the client without showing the
// browser anything, either with an error or by sending the ceremony straight to /auth/issue on the
// browser's session. Authorization.Run hands it such a request; the route table builds one and gives
// it to NewAuthorization.
type SilentAuthentication struct {
	database       silentAuthenticationDatabase
	sessions       silentAuthenticationSessions
	scopes         scopeFilter
	auditLogger    auditLogger
	legalDocuments legalDocumentsOwed
}

// NewSilentAuthentication builds the operation over the database, the user sessions, the scope
// filter, the audit log and the legal documents it uses.
func NewSilentAuthentication(database silentAuthenticationDatabase, sessions silentAuthenticationSessions,
	scopes scopeFilter, auditLogger auditLogger, legalDocuments legalDocumentsOwed) *SilentAuthentication {

	return &SilentAuthentication{database: database, sessions: sessions, scopes: scopes, auditLogger: auditLogger,
		legalDocuments: legalDocuments}
}

// SilentAuthenticationResult is what SilentAuthentication.Run did. When Refusal is nil, the
// ceremony was saved in ready_to_issue_code.
type SilentAuthenticationResult struct {
	// Refusal is the error the client is answered with. The ceremony ends with it: it was never
	// stored, whatever sign-in the browser holds is left as it was (#246), and no session was bumped.
	Refusal *ClientError

	// SaveErr is the failure of the save that sends the ceremony to /auth/issue. The handler
	// redirects there only when it is nil, and answers 500 otherwise.
	SaveErr error
}

// Run, in order:
//
//  1. Decides from the ceremony and its client (decideSilentAuthentication), loading each fact it
//     asks for, once: the browser's user session by sessionIdentifier with its user, its validity
//     with and without max_age, the scope narrowed to what the user holds, whether the user owes the
//     acceptance step a legal document for the client, and the user's consent to the client. A failed read is returned as an error, never taken for "no session" or "no
//     consent", so a database fault is no login_required or consent_required.
//  2. A refusal: records user_disabled when it is for a disabled account and returns Refusal.
//     Nothing past the check that refused is read, and nothing is written, so a silent request
//     refused in a browser holding a sign-in in progress leaves that sign-in alone (#246).
//  3. Otherwise adopts the session onto the ceremony, with the narrowed scope and the session's
//     AuthTime as the ceremony's AuthenticatedAt. A session with a zero AuthTime is returned as an
//     error before anything is written: no auth_time is invented for it (#580 decision 5).
//  4. Sets the ceremony's ACR to the higher of the target and the session's, bumps the session and
//     records bumped_user_session after it.
//  5. Saves the ceremony in ready_to_issue_code, skipping every hop between.
//
// settings are the request's, for the session's idle timeout and maximum lifetime. ipAddress is the
// browser's, which the bump records on the session.
//
// The bump passes no methods and no level: the session is reused only when it already holds the
// level asked for, so its own were all it could pass, and writing them back would undo a removal
// of the user's authenticator that lowered the session after it was read here (#542).
func (o *SilentAuthentication) Run(ctx context.Context, browser authorizeBrowser,
	settings *record.Settings, authContext *ceremony.AuthContext, client *record.Client, sessionIdentifier string,
	ipAddress string) (SilentAuthenticationResult, error) {

	idleTimeout, maxLifetime := settings.UserSessionIdleTimeoutInSeconds, settings.UserSessionMaxLifetimeInSeconds
	requestedMaxAge := authContext.RequestedMaxAge()
	facts := silentAuthenticationFacts{
		MaxAgeRequested:  requestedMaxAge != nil,
		HintSubject:      authContext.IdTokenHintSub,
		Target:           authContext.GetTargetAcrLevel(client.DefaultAcrLevel),
		ConsentRequired:  client.ConsentRequired,
		ClientIdentifier: client.ClientIdentifier,
	}

	answer, need := decideSilentAuthentication(facts)
	for need != silentFactNone {
		switch need {
		case silentFactSession:
			userSession, err := o.database.GetUserSessionBySessionIdentifier(ctx, nil, sessionIdentifier)
			if err != nil {
				return SilentAuthenticationResult{}, err
			}
			if userSession != nil {
				err = o.database.UserSessionLoadUser(ctx, nil, userSession)
				if err != nil {
					return SilentAuthenticationResult{}, err
				}
			}
			facts.SessionLoaded = true
			facts.Session = userSession

		case silentFactValidity:
			valid := o.sessions.HasValidUserSession(facts.Session, idleTimeout, maxLifetime, requestedMaxAge)
			facts.SessionValid = &valid

		case silentFactValidityWithoutMaxAge:
			valid := o.sessions.HasValidUserSession(facts.Session, idleTimeout, maxLifetime, nil)
			facts.SessionValidWithoutMaxAge = &valid

		case silentFactEffectiveScope:
			effectiveScope, err := o.scopes.FilterOutScopesWhereUserIsNotAuthorized(ctx, authContext.Scope,
				&facts.Session.User)
			if err != nil {
				return SilentAuthenticationResult{}, err
			}
			facts.EffectiveScope = &effectiveScope

		case silentFactLegalDocuments:
			owed, err := o.legalDocuments.Owed(ctx, client, facts.Session.User.Id)
			if err != nil {
				return SilentAuthenticationResult{}, err
			}
			owes := len(owed) > 0
			facts.LegalDocumentsOwed = &owes

		case silentFactConsent:
			consent, err := o.database.GetConsentByUserIdAndClientId(ctx, nil, facts.Session.User.Id, client.Id)
			if err != nil {
				return SilentAuthenticationResult{}, err
			}
			facts.ConsentLoaded = true
			facts.Consent = consent
		}
		answer, need = decideSilentAuthentication(facts)
	}

	if answer.ErrorCode != "" {
		if answer.UserDisabled {
			o.auditLogger.Log(ctx, audit.EventUserDisabled, map[string]interface{}{
				"user_id": facts.Session.UserId,
			})
		}
		return SilentAuthenticationResult{
			Refusal: &ClientError{Client: client, Code: answer.ErrorCode, Description: answer.ErrorDescription},
		}, nil
	}

	userSession := facts.Session
	authContext.AdoptSession(userSession)
	authContext.SetScope(*facts.EffectiveScope)
	if userSession.AuthTime.IsZero() {
		return SilentAuthenticationResult{}, errs.Errorf("user session %v has no auth time", userSession.Id)
	}
	authContext.AuthenticatedAt = &userSession.AuthTime

	err := authContext.SetAcrLevel(facts.Target, userSession)
	if err != nil {
		return SilentAuthenticationResult{}, err
	}

	_, err = o.sessions.BumpUserSession(ctx, sessionIdentifier, client.Id, "", "", ipAddress)
	if err != nil {
		return SilentAuthenticationResult{}, err
	}
	o.auditLogger.Log(ctx, audit.EventBumpedUserSession, map[string]interface{}{
		"user_id":   authContext.UserId,
		"client_id": client.Id,
	})

	authContext.AuthState = ceremony.AuthStateReadyToIssueCode
	return SilentAuthenticationResult{SaveErr: browser.AddAuthContext(authContext)}, nil
}
