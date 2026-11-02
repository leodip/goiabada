package authflow

import (
	"context"
	"database/sql"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/legaldocuments"
	"github.com/leodip/goiabada/authserver/internal/record"
)

// legalDocumentsOwed answers the must-accept legal documents a user owes the acceptance step on a
// sign-in to client: in effect for it, whose current version the user has not accepted. The admin
// console's own client owes none (#622). *legaldocuments.Reader satisfies it.
type legalDocumentsOwed interface {
	Owed(ctx context.Context, client *record.Client, userId int64) ([]legaldocuments.InEffect, error)
}

// consentReader reads the user's stored consent to a client.
type consentReader interface {
	GetConsentByUserIdAndClientId(ctx context.Context, tx *sql.Tx, userId int64, clientId int64) (*record.UserConsent, error)
}

// routeBoundCeremony decides where a ceremony bound to a session goes (decideAfterBinding), loading
// each fact it asks for: the scope narrowed to what the user holds, which replaces the ceremony's,
// and the user's stored consent. Completion asks it once the ceremony is bound, and the acceptance
// step asks it again once nothing is owed, since the consent and the user's permissions can have
// changed while the step was shown.
func routeBoundCeremony(ctx context.Context, database consentReader, scopes scopeFilter,
	authContext *ceremony.AuthContext, client *record.Client, user *record.User) (afterBindingAnswer, error) {

	facts := afterBindingFacts{
		PromptConsent:    authContext.HasPromptValue("consent"),
		ConsentRequired:  client.ConsentRequired,
		ClientIdentifier: client.ClientIdentifier,
		RemembersConsent: client.RemembersConsent(),
	}
	answer, need := decideAfterBinding(facts)
	for need != afterBindingFactNone {
		switch need {
		case afterBindingFactEffectiveScope:
			effectiveScope, err := scopes.FilterOutScopesWhereUserIsNotAuthorized(ctx, authContext.Scope, user)
			if err != nil {
				return afterBindingUndecided, err
			}
			authContext.SetScope(effectiveScope)
			scope := authContext.Scope
			facts.EffectiveScope = &scope
		case afterBindingFactConsent:
			consent, err := database.GetConsentByUserIdAndClientId(ctx, nil, user.Id, client.Id)
			if err != nil {
				return afterBindingUndecided, err
			}
			facts.ConsentLoaded = true
			facts.Consent = consent
		}
		answer, need = decideAfterBinding(facts)
	}
	return answer, nil
}

// moveBoundCeremonyOn answers routeBoundCeremony's answer: a user holding none of the scopes is
// answered access_denied once the ceremony is cleared, and otherwise the ceremony is saved towards
// /auth/consent or /auth/issue. It answers the next step, or the client's error, and the save's or
// the clear's failure.
func moveBoundCeremonyOn(answer afterBindingAnswer, browser legalAcceptanceBrowser,
	authContext *ceremony.AuthContext, client *record.Client) (string, *ClientError, error) {

	switch answer {
	case afterBindingNoScope:
		return "", &ClientError{Client: client, Code: "access_denied",
				Description: "The user is not authorized to access any of the requested scopes"},
			browser.ClearAuthContext(authContext.CeremonyId)
	case afterBindingConsent:
		authContext.AuthState = ceremony.AuthStateRequiresConsent
		return "/auth/consent", nil, browser.SaveAuthContext(authContext)
	default:
		authContext.AuthState = ceremony.AuthStateReadyToIssueCode
		return "/auth/issue", nil, browser.SaveAuthContext(authContext)
	}
}

// legalAcceptanceBrowser is the two browser-session writes a bound ceremony makes on its way on: the
// save that moves it to its next step, and the clear that ends a refused one.
type legalAcceptanceBrowser interface {
	stepSaver
	ceremonyClearer
}
