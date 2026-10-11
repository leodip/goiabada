package userconsent

import (
	"slices"

	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/builtin"
)

// manageAccountScope is authserver:manage-account as a request and a token spell it: the scope the
// Account API takes.
const manageAccountScope = builtin.AuthServerResourceIdentifier + ":" + builtin.ManageAccountPermissionIdentifier

// AlwaysOwed is the scopes of scope that a client gets only once the user's stored consent to it
// covers them, whatever the client's ConsentRequired says: authserver:manage-account, to every
// client but the admin console's, or none. scope is what is about to be granted, after the user's
// permissions have narrowed it, space delimited as a ceremony carries it.
//
// Every user holds manage-account from creation, and a token carrying it edits the user's account
// through the Account API, so a client with Consent required off could otherwise obtain one for any
// signed-in user, administrators included, with no screen shown (#509 decision 1). The admin
// console's client is matched by its built-in identifier, as
// record.Client.MayRequestAdministrativeScopes matches it, so an edited row cannot change who skips;
// a client allowed the administrative scopes under #499 is asked like any other (decision 2).
func AlwaysOwed(clientIdentifier string, scope string) []string {
	if clientIdentifier == builtin.AdminConsoleClientIdentifier {
		return nil
	}
	if slices.Contains(oidc.SplitScope(scope), manageAccountScope) {
		return []string{manageAccountScope}
	}
	return nil
}

// Covers reports whether consent, nil for none, holds every one of scopes. Nothing owed is covered
// by any consent, none included.
func Covers(consent *record.UserConsent, scopes []string) bool {
	for _, scope := range scopes {
		if consent == nil || !consent.HasScope(scope) {
			return false
		}
	}
	return true
}
