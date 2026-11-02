package authflow

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/i18n"
)

// manageAccountScope is authserver:manage-account as a request spells it: the scope the Account
// API takes.
const manageAccountScope = builtin.AuthServerResourceIdentifier + ":" + builtin.ManageAccountPermissionIdentifier

// ScopeInfo is one row of the consent screen: a scope the ceremony asks for, described in the
// request's locale, and whether the user's stored consent already covers it. The screen's checkbox
// for row i is named consent<i>, so the order of the rows is the order a submission is read in.
type ScopeInfo struct {
	Scope            string
	Description      string
	AlreadyConsented bool
}

// buildScopeInfoArray is the consent screen's rows for scope, in its order, each marked consented
// when consent holds it (consent may be nil). A claim scope and offline_access are described by
// their own message, authserver:manage-account in plain words, and every other resource permission
// by the generic template.
func buildScopeInfoArray(ctx context.Context, scope string, consent *record.UserConsent) []ScopeInfo {
	scopeInfoArr := []ScopeInfo{}

	if len(scope) == 0 {
		return scopeInfoArr
	}

	scopes := strings.Split(scope, " ")
	for _, scope := range scopes {
		switch {
		case oidc.IsClaimScope(scope) || oidc.IsOfflineAccessScope(scope):
			scopeInfoArr = append(scopeInfoArr, ScopeInfo{
				Scope:            scope,
				Description:      i18n.T(ctx, oidc.ScopeDescriptionKey(scope)),
				AlreadyConsented: consent != nil && consent.HasScope(scope),
			})
		case scope == manageAccountScope:
			// A client asking for this scope asks to edit the user's account through the Account API,
			// which the generic template would not say (#509 decision 4).
			scopeInfoArr = append(scopeInfoArr, ScopeInfo{
				Scope:            scope,
				Description:      i18n.T(ctx, "consent.scope.authserver_manage_account.description"),
				AlreadyConsented: consent != nil && consent.HasScope(scope),
			})
		default:
			// resource-permission
			parts := strings.Split(scope, ":")
			scopeInfoArr = append(scopeInfoArr, ScopeInfo{
				Scope: scope,
				Description: i18n.T(ctx, "consent.scope.permission_template",
					map[string]any{"permission": parts[1], "resource": parts[0]}),
				AlreadyConsented: consent != nil && consent.HasScope(scope),
			})
		}
	}
	return scopeInfoArr
}

// consentScreenOwed answers whether GET /auth/consent renders the screen rather than going straight
// on to issuance. It is shown when:
//   - the client does not remember consent (record.Client's RemembersConsent), a public client
//     with Remember consent off: nothing proves the request comes from the app the user approved,
//     so it is processed as if no previous request had been approved (RFC 6749 section 10.2, RFC
//     8252 section 8.6; #711 decision 2), OR
//   - not every requested scope is already consented, OR
//   - offline_access is requested (a refresh token grant is always re-confirmed), OR
//   - prompt=consent was explicitly requested (force consent UI).
func consentScreenOwed(scopes []ScopeInfo, scope string, promptConsent, remembersConsent bool) bool {
	fullyConsented := true
	for _, scopeInfo := range scopes {
		fullyConsented = fullyConsented && scopeInfo.AlreadyConsented
	}
	return !remembersConsent || !fullyConsented || oidc.HasOfflineAccessScope(scope) || promptConsent
}

// consentApproved reads the submission's action from the submitted body, which the handler hands
// over as r.PostForm.
//
// Both action controls are read from the body alone: this form posts to action="", so r.Form would
// merge the URL query in, and a button that was not clicked sends no key at all. Read from r.Form,
// a consent screen reached at /auth/consent?btnSubmit=submit would turn the user's click on Cancel
// into a grant of every box the form still had checked (#79).
//
// Approval needs the submit control alone. A body carrying both, which no browser sends, is
// refused rather than resolved in favour of granting.
func consentApproved(body url.Values) bool {
	return body.Get("btnSubmit") == "submit" && !body.Has("btnCancel")
}

// tickedScopes is the scopes whose checkbox the submitted body carries, in the ceremony's order.
//
// The checkbox names are positional, consent0 .. consentN, so the key is matched exactly: a
// substring match finds "consent1" inside "consent10" and grants a scope the user unchecked, from 11
// scopes upwards (#79).
//
// It takes the body alone, for consentApproved's reason: a crafted /auth/consent?consent5=on must
// not count as a tick.
func tickedScopes(body url.Values, scopes []ScopeInfo) []string {
	ticked := make([]string, 0, len(scopes))
	for idx, scopeInfo := range scopes {
		if body.Has(fmt.Sprintf("consent%d", idx)) {
			ticked = append(ticked, scopeInfo.Scope)
		}
	}
	return ticked
}

// consentSubmissionFact is a fact decideConsentSubmission needs and has not been given.
// ConsentSubmission.Run loads it and asks again.
type consentSubmissionFact int

const (
	// consentSubmissionFactNone means the answer is decided.
	consentSubmissionFactNone consentSubmissionFact = iota
	// consentSubmissionFactHeldScope is the ticked selection narrowed to the permissions the user
	// holds now.
	consentSubmissionFactHeldScope
)

// consentSubmissionAnswer is how a consent submission is answered.
type consentSubmissionAnswer int

const (
	// consentSubmissionUndecided is returned beside a fact still to load.
	consentSubmissionUndecided consentSubmissionAnswer = iota
	// consentSubmissionDeclined answers access_denied for a cancel.
	consentSubmissionDeclined
	// consentSubmissionNothingTicked answers access_denied, as a cancel does, for an approval
	// ticking no scope.
	consentSubmissionNothingTicked
	// consentSubmissionNothingHeld answers access_denied for a selection holding no scope the user
	// still has.
	consentSubmissionNothingHeld
	// consentSubmissionGranted records the consent and goes on to issuance.
	consentSubmissionGranted
)

// consentSubmissionFacts is what decideConsentSubmission decides from. The held scope is nil
// until ConsentSubmission.Run has loaded it.
type consentSubmissionFacts struct {
	approved bool
	// ticked is the scopes the user ticked, read only for an approval.
	ticked    []string
	heldScope *string
}

// decideConsentSubmission decides how a consent submission is answered, or names the next fact it
// needs to decide that. In order of precedence:
//
//  1. A cancel is declined.
//  2. An approval ticking nothing is refused as a cancel is. Refusal is decided by what was
//     consented to, not by whether a key named consent... arrived: an empty consented scope reaches
//     the issuers as "no consent screen was shown", which they answer with the full requested
//     scope (#79).
//  3. The held scope is asked for, only now, so a refusal the user chose reads no permission.
//  4. A selection holding nothing the user still has is refused (#241 decision 3).
//  5. Otherwise the consent is granted.
func decideConsentSubmission(f consentSubmissionFacts) (consentSubmissionAnswer, consentSubmissionFact) {
	if !f.approved {
		return consentSubmissionDeclined, consentSubmissionFactNone
	}
	if len(f.ticked) == 0 {
		return consentSubmissionNothingTicked, consentSubmissionFactNone
	}
	if f.heldScope == nil {
		return consentSubmissionUndecided, consentSubmissionFactHeldScope
	}
	if *f.heldScope == "" {
		return consentSubmissionNothingHeld, consentSubmissionFactNone
	}
	return consentSubmissionGranted, consentSubmissionFactNone
}
