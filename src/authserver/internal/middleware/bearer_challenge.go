package middleware

import (
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/core/oauth"
)

// BearerRealm is the realm every bearer challenge this server writes carries. One value, because
// /userinfo and the admin and account APIs accept the same access tokens: RFC 9110 section 11.5
// defines a protection space as the origin plus the realm, and these routes are one protection
// space. The realm is also what gives a challenge with no error an auth-param at all, which
// RFC 6750 section 3 requires of every Bearer challenge ("MUST be followed by one or more
// auth-param values") (#435). Its one definition is protocolvalidation.ChallengeRealm, which the token
// endpoint's Basic challenge reads too, so the two cannot name two realms (#437).
const BearerRealm = protocolvalidation.ChallengeRealm

// BearerChallenge builds the WWW-Authenticate value for a bearer refusal: `Bearer
// realm="goiabada"`, then `error="<errorCode>"` when errorCode is set, then
// `error_description="<description>"` when both are.
//
// errorCode empty is the challenge for a request carrying no bearer credential, which RFC 6750
// section 3.1 says SHOULD NOT include an error code or other error information; the description is
// then dropped with it.
//
// Every attribute value is written as a quoted-string, which RFC 9110 section 11.5 requires of the
// realm ("a sender MUST only generate the quoted-string syntax"). The description passes through
// oauth.ConformErrorDescription, which is RFC 6750 section 3's own set for error_description
// (%x20-21 / %x23-5B / %x5D-7E) and excludes both the double quote and the backslash, so no value
// can end the quoted-string early or smuggle an escape into the header. errorCode is always one of
// RFC 6750 section 3.1's three codes, chosen by this server.
func BearerChallenge(errorCode, description string) string {
	challenge := `Bearer realm="` + BearerRealm + `"`
	if errorCode == "" {
		return challenge
	}
	challenge += `, error="` + errorCode + `"`
	if description != "" {
		challenge += `, error_description="` + oauth.ConformErrorDescription(description) + `"`
	}
	return challenge
}

// InsufficientScopeChallenge is the insufficient_scope challenge with RFC 6750 section 3's scope
// attribute, naming the scope that would be enough. It is for a refusal whose remedy is one
// particular scope rather than whichever of a route's scopes: the administrative policy's
// MANAGE_SCOPE_REQUIRED, which no granular scope will ever satisfy (#402 decision 4).
//
// scope is chosen by this server, never by a request, and section 3's scope-token is
// %x21 / %x23-5B / %x5D-7E, which every scope this server names is spelled in.
func InsufficientScopeChallenge(description, scope string) string {
	return BearerChallenge("insufficient_scope", description) + `, scope="` + scope + `"`
}
