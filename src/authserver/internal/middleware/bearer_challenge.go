package middleware

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/clientauth"
	"github.com/leodip/goiabada/authserver/internal/dpop"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/oauth"
)

// BearerRealm is the realm every bearer challenge this server writes carries. One value, because
// /userinfo and the admin and account APIs accept the same access tokens: RFC 9110 section 11.5
// defines a protection space as the origin plus the realm, and these routes are one protection
// space. The realm is also what gives a challenge with no error an auth-param at all, which
// RFC 6750 section 3 requires of every Bearer challenge ("MUST be followed by one or more
// auth-param values") (#435). Its one definition is clientauth.ChallengeRealm, which the Basic
// challenge on every invalid_client reads too, so the two cannot name two realms (#437). The DPoP
// challenge names the same realm, since the two schemes guard the same routes.
const BearerRealm = clientauth.ChallengeRealm

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
// can end the quoted-string early or smuggle an escape into the header. errorCode is always chosen
// by this server: one of RFC 6750 section 3.1's three codes, RFC 9449's invalid_dpop_proof, or
// RFC 9470's insufficient_user_authentication through stepUpChallenges.
func BearerChallenge(errorCode, description string) string {
	return `Bearer realm="` + BearerRealm + `"` + challengeError(errorCode, description)
}

// dpopChallenge builds the DPoP challenge RFC 9449 section 7.1 defines: `DPoP realm="goiabada",
// algs="…"`, the algs parameter listing the algorithms a proof may be signed with (#42 decision 4),
// then the error and its description as BearerChallenge writes them. Section 7.1 lets every
// parameter be present or not; algs is its SHOULD.
func dpopChallenge(errorCode, description string) string {
	return `DPoP realm="` + BearerRealm + `", algs="` + strings.Join(dpop.SigningAlgorithms(), " ") + `"` +
		challengeError(errorCode, description)
}

// challengeError is a challenge's error parameters, as BearerChallenge's comment describes them.
func challengeError(errorCode, description string) string {
	if errorCode == "" {
		return ""
	}
	params := `, error="` + errorCode + `"`
	if description != "" {
		params += `, error_description="` + oauth.ConformErrorDescription(description) + `"`
	}
	return params
}

// schemes is the set of authentication schemes a request presented an access token with: RFC 6750's
// Bearer, in the Authorization header or the form body, and RFC 9449's DPoP, in the header only.
type schemes uint8

const (
	schemeBearer schemes = 1 << iota
	schemeDPoP
)

// schemesOf is the scheme of the token a guard behind the parse guard reads: DPoP when the parse
// guard accepted a proof beside it, Bearer otherwise. A request that used both was refused before.
func schemesOf(ctx context.Context) schemes {
	if _, ok := reqctx.DPoPProofFrom(ctx); ok {
		return schemeDPoP
	}
	return schemeBearer
}

// unauthorizedChallenges is the WWW-Authenticate value of a 401: a Bearer challenge, then a DPoP
// challenge, in one field line, the error in the challenge of each scheme used (RFC 9449 section
// 7.2, #42 decision 10). With no error, as for a request carrying no credential, both name the
// realm alone (RFC 6750 section 3.1). The resource accepts both schemes, so every 401 says so.
func unauthorizedChallenges(used schemes, errorCode, description string) string {
	bearerCode, bearerDescription, dpopCode, dpopDescription := "", "", "", ""
	if used&schemeBearer != 0 {
		bearerCode, bearerDescription = errorCode, description
	}
	if used&schemeDPoP != 0 {
		dpopCode, dpopDescription = errorCode, description
	}
	return BearerChallenge(bearerCode, bearerDescription) + ", " + dpopChallenge(dpopCode, dpopDescription)
}

// usedChallenges is the WWW-Authenticate value of a 400 or a 403: the challenge of each scheme the
// request used, Bearer first, each carrying the error, as RFC 9449 section 7.2 has a resource
// deliver error information in the challenge of the mechanism used. A request that used neither, a
// body that does not parse with no Authorization header, keeps the Bearer challenge it had before
// DPoP, so no Bearer refusal changes.
func usedChallenges(used schemes, errorCode, description string) string {
	var challenges []string
	if used&schemeBearer != 0 || used == 0 {
		challenges = append(challenges, BearerChallenge(errorCode, description))
	}
	if used&schemeDPoP != 0 {
		challenges = append(challenges, dpopChallenge(errorCode, description))
	}
	return strings.Join(challenges, ", ")
}

// UnauthorizedChallenge is the WWW-Authenticate value of a 401 a handler behind the bearer guards
// answers, such as /userinfo's for a user who is gone: both challenges, the error in the scheme the
// request's token was presented with, as the guards' own 401s.
func UnauthorizedChallenge(ctx context.Context, errorCode, description string) string {
	return unauthorizedChallenges(schemesOf(ctx), errorCode, description)
}

// InsufficientScopeChallenge is the insufficient_scope challenge with RFC 6750 section 3's scope
// attribute, naming the scope that would be enough, in the scheme the request's token was presented
// with. It is for a refusal whose remedy is one particular scope rather than whichever of a route's
// scopes: the administrative policy's MANAGE_SCOPE_REQUIRED, which no granular scope will ever
// satisfy (#402 decision 4). RFC 9449 section 7.1 lets a DPoP challenge carry scope too.
//
// scope is chosen by this server, never by a request, and section 3's scope-token is
// %x21 / %x23-5B / %x5D-7E, which every scope this server names is spelled in.
func InsufficientScopeChallenge(ctx context.Context, description, scope string) string {
	return usedChallenges(schemesOf(ctx), "insufficient_scope", description) + `, scope="` + scope + `"`
}

// stepUpChallenges is the WWW-Authenticate value of RFC 9470 section 3's 401: both challenges, as
// unauthorizedChallenges writes them, the challenge of the scheme used carrying
// insufficient_user_authentication, then the acr_values and max_age attributes, the authentication
// level and the age in whole seconds a new sign-in must meet. Section 3 defines the code and both
// attributes for the Bearer scheme and for RFC 9449's DPoP alike. Both attributes are always
// written, so a client signs the user in once and meets both.
//
// acrValues is chosen by this server, never by a request, and its levels are URNs, which hold no
// double quote or backslash; maxAge is written as a quoted decimal, as the section's own example
// writes it.
func stepUpChallenges(used schemes, description, acrValues string, maxAge time.Duration) string {
	const errorCode = "insufficient_user_authentication"
	requirements := `, acr_values="` + acrValues + `", max_age="` + strconv.FormatInt(int64(maxAge/time.Second), 10) + `"`
	bearerValue, dpopValue := BearerChallenge("", ""), dpopChallenge("", "")
	if used&schemeBearer != 0 {
		bearerValue = BearerChallenge(errorCode, description) + requirements
	}
	if used&schemeDPoP != 0 {
		dpopValue = dpopChallenge(errorCode, description) + requirements
	}
	return bearerValue + ", " + dpopValue
}
