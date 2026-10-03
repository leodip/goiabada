package protocolvalidation

import "github.com/leodip/goiabada/core/oauth"

// ChallengeRealm is the realm of every challenge this server writes, the Basic challenge the token
// endpoint answers invalid_client with and the Bearer challenge of /userinfo and the admin and
// account APIs, which middleware.BearerRealm names. RFC 7617 section 2 makes the realm REQUIRED on a
// Basic challenge, RFC 6750 section 3 wants an auth-param on every Bearer one, and RFC 9110 section
// 11.5 defines a protection space as the origin plus the realm, so one value keeps this server one
// protection space. It is declared here rather than in middleware because middleware imports this
// package, never the reverse (#435, #437).
const ChallengeRealm = "goiabada"

// BasicChallenge is the WWW-Authenticate value on every invalid_client the token endpoint answers,
// whether the client sent its credentials in the Authorization header or in the form body. RFC 9110
// section 15.5.2 requires a challenge on every 401, and RFC 7617 section 2 a quoted realm on a Basic
// one; before #437 only a failed Basic attempt got one, and a bare "Basic" at that.
const BasicChallenge = `Basic realm="` + ChallengeRealm + `"`

// NewErrorDetailWithHTTPStatusAndWWWAuthenticate builds an ErrorDetail carrying a
// WWW-Authenticate challenge. Per RFC 6749 section 5.2, a client that attempted to authenticate
// through the Authorization header and failed must be answered 401 with that header, and per
// RFC 6750 section 3 a bearer-token failure at a protected resource carries one too.
//
// It lives on the provider side rather than in core/oauth beside ErrorDetail because issuing a
// challenge is provider-side by definition: the admin console is a client of this protocol and
// never emits one (#385 decision 17). It sits here, beside the token validator that answers most of its challenges,
// rather than in apiresponse, which writes the admin API's envelope and nothing a protocol endpoint
// answers (#435). The result is still a *oauth.ErrorDetail, so JSONError and errors.Is
// behave exactly as they did when the four-argument constructor stood in core, field for field.
func NewErrorDetailWithHTTPStatusAndWWWAuthenticate(code string, description string,
	httpStatus int, wwwAuthenticate string) *oauth.ErrorDetail {
	return oauth.NewErrorDetailWithHTTPStatus(code, description, httpStatus).
		WithWWWAuthenticate(wwwAuthenticate)
}
