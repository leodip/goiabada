package protocolvalidation

import "github.com/leodip/goiabada/core/customerrors"

// NewErrorDetailWithHttpStatusCodeAndWWWAuthenticate builds an ErrorDetail carrying a
// WWW-Authenticate challenge. Per RFC 6749 section 5.2, a client that attempted to authenticate
// through the Authorization header and failed must be answered 401 with that header, and per
// RFC 6750 section 3 a bearer-token failure at a protected resource carries one too.
//
// It lives on the provider side rather than in core/customerrors because issuing a challenge is
// provider-side by definition: the admin console is a client of this protocol and never emits one
// (#385 decision 17). It sits here, beside the token validator that answers most of its challenges,
// rather than in apiresponse, which writes the admin API's envelope and nothing a protocol endpoint
// answers (#435). The result is still a *customerrors.ErrorDetail, so JsonError and errors.Is
// behave exactly as they did when the four-argument constructor stood in core, entry for entry.
func NewErrorDetailWithHttpStatusCodeAndWWWAuthenticate(code string, description string,
	httpStatusCode int, wwwAuthenticate string) *customerrors.ErrorDetail {
	return customerrors.NewErrorDetailWithHttpStatusCode(code, description, httpStatusCode).
		WithWWWAuthenticate(wwwAuthenticate)
}
