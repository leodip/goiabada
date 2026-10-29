package protocolvalidation

import "github.com/leodip/goiabada/core/oauth"

// NewErrorDetailWithHTTPStatusAndWWWAuthenticate builds an ErrorDetail carrying a
// WWW-Authenticate challenge. Per RFC 6749 section 5.2, a client that attempted to authenticate
// through the Authorization header and failed must be answered 401 with that header, and per
// RFC 6750 section 3 a bearer-token failure at a protected resource carries one too.
//
// It lives on the provider side rather than in core/oauth beside ErrorDetail because issuing a
// challenge is provider-side by definition: the admin console is a client of this protocol and
// never emits one (#385 decision 17). It sits here rather than in apiresponse, which writes the
// admin API's envelope and nothing a protocol endpoint answers (#435). The result is still a
// *oauth.ErrorDetail, so JSONError and errors.Is behave exactly as they did when the four-argument
// constructor stood in core, field for field. The Basic challenge on an invalid_client is built in
// clientauth, which this package imports, beside the realm both challenges share.
func NewErrorDetailWithHTTPStatusAndWWWAuthenticate(code string, description string,
	httpStatus int, wwwAuthenticate string) *oauth.ErrorDetail {
	return oauth.NewErrorDetailWithHTTPStatus(code, description, httpStatus).
		WithWWWAuthenticate(wwwAuthenticate)
}
