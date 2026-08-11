package handlers

import (
	"net/url"

	"github.com/leodip/goiabada/core/config"
)

// ResetPasswordPath and AccountActivatePath are the paths of the two endpoints an
// emailed link points at.
//
// They are constants rather than literals at each site because the link and the
// endpoint's own redirect target have to agree: both flows validate the code on the
// first request and then redirect to the same path with no query, so the shape is
// stated in two places and a drift between them breaks the flow silently (#112).
const ResetPasswordPath = "/reset-password"
const AccountActivatePath = "/account/activate"

// ResetPasswordLink builds the password reset link emailed to a user.
//
// The link carries the verification code and nothing else. It used to carry the
// address too, as ?email=<address>&code=<code>, which broke every address holding a
// '+' or a '%' followed by two hex digits: Go parses a query with
// form-urlencoded rules (WHATWG URL Standard section 5.1), where '+' decodes to a
// space, so the address came back mangled and the lookup failed. Carrying only the
// code removes the defect class rather than escaping around it, because the code's
// alphabet is entirely RFC 3986 unreserved (#112).
func ResetPasswordLink(code string) string {
	return config.GetAuthServer().BaseURL + ResetPasswordPath + "?" + codeQuery(code)
}

// AccountActivateLink builds the account activation link emailed to someone who has
// just self-registered. Same shape and same reasoning as ResetPasswordLink.
func AccountActivateLink(code string) string {
	return config.GetAuthServer().BaseURL + AccountActivatePath + "?" + codeQuery(code)
}

// codeQuery encodes the one query parameter both links carry.
//
// url.Values rather than concatenation, even though it is a no-op for every code
// GenerateSecurityRandomString can produce: those 65 characters are a strict subset
// of RFC 3986 unreserved, so there is nothing to escape today. It is here so that a
// caller passing a value from anywhere else cannot rebuild #112 by putting a '+'
// back into a query string. The round-trip test is what keeps that true.
func codeQuery(code string) string {
	return url.Values{"code": {code}}.Encode()
}
