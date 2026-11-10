package emaillinks

import (
	"net/url"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
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

// ForgotPasswordPath is the page a user asks for a reset link from. It carries no code, and the
// notice self-registration mails an existing account points at it (#207 decision 5), so the
// notice's link and the route are one constant.
const ForgotPasswordPath = "/forgot-password"

// ResetPasswordLink builds the password reset link emailed to a user, under the auth
// server's public base URL, which the caller is handed at construction (#434).
//
// The link carries the verification code, and no address. It used to carry the
// address too, as ?email=<address>&code=<code>, which broke every address holding a
// '+' or a '%' followed by two hex digits: Go parses a query with
// form-urlencoded rules (WHATWG URL Standard section 5.1), where '+' decodes to a
// space, so the address came back mangled and the lookup failed. Carrying only the
// code removes the defect class rather than escaping around it, because the code's
// alphabet is entirely RFC 3986 unreserved (#112).
//
// ceremonyId is the sign-in the forgot-password page's URL named, through the password
// page's Forgot password? link, so that resetting in the browser that holds it carries
// that sign-in on into the app, as an activation does (#812 decisions 9 and 10). Empty
// for a request made on a page naming none, and for the setup link an administrator
// sends a new user, whose links carry the code alone. The id's alphabet is RFC 3986
// unreserved too.
func ResetPasswordLink(baseURL, code, ceremonyId string) string {
	return baseURL + linkWithSignIn(ResetPasswordPath, code, ceremonyId)
}

// ResetPasswordContinuation is where the reset link's first hop sends the browser:
// ResetPasswordPath with the code gone and the sign-in the link carried kept, or with no
// query when it carried none.
func ResetPasswordContinuation(ceremonyId string) string {
	return continuationWithSignIn(ResetPasswordPath, ceremonyId)
}

// AccountActivateLink builds the account activation link emailed to someone who has
// just self-registered. Same shape and same reasoning as ResetPasswordLink, but for
// ceremonyId: the sign-in the registration came from, through the password page's
// Create an account link, so activating in the browser that holds it carries that
// sign-in on into the app (#622 decision 9). Empty for a registration reached from
// anywhere else, whose link carries the code alone. The id's alphabet is RFC 3986
// unreserved too.
func AccountActivateLink(baseURL, code, ceremonyId string) string {
	return baseURL + linkWithSignIn(AccountActivatePath, code, ceremonyId)
}

// AccountActivateContinuation is where the activation link's first hop sends the
// browser: AccountActivatePath with the code gone and the sign-in the link carried
// kept, or with no query when it carried none.
func AccountActivateContinuation(ceremonyId string) string {
	return continuationWithSignIn(AccountActivatePath, ceremonyId)
}

// linkWithSignIn is path with the code, and the sign-in when ceremonyId is not empty, as
// its query: the shape both emailed links share.
func linkWithSignIn(path, code, ceremonyId string) string {
	if ceremonyId == "" {
		return path + "?" + codeQuery(code)
	}
	return path + "?" + url.Values{"code": {code}, ceremony.QueryParameter: {ceremonyId}}.Encode()
}

// continuationWithSignIn is path with the sign-in alone as its query, or bare when
// ceremonyId is empty: where both links' first hops send the browser once the code is
// dropped.
func continuationWithSignIn(path, ceremonyId string) string {
	if ceremonyId == "" {
		return path
	}
	return path + "?" + url.Values{ceremony.QueryParameter: {ceremonyId}}.Encode()
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
