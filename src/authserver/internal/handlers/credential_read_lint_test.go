package handlers

import (
	"testing"

	"github.com/leodip/goiabada/core/testutil"
)

// TestHandlers_NoCredentialQueryFallback is the authserver half of the guard #202 asked for. Its
// admin console twin lives at src/adminconsole/internal/handlers/credential_read_lint_test.go with
// a deliberately different name list, for the reason spelled out below.
// testutil.AssertNoCredentialQueryFallback carries the walk, the four accessor shapes it refuses and
// the reasoning for each; what stays here is this module's policy, which is the half that must
// differ between the two (#333).
//
// The instrument's honest limit, stated because it decides what this file is worth: it asserts a
// spelling is absent, not that the replacement is right. In this module the four behavioural cases
// in handler_auth_pwd_test.go, handler_auth_otp_test.go, handler_reset_password_test.go and
// accounthandlers/handler_account_register_test.go cover the replacement; the lint covers the
// spelling coming back.
//
// The list below is this module's, not a shared one. It must not carry "state": handler_authorize.go
// reads .FormValue("state") at two sites, and OIDC Core 3.1.2.1 requires the authorization endpoint
// to accept both GET and POST, so that name has a lawful query source here. The admin console has no
// such endpoint, which is why its list is the longer one.
//
// handlers and middleware are named again beneath the internal/ tree as coverage floors. They are
// the two trees in this module whose code is handed an *http.Request: handlers holds every
// credential read there is, and middleware is where a form read would be just as invisible and just
// as unguarded by anything else. Naming them means a rename or a move that empties either one fails
// here instead of shrinking the walk in silence.
//
// The rate limiter is not one of them. It lives in src/core/middleware, outside the walk of this
// file and of its admin console twin, and its own .FormValue("email") account keys are deliberately
// absent from the list below: an email address is not a credential, and the limiter and the handler
// it protects must keep reading the account name the same way or a case variant buys a fresh bucket
// (#219).
func TestHandlers_NoCredentialQueryFallback(t *testing.T) {
	// The ten credential-bearing names, as quoted literals. A value under any of them
	// authenticates, authorizes or configures on its own.
	forbidden := []string{
		`"password"`,
		`"passwordConfirmation"`,
		`"currentPassword"`,
		`"newPassword"`,
		`"newPasswordConfirmation"`,
		`"otp"`,
		`"secretKey"`,
		`"base64Image"`,
		`"verificationCode"`,
		`"clientSecret"`,
		// The four token-endpoint credentials handler_token.go reads from r.PostForm.Get. None
		// was on either list until #333, so all four could have regressed to .FormValue with
		// every tier green; the check that found the gap moved the "code" and "client_secret"
		// reads to .FormValue and the whole authserver internal tier stayed green, while the
		// same move on the already-listed "password" failed it.
		//
		// Unlike "state", none of them has a lawful query source at any endpoint this module
		// serves. The authorization code is an authorization *response* value, delivered to the
		// client "by adding the following parameters to the query component of the redirection
		// URI" (RFC 6749 4.1.2), and returned by the client in the token request "in the HTTP
		// request entity-body" (4.1.3) -- so the OIDC Core 3.1.2.1 GET allowance that protects
		// "state" at /auth/authorize does not reach it. code_verifier rides in that same request
		// (RFC 7636 4.5), refresh_token in the refresh request "in the HTTP request entity-body"
		// (RFC 6749 section 6), and client_secret is a client credential, of which RFC 6749
		// 2.3.1 says outright: "The parameters can only be transmitted in the request-body and
		// MUST NOT be included in the request URI."
		//
		// The closing delimiter is what makes "code" safe to list: the walk matches
		// .FormValue("code") and never .FormValue("code_challenge") or
		// .FormValue("code_challenge_method"), both of which handler_authorize.go reads
		// legitimately from the authorization request.
		`"code"`,
		`"code_verifier"`,
		`"refresh_token"`,
		`"client_secret"`,
		// The form-binding markers, read through their constants rather than a literal.
		// They authorize nothing alone, but a marker supplied by a URL is not a submission,
		// and reading one from a URL reintroduces the shape #201 removed from the reset
		// link one indirection later.
		"ceremonyIdField",
		"continuationIdField",
	}

	testutil.AssertNoCredentialQueryFallback(t, forbidden,
		"authserver/internal",
		"authserver/internal/handlers",
		"authserver/internal/middleware")
}
