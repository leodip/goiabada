package handlers

import (
	"testing"

	"github.com/leodip/goiabada/core/testutil"
)

// TestHandlers_NoCredentialQueryFallback is the admin console half of the guard #202 asked for. Its
// authserver twin lives at src/authserver/internal/handlers/credential_read_lint_test.go with a
// deliberately different name list, for the reason spelled out below.
// testutil.AssertNoCredentialQueryFallback carries the walk, the four accessor shapes it refuses and
// the reasoning for each; what stays here is this module's policy, which is the half that must
// differ between the two (#333).
//
// This module carries the whole weight of the guard, which is why it exists at all. The admin
// console has no handler tests: its seven test_main_test.go files are stubs and the only real
// handler test is adminclienthandlers/handler_admin_client_redirect_uris_test.go, so the sixteen
// reads this file covers have no behavioural instrument available. That is the same gap #155 left
// behind and csrf_lint_test.go was written to cover, in the same module, for the same reason.
// Building this module's first handler harness would outlive this change and is drafted as a
// follow-up rather than done here.
//
// The list below is this module's, not a shared one, and it is the longer of the two. It carries
// "code", "state", "error" and "error_description" on top of the ten credential names because this
// module has no authorization endpoint: those four reach it only at /auth/callback, which
// auth_helper.go arranges by asking for response_mode=form_post precisely so they arrive in a body,
// and which is registered POST-only. The authserver's list must not carry "state", because
// handler_authorize.go reads .FormValue("state") legitimately: OIDC Core 3.1.2.1 requires the
// authorization endpoint to accept both GET and POST, so there that name has a lawful query source.
//
// The walk is this module's internal/ tree, so a credential read that appeared in src/core would be
// seen by neither this file nor its authserver twin. No such read exists today: the only .FormValue
// reads in core are the rate limiter's own "email" and "username" account keys, which are
// deliberately absent from the list below because they are not credentials and because the limiter
// and the handler it protects must keep reading the account name the same way (#219).
//
// handlers and middleware are named again beneath that tree as coverage floors. They are the two
// trees in this module whose code is handed an *http.Request: handlers holds every credential read
// there is, and middleware is where a form read would be just as invisible and just as unguarded by
// anything else. Naming them means a rename or a move that empties either one fails here instead of
// shrinking the walk in silence.
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
		// The four form_post arrivals at /auth/callback. The authorization code is a
		// credential on the same terms as the rest; state, error and error_description travel
		// with it and are read in the same function, so splitting them would leave four reads
		// in one place divided two ways with nothing saying why.
		`"code"`,
		`"state"`,
		`"error"`,
		`"error_description"`,
	}

	testutil.AssertNoCredentialQueryFallback(t, forbidden,
		"adminconsole/internal",
		"adminconsole/internal/handlers",
		"adminconsole/internal/middleware")
}
