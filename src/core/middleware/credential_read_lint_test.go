package middleware

import (
	"testing"

	"github.com/leodip/goiabada/core/testutil"
)

// TestMiddleware_NoCredentialQueryFallback is the kernel's caller of the guard #202 asked for. Its
// two application twins live at src/adminconsole/internal/handlers/credential_read_lint_test.go and
// src/authserver/internal/handlers/credential_read_lint_test.go, each with its own name list.
// testutil.AssertNoCredentialQueryFallback carries the walk, the four accessor shapes it refuses and
// the reasoning for each; what stays here is this tree's policy.
//
// Why the kernel needs a caller of its own: both application callers walk their own module's
// internal/ tree, so until this file existed no walk reached core at all, while
// JwtAuthorizationHeaderToContext in middleware_jwt.go reads a bearer token out of a form body.
// That read is correct -- it is r.PostFormValue -- and this file is the only thing holding it
// there. Moved to r.FormValue it left the whole module tier green, which is the regression this
// caller exists to redden (#333).
//
// A bearer token is the value the specifications are loudest about keeping out of a URL. RFC 6750
// section 2.3 says the URI query method "has a high likelihood of being logged" with the other
// parameters and SHOULD NOT be used where the header or the request body is available, and RFC 9700
// section 4.3.2 hardens that to "Clients MUST NOT pass access tokens in a URI query parameter".
// r.FormValue accepts exactly that request, because ParseForm merges the URL query behind the body,
// so the accessor is the whole of the difference between honouring those sentences and not.
//
// The list is one name because one name qualifies. The other form reads under core are deliberately
// absent, each for its own reason:
//
//   - middleware_ratelimiter.go reads "email" with r.FormValue and "username" with r.PostFormValue
//     as account keys. An account name is not a credential, and the limiter and the handler it
//     protects must keep reading it the same way or a variant buys a fresh bucket (#219).
//   - middleware_ratelimiter.go reads "grant_type" to decide whether the request is the ROPC one.
//     It selects a branch and authenticates nothing.
//   - handlerhelpers/http_helper.go reads a key its caller supplies, for the query-or-body lookup
//     RP-initiated logout needs (#109). It owns no credential policy, so a name listed here would
//     be enforced there by accident rather than by decision.
//
// core is named as the tree to walk and core/middleware beneath it as a coverage floor, so the read
// moving to another kernel package stays covered while a rename that empties core/middleware fails
// here instead of shrinking the walk in silence.
func TestMiddleware_NoCredentialQueryFallback(t *testing.T) {
	// The one credential-bearing name the kernel reads from a form. A value under it authorizes on
	// its own: it is the access token the request is authenticated with.
	forbidden := []string{
		`"access_token"`,
	}

	testutil.AssertNoCredentialQueryFallback(t, forbidden,
		"core",
		"core/middleware")
}
