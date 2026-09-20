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
// Why the kernel still needs a caller of its own, now that the read has left: both application
// callers walk their own module's internal/ tree, so nothing but this file reaches core. Until
// #385 this caller held JwtAuthorizationHeaderToContext in middleware_jwt.go, which reads a bearer
// token out of a form body -- correctly, with r.PostFormValue, and moved to r.FormValue it left
// the whole module tier green, which is the regression this caller was written to redden (#333).
// That middleware is now authserver/internal/middleware's and the name is on the auth server's
// list, where the same mutation reddens the auth server's tier instead.
//
// What this file refuses now is that read coming back to core. A kernel package compiled into
// both binaries has no business reading a credential off a form at all, so the list below is the
// shape of the thing rather than a site: an access_token read appearing anywhere under core is a
// package taking on one application's authentication, which is what #385 removed.
//
// A bearer token is the value the specifications are loudest about keeping out of a URL. RFC 6750
// section 2.3 says the URI query method "has a high likelihood of being logged" with the other
// parameters and SHOULD NOT be used where the header or the request body is available, and RFC 9700
// section 4.3.2 hardens that to "Clients MUST NOT pass access tokens in a URI query parameter".
// r.FormValue accepts exactly that request, because ParseForm merges the URL query behind the body,
// so the accessor is the whole of the difference between honouring those sentences and not.
//
// The list is one name. The other form read under core is deliberately absent for its own reason:
//
//   - handlerhelpers/http_helper.go reads a key its caller supplies, for the query-or-body lookup
//     RP-initiated logout needs (#109). It owns no credential policy, so a name listed here would
//     be enforced there by accident rather than by decision.
//
// core is named as the tree to walk and core/middleware beneath it as a coverage floor, so the read
// moving to another kernel package stays covered while a rename that empties core/middleware fails
// here instead of shrinking the walk in silence.
func TestMiddleware_NoCredentialQueryFallback(t *testing.T) {
	// The one credential-bearing name no kernel package may read from a form. A value under it
	// authorizes on its own: it is the access token a request is authenticated with.
	forbidden := []string{
		`"access_token"`,
	}

	testutil.AssertNoCredentialQueryFallback(t, forbidden,
		"core",
		"core/middleware")
}
