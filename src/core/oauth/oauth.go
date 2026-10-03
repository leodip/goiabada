// Package oauth is the OAuth2/OIDC surface both processes share: the value types that
// cross the wire or a session (TokenResponse, JwtToken, Jwk, Jwks), the PKCE challenge
// helper, and the error response of RFC 6749 section 5.2 (ErrorDetail, with
// ConformErrorDescription, the Appendix A.8 rule its description is held to). It reaches no
// database and no persistence type, which is what lets the admin console link it without
// linking a driver. The error response is here because it belongs to the same specification
// as the token types, and every binary that links it links this package too.
//
// What belongs here is what both binaries name (#385). A symbol one process uses moves to
// that process, even where staying would save an import edge: the client side of the
// protocol, the JWKS token parser, the code-for-token exchanger and the authorize redirect,
// is adminconsole/internal/oauthclient's, and response_type parsing is in
// authserver/internal/protocolvalidation, where its only callers are. src/core/OWNERSHIP.md
// holds the rule per symbol, one row each, and the tier refuses a new symbol here that
// neither application names.
//
// IsWellFormedSpaceDelimited and SplitSpaceDelimited are the grammar and the splitter of the five
// space-delimited request parameters. They are here because core/i18n reads ui_locales through
// them in a middleware both processes mount, and the auth server reads scope, response_type,
// prompt and acr_values through them, so neither side can hold the rule alone (#244).
package oauth

import (
	"crypto/sha256"
	"encoding/base64"
)

func GeneratePKCECodeChallenge(codeVerifier string) string {
	bytes := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(bytes[:])
}
