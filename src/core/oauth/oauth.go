// Package oauth is the OAuth2/OIDC surface both processes share: the value types that
// cross the wire or a session (TokenResponse, JwtInfo, JwtToken, Jwk, Jwks), the client
// side of the protocol (the JWKS token parser and the code-for-token exchanger), the
// PKCE challenge helper and the response_type parser. It reaches no database and no
// persistence type, which is what lets the admin console link it without linking a
// driver.
//
// ParseResponseType sits here although only the auth server calls it directly.
// core/validators calls it as well, and the admin console links core/validators for
// unrelated helpers, so on the provider side this one dependency-free file drags
// core/oauthprovider -- and through it core/data and all four drivers -- into the admin
// console's binary. What belongs here is decided by what each binary ends up containing
// rather than by which process names the symbol (#338).
//
// Provider-side issuance -- authorization codes, tokens and signing keys -- is
// core/oauthprovider (#338).
package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"time"
)

// TokenExchangeTimeout bounds one call the admin console makes to the auth server, and
// MaxTokenResponseBytes bounds how much of the answer is read. Both take the values the
// admin console already applies to the same endpoint: SessionTokenSource in
// adminconsole/internal/apiclient/session_client.go performs a client_credentials exchange
// against /auth/token with exactly this timeout and this limit, and its sibling
// session_backend.go writes down the reason for the ten seconds -- a lookup on the request
// path of every page has to become an error quickly rather than holding the browser open.
// Three calls doing the same thing against the same endpoint must not carry three different
// numbers.
//
// Neither is configuration. A new environment variable is a name the product has to keep,
// and nothing here needs tuning per deployment: a deployment where these bite was already
// failing at session_backend.go (#338).
const (
	TokenExchangeTimeout  = 10 * time.Second
	MaxTokenResponseBytes = 1 << 20
)

func GeneratePKCECodeChallenge(codeVerifier string) string {
	bytes := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(bytes[:])
}
