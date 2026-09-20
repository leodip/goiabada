// Package oauth is the OAuth2/OIDC surface both processes share: the value types that
// cross the wire or a session (TokenResponse, JwtInfo, JwtToken, Jwk, Jwks), the PKCE
// challenge helper and the response_type parser. It reaches no database and no
// persistence type, which is what lets the admin console link it without linking a
// driver.
//
// The client side of the protocol is no longer here. The JWKS token parser, the
// code-for-token exchanger and the two bounds they share went to
// adminconsole/internal/oauthclient in #385, with the authorize redirect that starts the
// ceremony: one application speaks that half, so a shared package was hiding its
// implementation.
//
// ParseResponseType sits here although only the auth server calls it. Its one other
// caller was core/validators, which the admin console linked for unrelated helpers, so
// moving this dependency-free file to the provider side would have dragged the data layer and
// all four drivers into the admin console's binary. #344 removed that caller and nothing
// in core names ParseResponseType any more, but the conclusion stands on the reason
// beside it: since #339 put code and token issuance and key rotation under
// authserver/internal, that edge is not merely expensive but refused, because core may
// not import the auth server at all and ARCHITECTURE.md's module direction rule fails the
// tier that tries. What belongs here is decided by what each binary ends up containing
// rather than by which process names the symbol (#338, #339, #344).
package oauth

import (
	"crypto/sha256"
	"encoding/base64"
)

func GeneratePKCECodeChallenge(codeVerifier string) string {
	bytes := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(bytes[:])
}
