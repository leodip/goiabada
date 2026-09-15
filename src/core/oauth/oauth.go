// Package oauth is the OAuth2/OIDC surface both processes share: the value types that
// cross the wire or a session (TokenResponse, JwtInfo, JwtToken, Jwk, Jwks), the client
// side of the protocol (the JWKS token parser and the code-for-token exchanger), and the
// PKCE challenge helper. It reaches no database and no persistence type, which is what
// lets the admin console link it without linking a driver.
//
// Provider-side issuance -- authorization codes, tokens and signing keys -- is
// core/oauthprovider (#338).
package oauth

import (
	"crypto/sha256"
	"encoding/base64"
)

func GeneratePKCECodeChallenge(codeVerifier string) string {
	bytes := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(bytes[:])
}
