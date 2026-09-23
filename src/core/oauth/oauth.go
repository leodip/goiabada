// Package oauth is the OAuth2/OIDC surface both processes share: the value types that
// cross the wire or a session (TokenResponse, JwtToken, Jwk, Jwks) and the PKCE
// challenge helper. It reaches no database and no persistence type, which is what lets
// the admin console link it without linking a driver.
//
// The client side of the protocol is no longer here. The JWKS token parser, the
// code-for-token exchanger and the two bounds they share went to
// adminconsole/internal/oauthclient in #385, with the authorize redirect that starts the
// ceremony: one application speaks that half, so a shared package was hiding its
// implementation.
//
// What belongs here is what both binaries name. That is the rule #385 replaced the
// earlier one with, and it is stricter: the old rule asked what each binary ends up
// containing, so a symbol only the auth server called could stay as long as moving it
// would have cost an import edge. response_type parsing stayed on exactly that argument
// and is now in authserver/internal/protocolvalidation, where its only callers are.
//
// The cost the old rule was buying off has not gone away, and the answer to it is that a
// symbol one process uses moves to that process rather than staying behind a cheaper
// import. src/core/OWNERSHIP.md carries the per-symbol version of this, one row each,
// and the tier refuses a new symbol here that neither application names (#385). JwtInfo
// went the same way in #424, to adminconsole/internal/oauthclient, once the auth
// server's one method returning it was found to have no caller.
package oauth

import (
	"crypto/sha256"
	"encoding/base64"
)

func GeneratePKCECodeChallenge(codeVerifier string) string {
	bytes := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(bytes[:])
}
