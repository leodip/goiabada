package oauthclient

import (
	"strings"

	"github.com/leodip/goiabada/core/oauth"
)

// JwtInfo is a token response with its ID token verified and decoded, as the JWKS parser produces
// it and the JWT session middleware puts it on the request context. The ID token is the one token
// addressed to the console (OIDC Core 3.1.3.7); the access and refresh tokens stay the strings in
// TokenResponse, carried and never decoded, as RFC 6749 sections 1.4 and 1.5 describe a client
// treating them. What the access token grants is read from the response's scope (HasScope), and
// when it lapses from expires_in (ExpiresAt), not from inside it (#427).
//
// It is here rather than in core/oauth because the admin console is the only process that names it:
// the auth server's parser method producing one had no caller and went in #424, and a type one
// process uses moves to that process, as this package's doc says. It never reaches the session,
// which stores the TokenResponse alone, so the move renamed nothing persisted.
type JwtInfo struct {
	TokenResponse oauth.TokenResponse
	IdToken       *oauth.JwtToken
}

// HasScope reports whether the grant the token response records includes scope, matched
// exactly against its space-delimited values (RFC 6749 section 3.3). It reads the response
// rather than the access token, which the console carries without decoding (#427). An empty
// scope never matches, so a doubled space in the grant grants nothing.
func (j JwtInfo) HasScope(scope string) bool {
	if scope == "" {
		return false
	}
	for _, granted := range strings.Split(j.TokenResponse.Scope, " ") {
		if granted == scope {
			return true
		}
	}
	return false
}
