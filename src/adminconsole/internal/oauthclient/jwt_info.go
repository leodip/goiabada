package oauthclient

import (
	"strings"

	"github.com/leodip/goiabada/core/oauth"
)

// JwtInfo is a token response with each of its tokens validated and decoded, as the JWKS parser
// produces it and the JWT session middleware puts it on the request context. A token the response
// does not carry stays nil.
//
// It is here rather than in core/oauth because the admin console is the only process that names it:
// the auth server's parser method producing one had no caller and went in #424, and a type one
// process uses moves to that process, as this package's doc says. It never reaches the session,
// which stores the TokenResponse alone, so the move renamed nothing persisted.
type JwtInfo struct {
	TokenResponse oauth.TokenResponse

	AccessToken  *oauth.JwtToken
	IdToken      *oauth.JwtToken
	RefreshToken *oauth.JwtToken
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
