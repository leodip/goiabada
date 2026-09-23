package oauthclient

import "github.com/leodip/goiabada/core/oauth"

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
