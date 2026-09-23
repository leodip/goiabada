// Package oauthclient is the admin console's OAuth client: the redirect that starts
// sign-in and mints the PKCE verifier, state and nonce, the code-for-token exchanger
// that completes it, and the JWKS parser that validates what comes back. All three
// speak the client half of the protocol to one peer, the auth server, and nothing in
// the auth server or in core calls any of them, which is why they are not in core: a
// shared package holding one application's implementation is what #385 ends. The value
// types they pass around -- TokenResponse, JwtToken, Jwk, Jwks -- stay in core/oauth,
// since both processes name them. JwtInfo, the decoded token set the parser returns, is
// here, because only this process names it (#424).
//
// An http.Handler wrapper is not here: the session middleware that calls
// RedirToAuthorize lives in adminconsole/internal/middleware, beside the other
// wrappers, so this package has one job and no net/http middleware in it (#385).
package oauthclient

import "time"

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
