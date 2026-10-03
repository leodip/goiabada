// Package sessionkeys names the keys of the admin console's browser session. Every value here is
// stored data: a live session carries these spellings, so renaming one signs every administrator
// out at deploy, and a sign-in in flight across it fails at the callback. Request-scoped values are
// not session keys and live in reqctx. It was internal/constants until the two context keys left
// for reqctx, as the auth server's twin was (#433, #440).
//
// They name entries in the admin console's own browser session, written and read by
// this process alone: the authenticated-session key with the access token's recorded
// expiry beside it, and the six the OAuth ceremony parks between the authorize redirect
// and the callback. The auth server stores that
// session server-side but never opens it, so there is nothing for the two binaries to
// agree on beyond the session's name, which is the one key core still declares (#385).
package sessionkeys

// JWT is the authenticated-session key. Its string value, like every one here, is the
// one core declared, byte for byte: a session written before #385 moved them and read after it
// must still resolve, since the admin console's sessions outlive a deployment.
const JWT string = "Jwt"

// JWTExpiresAt is the Unix second the stored access token lapses at, computed from
// the token response's expires_in when it arrives, or 0 when the response gave none and the
// expiry is unknown. It is written beside JWT at sign-in and at every refresh and
// deleted wherever JWT is, because the console never decodes its access token to
// read an expiry out of it (#427).
const JWTExpiresAt string = "JwtExpiresAt"

const State string = "State"
const Nonce string = "Nonce"
const RedirectURI string = "RedirectURI"
const CodeVerifier string = "CodeVerifier"
const RedirectBack string = "RedirectBack"

// RequestedScope is the scope the authorize request asked for. The callback takes the
// grant to equal it when the token response carries no scope parameter, which RFC 6749 section
// 3.3 allows only when the two are identical (#427).
const RequestedScope string = "RequestedScope"
