package constants

// The admin console's own session keys.
//
// They name entries in the admin console's own browser session, written and read by
// this process alone: the authenticated-session key with the access token's recorded
// expiry beside it, and the six the OAuth ceremony parks between the authorize redirect
// and the callback. The auth server stores that
// session server-side but never opens it, so there is nothing for the two binaries to
// agree on beyond the session's name, which is the one key core still declares (#385).
//
// The string values are the ones core declared, byte for byte. A session written before
// this move and read after it must still resolve, since the admin console's sessions
// outlive a deployment.
const SessionKeyJwt string = "Jwt"

// SessionKeyJwtExpiresAt is the Unix second the stored access token lapses at, computed from
// the token response's expires_in when it arrives, or 0 when the response gave none and the
// expiry is unknown. It is written beside SessionKeyJwt at sign-in and at every refresh and
// deleted wherever SessionKeyJwt is, because the console never decodes its access token to
// read an expiry out of it (#427).
const SessionKeyJwtExpiresAt string = "JwtExpiresAt"

const SessionKeyState string = "State"
const SessionKeyNonce string = "Nonce"
const SessionKeyRedirectURI string = "RedirectURI"
const SessionKeyCodeVerifier string = "CodeVerifier"
const SessionKeyRedirectBack string = "RedirectBack"

// SessionKeyRequestedScope is the scope the authorize request asked for. The callback takes the
// grant to equal it when the token response carries no scope parameter, which RFC 6749 section
// 3.3 allows only when the two are identical (#427).
const SessionKeyRequestedScope string = "RequestedScope"
