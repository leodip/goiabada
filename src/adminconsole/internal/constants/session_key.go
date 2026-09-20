package constants

// The admin console's own session keys.
//
// They name entries in the admin console's own browser session, written and read by
// this process alone: the authenticated-session key and the five the OAuth ceremony
// parks between the authorize redirect and the callback. The auth server stores that
// session server-side but never opens it, so there is nothing for the two binaries to
// agree on beyond the session's name, which is the one key core still declares (#385).
//
// The string values are the ones core declared, byte for byte. A session written before
// this move and read after it must still resolve, since the admin console's sessions
// outlive a deployment.
const SessionKeyJwt string = "Jwt"

const SessionKeyState string = "State"
const SessionKeyNonce string = "Nonce"
const SessionKeyRedirectURI string = "RedirectURI"
const SessionKeyCodeVerifier string = "CodeVerifier"
const SessionKeyRedirectBack string = "RedirectBack"
