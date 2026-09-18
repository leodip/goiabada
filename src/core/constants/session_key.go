package constants

// AdminConsoleSessionName is the name of the admin console's browser session, and it is in
// core because both processes name it: the auth server's session backend stores the admin
// console's server-side sessions under it, so the two must agree on the string or the admin
// console's sessions are written under a name it does not read (#266).
//
// The auth server's own name is not here. Nothing outside that module names it (#351).
const AdminConsoleSessionName string = "adminconsole"

// SessionKeyJwt is the admin console's authenticated-session key, read by core/middleware.
const SessionKeyJwt string = "Jwt"

// The OAuth client's ceremony keys. The admin console writes and reads them and
// core/handlerhelpers reads them in both binaries, so they stay in core (#351).
const SessionKeyState string = "State"
const SessionKeyNonce string = "Nonce"
const SessionKeyRedirectURI string = "RedirectURI"
const SessionKeyCodeVerifier string = "CodeVerifier"
const SessionKeyRedirectBack string = "RedirectBack"
