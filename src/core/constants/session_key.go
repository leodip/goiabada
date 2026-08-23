package constants

// Session name constants for each application
const AuthServerSessionName string = "authserver"
const AdminConsoleSessionName string = "adminconsole"

const SessionKeySessionIdentifier string = "SessionIdentifier"
const SessionKeyAuthContext string = "AuthContext"
const SessionKeyJwt string = "Jwt"

// SessionKeyLinkMarker holds the marker written once an emailed reset or activation
// link has been validated, so the rest of the flow runs on a URL carrying no
// credential (#112).
//
// One key for both flows rather than one each: a user is in one of them at a time,
// and sharing the key is what lets a marker belonging to the other flow be told
// apart from no marker at all.
const SessionKeyLinkMarker string = "LinkMarker"

const SessionKeyState string = "State"
const SessionKeyNonce string = "Nonce"
const SessionKeyRedirectURI string = "RedirectURI"
const SessionKeyCodeVerifier string = "CodeVerifier"
const SessionKeyRedirectBack string = "RedirectBack"
