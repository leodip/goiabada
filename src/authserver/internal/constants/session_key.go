package constants

// AuthServerSessionName is the name of the auth server's own browser session, and the row
// set its server-side sessions are stored under.
//
// The admin console's name stays in core, because the auth server's session backend writes
// the admin console's rows and the two processes must agree on that string or the admin
// console's sessions are written under a name it does not read (#266). Nothing outside this
// module names this one (#351).
const AuthServerSessionName string = "authserver"

const SessionKeySessionIdentifier string = "SessionIdentifier"
const SessionKeyAuthContext string = "AuthContext"

// SessionKeyLinkMarker holds the marker written once an emailed reset or activation
// link has been validated, so the rest of the flow runs on a URL carrying no
// credential (#112).
//
// One key for both flows rather than one each: a user is in one of them at a time,
// and sharing the key is what lets a marker belonging to the other flow be told
// apart from no marker at all.
const SessionKeyLinkMarker string = "LinkMarker"
