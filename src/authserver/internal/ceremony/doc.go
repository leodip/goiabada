// Package ceremony holds the authorization ceremony between /auth/authorize and /auth/issue: the
// AuthContext each hop reads and writes, the AuthState machine every gated route checks with
// InState, and the Store that keeps the context in the browser's server-side session. The amr
// values AuthContext.AddAuthMethod accumulates are oidc.AuthMethod (#437). The handlers decide
// each transition; this package says what a transition may keep. An AuthContext field is either
// the request /auth/authorize accepted or the attempt an authentication wrote, and Restart keeps
// the first and discards the second (#436).
package ceremony
