package sessiontest

import "context"

// KeepEverySignedInSession is a sessionstore.KeepSignedIn that keeps every signed-in session's
// cookie past the browser, the auth server's store under Always. A test that builds a
// sessionstore.PersistentCookie store for something other than the mode passes it, so the cookie
// it observes carries the row's expiry whatever the deployment's setting (#743). The rule the auth
// server's store runs is its own, tested beside it.
func KeepEverySignedInSession(context.Context, map[string]any) (bool, error) {
	return true, nil
}
