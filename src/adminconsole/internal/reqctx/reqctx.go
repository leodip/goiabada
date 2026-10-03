// Package reqctx holds the admin console's two request-scoped values: the signed-in
// administrator's token set and the auth server's public settings. Each is written by one
// middleware and read back through a typed accessor, so a reader that finds a value absent
// answers with one sentinel error rather than a type assertion of its own (#440). It is the twin
// of the auth server's internal/reqctx (#433).
//
// The keys are unexported, so nothing outside this package can write either value or read it under
// the wrong type, and core/testutil.AssertContextValuesThroughAccessors, called from the unit tier,
// refuses a raw context read or write anywhere else in the module. The settings key once shared its
// spelling with the auth server's, which was never one key: a context key does not leave the process
// that set it, and the two processes store different types under theirs (#351).
package reqctx

import (
	"context"
	"errors"

	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/core/api"
)

// ErrNoJwtInfo is what a reader answers its request with when no token set is on the context.
// Every route that reads one is mounted under RequiresScope, which sends a browser without one to
// sign in, so reaching a reader without it is a wiring defect.
var ErrNoJwtInfo = errors.New("no token set on the request context")

// ErrNoSettings is what a reader answers its request with when the settings middleware did not
// run before it: every application route is mounted under that middleware, so reaching a reader
// without settings is a wiring defect, not a condition a request can produce.
var ErrNoSettings = errors.New("no settings on the request context")

type key int

const (
	jwtInfoKey key = iota
	settingsKey
)

func WithJwtInfo(ctx context.Context, jwtInfo oauthclient.JwtInfo) context.Context {
	return context.WithValue(ctx, jwtInfoKey, jwtInfo)
}

// JwtInfoFrom answers false when the browser holds no signed-in session, which the scope check and
// the locale refinement treat as an anonymous request and every other reader as ErrNoJwtInfo.
func JwtInfoFrom(ctx context.Context) (oauthclient.JwtInfo, bool) {
	jwtInfo, ok := ctx.Value(jwtInfoKey).(oauthclient.JwtInfo)
	return jwtInfo, ok
}

func WithSettings(ctx context.Context, s *api.PublicSettingsResponse) context.Context {
	return context.WithValue(ctx, settingsKey, s)
}

// SettingsFrom answers false both when no settings were written and when a nil pointer was, so a
// caller that sees true can dereference the value.
func SettingsFrom(ctx context.Context) (*api.PublicSettingsResponse, bool) {
	s, ok := ctx.Value(settingsKey).(*api.PublicSettingsResponse)
	return s, ok && s != nil
}
