// Package reqctx holds the auth server's request-scoped values: the settings, the browser's
// session identifier, the bearer token read off the request, and the token a scope guard
// validated. Each is written by one middleware and read back through a typed accessor, over
// an unexported key, so nothing outside this package can write one or read it under the
// wrong type (#433).
package reqctx

import (
	"context"
	"errors"

	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/oauth"
)

type key int

const (
	settingsKey key = iota
	sessionIdentifierKey
	bearerTokenKey
	validatedTokenKey
)

// ErrNoSettings is what a reader answers its request with when the settings middleware did
// not run before it: every application route is mounted under that middleware, so reaching
// a reader without settings is a wiring defect, not a condition a request can produce.
var ErrNoSettings = errors.New("no settings on the request context")

func WithSettings(ctx context.Context, s *models.Settings) context.Context {
	return context.WithValue(ctx, settingsKey, s)
}

// SettingsFrom answers false both when no settings were written and when a nil pointer was,
// so a caller that sees true can dereference the value.
func SettingsFrom(ctx context.Context) (*models.Settings, bool) {
	s, ok := ctx.Value(settingsKey).(*models.Settings)
	return s, ok && s != nil
}

func WithSessionIdentifier(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, sessionIdentifierKey, id)
}

// SessionIdentifierFrom answers false when the browser holds no session, which is normal.
func SessionIdentifierFrom(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(sessionIdentifierKey).(string)
	return id, ok
}

func WithBearerToken(ctx context.Context, t oauth.JwtToken) context.Context {
	return context.WithValue(ctx, bearerTokenKey, t)
}

// BearerTokenFrom answers the token the bearer middleware validated off the request, whether
// or not any scope guard has run.
func BearerTokenFrom(ctx context.Context) (oauth.JwtToken, bool) {
	t, ok := ctx.Value(bearerTokenKey).(oauth.JwtToken)
	return t, ok
}

func WithValidatedToken(ctx context.Context, t oauth.JwtToken) context.Context {
	return context.WithValue(ctx, validatedTokenKey, t)
}

// ValidatedTokenFrom answers the token a scope guard accepted; true means one did.
func ValidatedTokenFrom(ctx context.Context) (oauth.JwtToken, bool) {
	t, ok := ctx.Value(validatedTokenKey).(oauth.JwtToken)
	return t, ok
}
