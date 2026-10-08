// Package reqctx holds the auth server's five request-scoped values: the settings, the browser's
// session identifier, the bearer token read off the request, the token a scope guard validated,
// and the credential reservation a failures-only rate-limit tier holds (#439). Each is written by
// one middleware and read back through a typed accessor, over an unexported key, so nothing
// outside this package can write one or read it under the wrong type (#433).
package reqctx

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/oauth"
)

type key int

const (
	settingsKey key = iota
	sessionIdentifierKey
	bearerTokenKey
	validatedTokenKey
	credentialReservationKey
)

// ErrNoSettings is what a reader answers its request with when the settings middleware did
// not run before it: every application route is mounted under that middleware, so reaching
// a reader without settings is a wiring defect, not a condition a request can produce.
var ErrNoSettings = errors.New("no settings on the request context")

func WithSettings(ctx context.Context, s *record.Settings) context.Context {
	return context.WithValue(ctx, settingsKey, s)
}

// SettingsFrom answers false both when no settings were written and when a nil pointer was,
// so a caller that sees true can dereference the value.
func SettingsFrom(ctx context.Context) (*record.Settings, bool) {
	s, ok := ctx.Value(settingsKey).(*record.Settings)
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

// BearerSubject answers the subject of the bearer token, read as subjectOf reads it. It is for
// RequireValidSession, which reads the bearer token so that it runs whether or not a scope guard
// ran first. False means there is no bearer token or its subject is blank.
func BearerSubject(ctx context.Context) (string, bool) {
	t, ok := BearerTokenFrom(ctx)
	if !ok {
		return "", false
	}
	return subjectOf(t)
}

// ValidatedSubject answers the subject of the token a scope guard accepted, read as subjectOf
// reads it: the user a per-subject rate-limit tier counts against and the user an account
// handler acts as. False means no guard accepted a token or its subject is blank.
func ValidatedSubject(ctx context.Context) (string, bool) {
	t, ok := ValidatedTokenFrom(ctx)
	if !ok {
		return "", false
	}
	return subjectOf(t)
}

// subjectOf is the one reading of a token's subject on a bearer-authenticated route: trimmed,
// and false when nothing is left. The session check looks the user up by it, the per-subject
// rate limiter keys on it and the account handlers act as it, so the three cannot name different
// users for one token. They used to read it separately, the first two trimming and the handlers
// not, which agreed only because the auth server mints no subject with surrounding whitespace.
func subjectOf(t oauth.JwtToken) (string, bool) {
	subject := strings.TrimSpace(t.StringClaim("sub"))
	return subject, subject != ""
}

// CredentialReservation is the slot a failures-only rate-limit tier holds for the life of one
// request.
//
// It is what a handler marks instead of naming a bucket. The rate limiter chooses the key,
// reserves against it and writes the reservation here; a handler that finds the credential
// wrong marks it and nothing else, and the limiter reads the verdict off the reservation it
// kept once the handler has returned. A limiter and a handler deriving the account separately
// and disagreeing about it is precisely the defect that voided the per-account tiers in the
// first place (#219). The flag is atomic because the handler that marks it and the limiter
// that reads it need not share a goroutine.
type CredentialReservation struct {
	failed atomic.Bool
}

// MarkFailed records that the credential check this reservation covers failed, so the limiter
// charges the slot rather than dropping it.
func (c *CredentialReservation) MarkFailed() {
	c.failed.Store(true)
}

// Failed answers whether MarkFailed was called.
func (c *CredentialReservation) Failed() bool {
	return c.failed.Load()
}

func WithCredentialReservation(ctx context.Context, res *CredentialReservation) context.Context {
	return context.WithValue(ctx, credentialReservationKey, res)
}

// CredentialReservationFrom answers false when no failures-only tier reserved for this request,
// which is the disabled limiter, a route with no such tier, and a handler invoked outside its
// middleware. Like SettingsFrom it answers false for a nil pointer, so a caller that sees true
// can mark the reservation.
func CredentialReservationFrom(ctx context.Context) (*CredentialReservation, bool) {
	res, ok := ctx.Value(credentialReservationKey).(*CredentialReservation)
	return res, ok && res != nil
}
