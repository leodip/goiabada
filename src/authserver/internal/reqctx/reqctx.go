// Package reqctx holds the auth server's nine request-scoped values: the settings, the browser's
// session identifier and that session's user, the bearer token read off the request, the token a
// scope guard validated, the credential reservation a failures-only rate-limit tier holds
// (#439), the user whose token the session guard found live (#780), the DPoP proof the token
// was presented with (#42), and the client a page is drawn for (#812). Each is written by
// one middleware and read back through a typed accessor, over an unexported key, so nothing
// outside this package can write one or read it under the wrong type (#433).
package reqctx

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/leodip/goiabada/authserver/internal/dpop"
	"github.com/leodip/goiabada/authserver/internal/liveness"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/oauth"
)

type key int

const (
	settingsKey key = iota
	sessionIdentifierKey
	sessionUserIdKey
	bearerTokenKey
	validatedTokenKey
	credentialReservationKey
	actingUserIdKey
	dpopProofKey
	pageClientKey
	brandSafeModeKey
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

// WithSessionUserId records the user of the session the session identifier names, which the
// session identifier middleware read with it, so a reader of the user need not read the session
// again.
func WithSessionUserId(ctx context.Context, userId int64) context.Context {
	return context.WithValue(ctx, sessionUserIdKey, userId)
}

// SessionUserIdFrom answers false when the browser holds no session, as SessionIdentifierFrom does.
func SessionUserIdFrom(ctx context.Context) (int64, bool) {
	userId, ok := ctx.Value(sessionUserIdKey).(int64)
	return userId, ok
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

// ValidatedSubject answers the subject of the token a scope guard accepted, read as
// liveness.Subject reads it: the user a per-subject rate-limit tier counts against and the user an
// account handler acts as. False means no guard accepted a token or its subject is blank.
func ValidatedSubject(ctx context.Context) (string, bool) {
	t, ok := ValidatedTokenFrom(ctx)
	if !ok {
		return "", false
	}
	return liveness.Subject(t)
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

// WithActingUserId records the user whose access token made the request, which the session guard
// found live, so the audit logger can record who acted without reading the user again (#780
// decision 2).
func WithActingUserId(ctx context.Context, userId int64) context.Context {
	return context.WithValue(ctx, actingUserIdKey, userId)
}

// ActingUserIdFrom answers false when no user's token made the request: a browser flow, a client
// credentials token, or a request the session guard never ran for.
func ActingUserIdFrom(ctx context.Context) (int64, bool) {
	userId, ok := ctx.Value(actingUserIdKey).(int64)
	return userId, ok
}

// WithDPoPProof records the DPoP proof the bearer guard accepted beside the request's access token,
// which says the token was presented with the DPoP scheme (RFC 9449 section 7.1): the guards behind
// it challenge in that scheme, and the replay guard records the proof (#42 decision 10).
func WithDPoPProof(ctx context.Context, proof *dpop.Proof) context.Context {
	return context.WithValue(ctx, dpopProofKey, proof)
}

// DPoPProofFrom answers false when the request's token was not presented with the DPoP scheme, or
// no bearer guard read it.
func DPoPProofFrom(ctx context.Context) (*dpop.Proof, bool) {
	proof, ok := ctx.Value(dpopProofKey).(*dpop.Proof)
	return proof, ok && proof != nil
}

// PageClient is the client the pages of one request are drawn for, whose brand they take: the client
// of the sign-in a step's request names, or of an authorization request once its client is known
// (#812). Empty means none, and the page is drawn in the default brand.
//
// Like CredentialReservation it is what a handler marks rather than a value it writes: the page
// middleware puts an empty one on every page request, and the client is named part way through the
// request, by whichever code learns it, on the request every helper below it was already handed. A
// page that by design belongs to no sign-in forgets it before it is drawn. It is read and marked on
// the request's own goroutine.
//
// It also carries whether the sign-in the pages belong to asked for safe mode, goiabada_safe_mode=true
// (#816 decision 3): its pages are then drawn safe, whatever client they are drawn for.
type PageClient struct {
	clientIdentifier string
	safeMode         bool
}

// Name says the request's pages are drawn for the client with this identifier.
func (p *PageClient) Name(clientIdentifier string) {
	p.clientIdentifier = clientIdentifier
}

// Forget says the request's pages are drawn for no client, so in the default brand, and for no
// sign-in, so not in a sign-in's safe mode.
func (p *PageClient) Forget() {
	p.clientIdentifier = ""
	p.safeMode = false
}

// KeepSafeMode says the request's pages belong to a sign-in that asked for safe mode.
func (p *PageClient) KeepSafeMode() {
	p.safeMode = true
}

// SafeMode answers whether the request's pages belong to a sign-in that asked for safe mode.
func (p *PageClient) SafeMode() bool {
	return p.safeMode
}

// ClientIdentifier answers the client named, or empty for none.
func (p *PageClient) ClientIdentifier() string {
	return p.clientIdentifier
}

func WithPageClient(ctx context.Context, p *PageClient) context.Context {
	return context.WithValue(ctx, pageClientKey, p)
}

// PageClientFrom answers false when neither the page middleware nor the account API's ran: another
// API or a protocol request, which draws no page and sends no email, or a handler invoked outside its
// middleware. Like SettingsFrom it answers
// false for a nil pointer.
func PageClientFrom(ctx context.Context) (*PageClient, bool) {
	p, ok := ctx.Value(pageClientKey).(*PageClient)
	return p, ok && p != nil
}

// NamePageClient names the client ctx's pages are drawn for, when ctx carries a PageClient, and does
// nothing otherwise.
func NamePageClient(ctx context.Context, clientIdentifier string) {
	if p, ok := PageClientFrom(ctx); ok {
		p.Name(clientIdentifier)
	}
}

// ForgetPageClient draws ctx's pages for no client, when ctx carries a PageClient.
func ForgetPageClient(ctx context.Context) {
	if p, ok := PageClientFrom(ctx); ok {
		p.Forget()
	}
}

// PageClientIdentifier answers the client ctx's pages are drawn for, or empty for none.
func PageClientIdentifier(ctx context.Context) string {
	if p, ok := PageClientFrom(ctx); ok {
		return p.ClientIdentifier()
	}
	return ""
}

// KeepPageSafeMode draws ctx's pages in safe mode, for a sign-in that asked for it, when ctx carries
// a PageClient, and does nothing otherwise.
func KeepPageSafeMode(ctx context.Context) {
	if p, ok := PageClientFrom(ctx); ok {
		p.KeepSafeMode()
	}
}

// PageSafeMode answers whether ctx's pages belong to a sign-in that asked for safe mode.
func PageSafeMode(ctx context.Context) bool {
	if p, ok := PageClientFrom(ctx); ok {
		return p.SafeMode()
	}
	return false
}

// WithBrandSafeMode draws every page of ctx in safe mode: the operator's switch,
// GOIABADA_AUTHSERVER_BRAND_SAFE_MODE, which the root middleware puts on every request while it is on
// (#816 decision 3).
func WithBrandSafeMode(ctx context.Context) context.Context {
	return context.WithValue(ctx, brandSafeModeKey, true)
}

// BrandSafeMode answers whether the operator's switch draws ctx's pages in safe mode.
func BrandSafeMode(ctx context.Context) bool {
	on, _ := ctx.Value(brandSafeModeKey).(bool)
	return on
}
