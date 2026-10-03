package middleware

import (
	"context"
	"encoding/gob"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient/oauthclienttest"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/adminconsole/internal/sessionkeys"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/sessionstore/sessiontest"

	mock_middleware "github.com/leodip/goiabada/adminconsole/internal/middleware/mocks"
)

// Seam 5 of #427: SessionHandler, one row per step of its per-request order, over a real
// ServerSideStore so what each row leaves in the session is read back through the store's own Get
// with the browser's cookie, the way the next request would read it. The parser is the generated
// mock, so these rows are thin on classification by design: which token is foreign is the parser's
// to decide, and its own tests decide it on real tokens. One row further down drives the real
// parser, for the one branch whose classification the mock cannot supply.

const (
	sessionTestName     = "the-console-session"
	storedIDTokenRaw    = "the.stored.id-token"
	refreshedIDTokenRaw = "the.refreshed.id-token"
	storedAccessToken   = "the-stored-access-token"
	storedRefreshToken  = "the-stored-refresh-token"
	storedGrant         = "openid email profile authserver:manage"
)

// fakeRefresher is the token client's refresh grant, which owns the transport, the kept refresh
// token and the grant's own detachment (#441 decision 2): it answers every call with one scripted
// response or error and records what it was handed. during, when set, runs inside the call, which is
// where a browser that goes away mid-refresh goes away.
type fakeRefresher struct {
	answer *oauth.TokenResponse
	err    error
	during func()

	mu           sync.Mutex
	calls        int
	refreshToken string
	requestID    string
	returnedAt   time.Time
}

func (f *fakeRefresher) Refresh(ctx context.Context, refreshToken string) (*oauth.TokenResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.refreshToken = refreshToken
	f.requestID = chimiddleware.GetReqID(ctx)
	if f.during != nil {
		f.during()
	}
	f.returnedAt = time.Now()
	if f.err != nil {
		return nil, f.err
	}
	answer := *f.answer
	return &answer, nil
}

func (f *fakeRefresher) sent() (int, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls, f.refreshToken
}

// contextHonouringBackend is the memory backend refusing a call on a context that is done, which is
// what the console's real backend, an HTTP call to the auth server, does. It records the context of
// every write, so a case can read what the write was handed.
type contextHonouringBackend struct {
	*sessiontest.MemoryBackend

	mu     sync.Mutex
	writes []observedContext
}

// observedContext is what a context looked like at the moment it was handed over.
type observedContext struct {
	err         error
	deadline    time.Time
	hasDeadline bool
	requestID   string
}

func observe(ctx context.Context) observedContext {
	deadline, hasDeadline := ctx.Deadline()
	return observedContext{err: ctx.Err(), deadline: deadline, hasDeadline: hasDeadline,
		requestID: chimiddleware.GetReqID(ctx)}
}

func (b *contextHonouringBackend) Load(ctx context.Context, id string) (*sessionstore.Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return b.MemoryBackend.Load(ctx, id)
}

func (b *contextHonouringBackend) Create(ctx context.Context, id string, data []byte, authenticated bool) (time.Time, error) {
	b.record(ctx)
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	return b.MemoryBackend.Create(ctx, id, data, authenticated)
}

func (b *contextHonouringBackend) Update(ctx context.Context, id string, data []byte, authenticated bool) (time.Time, error) {
	b.record(ctx)
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	return b.MemoryBackend.Update(ctx, id, data, authenticated)
}

func (b *contextHonouringBackend) Touch(ctx context.Context, id string, authenticated bool) (time.Time, error) {
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	return b.MemoryBackend.Touch(ctx, id, authenticated)
}

func (b *contextHonouringBackend) Delete(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return b.MemoryBackend.Delete(ctx, id)
}

func (b *contextHonouringBackend) record(ctx context.Context) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.writes = append(b.writes, observe(ctx))
}

func (b *contextHonouringBackend) recordedWrites() []observedContext {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]observedContext(nil), b.writes...)
}

type sessionHarness struct {
	t         *testing.T
	store     *sessionstore.ServerSideStore
	backend   *contextHonouringBackend
	parser    *mock_middleware.TokenParser
	refresher *fakeRefresher
	logs      *logtest.SlogCapture
}

func newSessionHarness(t *testing.T) *sessionHarness {
	t.Helper()
	gob.Register(oauth.TokenResponse{})
	backend := &contextHonouringBackend{MemoryBackend: sessiontest.NewMemoryBackend()}
	store, err := sessionstore.NewServerSideStore(backend, sessionkeys.JWT, false, sessionstore.BrowserSessionCookie,
		sessionstore.KeyPair{
			AuthenticationKey: []byte("12345678901234567890123456789012"),
			EncryptionKey:     []byte("abcdefghijklmnopqrstuvwxyz123456"),
		}, nil)
	require.NoError(t, err)
	return &sessionHarness{
		t:         t,
		store:     store,
		backend:   backend,
		parser:    mock_middleware.NewTokenParser(t),
		refresher: &fakeRefresher{},
		logs:      logtest.CaptureSlog(t),
	}
}

// seed stores values as the browser's session and returns the cookies naming it.
func (h *sessionHarness) seed(values map[string]any) []*http.Cookie {
	h.t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	sess, err := h.store.Get(req, sessionTestName)
	require.NoError(h.t, err)
	for k, v := range values {
		sess.Values[k] = v
	}
	w := httptest.NewRecorder()
	require.NoError(h.t, h.store.Save(req, w, sess))
	cookies := w.Result().Cookies()
	require.NotEmpty(h.t, cookies)
	return cookies
}

// readBack loads the session the cookies name through the store's own Get.
func (h *sessionHarness) readBack(cookies []*http.Cookie) *sessionstore.Session {
	h.t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	sess, err := h.store.Get(req, sessionTestName)
	require.NoError(h.t, err)
	return sess
}

// served is what one request through the middleware came to.
type served struct {
	recorder *httptest.ResponseRecorder
	reached  bool
	jwtInfo  *oauthclient.JwtInfo
}

// serve sends one request carrying cookies through SessionHandler over parser.
func (h *sessionHarness) serve(parser tokenParser, cookies []*http.Cookie) served {
	h.t.Helper()
	return h.serveOn(context.Background(), parser, cookies)
}

// serveOn is serve with the request on ctx, the browser's own context.
func (h *sessionHarness) serveOn(ctx context.Context, parser tokenParser, cookies []*http.Cookie) served {
	h.t.Helper()
	m := NewJWT(h.store, sessionTestName, parser, h.refresher, new(mock_middleware.AuthHelper),
		stubErrorRenderer{}, "http://console.example", "admin-console-client")

	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil).WithContext(ctx)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	var out served
	out.recorder = httptest.NewRecorder()
	m.SessionHandler()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out.reached = true
		if jwtInfo, ok := reqctx.JwtInfoFrom(r.Context()); ok {
			out.jwtInfo = &jwtInfo
		}
	})).ServeHTTP(out.recorder, req)
	return out
}

// storedResponse is a signed-in session's token response as the callback records it.
func storedResponse() oauth.TokenResponse {
	return oauth.TokenResponse{
		AccessToken:  storedAccessToken,
		IdToken:      storedIDTokenRaw,
		RefreshToken: storedRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    300,
		Scope:        storedGrant,
	}
}

func signedIn(expiresAt int64) map[string]any {
	return map[string]any{
		sessionkeys.JWT:          storedResponse(),
		sessionkeys.JWTExpiresAt: expiresAt,
		"unrelated":              "kept",
	}
}

// verifiedStored is the stored ID token as the parser hands it back once it verified.
var verifiedStored = &oauth.JwtToken{TokenBase64: storedIDTokenRaw, Claims: map[string]any{"sub": "the-admin"}}

func due() int64    { return time.Now().Add(10 * time.Second).Unix() }
func notDue() int64 { return time.Now().Add(time.Hour).Unix() }

// assertSignedOut asserts the token values are gone from the session the cookies name and an
// unrelated value survived, which is a deletion of the two keys rather than a destroyed session.
func (h *sessionHarness) assertSignedOut(cookies []*http.Cookie) {
	h.t.Helper()
	sess := h.readBack(cookies)
	assert.NotContains(h.t, sess.Values, sessionkeys.JWT, "the token response is deleted")
	assert.NotContains(h.t, sess.Values, sessionkeys.JWTExpiresAt, "and its expiry with it")
	assert.Equal(h.t, "kept", sess.Values["unrelated"], "the session itself survives")
}

// assertOneRecord asserts exactly one record was written, at level, with message, and, when cause
// is not empty, an error attribute naming it.
func (h *sessionHarness) assertOneRecord(level slog.Level, message, cause string) {
	h.t.Helper()
	records := h.logs.Records()
	require.Len(h.t, records, 1, h.logs.Text())
	assert.Equal(h.t, level, records[0].Level)
	assert.Equal(h.t, message, records[0].Message)
	if cause != "" {
		assert.Contains(h.t, fmt.Sprint(records[0].Attrs["error"]), cause, "the record names the cause")
	}
}

func (h *sessionHarness) assertNoRefreshSent() {
	h.t.Helper()
	calls, _ := h.refresher.sent()
	assert.Zero(h.t, calls, "no refresh grant is sent")
}

func (h *sessionHarness) assertRedirectedToRoot(out served) {
	h.t.Helper()
	assert.False(h.t, out.reached, "the page asked for is not served")
	assert.Equal(h.t, http.StatusFound, out.recorder.Code)
	assert.Equal(h.t, "/", out.recorder.Header().Get("Location"))
}

func (h *sessionHarness) assertContinuedUnauthenticated(out served) {
	h.t.Helper()
	assert.True(h.t, out.reached, "the chain continues")
	assert.Nil(h.t, out.jwtInfo, "with no identity on the request")
}

// Step 1.
func TestSessionHandler_NoTokenResponseContinuesUnauthenticated(t *testing.T) {
	h := newSessionHarness(t)
	cookies := h.seed(map[string]any{"unrelated": "kept"})

	out := h.serve(h.parser, cookies)

	h.assertContinuedUnauthenticated(out)
	h.assertNoRefreshSent()
	assert.Empty(t, h.logs.Records())
}

// Step 2: a session signed in before #427 recorded no expiry, and is signed out once rather than
// carried across on a transitional path (decision 15). A token response with no ID token has
// nothing to verify and goes the same way. Neither consults the parser nor sends a refresh, even
// with a refresh token in hand.
func TestSessionHandler_SignsOutASessionItCannotVerify(t *testing.T) {
	noIDToken := storedResponse()
	noIDToken.IdToken = ""

	testCases := []struct {
		name    string
		values  map[string]any
		message string
	}{
		{
			name:    "no recorded expiry, as every session signed in before the upgrade",
			values:  map[string]any{sessionkeys.JWT: storedResponse(), "unrelated": "kept"},
			message: "the session holds a token response with no recorded expiry, signing it out",
		},
		{
			name: "an expiry of another type than int64",
			values: map[string]any{sessionkeys.JWT: storedResponse(),
				sessionkeys.JWTExpiresAt: "1700000000", "unrelated": "kept"},
			message: "the session holds a token response with no recorded expiry, signing it out",
		},
		{
			name: "no id token",
			values: map[string]any{sessionkeys.JWT: noIDToken,
				sessionkeys.JWTExpiresAt: due(), "unrelated": "kept"},
			message: "the session holds a token response with no id token, signing it out",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := newSessionHarness(t)
			cookies := h.seed(tc.values)

			out := h.serve(h.parser, cookies)

			h.assertContinuedUnauthenticated(out)
			h.assertSignedOut(cookies)
			h.assertNoRefreshSent()
			h.assertOneRecord(slog.LevelWarn, tc.message, "")
		})
	}
}

// Step 3, foreign: a stored ID token naming another issuer or audience ends the session with a
// redirect to the root and is never refreshed, even when its access token is due, so a changed
// issuer setting signs every other administrator out on their next page load rather than migrating
// them silently (decision 3). Warn, not Error: #320 decision 5, pinned here so nobody restores
// Error on the reasoning that another issuer sounds severe.
func TestSessionHandler_InvalidIssuer(t *testing.T) {
	h := newSessionHarness(t)
	cookies := h.seed(signedIn(due()))
	h.parser.On("DecodeAndValidateStoredIDToken", mock.Anything, storedIDTokenRaw).
		Return(nil, errs.Wrap(oauthclient.ErrForeignToken, "the id token's iss is another"))

	out := h.serve(h.parser, cookies)

	h.assertRedirectedToRoot(out)
	h.assertSignedOut(cookies)
	h.assertNoRefreshSent()
	h.assertOneRecord(slog.LevelWarn,
		"the id token names another issuer or audience, clearing the session and redirecting to root",
		"the id token's iss is another")
}

// Step 3, any other failure: decision 19's answer. The stored ID token no longer verifies, a key
// that left the JWKS for one, so there is no verified token to compare a refreshed one with or to
// keep, and the session is signed out with no refresh sent.
func TestSessionHandler_AStoredIDTokenThatNoLongerVerifiesIsSignedOutWithoutARefresh(t *testing.T) {
	h := newSessionHarness(t)
	cookies := h.seed(signedIn(due()))
	h.parser.On("DecodeAndValidateStoredIDToken", mock.Anything, storedIDTokenRaw).
		Return(nil, errs.New("unable to verify the id token's signature"))

	out := h.serve(h.parser, cookies)

	h.assertContinuedUnauthenticated(out)
	h.assertSignedOut(cookies)
	h.assertNoRefreshSent()
	h.assertOneRecord(slog.LevelWarn, "the stored id token no longer verifies, signing the session out",
		"unable to verify the id token's signature")
}

// Decision 19 on real tokens. The mock above cannot prove this: which failures are foreign is the
// parser's decision, so a mock answering a plain error proves only what the middleware does with
// one. Here the stored ID token is signed by a key the JWKS no longer publishes when the console
// first fetches it, a console started after the key was removed, and its access token is due, so
// a middleware that fell through from step 3 to the refresh would send one.
func TestSessionHandler_AStoredIDTokenUnderAKeyUnpublishedAtTheFirstFetchIsSignedOutWithoutARefresh(t *testing.T) {
	h := newSessionHarness(t)

	signing, retired := oauthclienttest.Keys(t)
	jwks, _ := oauthclienttest.NewJwksServer(t, oauthclienttest.JwkFromPublicKey("current", &signing.PublicKey))
	parser := oauthclient.NewJWKSTokenParser(jwks.URL, jwks.Client(), oauthclienttest.ClientID,
		oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	response := storedResponse()
	response.IdToken = oauthclienttest.SignRS256(t, retired, "retired", oauthclienttest.ValidClaims())
	cookies := h.seed(map[string]any{
		sessionkeys.JWT:          response,
		sessionkeys.JWTExpiresAt: due(),
		"unrelated":              "kept",
	})
	h.refresher.answer = &oauth.TokenResponse{AccessToken: "new", IdToken: "new", RefreshToken: "new", ExpiresIn: 300}

	out := h.serve(parser, cookies)

	h.assertContinuedUnauthenticated(out)
	h.assertNoRefreshSent()
	h.assertSignedOut(cookies)
	h.assertOneRecord(slog.LevelWarn, "the stored id token no longer verifies, signing the session out",
		"public key not found for token kid")
}

// Decision 20, the same on a warm cache: the console fetched the key while it was published and
// the auth server removed it afterwards, which OIDC Core 10.1.1's refetch on an unfamiliar kid
// never notices. Within the parser's ten-minute JWKS age the stored ID token still verifies; from
// the age on, the next request refetches /certs, finds the key gone, and signs the session out
// with no refresh sent although the access token is due.
func TestSessionHandler_AKeyRemovedAfterTheConsoleFetchedIt(t *testing.T) {
	signing, _ := oauthclienttest.Keys(t)
	stored := oauthclienttest.SignRS256(t, signing, "removed", oauthclienttest.ValidClaims())

	// warm returns a parser that verified stored while its key was published, over a JWKS that
	// has since removed it, and the clock the parser measures its cache's age by.
	warm := func(t *testing.T) (*oauthclient.JWKSTokenParser, *oauthclienttest.JwksServer, *oauthclienttest.Clock) {
		t.Helper()
		jwks := oauthclienttest.NewMutableJwksServer(t, oauthclienttest.JwkFromPublicKey("removed", &signing.PublicKey))
		clock := oauthclienttest.NewClock()
		parser := oauthclient.NewJWKSTokenParser(jwks.URL, jwks.Client(), oauthclienttest.ClientID,
			oauthclienttest.StaticIssuer(oauthclienttest.Issuer), oauthclient.WithClock(clock.Now))
		_, err := parser.DecodeAndValidateStoredIDToken(context.Background(), stored)
		require.NoError(t, err)
		jwks.Publish()
		return parser, jwks, clock
	}
	session := func(expiresAt int64) map[string]any {
		response := storedResponse()
		response.IdToken = stored
		return map[string]any{
			sessionkeys.JWT:          response,
			sessionkeys.JWTExpiresAt: expiresAt,
			"unrelated":              "kept",
		}
	}

	t.Run("within the age the stored ID token still verifies", func(t *testing.T) {
		h := newSessionHarness(t)
		parser, jwks, clock := warm(t)
		cookies := h.seed(session(notDue()))
		clock.Advance(10*time.Minute - time.Second)

		out := h.serve(parser, cookies)

		assert.True(t, out.reached)
		require.NotNil(t, out.jwtInfo, "the administrator is still signed in")
		require.NotNil(t, out.jwtInfo.IdToken)
		assert.Equal(t, stored, out.jwtInfo.IdToken.TokenBase64)
		assert.Equal(t, int32(1), jwks.Hits.Load(), "the cache answered")
		h.assertNoRefreshSent()
		assert.Empty(t, h.logs.Records())
	})

	t.Run("from the age the session is signed out without a refresh", func(t *testing.T) {
		h := newSessionHarness(t)
		parser, jwks, clock := warm(t)
		cookies := h.seed(session(due()))
		clock.Advance(10 * time.Minute)

		out := h.serve(parser, cookies)

		h.assertContinuedUnauthenticated(out)
		h.assertNoRefreshSent()
		h.assertSignedOut(cookies)
		h.assertOneRecord(slog.LevelWarn, "the stored id token no longer verifies, signing the session out",
			"public key not found for token kid")
		assert.Equal(t, int32(2), jwks.Hits.Load(), "the age sent the parser back to /certs")
	})
}

// Step 4: nothing is refreshed until the recorded expiry is within the margin, and an unknown
// expiry, 0, never is (decision 16). The stored response and the verified ID token reach the
// request as they are, and the session is not written.
func TestSessionHandler_UsesTheStoredTokensUntilTheyAreDue(t *testing.T) {
	testCases := []struct {
		name      string
		expiresAt int64
	}{
		{"an hour out", notDue()},
		{"unknown", 0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := newSessionHarness(t)
			cookies := h.seed(signedIn(tc.expiresAt))
			h.parser.On("DecodeAndValidateStoredIDToken", mock.Anything, storedIDTokenRaw).Return(verifiedStored, nil)

			out := h.serve(h.parser, cookies)

			assert.True(t, out.reached)
			require.NotNil(t, out.jwtInfo, "the administrator is signed in")
			assert.Equal(t, storedResponse(), out.jwtInfo.TokenResponse)
			assert.Same(t, verifiedStored, out.jwtInfo.IdToken, "the ID token the parser verified")
			h.assertNoRefreshSent()
			assert.Empty(t, out.recorder.Result().Cookies(), "the session is not written")
			assert.Empty(t, h.logs.Records())

			sess := h.readBack(cookies)
			assert.Equal(t, storedResponse(), sess.Values[sessionkeys.JWT])
			assert.Equal(t, tc.expiresAt, sess.Values[sessionkeys.JWTExpiresAt])
		})
	}
}

// expectRefreshValidation answers the refresh response's validation with accepted or refused and
// records, at the moment the parser is asked, what the session held: anything the middleware
// stored before validating would show there.
func (h *sessionHarness) expectRefreshValidation(cookies []*http.Cookie, accepted *oauthclient.JwtInfo,
	refused error, heldAtValidation *any) {
	h.parser.On("DecodeAndValidateRefreshResponse", mock.Anything, mock.Anything, verifiedStored).
		Run(func(mock.Arguments) {
			*heldAtValidation = h.readBack(cookies).Values[sessionkeys.JWT]
		}).
		Return(accepted, refused)
}

// Step 5, the refusals: the auth server answered and its answer failed validation. A foreign one
// ends the session at Warn, as step 3 does; any other, a different sub or sign-in time, ends it at
// Error, because someone must look at that (decision 14). Nothing from the answer reaches the
// session, before validation or after.
func TestSessionHandler_ARefusedRefreshEndsTheSession(t *testing.T) {
	testCases := []struct {
		name    string
		refused error
		level   slog.Level
		message string
	}{
		{
			name:    "foreign",
			refused: errs.Wrap(oauthclient.ErrForeignToken, "the refreshed id token's iss differs from the previous one's"),
			level:   slog.LevelWarn,
			message: "the id token names another issuer or audience, clearing the session and redirecting to root",
		},
		{
			name:    "another sub",
			refused: errs.New("the refreshed id token's sub differs from the previous one's"),
			level:   slog.LevelError,
			message: "the refresh response was refused, clearing the session and redirecting to root",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := newSessionHarness(t)
			cookies := h.seed(signedIn(due()))
			h.parser.On("DecodeAndValidateStoredIDToken", mock.Anything, storedIDTokenRaw).Return(verifiedStored, nil)
			h.refresher.answer = &oauth.TokenResponse{AccessToken: "the-new-access-token",
				IdToken: refreshedIDTokenRaw, RefreshToken: "the-new-refresh-token", ExpiresIn: 300}
			var held any
			h.expectRefreshValidation(cookies, nil, tc.refused, &held)

			out := h.serve(h.parser, cookies)

			h.assertRedirectedToRoot(out)
			assert.Equal(t, storedResponse(), held, "nothing is stored before the answer is validated")
			h.assertSignedOut(cookies)
			h.assertOneRecord(tc.level, tc.message, tc.refused.Error())
		})
	}
}

// Step 5, a grant that never produced an answer to validate: the auth server refused the refresh
// token, or there is none to send. The session is signed out as it always was on a failed refresh,
// and the chain continues unauthenticated. The refusal is the token client's one error (#441
// decision 3), and the record names it as the client wrote it.
func TestSessionHandler_AFailedRefreshGrantSignsTheSessionOut(t *testing.T) {
	t.Run("the auth server refuses the grant", func(t *testing.T) {
		h := newSessionHarness(t)
		cookies := h.seed(signedIn(due()))
		h.parser.On("DecodeAndValidateStoredIDToken", mock.Anything, storedIDTokenRaw).Return(verifiedStored, nil)
		h.refresher.err = errs.WithStack(&oauthclient.TokenEndpointError{
			StatusCode: http.StatusBadRequest, ErrorCode: "invalid_grant"})

		out := h.serve(h.parser, cookies)

		h.assertContinuedUnauthenticated(out)
		h.assertSignedOut(cookies)
		calls, sent := h.refresher.sent()
		assert.Equal(t, 1, calls)
		assert.Equal(t, storedRefreshToken, sent)
		h.assertOneRecord(slog.LevelWarn, "unable to refresh the access token, signing the session out",
			"the auth server's token endpoint answered 400 (invalid_grant)")
	})

	t.Run("the grant fails in transport", func(t *testing.T) {
		h := newSessionHarness(t)
		cookies := h.seed(signedIn(due()))
		h.parser.On("DecodeAndValidateStoredIDToken", mock.Anything, storedIDTokenRaw).Return(verifiedStored, nil)
		h.refresher.err = errs.New("error sending request: connection refused")

		out := h.serve(h.parser, cookies)

		h.assertContinuedUnauthenticated(out)
		h.assertSignedOut(cookies)
		h.assertOneRecord(slog.LevelWarn, "unable to refresh the access token, signing the session out",
			"connection refused")
	})

	t.Run("there is no refresh token", func(t *testing.T) {
		h := newSessionHarness(t)
		response := storedResponse()
		response.RefreshToken = ""
		cookies := h.seed(map[string]any{
			sessionkeys.JWT:          response,
			sessionkeys.JWTExpiresAt: due(),
			"unrelated":              "kept",
		})
		h.parser.On("DecodeAndValidateStoredIDToken", mock.Anything, storedIDTokenRaw).Return(verifiedStored, nil)

		out := h.serve(h.parser, cookies)

		h.assertContinuedUnauthenticated(out)
		h.assertSignedOut(cookies)
		h.assertNoRefreshSent()
		assert.Empty(t, h.logs.Records(), "a session that was never refreshable is not a failure")
	})
}

// Step 5, accepted: the grant sends the stored refresh token, the answer is validated against the
// stored ID token before anything is written, and what is written is what the parser accepted, with
// the effective grant (RFC 6749 section 6: an omitted scope is the one originally granted) and the
// expiry recomputed from the answer's expires_in. The refreshed identity reaches the request.
func TestSessionHandler_ARefreshIsValidatedThenStored(t *testing.T) {
	testCases := []struct {
		name string
		// answer is the token client's, the refresh token already kept when the endpoint issued
		// none (the client's rule, which its own tests hold).
		answer oauth.TokenResponse
		// accepted is the response the parser hands back, having filled in a kept ID token when
		// the answer carried none (the parser's rule, which this row only shows the middleware
		// storing).
		accepted     oauth.TokenResponse
		acceptedID   *oauth.JwtToken
		wantScope    string
		wantRefresh  string
		wantIDToken  string
		wantLifetime int64
	}{
		{
			name: "the answer names its own scope",
			answer: oauth.TokenResponse{AccessToken: "the-new-access-token", IdToken: refreshedIDTokenRaw,
				RefreshToken: "the-new-refresh-token", ExpiresIn: 600, Scope: "openid authserver:manage"},
			accepted: oauth.TokenResponse{AccessToken: "the-new-access-token", IdToken: refreshedIDTokenRaw,
				RefreshToken: "the-new-refresh-token", ExpiresIn: 600, Scope: "openid authserver:manage"},
			acceptedID:   &oauth.JwtToken{TokenBase64: refreshedIDTokenRaw},
			wantScope:    "openid authserver:manage",
			wantRefresh:  "the-new-refresh-token",
			wantIDToken:  refreshedIDTokenRaw,
			wantLifetime: 600,
		},
		{
			name: "the answer omits scope",
			answer: oauth.TokenResponse{AccessToken: "the-new-access-token", IdToken: refreshedIDTokenRaw,
				RefreshToken: "the-new-refresh-token", ExpiresIn: 600},
			accepted: oauth.TokenResponse{AccessToken: "the-new-access-token", IdToken: refreshedIDTokenRaw,
				RefreshToken: "the-new-refresh-token", ExpiresIn: 600},
			acceptedID:   &oauth.JwtToken{TokenBase64: refreshedIDTokenRaw},
			wantScope:    storedGrant,
			wantRefresh:  "the-new-refresh-token",
			wantIDToken:  refreshedIDTokenRaw,
			wantLifetime: 600,
		},
		{
			name: "the answer carries no id token, and the parser keeps the stored one",
			answer: oauth.TokenResponse{AccessToken: "the-new-access-token",
				RefreshToken: "the-new-refresh-token", ExpiresIn: 600},
			accepted: oauth.TokenResponse{AccessToken: "the-new-access-token", IdToken: storedIDTokenRaw,
				RefreshToken: "the-new-refresh-token", ExpiresIn: 600},
			acceptedID:   verifiedStored,
			wantScope:    storedGrant,
			wantRefresh:  "the-new-refresh-token",
			wantIDToken:  storedIDTokenRaw,
			wantLifetime: 600,
		},
		{
			name: "the answer carries no expires_in, an unknown expiry",
			answer: oauth.TokenResponse{AccessToken: "the-new-access-token", IdToken: refreshedIDTokenRaw,
				RefreshToken: "the-new-refresh-token"},
			accepted: oauth.TokenResponse{AccessToken: "the-new-access-token", IdToken: refreshedIDTokenRaw,
				RefreshToken: "the-new-refresh-token"},
			acceptedID:  &oauth.JwtToken{TokenBase64: refreshedIDTokenRaw},
			wantScope:   storedGrant,
			wantRefresh: "the-new-refresh-token",
			wantIDToken: refreshedIDTokenRaw,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := newSessionHarness(t)
			cookies := h.seed(signedIn(due()))
			h.parser.On("DecodeAndValidateStoredIDToken", mock.Anything, storedIDTokenRaw).Return(verifiedStored, nil)
			h.refresher.answer = &tc.answer
			var held any
			h.expectRefreshValidation(cookies,
				&oauthclient.JwtInfo{TokenResponse: tc.accepted, IdToken: tc.acceptedID}, nil, &held)

			before := time.Now().Unix()
			out := h.serve(h.parser, cookies)
			after := time.Now().Unix()

			calls, sent := h.refresher.sent()
			require.Equal(t, 1, calls, "one refresh grant")
			assert.Equal(t, storedRefreshToken, sent, "the stored refresh token is the one sent")
			assert.Equal(t, storedResponse(), held, "nothing is stored before the answer is validated")
			h.parser.AssertCalled(t, "DecodeAndValidateRefreshResponse", mock.Anything, &tc.answer, verifiedStored)

			sess := h.readBack(cookies)
			stored, ok := sess.Values[sessionkeys.JWT].(oauth.TokenResponse)
			require.True(t, ok, "the accepted response is stored")
			assert.Equal(t, "the-new-access-token", stored.AccessToken)
			assert.Equal(t, tc.wantIDToken, stored.IdToken)
			assert.Equal(t, tc.wantRefresh, stored.RefreshToken)
			assert.Equal(t, tc.wantScope, stored.Scope, "the effective grant")

			expiresAt, ok := sess.Values[sessionkeys.JWTExpiresAt].(int64)
			require.True(t, ok, "the expiry is recorded as int64")
			if tc.wantLifetime == 0 {
				assert.Zero(t, expiresAt, "an absent expires_in is an unknown expiry")
			} else {
				assert.GreaterOrEqual(t, expiresAt, before+tc.wantLifetime)
				assert.LessOrEqual(t, expiresAt, after+tc.wantLifetime)
			}

			assert.True(t, out.reached)
			require.NotNil(t, out.jwtInfo)
			assert.Equal(t, stored, out.jwtInfo.TokenResponse, "the refreshed response reaches the request")
			assert.Same(t, tc.acceptedID, out.jwtInfo.IdToken)
			assert.Empty(t, h.logs.Records())
		})
	}
}

// Decision 2 of #441: the refresh is done when the new token is written down, not when the grant
// returns. The auth server revoked the old refresh token when it issued the new one, so a check or a
// write refused because the browser went away leaves the administrator holding a dead token and signs
// them out on their next page load. The token client detaches the grant itself; what follows it, the
// parser's check of the answer, which may fetch the JWKS, and the session write, runs on one context
// of the middleware's own, detached the same way and deadlined at TokenExchangeTimeout.
//
// The browser goes away while the grant is in flight, which is where it goes away in practice, and
// the backend refuses a done context as the real one does, so a check or a write still on the
// browser's context fails this case by what it leaves in the session as well as by what it observed.
func TestSessionHandler_TheCheckAndTheWriteOutliveTheBrowser(t *testing.T) {
	h := newSessionHarness(t)
	cookies := h.seed(signedIn(due()))

	const wantRequestID = "the-inbound-request-id"
	ctx, cancel := context.WithCancel(
		context.WithValue(context.Background(), chimiddleware.RequestIDKey, wantRequestID))
	defer cancel()

	h.parser.On("DecodeAndValidateStoredIDToken", mock.Anything, storedIDTokenRaw).Return(verifiedStored, nil)
	h.refresher.answer = &oauth.TokenResponse{AccessToken: "the-new-access-token", IdToken: refreshedIDTokenRaw,
		RefreshToken: "the-new-refresh-token", ExpiresIn: 600}
	h.refresher.during = func() {
		cancel()
		// The check's budget starts when the grant's ends; the pause is what makes the two
		// distinguishable below.
		time.Sleep(20 * time.Millisecond)
	}
	var checked observedContext
	h.parser.On("DecodeAndValidateRefreshResponse", mock.Anything, mock.Anything, verifiedStored).
		Run(func(args mock.Arguments) {
			checked = observe(args.Get(0).(context.Context))
		}).
		Return(func(_ context.Context, tr *oauth.TokenResponse, previous *oauth.JwtToken) (*oauthclient.JwtInfo, error) {
			return &oauthclient.JwtInfo{TokenResponse: *tr, IdToken: &oauth.JwtToken{TokenBase64: refreshedIDTokenRaw}}, nil
		})
	h.backend.mu.Lock()
	h.backend.writes = nil
	h.backend.mu.Unlock()

	out := h.serveOn(ctx, h.parser, cookies)

	assert.True(t, out.reached, "the chain continues")
	stored, ok := h.readBack(cookies).Values[sessionkeys.JWT].(oauth.TokenResponse)
	require.True(t, ok, "the refreshed response reached the session")
	assert.Equal(t, "the-new-access-token", stored.AccessToken)
	assert.Equal(t, "the-new-refresh-token", stored.RefreshToken)
	assert.Empty(t, h.logs.Records(), h.logs.Text())

	// The grant is handed the request's values; its detachment is the token client's to make.
	h.refresher.mu.Lock()
	grantRequestID, grantReturnedAt := h.refresher.requestID, h.refresher.returnedAt
	h.refresher.mu.Unlock()
	assert.Equal(t, wantRequestID, grantRequestID, "the grant is sent with the request's values")

	// The check.
	assert.NoError(t, checked.err, "the answer is checked on a context the browser's departure did not cancel")
	require.True(t, checked.hasDeadline, "detached, but not unbounded")
	assert.Equal(t, wantRequestID, checked.requestID, "and keeping request_id for the parser's records")

	// Two budgets, not one: the check's deadline is taken once the grant has returned, so it is at
	// least TokenExchangeTimeout past that moment, and no more than that past now.
	assert.False(t, checked.deadline.Before(grantReturnedAt.Add(oauthclient.TokenExchangeTimeout)),
		"the check and the write have a budget of their own, taken after the grant's")
	assert.LessOrEqual(t, time.Until(checked.deadline), oauthclient.TokenExchangeTimeout,
		"bounded by TokenExchangeTimeout")

	// The write: the same context as the check, so one deadline covers both.
	writes := h.backend.recordedWrites()
	require.Len(t, writes, 1, "one write, the refreshed session")
	assert.NoError(t, writes[0].err, "the session write runs on the detached context too")
	require.True(t, writes[0].hasDeadline)
	assert.True(t, checked.deadline.Equal(writes[0].deadline),
		"one deadline covers the check and the write together")
	assert.Equal(t, wantRequestID, writes[0].requestID, "and the write keeps request_id")
}
