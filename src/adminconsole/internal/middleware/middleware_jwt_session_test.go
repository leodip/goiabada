package middleware

import (
	"context"
	"encoding/gob"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/constants"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient/oauthclienttest"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/sessionstore/sessiontest"
	"github.com/leodip/goiabada/core/testutil"

	mock_middleware "github.com/leodip/goiabada/adminconsole/internal/middleware/mocks"
)

// Seam 5 of #427: JwtSessionHandler, one row per step of its per-request order, over a real
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

// recordingRefreshClient is the auth server's token endpoint: it answers every refresh grant with
// one scripted status and body and records what it was sent.
type recordingRefreshClient struct {
	status int
	body   string

	mu    sync.Mutex
	calls int
	form  url.Values
}

func (c *recordingRefreshClient) Do(req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	sent, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	c.form, err = url.ParseQuery(string(sent))
	if err != nil {
		return nil, err
	}
	return &http.Response{StatusCode: c.status, Body: io.NopCloser(strings.NewReader(c.body))}, nil
}

func (c *recordingRefreshClient) sent() (int, url.Values) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls, c.form
}

type sessionHarness struct {
	t      *testing.T
	store  *sessionstore.ServerSideStore
	parser *mock_middleware.TokenParser
	client *recordingRefreshClient
	logs   *testutil.SlogCapture
}

func newSessionHarness(t *testing.T) *sessionHarness {
	t.Helper()
	gob.Register(oauth.TokenResponse{})
	store, err := sessionstore.NewServerSideStore(sessiontest.NewMemoryBackend(), constants.SessionKeyJwt, false,
		sessionstore.KeyPair{
			AuthenticationKey: []byte("12345678901234567890123456789012"),
			EncryptionKey:     []byte("abcdefghijklmnopqrstuvwxyz123456"),
		}, nil)
	require.NoError(t, err)
	return &sessionHarness{
		t:      t,
		store:  store,
		parser: mock_middleware.NewTokenParser(t),
		client: &recordingRefreshClient{status: http.StatusOK},
		logs:   testutil.CaptureSlog(t),
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

// serve sends one request carrying cookies through JwtSessionHandler over parser.
func (h *sessionHarness) serve(parser tokenParser, cookies []*http.Cookie) served {
	h.t.Helper()
	m := NewMiddlewareJwt(h.store, sessionTestName, parser, new(mock_middleware.AuthHelper),
		stubErrorRenderer{}, h.client, "http://auth.example", "http://console.example",
		"admin-console-client", "the-client-secret")

	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	var out served
	out.recorder = httptest.NewRecorder()
	m.JwtSessionHandler()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out.reached = true
		if jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauthclient.JwtInfo); ok {
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
		constants.SessionKeyJwt:          storedResponse(),
		constants.SessionKeyJwtExpiresAt: expiresAt,
		"unrelated":                      "kept",
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
	assert.NotContains(h.t, sess.Values, constants.SessionKeyJwt, "the token response is deleted")
	assert.NotContains(h.t, sess.Values, constants.SessionKeyJwtExpiresAt, "and its expiry with it")
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
	calls, _ := h.client.sent()
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
func TestJwtSessionHandler_NoTokenResponseContinuesUnauthenticated(t *testing.T) {
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
func TestJwtSessionHandler_SignsOutASessionItCannotVerify(t *testing.T) {
	noIDToken := storedResponse()
	noIDToken.IdToken = ""

	testCases := []struct {
		name    string
		values  map[string]any
		message string
	}{
		{
			name:    "no recorded expiry, as every session signed in before the upgrade",
			values:  map[string]any{constants.SessionKeyJwt: storedResponse(), "unrelated": "kept"},
			message: "the session holds a token response with no recorded expiry, signing it out",
		},
		{
			name: "an expiry of another type than int64",
			values: map[string]any{constants.SessionKeyJwt: storedResponse(),
				constants.SessionKeyJwtExpiresAt: "1700000000", "unrelated": "kept"},
			message: "the session holds a token response with no recorded expiry, signing it out",
		},
		{
			name: "no id token",
			values: map[string]any{constants.SessionKeyJwt: noIDToken,
				constants.SessionKeyJwtExpiresAt: due(), "unrelated": "kept"},
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
func TestJwtSessionHandler_InvalidIssuer(t *testing.T) {
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
func TestJwtSessionHandler_AStoredIDTokenThatNoLongerVerifiesIsSignedOutWithoutARefresh(t *testing.T) {
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
// one. Here the stored ID token is signed by a key the JWKS no longer publishes and its access
// token is due, so a middleware that fell through from step 3 to the refresh would send one.
func TestJwtSessionHandler_AStoredIDTokenUnderARetiredKeyIsSignedOutWithoutARefresh(t *testing.T) {
	h := newSessionHarness(t)

	signing, retired := oauthclienttest.Keys(t)
	jwks, _ := oauthclienttest.NewJwksServer(t, oauthclienttest.JwkFromPublicKey("current", &signing.PublicKey))
	parser := oauthclient.NewJWKSTokenParser(jwks.URL, jwks.Client(), oauthclienttest.ClientID,
		oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	response := storedResponse()
	response.IdToken = oauthclienttest.SignRS256(t, retired, "retired", oauthclienttest.ValidClaims())
	cookies := h.seed(map[string]any{
		constants.SessionKeyJwt:          response,
		constants.SessionKeyJwtExpiresAt: due(),
		"unrelated":                      "kept",
	})
	h.client.body = `{"access_token":"new","id_token":"new","refresh_token":"new","expires_in":300}`

	out := h.serve(parser, cookies)

	h.assertContinuedUnauthenticated(out)
	h.assertNoRefreshSent()
	h.assertSignedOut(cookies)
	h.assertOneRecord(slog.LevelWarn, "the stored id token no longer verifies, signing the session out",
		"public key not found for token kid")
}

// Step 4: nothing is refreshed until the recorded expiry is within the margin, and an unknown
// expiry, 0, never is (decision 16). The stored response and the verified ID token reach the
// request as they are, and the session is not written.
func TestJwtSessionHandler_UsesTheStoredTokensUntilTheyAreDue(t *testing.T) {
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
			assert.Equal(t, storedResponse(), sess.Values[constants.SessionKeyJwt])
			assert.Equal(t, tc.expiresAt, sess.Values[constants.SessionKeyJwtExpiresAt])
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
			*heldAtValidation = h.readBack(cookies).Values[constants.SessionKeyJwt]
		}).
		Return(accepted, refused)
}

// Step 5, the refusals: the auth server answered and its answer failed validation. A foreign one
// ends the session at Warn, as step 3 does; any other, a different sub or sign-in time, ends it at
// Error, because someone must look at that (decision 14). Nothing from the answer reaches the
// session, before validation or after.
func TestJwtSessionHandler_ARefusedRefreshEndsTheSession(t *testing.T) {
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
			h.client.body = `{"access_token":"the-new-access-token","id_token":"` + refreshedIDTokenRaw +
				`","refresh_token":"the-new-refresh-token","expires_in":300}`
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
// and the chain continues unauthenticated.
func TestJwtSessionHandler_AFailedRefreshGrantSignsTheSessionOut(t *testing.T) {
	t.Run("the auth server refuses the grant", func(t *testing.T) {
		h := newSessionHarness(t)
		cookies := h.seed(signedIn(due()))
		h.parser.On("DecodeAndValidateStoredIDToken", mock.Anything, storedIDTokenRaw).Return(verifiedStored, nil)
		h.client.status = http.StatusBadRequest
		h.client.body = `{"error":"invalid_grant"}`

		out := h.serve(h.parser, cookies)

		h.assertContinuedUnauthenticated(out)
		h.assertSignedOut(cookies)
		calls, _ := h.client.sent()
		assert.Equal(t, 1, calls)
		h.assertOneRecord(slog.LevelWarn, "unable to refresh the access token, signing the session out", "invalid_grant")
	})

	t.Run("there is no refresh token", func(t *testing.T) {
		h := newSessionHarness(t)
		response := storedResponse()
		response.RefreshToken = ""
		cookies := h.seed(map[string]any{
			constants.SessionKeyJwt:          response,
			constants.SessionKeyJwtExpiresAt: due(),
			"unrelated":                      "kept",
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
func TestJwtSessionHandler_ARefreshIsValidatedThenStored(t *testing.T) {
	testCases := []struct {
		name string
		// body is the token endpoint's answer.
		body string
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
			body: `{"access_token":"the-new-access-token","id_token":"` + refreshedIDTokenRaw +
				`","refresh_token":"the-new-refresh-token","expires_in":600,"scope":"openid authserver:manage"}`,
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
			body: `{"access_token":"the-new-access-token","id_token":"` + refreshedIDTokenRaw +
				`","refresh_token":"the-new-refresh-token","expires_in":600}`,
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
			body: `{"access_token":"the-new-access-token","refresh_token":"the-new-refresh-token","expires_in":600}`,
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
			body: `{"access_token":"the-new-access-token","id_token":"` + refreshedIDTokenRaw +
				`","refresh_token":"the-new-refresh-token"}`,
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
			h.client.body = tc.body
			var held any
			h.expectRefreshValidation(cookies,
				&oauthclient.JwtInfo{TokenResponse: tc.accepted, IdToken: tc.acceptedID}, nil, &held)

			before := time.Now().Unix()
			out := h.serve(h.parser, cookies)
			after := time.Now().Unix()

			calls, form := h.client.sent()
			require.Equal(t, 1, calls, "one refresh grant")
			assert.Equal(t, "refresh_token", form.Get("grant_type"))
			assert.Equal(t, storedRefreshToken, form.Get("refresh_token"))
			assert.Equal(t, storedResponse(), held, "nothing is stored before the answer is validated")

			sess := h.readBack(cookies)
			stored, ok := sess.Values[constants.SessionKeyJwt].(oauth.TokenResponse)
			require.True(t, ok, "the accepted response is stored")
			assert.Equal(t, "the-new-access-token", stored.AccessToken)
			assert.Equal(t, tc.wantIDToken, stored.IdToken)
			assert.Equal(t, tc.wantRefresh, stored.RefreshToken)
			assert.Equal(t, tc.wantScope, stored.Scope, "the effective grant")

			expiresAt, ok := sess.Values[constants.SessionKeyJwtExpiresAt].(int64)
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

// RFC 6749 section 6 lets the auth server issue a new refresh token or not. An answer that issues
// none leaves the old one the client's, so it is kept rather than stored away as empty, which would
// sign the administrator out at the next refresh. The kept token is also what the parser is shown.
func TestJwtSessionHandler_ARefreshThatIssuesNoRefreshTokenKeepsTheOldOne(t *testing.T) {
	h := newSessionHarness(t)
	cookies := h.seed(signedIn(due()))
	h.parser.On("DecodeAndValidateStoredIDToken", mock.Anything, storedIDTokenRaw).Return(verifiedStored, nil)
	h.client.body = `{"access_token":"the-new-access-token","id_token":"` + refreshedIDTokenRaw + `","expires_in":600}`
	h.parser.EXPECT().DecodeAndValidateRefreshResponse(mock.Anything,
		mock.MatchedBy(func(tr *oauth.TokenResponse) bool { return tr.RefreshToken == storedRefreshToken }),
		verifiedStored).
		RunAndReturn(func(_ context.Context, tr *oauth.TokenResponse, _ *oauth.JwtToken) (*oauthclient.JwtInfo, error) {
			return &oauthclient.JwtInfo{TokenResponse: *tr, IdToken: &oauth.JwtToken{TokenBase64: refreshedIDTokenRaw}}, nil
		})

	out := h.serve(h.parser, cookies)

	require.True(t, out.reached)
	stored, ok := h.readBack(cookies).Values[constants.SessionKeyJwt].(oauth.TokenResponse)
	require.True(t, ok)
	assert.Equal(t, "the-new-access-token", stored.AccessToken)
	assert.Equal(t, storedRefreshToken, stored.RefreshToken, "the old refresh token is kept")
}
