package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/config"
	"github.com/leodip/goiabada/adminconsole/internal/constants"
	mocks_handlerhelpers "github.com/leodip/goiabada/adminconsole/internal/handlerhelpers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient/oauthclienttest"
	coreconstants "github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/sessionstore"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
	"github.com/leodip/goiabada/core/sessionstore/sessiontest"
	"github.com/leodip/goiabada/core/testutil"
)

// Seam 4 of #427: HandleAuthCallbackPost over HTTP, one row per branch. Everything below the
// handler is real except the code exchange: the session store is the production ServerSideStore
// over an in-memory backend, so "nothing was written" and "the identifier rotated" are read back
// through the store's own Get with the cookies a browser would hold; and the parser is the
// production JWKSTokenParser verifying real RS256 tokens, so a token row proves the refusal the
// parser owes reaches the page, not merely that a stubbed error propagates.

const (
	callbackKid            = "callback-kid"
	callbackState          = "the-state"
	callbackCode           = "the-code"
	callbackRawNonce       = "the-raw-nonce"
	callbackVerifier       = "the-code-verifier"
	callbackRedirectURI    = "https://adminconsole.example/auth/callback"
	callbackRedirectBack   = "https://adminconsole.example/admin/clients"
	callbackRequestedScope = "openid profile authserver:manage"
	callbackGrantedScope   = "openid authserver:manage"
	callbackRequestID      = "req-callback"
)

// armableBackend is the in-memory backend with a Create that can be made to fail once the
// handshake has been seeded, which is how a rotation that cannot write its new row is reached.
type armableBackend struct {
	*sessiontest.MemoryBackend
	failCreate bool
}

func (b *armableBackend) Create(ctx context.Context, id string, data []byte, authenticated bool) (time.Time, error) {
	if b.failCreate {
		return time.Time{}, errs.New("the backend refused the write")
	}
	return b.MemoryBackend.Create(ctx, id, data, authenticated)
}

// saveOnlyStore hides the store's Regenerate, which is what a store that cannot rotate looks
// like to the handler: it reaches the Save fallback.
type saveOnlyStore struct{ sessionstore.Store }

// recordingExchanger answers the configured response or error, and records the call.
type recordingExchanger struct {
	response *oauth.TokenResponse
	err      error

	called                                    bool
	code, redirectURI, clientID, codeVerifier string
	tokenEndpoint                             string
}

func (e *recordingExchanger) ExchangeCodeForTokens(_ context.Context, code, redirectURI, clientId,
	_, codeVerifier, tokenEndpoint string) (*oauth.TokenResponse, error) {
	e.called = true
	e.code, e.redirectURI, e.clientID, e.codeVerifier, e.tokenEndpoint =
		code, redirectURI, clientId, codeVerifier, tokenEndpoint
	return e.response, e.err
}

type callbackHarness struct {
	t          *testing.T
	backend    *armableBackend
	store      *sessionstore.ServerSideStore
	parser     *oauthclient.JWKSTokenParser
	httpHelper *mocks_handlerhelpers.HttpHelper
	logs       *testutil.SlogCapture
}

func newCallbackHarness(t *testing.T) *callbackHarness {
	t.Helper()
	gob.Register(oauth.TokenResponse{})

	backend := &armableBackend{MemoryBackend: sessiontest.NewMemoryBackend()}
	store, err := sessionstore.NewServerSideStore(backend, constants.SessionKeyJwt, false,
		sessionstore.KeyPair{
			AuthenticationKey: []byte("12345678901234567890123456789012"),
			EncryptionKey:     []byte("abcdefghijklmnopqrstuvwxyz123456"),
		}, nil)
	require.NoError(t, err)

	signing, _ := oauthclienttest.Keys(t)
	jwks, _ := oauthclienttest.NewJwksServer(t, oauthclienttest.JwkFromPublicKey(callbackKid, &signing.PublicKey))
	parser := oauthclient.NewJWKSTokenParser(jwks.URL, jwks.Client(), oauthclienttest.ClientID,
		oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	return &callbackHarness{
		t:          t,
		backend:    backend,
		store:      store,
		parser:     parser,
		httpHelper: mocks_handlerhelpers.NewHttpHelper(t),
		logs:       testutil.CaptureSlog(t),
	}
}

// handshake is the six values RedirToAuthorize parks, as it parks them.
func handshake() map[string]any {
	return map[string]any{
		constants.SessionKeyState:          callbackState,
		constants.SessionKeyCodeVerifier:   callbackVerifier,
		constants.SessionKeyRedirectURI:    callbackRedirectURI,
		constants.SessionKeyNonce:          callbackRawNonce,
		constants.SessionKeyRedirectBack:   callbackRedirectBack,
		constants.SessionKeyRequestedScope: callbackRequestedScope,
	}
}

// seed stores values as a browser's session and returns the cookies that name it.
func (h *callbackHarness) seed(values map[string]any) []*http.Cookie {
	h.t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	sess, err := h.store.Get(req, coreconstants.AdminConsoleSessionName)
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

// readBack loads the session the cookies name, through the store's own Get, as the browser's next
// request would.
func (h *callbackHarness) readBack(cookies []*http.Cookie) *sessionstore.Session {
	h.t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	sess, err := h.store.Get(req, coreconstants.AdminConsoleSessionName)
	require.NoError(h.t, err)
	return sess
}

// serve posts form to the callback with cookies, behind chi's RequestID as in production.
func (h *callbackHarness) serve(store sessionstore.Store, exchanger TokenExchanger,
	cookies []*http.Cookie, form url.Values) *httptest.ResponseRecorder {
	h.t.Helper()
	req := handlertest.Request(http.MethodPost, "/auth/callback", handlertest.WithForm(form))
	req.Header.Set("X-Request-Id", callbackRequestID)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	chimiddleware.RequestID(HandleAuthCallbackPost(h.httpHelper, store, h.parser, exchanger)).ServeHTTP(w, req)
	return w
}

// idToken signs an ID token carrying the nonce this sign-in sent, with edit applied to its claims.
func (h *callbackHarness) idToken(edit func(jwt.MapClaims)) string {
	h.t.Helper()
	claims := oauthclienttest.ValidClaims()
	sent := sha256.Sum256([]byte(callbackRawNonce))
	claims["nonce"] = hex.EncodeToString(sent[:])
	if edit != nil {
		edit(claims)
	}
	signing, _ := oauthclienttest.Keys(h.t)
	return oauthclienttest.SignRS256(h.t, signing, callbackKid, claims)
}

// tokenResponse is what a successful exchange answers, with the granted scope named.
func (h *callbackHarness) tokenResponse() *oauth.TokenResponse {
	return &oauth.TokenResponse{
		AccessToken:  "the-access-token",
		IdToken:      h.idToken(nil),
		TokenType:    "Bearer",
		ExpiresIn:    300,
		RefreshToken: "the-refresh-token",
		Scope:        callbackGrantedScope,
	}
}

func callbackForm() url.Values {
	return url.Values{"state": {callbackState}, "code": {callbackCode}}
}

// assertRefused asserts the page a refusal rendered, the one record it logged, and that it wrote
// nothing: no cookie in the answer, and, when the browser brought a session, that session reads
// back exactly as it was seeded.
func (h *callbackHarness) assertRefused(w *httptest.ResponseRecorder, cookies []*http.Cookie,
	seeded map[string]any, want signInRefusal, wantLevel slog.Level) map[string]interface{} {
	h.t.Helper()

	bind := handlertest.Bind(h.t, h.httpHelper)
	assert.Equal(h.t, want.status, bind["_httpStatus"])
	assert.Equal(h.t, want.titleKey, bind["titleKey"])
	assert.Equal(h.t, want.messageKey, bind["messageKey"])
	serverFault := want.status == http.StatusInternalServerError
	assert.Equal(h.t, serverFault, bind["serverFault"], "the request id and log line on a 500, the start-again link on a 400")
	assert.Equal(h.t, callbackRequestID, bind["requestId"])

	records := h.logs.Records()
	require.NotEmpty(h.t, records)
	last := records[len(records)-1]
	assert.Equal(h.t, wantLevel, last.Level, "Warn for what came from the browser, Error for what the auth server answered")
	if serverFault {
		assert.Equal(h.t, "unable to complete the sign-in", last.Message)
	} else {
		assert.Equal(h.t, "sign-in refused", last.Message)
	}
	assert.NotNil(h.t, last.Attrs["error"], "the exact cause is logged")
	if !serverFault {
		for _, r := range records {
			assert.NotEqualf(h.t, slog.LevelError, r.Level, "no Error record for a browser-side refusal: %s", r.Message)
		}
	}

	assert.Empty(h.t, w.Result().Cookies(), "a refusal sets no cookie")
	if cookies != nil {
		readBack := h.readBack(cookies)
		assert.False(h.t, readBack.IsNew, "the browser's session is still there")
		assert.Equal(h.t, seeded, readBack.Values, "and unchanged")
	}
	return bind
}

// A handshake value that is absent, not a string, or empty is refused before the code is spent,
// whichever of the six it is. The nonce row is the one #412 found: a session with no nonce used to
// skip the nonce check and sign the administrator in (#427 decision 5).
func TestHandleAuthCallbackPost_RefusesAMalformedHandshakeBeforeTheExchange(t *testing.T) {
	malformations := []struct {
		name  string
		apply func(values map[string]any, key string)
	}{
		{"missing", func(values map[string]any, key string) { delete(values, key) }},
		{"not a string", func(values map[string]any, key string) { values[key] = 42 }},
		{"empty", func(values map[string]any, key string) { values[key] = "" }},
	}

	for _, key := range signInHandshakeKeys {
		for _, m := range malformations {
			t.Run(fmt.Sprintf("%s %s", key, m.name), func(t *testing.T) {
				h := newCallbackHarness(t)
				handlertest.RefuseInternalServerError(t, h.httpHelper)
				handlertest.ExpectRender(h.httpHelper, "/layouts/no_menu_layout.html", "/sign_in_error.html").Once()

				seeded := handshake()
				m.apply(seeded, key)
				cookies := h.seed(seeded)
				exchanger := &recordingExchanger{response: h.tokenResponse()}

				w := h.serve(h.store, exchanger, cookies, callbackForm())

				h.assertRefused(w, cookies, seeded, refusalSession, slog.LevelWarn)
				assert.False(t, exchanger.called, "refused before the code is spent")
			})
		}
	}
}

// The refusals decided from the browser's request and session alone, before the exchange.
func TestHandleAuthCallbackPost_RefusesFromTheRequestBeforeTheExchange(t *testing.T) {
	testCases := []struct {
		name string
		// cookies builds what the browser brings; nil seeds the whole handshake.
		cookies         func(h *callbackHarness) []*http.Cookie
		form            url.Values
		want            signInRefusal
		wantCode        string
		wantDescription string
	}{
		{
			// Decision 11: the store made a session up on this request, so the browser brought
			// none back, which has causes worth naming.
			name:    "no session cookie",
			cookies: func(*callbackHarness) []*http.Cookie { return []*http.Cookie{} },
			form:    callbackForm(),
			want:    refusalNoSession,
		},
		{
			name: "a session cookie that does not decode",
			cookies: func(h *callbackHarness) []*http.Cookie {
				return []*http.Cookie{{Name: h.store.CookieName(coreconstants.AdminConsoleSessionName), Value: "garbage"}}
			},
			form: callbackForm(),
			want: refusalNoSession,
		},
		{
			name: "the posted state is another",
			form: url.Values{"state": {"another-state"}, "code": {callbackCode}},
			want: refusalSession,
		},
		{
			name: "no posted state",
			form: url.Values{"code": {callbackCode}},
			want: refusalSession,
		},
		{
			name: "neither a code nor an error",
			form: url.Values{"state": {callbackState}},
			want: refusalSession,
		},
		{
			name: "the auth server posted an error with a description",
			form: url.Values{"state": {callbackState}, "error": {"access_denied"},
				"error_description": {"The user is disabled."}},
			want: signInRefusal{http.StatusBadRequest,
				"adminconsole.sign_in_error.refused.title", "adminconsole.sign_in_error.refused.body_description"},
			wantCode:        "access_denied",
			wantDescription: "The user is disabled.",
		},
		{
			name: "the auth server posted an error with no description",
			form: url.Values{"state": {callbackState}, "error": {"access_denied"}},
			want: signInRefusal{http.StatusBadRequest,
				"adminconsole.sign_in_error.refused.title", "adminconsole.sign_in_error.refused.body_code"},
			wantCode: "access_denied",
		},
		{
			// RFC 6749 Appendix A.8 has no '"' or line feed in an error_description; both
			// reach the page and the log conformed.
			name: "the posted error and description are conformed",
			form: url.Values{"state": {callbackState}, "error": {"bad\"code"},
				"error_description": {"line one\nline \"two\""}},
			want: signInRefusal{http.StatusBadRequest,
				"adminconsole.sign_in_error.refused.title", "adminconsole.sign_in_error.refused.body_description"},
			wantCode:        "bad?code",
			wantDescription: "line one?line ?two?",
		},
		{
			// The posted error is read only once the state has matched, so one planted by a
			// cross-site post to this CSRF-exempt route is never shown.
			name: "an error the state does not vouch for is not shown",
			form: url.Values{"state": {"another-state"}, "error": {"access_denied"},
				"error_description": {"Planted text."}},
			want: refusalSession,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := newCallbackHarness(t)
			handlertest.RefuseInternalServerError(t, h.httpHelper)
			handlertest.ExpectRender(h.httpHelper, "/layouts/no_menu_layout.html", "/sign_in_error.html").Once()

			var cookies []*http.Cookie
			var seeded map[string]any
			if tc.cookies != nil {
				cookies = tc.cookies(h)
			} else {
				seeded = handshake()
				cookies = h.seed(seeded)
			}
			exchanger := &recordingExchanger{response: h.tokenResponse()}

			w := h.serve(h.store, exchanger, cookies, tc.form)

			readBackCookies := cookies
			if seeded == nil {
				readBackCookies = nil
			}
			bind := h.assertRefused(w, readBackCookies, seeded, tc.want, slog.LevelWarn)
			assert.False(t, exchanger.called, "refused before the code is spent")
			assert.Equal(t, tc.wantCode, bind["code"])
			assert.Equal(t, tc.wantDescription, bind["description"])
		})
	}
}

// The refusals of what the auth server answered, after the code is spent: 500 at Error, and the
// token rows through the real parser. They share one message on purpose (decision 10).
func TestHandleAuthCallbackPost_RefusesWhatTheAuthServerAnswered(t *testing.T) {
	testCases := []struct {
		name     string
		exchange func(h *callbackHarness) (*oauth.TokenResponse, error)
		want     signInRefusal
	}{
		{
			name: "the exchange fails",
			exchange: func(*callbackHarness) (*oauth.TokenResponse, error) {
				return nil, errs.New("the auth server refused the code")
			},
			want: refusalExchange,
		},
		{
			name: "no id token",
			exchange: func(h *callbackHarness) (*oauth.TokenResponse, error) {
				r := h.tokenResponse()
				r.IdToken = ""
				return r, nil
			},
			want: refusalUnverified,
		},
		{
			name: "no access token",
			exchange: func(h *callbackHarness) (*oauth.TokenResponse, error) {
				r := h.tokenResponse()
				r.AccessToken = ""
				return r, nil
			},
			want: refusalUnverified,
		},
		{
			name: "an id token from another issuer",
			exchange: func(h *callbackHarness) (*oauth.TokenResponse, error) {
				r := h.tokenResponse()
				r.IdToken = h.idToken(func(c jwt.MapClaims) { c["iss"] = "https://another-issuer.example" })
				return r, nil
			},
			want: refusalUnverified,
		},
		{
			name: "an id token for another audience",
			exchange: func(h *callbackHarness) (*oauth.TokenResponse, error) {
				r := h.tokenResponse()
				r.IdToken = h.idToken(func(c jwt.MapClaims) { c["aud"] = "another-client" })
				return r, nil
			},
			want: refusalUnverified,
		},
		{
			name: "an id token with no nonce",
			exchange: func(h *callbackHarness) (*oauth.TokenResponse, error) {
				r := h.tokenResponse()
				r.IdToken = h.idToken(func(c jwt.MapClaims) { delete(c, "nonce") })
				return r, nil
			},
			want: refusalUnverified,
		},
		{
			name: "an id token with another sign-in's nonce",
			exchange: func(h *callbackHarness) (*oauth.TokenResponse, error) {
				r := h.tokenResponse()
				other := sha256.Sum256([]byte("another-raw-nonce"))
				r.IdToken = h.idToken(func(c jwt.MapClaims) { c["nonce"] = hex.EncodeToString(other[:]) })
				return r, nil
			},
			want: refusalUnverified,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := newCallbackHarness(t)
			handlertest.RefuseInternalServerError(t, h.httpHelper)
			handlertest.ExpectRender(h.httpHelper, "/layouts/no_menu_layout.html", "/sign_in_error.html").Once()

			seeded := handshake()
			cookies := h.seed(seeded)
			response, err := tc.exchange(h)
			exchanger := &recordingExchanger{response: response, err: err}

			w := h.serve(h.store, exchanger, cookies, callbackForm())

			bind := h.assertRefused(w, cookies, seeded, tc.want, slog.LevelError)
			assert.True(t, exchanger.called)
			assert.Empty(t, bind["code"])
			assert.Empty(t, bind["description"])
		})
	}
}

// A session store that cannot be read answers the generic 500 page, as it did.
func TestHandleAuthCallbackPost_ASessionThatCannotBeRead(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Return().Once()
	httpSession := mocks_sessionstore.NewStore(t)
	httpSession.On("Get", mock.Anything, coreconstants.AdminConsoleSessionName).
		Return(&sessionstore.Session{Values: map[string]any{}}, errs.New("the store is down"))
	exchanger := &recordingExchanger{}

	req := handlertest.Request(http.MethodPost, "/auth/callback", handlertest.WithForm(callbackForm()))
	HandleAuthCallbackPost(httpHelper, httpSession, unusedTokenParser{t: t}, exchanger).
		ServeHTTP(httptest.NewRecorder(), req)

	assert.False(t, exchanger.called)
}

// A rotation that cannot write the new row answers the generic 500 page and leaves the browser's
// session as it was: Regenerate writes nothing and sets no cookie until every step has succeeded.
func TestHandleAuthCallbackPost_ARotationThatFails(t *testing.T) {
	h := newCallbackHarness(t)
	h.httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Return().Once()

	seeded := handshake()
	cookies := h.seed(seeded)
	h.backend.failCreate = true
	exchanger := &recordingExchanger{response: h.tokenResponse()}

	w := h.serve(h.store, exchanger, cookies, callbackForm())

	assert.True(t, exchanger.called)
	assert.Empty(t, w.Result().Cookies())
	h.backend.failCreate = false
	readBack := h.readBack(cookies)
	assert.False(t, readBack.IsNew)
	assert.Equal(t, seeded, readBack.Values)
}

// assertSignedIn asserts what a completed sign-in stores: the token response with the effective
// grant, the access token's expiry recorded from expires_in, and none of the six handshake values.
func assertSignedIn(t *testing.T, sess *sessionstore.Session, want oauth.TokenResponse, before, after time.Time) {
	t.Helper()
	require.False(t, sess.IsNew, "a session is stored")
	stored, ok := sess.Values[constants.SessionKeyJwt].(oauth.TokenResponse)
	require.True(t, ok, "the token response is stored")
	assert.Equal(t, want, stored)

	expiresAt, ok := sess.Values[constants.SessionKeyJwtExpiresAt].(int64)
	require.True(t, ok, "the expiry is stored as int64 Unix seconds")
	assert.GreaterOrEqual(t, expiresAt, before.Unix()+want.ExpiresIn)
	assert.LessOrEqual(t, expiresAt, after.Unix()+want.ExpiresIn)

	for _, key := range signInHandshakeKeys {
		assert.NotContainsf(t, sess.Values, key, "the handshake's %s is deleted", key)
	}
	assert.Len(t, sess.Values, 2, "the token response and its expiry, and nothing else")
}

// A sign-in that passes every check is stored under a new identifier, and the identifier the
// browser brought reads back as nothing: this is the rotation #266 requires at the console's one
// privilege transition, observed through the store rather than lexically.
func TestHandleAuthCallbackPost_SignsInAndRotatesTheIdentifier(t *testing.T) {
	testCases := []struct {
		name      string
		scope     string
		wantScope string
	}{
		{"the response names its grant", callbackGrantedScope, callbackGrantedScope},
		// RFC 6749 section 3.3: an omitted scope means the grant is the request.
		{"the response names no scope", "", callbackRequestedScope},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := newCallbackHarness(t)
			handlertest.RefuseInternalServerError(t, h.httpHelper)

			cookies := h.seed(handshake())
			response := h.tokenResponse()
			response.Scope = tc.scope
			exchanger := &recordingExchanger{response: response}

			before := time.Now()
			w := h.serve(h.store, exchanger, cookies, callbackForm())
			after := time.Now()

			require.Equal(t, http.StatusFound, w.Code)
			assert.Equal(t, callbackRedirectBack, w.Header().Get("Location"))

			assert.True(t, exchanger.called)
			assert.Equal(t, callbackCode, exchanger.code)
			assert.Equal(t, callbackRedirectURI, exchanger.redirectURI)
			assert.Equal(t, coreconstants.AdminConsoleClientIdentifier, exchanger.clientID)
			assert.Equal(t, callbackVerifier, exchanger.codeVerifier)
			assert.Equal(t, config.GetAuthServer().GetEffectiveBaseURL()+"/auth/token", exchanger.tokenEndpoint)

			want := *response
			want.Scope = tc.wantScope
			newCookies := w.Result().Cookies()
			require.NotEmpty(t, newCookies, "the new identifier is sent")
			assertSignedIn(t, h.readBack(newCookies), want, before, after)

			assert.True(t, h.readBack(cookies).IsNew, "the identifier the browser brought names nothing any more")
		})
	}
}

// A store that cannot rotate still signs the administrator in, through Save.
func TestHandleAuthCallbackPost_TheSaveFallback(t *testing.T) {
	h := newCallbackHarness(t)
	handlertest.RefuseInternalServerError(t, h.httpHelper)

	cookies := h.seed(handshake())
	response := h.tokenResponse()
	exchanger := &recordingExchanger{response: response}

	before := time.Now()
	w := h.serve(saveOnlyStore{h.store}, exchanger, cookies, callbackForm())
	after := time.Now()

	require.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, callbackRedirectBack, w.Header().Get("Location"))
	assertSignedIn(t, h.readBack(cookies), *response, before, after)
}
