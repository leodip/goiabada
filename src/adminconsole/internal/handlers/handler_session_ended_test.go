package handlers

import (
	"encoding/gob"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/adminconsole/internal/sessionkeys"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/sessionstore/mocks"
	"github.com/leodip/goiabada/core/sessionstore/sessiontest"
)

// Seam 6 of #427, the half after the API-error helpers: the route an admin API 401 sends the
// browser to, and the home page that says why. Both run over the production ServerSideStore on an
// in-memory backend, and every assertion about the session is read back through the store's own
// Get with the cookie a browser would hold, because the notice's whole contract is what the *next*
// request sees: TakeFlash edits the session in memory only, and a handler that forgot to save would
// pass any test that read the same object back.

// indexAuthServerBaseURL is the auth server base URL the home page is built with here. It is not
// the configuration's default, http://localhost:9090, so a page reading anything but the value it
// was given cannot pass (#441).
const indexAuthServerBaseURL = "https://auth.example.test"

// newMemoryStore is the production store over an in-memory backend.
func newMemoryStore(t *testing.T) *sessionstore.ServerSideStore {
	t.Helper()
	gob.Register(oauth.TokenResponse{})
	store, err := sessionstore.NewServerSideStore(sessiontest.NewMemoryBackend(), sessionkeys.JWT, false, sessionstore.BrowserSessionCookie,
		sessionstore.KeyPair{
			AuthenticationKey: []byte("12345678901234567890123456789012"),
			EncryptionKey:     []byte("abcdefghijklmnopqrstuvwxyz123456"),
		}, nil)
	require.NoError(t, err)
	return store
}

// seedSession stores values as a browser's session and returns the cookies that name it.
func seedSession(t *testing.T, store sessionstore.Store, values map[string]any) []*http.Cookie {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	sess, err := store.Get(req, builtin.AdminConsoleSessionName)
	require.NoError(t, err)
	for k, v := range values {
		sess.Values[k] = v
	}
	w := httptest.NewRecorder()
	require.NoError(t, store.Save(req, w, sess))
	cookies := w.Result().Cookies()
	require.NotEmpty(t, cookies)
	return cookies
}

// readSession loads the session the cookies name, as the browser's next request would.
func readSession(t *testing.T, store sessionstore.Store, cookies []*http.Cookie) *sessionstore.Session {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	sess, err := store.Get(req, builtin.AdminConsoleSessionName)
	require.NoError(t, err)
	return sess
}

// withCookies adds cookies to req and returns it.
func withCookies(req *http.Request, cookies []*http.Cookie) *http.Request {
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return req
}

// signedInValues is what a signed-in session holds, plus one value that is not a token, which is
// how the tests tell "the tokens were cleared" from "the session was destroyed".
func signedInValues() map[string]any {
	return map[string]any{
		sessionkeys.JWT:          oauth.TokenResponse{AccessToken: "the-access-token", IdToken: "the-id-token"},
		sessionkeys.JWTExpiresAt: int64(1_900_000_000),
		"somethingElse":          "kept",
	}
}

func TestHandleSessionEndedGet_ClearsTheTokensAndLeavesTheNoticeForTheNextRequest(t *testing.T) {
	store := newMemoryStore(t)
	logs := logtest.CaptureSlog(t)
	cookies := seedSession(t, store, signedInValues())

	httpHelper := handlersmocks.NewHttpHelper(t)
	w := httptest.NewRecorder()
	HandleSessionEndedGet(httpHelper, store).ServeHTTP(w,
		withCookies(handlertest.Request(http.MethodGet, "/auth/session-ended"), cookies))

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/", w.Header().Get("Location"),
		"the home page, which requires no sign-in, so nothing can loop with the auth server")

	sess := readSession(t, store, cookies)
	assert.NotContains(t, sess.Values, sessionkeys.JWT)
	assert.NotContains(t, sess.Values, sessionkeys.JWTExpiresAt,
		"the expiry goes with the token, or the next sign-in inherits a stale one")
	assert.Equal(t, "kept", sess.Values["somethingElse"],
		"only the tokens go: the session survives to carry the notice")
	_, noticed := sess.TakeFlash(flashSessionEnded)
	assert.True(t, noticed, "the notice was saved for the home page's request")

	records := logs.Records()
	require.Len(t, records, 1)
	assert.Equal(t, slog.LevelWarn, records[0].Level, "a refusal met and handled; nobody has to act")
	assert.Equal(t, "the admin api refused the access token, signing the session out", records[0].Message)
}

func TestHandleSessionEndedGet_AnswersTheErrorPageWhenTheSessionCannotBeReadOrSaved(t *testing.T) {
	testCases := []struct {
		name    string
		getErr  error
		saveErr error
	}{
		{name: "the session cannot be read", getErr: errs.New("the store is down")},
		{name: "the session cannot be saved", saveErr: errs.New("the store refused the write")},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			store := sessionstoremocks.NewStore(t)
			store.On("Get", mock.Anything, builtin.AdminConsoleSessionName).
				Return(&sessionstore.Session{Values: signedInValues()}, testCase.getErr)
			if testCase.getErr == nil {
				store.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(testCase.saveErr)
			}
			httpHelper := handlersmocks.NewHttpHelper(t)
			httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Return().Once()

			w := httptest.NewRecorder()
			HandleSessionEndedGet(httpHelper, store).ServeHTTP(w,
				handlertest.Request(http.MethodGet, "/auth/session-ended"))

			httpHelper.AssertExpectations(t)
			assert.Empty(t, w.Header().Get("Location"), "no redirect after the error page")
		})
	}
}

// serveIndex answers one home page request with cookies, and returns the bind it rendered with.
func serveIndex(t *testing.T, store sessionstore.Store, cookies []*http.Cookie) map[string]interface{} {
	t.Helper()
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.ExpectRender(httpHelper, "/layouts/no_menu_layout.html", "/index.html").Once()
	HandleIndexGet(nil, httpHelper, store, indexAuthServerBaseURL).ServeHTTP(httptest.NewRecorder(),
		withCookies(handlertest.Request(http.MethodGet, "/"), cookies))
	return handlertest.Bind(t, httpHelper)
}

// The home page is mounted outside RequiresScope, so it reads the token set itself: a signed-in
// administrator is greeted by the email the ID token carries and offered the logout link, and a
// visitor without a token set is anonymous rather than a fault. The real AuthHelper decides, so a
// token set the reader lost on the way would read as anonymous here.
func TestHandleIndexGet_ReadsTheSignedInAdministratorFromTheTokenSet(t *testing.T) {
	store := sessionstoremocks.NewStore(t)
	store.On("Get", mock.Anything, builtin.AdminConsoleSessionName).
		Return(&sessionstore.Session{Values: map[string]any{}}, nil)
	authHelper := oauthclient.NewAuthHelper(store, builtin.AdminConsoleSessionName, "", "")

	serve := func(opts ...handlertest.Option) map[string]interface{} {
		httpHelper := handlersmocks.NewHttpHelper(t)
		handlertest.ExpectRender(httpHelper, "/layouts/no_menu_layout.html", "/index.html").Once()
		HandleIndexGet(authHelper, httpHelper, store, indexAuthServerBaseURL).ServeHTTP(httptest.NewRecorder(),
			handlertest.Request(http.MethodGet, "/", opts...))
		return handlertest.Bind(t, httpHelper)
	}

	signedIn := serve(handlertest.WithJwtInfo(oauthclient.JwtInfo{
		IdToken: &oauth.JwtToken{Claims: jwt.MapClaims{"email": "admin@example.com"}},
	}))
	assert.Equal(t, true, signedIn["IsAuthenticated"])
	assert.Equal(t, "admin@example.com", signedIn["LoggedInUser"])
	assert.Equal(t, "/auth/logout", signedIn["LogoutLink"])

	anonymous := serve()
	assert.Equal(t, false, anonymous["IsAuthenticated"])
	assert.Equal(t, "", anonymous["LoggedInUser"])
	assert.Equal(t, "", anonymous["LogoutLink"])

	// The page links to the auth server's public base URL it was built with, signed in or not.
	for name, bind := range map[string]map[string]interface{}{"signed in": signedIn, "anonymous": anonymous} {
		assert.Equal(t, "https://auth.example.test", bind["AuthServerBaseUrl"], name)
	}
}

// The notice is shown once: the second request replays the first one's cookie through a real
// store, which is the only way to see that the taken flash was saved (plan review round 1,
// finding 4).
func TestHandleIndexGet_ShowsTheSessionEndedNoticeOnce(t *testing.T) {
	store := newMemoryStore(t)
	cookies := seedSession(t, store, map[string]any{flashSessionEnded: "true"})

	assert.Equal(t, true, serveIndex(t, store, cookies)["SessionEnded"], "the first visit shows the notice")
	assert.Equal(t, false, serveIndex(t, store, cookies)["SessionEnded"], "the next visit does not")
}

func TestHandleIndexGet_NoNoticeWithoutTheFlash(t *testing.T) {
	store := newMemoryStore(t)

	assert.Equal(t, false, serveIndex(t, store, nil)["SessionEnded"], "a visitor with no session")
	cookies := seedSession(t, store, signedInValues())
	assert.Equal(t, false, serveIndex(t, store, cookies)["SessionEnded"], "a session with no notice")
}

// The home page saves only when it took a notice: an anonymous visit writes nothing, which the mock
// store proves by failing on a Save nobody expected.
func TestHandleIndexGet_SavesOnlyWhenItTookTheNotice(t *testing.T) {
	store := sessionstoremocks.NewStore(t)
	store.On("Get", mock.Anything, builtin.AdminConsoleSessionName).
		Return(&sessionstore.Session{Values: map[string]any{}}, nil)

	assert.Equal(t, false, serveIndex(t, store, nil)["SessionEnded"])
}

func TestHandleIndexGet_AnswersTheErrorPageWhenTheSessionCannotBeReadOrSaved(t *testing.T) {
	testCases := []struct {
		name    string
		getErr  error
		saveErr error
	}{
		{name: "the session cannot be read", getErr: errs.New("the store is down")},
		{name: "the taken notice cannot be saved", saveErr: errs.New("the store refused the write")},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			store := sessionstoremocks.NewStore(t)
			store.On("Get", mock.Anything, builtin.AdminConsoleSessionName).
				Return(&sessionstore.Session{Values: map[string]any{flashSessionEnded: "true"}}, testCase.getErr)
			if testCase.getErr == nil {
				store.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(testCase.saveErr)
			}
			httpHelper := handlersmocks.NewHttpHelper(t)
			httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Return().Once()

			HandleIndexGet(nil, httpHelper, store, indexAuthServerBaseURL).ServeHTTP(httptest.NewRecorder(),
				handlertest.Request(http.MethodGet, "/"))

			httpHelper.AssertExpectations(t)
		})
	}
}

// #427 decision 18: the page RequiresScope sends a signed-in administrator without the scope to is a
// 403, since a 401 owes a WWW-Authenticate challenge the console does not have.
func TestHandleUnauthorizedGet_Answers403(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.ExpectRender(httpHelper, "/layouts/no_menu_layout.html", "/unauthorized.html").Once()

	HandleUnauthorizedGet(httpHelper).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodGet, "/unauthorized"))

	assert.Equal(t, http.StatusForbidden, handlertest.Bind(t, httpHelper)["_httpStatus"])
}
