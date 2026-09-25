package handlers

import (
	"encoding/gob"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/constants"
	mocks_handlerhelpers "github.com/leodip/goiabada/adminconsole/internal/handlerhelpers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	coreconstants "github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/sessionstore"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
	"github.com/leodip/goiabada/core/sessionstore/sessiontest"
	"github.com/leodip/goiabada/core/testutil"
)

// Seam 6 of #427, the half after the API-error helpers: the route an admin API 401 sends the
// browser to, and the home page that says why. Both run over the production ServerSideStore on an
// in-memory backend, and every assertion about the session is read back through the store's own
// Get with the cookie a browser would hold, because the notice's whole contract is what the *next*
// request sees: TakeFlash edits the session in memory only, and a handler that forgot to save would
// pass any test that read the same object back.

// newMemoryStore is the production store over an in-memory backend.
func newMemoryStore(t *testing.T) *sessionstore.ServerSideStore {
	t.Helper()
	gob.Register(oauth.TokenResponse{})
	store, err := sessionstore.NewServerSideStore(sessiontest.NewMemoryBackend(), constants.SessionKeyJwt, false,
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
	sess, err := store.Get(req, coreconstants.AdminConsoleSessionName)
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
	sess, err := store.Get(req, coreconstants.AdminConsoleSessionName)
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
		constants.SessionKeyJwt:          oauth.TokenResponse{AccessToken: "the-access-token", IdToken: "the-id-token"},
		constants.SessionKeyJwtExpiresAt: int64(1_900_000_000),
		"somethingElse":                  "kept",
	}
}

func TestHandleSessionEndedGet_ClearsTheTokensAndLeavesTheNoticeForTheNextRequest(t *testing.T) {
	store := newMemoryStore(t)
	logs := testutil.CaptureSlog(t)
	cookies := seedSession(t, store, signedInValues())

	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	w := httptest.NewRecorder()
	HandleSessionEndedGet(httpHelper, store).ServeHTTP(w,
		withCookies(handlertest.Request(http.MethodGet, "/auth/session-ended"), cookies))

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/", w.Header().Get("Location"),
		"the home page, which requires no sign-in, so nothing can loop with the auth server")

	sess := readSession(t, store, cookies)
	assert.NotContains(t, sess.Values, constants.SessionKeyJwt)
	assert.NotContains(t, sess.Values, constants.SessionKeyJwtExpiresAt,
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
			store := mocks_sessionstore.NewStore(t)
			store.On("Get", mock.Anything, coreconstants.AdminConsoleSessionName).
				Return(&sessionstore.Session{Values: signedInValues()}, testCase.getErr)
			if testCase.getErr == nil {
				store.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(testCase.saveErr)
			}
			httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
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
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	handlertest.ExpectRender(httpHelper, "/layouts/no_menu_layout.html", "/index.html").Once()
	HandleIndexGet(nil, httpHelper, store).ServeHTTP(httptest.NewRecorder(),
		withCookies(handlertest.Request(http.MethodGet, "/"), cookies))
	return handlertest.Bind(t, httpHelper)
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
	store := mocks_sessionstore.NewStore(t)
	store.On("Get", mock.Anything, coreconstants.AdminConsoleSessionName).
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
			store := mocks_sessionstore.NewStore(t)
			store.On("Get", mock.Anything, coreconstants.AdminConsoleSessionName).
				Return(&sessionstore.Session{Values: map[string]any{flashSessionEnded: "true"}}, testCase.getErr)
			if testCase.getErr == nil {
				store.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(testCase.saveErr)
			}
			httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
			httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Return().Once()

			HandleIndexGet(nil, httpHelper, store).ServeHTTP(httptest.NewRecorder(),
				handlertest.Request(http.MethodGet, "/"))

			httpHelper.AssertExpectations(t)
		})
	}
}

// #427 decision 18: the page RequiresScope sends a signed-in administrator without the scope to is a
// 403, since a 401 owes a WWW-Authenticate challenge the console does not have.
func TestHandleUnauthorizedGet_Answers403(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	handlertest.ExpectRender(httpHelper, "/layouts/no_menu_layout.html", "/unauthorized.html").Once()

	HandleUnauthorizedGet(httpHelper).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodGet, "/unauthorized"))

	assert.Equal(t, http.StatusForbidden, handlertest.Bind(t, httpHelper)["_httpStatus"])
}
