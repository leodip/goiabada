package middleware

import (
	"context"
	"encoding/gob"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	middlewaremocks "github.com/leodip/goiabada/adminconsole/internal/middleware/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/adminconsole/internal/sessionkeys"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/sessionstore"
	sessionstoremocks "github.com/leodip/goiabada/core/sessionstore/mocks"
	"github.com/leodip/goiabada/core/sessionstore/sessiontest"
)

// The sign-in arm of RequiresScope at #620: an anonymous request starts a sign-in whose handshake
// rides in a sealed cookie, so it writes no browser-session row, and the return target that cookie
// carries is bounded so it no longer tracks the request line's length.

// createCountingBackend counts the rows the store inserts, which is what an anonymous request
// used to cost the auth server: one Create per sign-in redirect.
type createCountingBackend struct {
	*sessiontest.MemoryBackend
	creates atomic.Int64
}

func (c *createCountingBackend) Create(ctx context.Context, id string, data []byte, authenticated bool) (time.Time, error) {
	c.creates.Add(1)
	return c.MemoryBackend.Create(ctx, id, data, authenticated)
}

// The real AuthHelper over the real store: anonymous requests to the console's pages each start a
// sign-in and set the handshake cookie, and not one of them creates a row. The cookie opens to the
// handshake the redirect sent.
func TestRequiresScope_AnAnonymousRequestWritesNoRow(t *testing.T) {
	gob.Register(oauth.TokenResponse{})
	backend := &createCountingBackend{MemoryBackend: sessiontest.NewMemoryBackend()}
	store, err := sessionstore.NewServerSideStore(backend, sessionkeys.JWT, true, sessionstore.BrowserSessionCookie,
		sessionstore.KeyPair{
			AuthenticationKey: []byte("12345678901234567890123456789012"),
			EncryptionKey:     []byte("abcdefghijklmnopqrstuvwxyz123456"),
		}, nil)
	require.NoError(t, err)
	authHelper := oauthclient.NewAuthHelper(store, "https://console.example", "https://auth.example")
	mw := NewJWT(store, nil, builtin.AdminConsoleSessionName, nil, nil, authHelper,
		stubErrorRenderer{}, "https://console.example", builtin.AdminConsoleClientIdentifier)
	handler := mw.RequiresScope([]string{"required:scope"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("an anonymous request never reaches the page it asked for")
	}))

	requests := map[string]*http.Request{
		"an /admin path":          httptest.NewRequest(http.MethodGet, "/admin/clients", nil),
		"an /account path":        httptest.NewRequest(http.MethodGet, "/account/profile", nil),
		"a path no route answers": httptest.NewRequest(http.MethodGet, "/admin/no-such-page", nil),
	}

	for name, req := range requests {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			require.Equal(t, http.StatusFound, w.Code)
			assert.True(t, strings.HasPrefix(w.Header().Get("Location"), "https://auth.example/auth/authorize?"))
			cookies := w.Result().Cookies()
			require.Len(t, cookies, 1, "the handshake's cookie, and no session cookie")
			cookie := cookies[0]
			assert.Equal(t, "__Host-"+oauthclient.SignInHandshakeCookie, cookie.Name)
			assert.True(t, cookie.Secure)
			assert.True(t, cookie.HttpOnly)
			assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
			assert.Equal(t, "/", cookie.Path)
			assert.Empty(t, cookie.Domain)
			assert.Equal(t, int(sessionstore.PreAuthLifetime.Seconds()), cookie.MaxAge)

			handshake, err := store.OpenCookieValues(oauthclient.SignInHandshakeCookie, cookie.Value)
			require.NoError(t, err)
			assert.Equal(t, "https://console.example"+req.URL.RequestURI(), handshake[sessionkeys.RedirectBack])
		})
	}
	assert.Zero(t, backend.creates.Load(), "no anonymous request writes a browser-session row (#620)")
}

// The return target the sign-in seals for its callback is bounded, so the cookie it rides in no
// longer tracks the request line's length: a path and query of exactly the bound pass through
// whole, and one byte more is answered with the home page's target (#620).
func TestRequiresScope_BoundsTheReturnTargetItStoresForTheSignIn(t *testing.T) {
	padTo := func(n int) string {
		prefix := "/admin/clients?pad="
		return prefix + strings.Repeat("a", n-len(prefix))
	}
	atBound := padTo(redirectBackMaxLen)
	pastBound := padTo(redirectBackMaxLen + 1)
	require.Len(t, atBound, redirectBackMaxLen)
	require.Len(t, pastBound, redirectBackMaxLen+1)

	testCases := []struct {
		name         string
		requestURI   string
		redirectBack string
	}{
		{
			name:         "a page's own path and query pass through whole",
			requestURI:   "/admin/clients?filter=active",
			redirectBack: "http://localhost:9091/admin/clients?filter=active",
		},
		{
			name:         "a path and query of exactly the bound pass through whole",
			requestURI:   atBound,
			redirectBack: "http://localhost:9091" + atBound,
		},
		{
			name:         "one byte past the bound falls back to the home page",
			requestURI:   pastBound,
			redirectBack: "http://localhost:9091/",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			mockAuthHelper := new(middlewaremocks.AuthHelper)
			mockSessionStore := new(sessionstoremocks.Store)

			mw := NewJWT(mockSessionStore, nil, "test-session", nil, nil, mockAuthHelper,
				stubErrorRenderer{}, "http://localhost:9091", builtin.AdminConsoleClientIdentifier)

			jwtInfo := oauthclient.JwtInfo{}
			mockAuthHelper.On("IsAuthorizedToAccessResource", jwtInfo, []string{"required:scope"}).Return(false)
			mockAuthHelper.On("IsAuthenticated", jwtInfo).Return(false)
			mockAuthHelper.On("RedirToAuthorize", mock.Anything, mock.Anything,
				builtin.AdminConsoleClientIdentifier, mock.AnythingOfType("string"),
				testCase.redirectBack).Return(nil)

			req := httptest.NewRequest(http.MethodGet, testCase.requestURI, nil)
			req = req.WithContext(reqctx.WithJwtInfo(req.Context(), jwtInfo))

			rr := httptest.NewRecorder()
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Error("an anonymous request never reaches the page it asked for")
			})
			mw.RequiresScope([]string{"required:scope"})(next).ServeHTTP(rr, req)

			// The redirect itself is the mock's to answer, so the recorded target is the
			// assertion: what the sign-in was handed to seal for the callback.
			mockAuthHelper.AssertExpectations(t)
		})
	}
}

// Through the real AuthHelper and store: a target of exactly the bound never fails the sign-in,
// whatever bytes fill it. '&' and '<', which an HTML-escaping encoder widened to six bytes each and
// so past the cookie's bound, pass through whole; invalid UTF-8 costs three, its replacement rune,
// which is what the callback then redirects to. Each answers the redirect with a handshake cookie
// that opens (#620).
func TestRequiresScope_ATargetWithinTheBoundAlwaysSeals(t *testing.T) {
	gob.Register(oauth.TokenResponse{})
	store, err := sessionstore.NewServerSideStore(sessiontest.NewMemoryBackend(), sessionkeys.JWT, true,
		sessionstore.BrowserSessionCookie, sessionstore.KeyPair{
			AuthenticationKey: []byte("12345678901234567890123456789012"),
			EncryptionKey:     []byte("abcdefghijklmnopqrstuvwxyz123456"),
		}, nil)
	require.NoError(t, err)
	const baseURL = "https://console.example"
	mw := NewJWT(store, nil, builtin.AdminConsoleSessionName, nil, nil,
		oauthclient.NewAuthHelper(store, baseURL, "https://auth.example"),
		stubErrorRenderer{}, baseURL, builtin.AdminConsoleClientIdentifier)
	handler := mw.RequiresScope([]string{"required:scope"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("an anonymous request never reaches the page it asked for")
	}))

	padWith := func(pad string) string {
		prefix := "/admin/clients?pad="
		return prefix + strings.Repeat(pad, redirectBackMaxLen-len(prefix))
	}
	testCases := []struct {
		name         string
		requestURI   string
		redirectBack string
	}{
		{"padded with '&'", padWith("&"), baseURL + padWith("&")},
		{"padded with '<'", padWith("<"), baseURL + padWith("<")},
		{"padded with invalid UTF-8", padWith("\xff"), baseURL + strings.ReplaceAll(padWith("\xff"), "\xff", "\uFFFD")},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.requestURI, nil)
			require.Len(t, req.URL.RequestURI(), redirectBackMaxLen, "the target is exactly the bound")

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			require.Equal(t, http.StatusFound, w.Code)
			assert.True(t, strings.HasPrefix(w.Header().Get("Location"), "https://auth.example/auth/authorize?"))
			cookies := w.Result().Cookies()
			require.Len(t, cookies, 1, "one handshake cookie, from the seal that succeeded")
			handshake, err := store.OpenCookieValues(oauthclient.SignInHandshakeCookie, cookies[0].Value)
			require.NoError(t, err)
			assert.Equal(t, tc.redirectBack, handshake[sessionkeys.RedirectBack])
		})
	}
}

// The fallback's branches, with the helper mocked: a seal refused for its length is tried once
// more with the home page's target; any other refusal, and a refusal of the home page's target
// itself, is the 500 it was.
func TestRequiresScope_FallsBackToTheHomePageWhenTheSealIsTooLong(t *testing.T) {
	tooLong := errs.Wrap(sessionstore.ErrCookieValuesTooLong, "unable to seal the cookie values")
	testCases := []struct {
		name       string
		requestURI string
		first      error
		retried    bool
		retry      error
		wantStatus int
	}{
		{"too long: the home page's target is sealed instead", "/admin/clients", tooLong, true, nil, http.StatusOK},
		{"too long again for the home page: 500", "/admin/clients", tooLong, true, tooLong, http.StatusInternalServerError},
		{"the home page's own target too long: no second try", "/", tooLong, false, nil, http.StatusInternalServerError},
		{"any other refusal: no second try", "/admin/clients", assert.AnError, false, nil, http.StatusInternalServerError},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockAuthHelper := new(middlewaremocks.AuthHelper)
			mw := NewJWT(new(sessionstoremocks.Store), nil, "test-session", nil, nil, mockAuthHelper,
				stubErrorRenderer{}, "http://localhost:9091", builtin.AdminConsoleClientIdentifier)

			jwtInfo := oauthclient.JwtInfo{}
			mockAuthHelper.On("IsAuthorizedToAccessResource", jwtInfo, []string{"required:scope"}).Return(false)
			mockAuthHelper.On("IsAuthenticated", jwtInfo).Return(false)
			mockAuthHelper.On("RedirToAuthorize", mock.Anything, mock.Anything, builtin.AdminConsoleClientIdentifier,
				mock.AnythingOfType("string"), "http://localhost:9091"+tc.requestURI).Return(tc.first).Once()
			if tc.retried {
				mockAuthHelper.On("RedirToAuthorize", mock.Anything, mock.Anything, builtin.AdminConsoleClientIdentifier,
					mock.AnythingOfType("string"), "http://localhost:9091/").Return(tc.retry).Once()
			}

			req := httptest.NewRequest(http.MethodGet, tc.requestURI, nil)
			req = req.WithContext(reqctx.WithJwtInfo(req.Context(), jwtInfo))
			rr := httptest.NewRecorder()
			mw.RequiresScope([]string{"required:scope"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Error("an anonymous request never reaches the page it asked for")
			})).ServeHTTP(rr, req)

			// The mocked helper writes nothing, so a recorder left at 200 is a sign-in that
			// went ahead, and 500 is the error renderer's.
			assert.Equal(t, tc.wantStatus, rr.Code)
			mockAuthHelper.AssertExpectations(t)
			calls := 1
			if tc.retried {
				calls = 2
			}
			mockAuthHelper.AssertNumberOfCalls(t, "RedirToAuthorize", calls)
		})
	}
}
