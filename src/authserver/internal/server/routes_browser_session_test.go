package server

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"runtime"
	"slices"
	"sync"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/sessionkeys"
	"github.com/leodip/goiabada/core/routing"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/sessionstore/sessiontest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Only the page branch looks at the browser's session cookie (#825 decision 1). A browser whose
// user session has ended still sends its browser-session cookie, and the page branch answers it by
// removing the pointer and sending the cookie again. Off the page branch nothing reads that
// session, so nothing sends that cookie: the OpenAPI document, a client logo, discovery and the key
// set are kept by shared caches, and Set-Cookie does not stop a cache storing an answer (RFC 9111
// section 7.3).
//
// Two reads are watched, each where it can be seen. The strict database mock sees the lookup of the
// user session the pointer names; it cannot see the browser session being loaded, which the store
// keeps on its own backend, so the backend counts its loads.

// endedUserSession is the user session the browser session points at, which has ended.
const endedUserSession = "ended-session"

// oldChunkedCookie is a cookie the chunked cookie store left in a browser, which the cookie reset
// deletes.
const oldChunkedCookie = sessionkeys.AuthServerSessionName + "-chunk-0"

// loadCountingBackend is the in-memory backend with each load counted by the session it names.
type loadCountingBackend struct {
	*sessiontest.MemoryBackend
	mu    sync.Mutex
	loads map[string]int
}

func (b *loadCountingBackend) Load(ctx context.Context, id string) (*sessionstore.Record, error) {
	b.mu.Lock()
	b.loads[id]++
	b.mu.Unlock()
	return b.MemoryBackend.Load(ctx, id)
}

// loadsOf is how many times the browser session id has been loaded.
func (b *loadCountingBackend) loadsOf(id string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.loads[id]
}

// newBrowserSessionTestServer is the server main builds, with every route registered as Start
// registers them, over database, and its browser sessions on a backend the test reads.
func newBrowserSessionTestServer(t *testing.T, database *datamocks.Database) (*Server, *loadCountingBackend) {
	t.Helper()

	database.On("PoolStats").Return(testPoolStats).Maybe()
	backend := &loadCountingBackend{MemoryBackend: sessiontest.NewMemoryBackend(), loads: map[string]int{}}

	cfg := &config.Config{}
	cfg.AuthServer.ProfilePictureMaxSizeBytes = testProfilePictureMaxSizeBytes

	s := NewServer(routing.New(), database, newTestSessionStoreOver(backend), nil, nil, cfg, testTokenProofs(t))
	s.registerRoutes()
	return s, backend
}

// danglingPointerCookies mints the cookies of a browser whose browser session points at a user
// session that has ended, saved through the server's own store as a sign-in saves it, and which
// still holds a cookie of the old chunked cookie store. It answers them and the browser session's
// id.
func danglingPointerCookies(t *testing.T, s *Server) ([]*http.Cookie, string) {
	t.Helper()

	seed := httptest.NewRequest(http.MethodGet, "/", nil)
	session, err := s.sessionStore.Get(seed, sessionkeys.AuthServerSessionName)
	require.NoError(t, err)
	session.Values[sessionkeys.SessionIdentifier] = endedUserSession
	seeded := httptest.NewRecorder()
	require.NoError(t, s.sessionStore.Save(seed, seeded, session))
	cookies := seeded.Result().Cookies()
	require.Len(t, cookies, 1)
	id, err := s.sessionStore.OpenCookie(sessionkeys.AuthServerSessionName, cookies[0].Value)
	require.NoError(t, err)

	return []*http.Cookie{cookies[0], {Name: oldChunkedCookie, Value: "left-by-the-chunked-store"}}, id
}

// withCookies is request carrying cookies.
func withCookies(request *http.Request, cookies []*http.Cookie) *http.Request {
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	return request
}

// The routes the issue lists, each sent the cookie of a browser session pointing at an ended user
// session: none answers with a Set-Cookie, none loads that browser session, and none looks up the
// user session its pointer names. Each keeps its cache lifetime.
func TestRegisterRoutes_TheListedRoutesCarryNoBrowserSession(t *testing.T) {
	logo := []byte("a client's logo")
	digest := sha256.Sum256(logo)
	entityTag := fmt.Sprintf("%q", fmt.Sprintf("%x", digest[:8]))

	for _, route := range []struct {
		name, method, target string
		header               http.Header
		status               int
		cacheControl         string
	}{
		{"the OpenAPI document", http.MethodGet, "/openapi.yaml", nil, http.StatusOK, "public, max-age=3600"},
		{"a client logo", http.MethodGet, "/client/logo/shop", nil, http.StatusOK, "public, max-age=300, must-revalidate"},
		{"a client logo", http.MethodHead, "/client/logo/shop", nil, http.StatusOK, "public, max-age=300, must-revalidate"},
		{"a client logo not modified", http.MethodGet, "/client/logo/shop", http.Header{"If-None-Match": {entityTag}},
			http.StatusNotModified, "public, max-age=300, must-revalidate"},
		{"OIDC discovery", http.MethodGet, oidcDiscoveryPath, nil, http.StatusOK, "public, max-age=300"},
		{"OIDC discovery", http.MethodHead, oidcDiscoveryPath, nil, http.StatusOK, "public, max-age=300"},
		{"RFC 8414 discovery", http.MethodGet, rfc8414DiscoveryPath, nil, http.StatusOK, "public, max-age=300"},
		{"RFC 8414 discovery", http.MethodHead, rfc8414DiscoveryPath, nil, http.StatusOK, "public, max-age=300"},
		{"the key set", http.MethodGet, certsPath, nil, http.StatusOK, "public, max-age=300"},
		{"the key set", http.MethodHead, certsPath, nil, http.StatusOK, "public, max-age=300"},
	} {
		t.Run(route.name+" "+route.method, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			database.On("GetSettingsById", mock.Anything, mock.Anything, int64(1)).
				Return(&record.Settings{Id: 1, Issuer: "https://issuer.example"}, nil).Maybe()
			database.On("GetAllSigningKeys", mock.Anything, mock.Anything).
				Return([]record.KeyPair{currentSigningKey()}, nil).Maybe()
			database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "shop").
				Return(&record.Client{Id: 3, ClientIdentifier: "shop"}, nil).Maybe()
			database.On("GetClientLogoByClientId", mock.Anything, mock.Anything, int64(3)).
				Return(&record.ClientLogo{ClientId: 3, Logo: logo, ContentType: "image/png"}, nil).Maybe()
			// The pointer dangles: the user session it names is gone. A lookup would find nothing.
			database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, endedUserSession).
				Return(nil, nil).Maybe()
			s, backend := newBrowserSessionTestServer(t, database)
			cookies, id := danglingPointerCookies(t, s)

			request := withCookies(httptest.NewRequest(route.method, route.target, nil), cookies)
			for name, values := range route.header {
				request.Header[name] = values
			}
			rr := httptest.NewRecorder()
			s.router.ServeHTTP(rr, request)

			require.Equal(t, route.status, rr.Code, rr.Body.String())
			assert.Equal(t, route.cacheControl, rr.Header().Get("Cache-Control"), "the resource keeps its lifetime")
			assert.Empty(t, rr.Header().Values("Set-Cookie"), "a publicly cacheable answer sets no cookie")
			assert.Zero(t, backend.loadsOf(id), "the browser session the cookie names is not loaded")
			database.AssertNotCalled(t, "GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// answerEveryOtherCallWithNothing lets every database method answer its zero values, after whatever
// the test expected itself: no row, no list and no error. Every route outside the page branch is
// sent a request, and their handlers read what they read; what is asserted is the answer's cookies.
func answerEveryOtherCallWithNothing(database *datamocks.Database) {
	databaseType := reflect.TypeFor[data.Database]()
	for i := range databaseType.NumMethod() {
		method := databaseType.Method(i)
		arguments := make([]any, method.Type.NumIn())
		for j := range arguments {
			arguments[j] = mock.Anything
		}
		returns := make([]any, method.Type.NumOut())
		for j := range returns {
			returns[j] = reflect.Zero(method.Type.Out(j)).Interface()
		}
		database.On(method.Name, arguments...).Return(returns...).Maybe()
	}
}

// middlewareNames are the functions middlewares are, as the runtime names them.
func middlewareNames(middlewares []func(http.Handler) http.Handler) []string {
	names := make([]string, 0, len(middlewares))
	for _, mounted := range middlewares {
		names = append(names, runtime.FuncForPC(reflect.ValueOf(mounted).Pointer()).Name())
	}
	return names
}

// runsThePageChain reports whether chain holds the page branch's chain, whole and in order.
func runsThePageChain(chain []string, pageChain []string) bool {
	for start := 0; start+len(pageChain) <= len(chain); start++ {
		if slices.Equal(chain[start:start+len(pageChain)], pageChain) {
			return true
		}
	}
	return false
}

// guardStaticFile is a file the static files hold, which the guard asks for: a directory there is
// the 404 page, a page answer.
const guardStaticFile = "/static/favicon/favicon.ico"

// guardRequest is the request the guard sends a route, by the method and the name the walk gives it.
func guardRequest(method, route string) *http.Request {
	if method == "*" {
		method = http.MethodDelete
	}
	target := routeTestTarget(route)
	if route == staticPrefix+"/*" {
		target = guardStaticFile
	}
	return httptest.NewRequest(method, target, nil)
}

// No route outside the page branch answers with a Set-Cookie, sent the cookie of a browser session
// pointing at an ended user session and a cookie the old chunked cookie store left. It walks the
// route table as the server registers it, the static files, the favicon, the health check and every
// branch's routes included, so a route added later is covered without anyone naming it. A page
// route is told by the chain it is registered with, the page branch's, and is the page branch's to
// answer; so is a static directory, the 404 page drawn behind that chain, and a method a path under
// a page group does not serve, which TestRegisterRoutes_APageRequestStillClearsTheDanglingPointer
// holds to the page branch's answer.
func TestRegisterRoutes_NoRouteOutsideThePageBranchSendsACookie(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetSettingsById", mock.Anything, mock.Anything, int64(1)).
		Return(&record.Settings{Id: 1, AppName: "Goiabada", Issuer: "https://issuer.example"}, nil).Maybe()
	answerEveryOtherCallWithNothing(database)
	s, backend := newBrowserSessionTestServer(t, database)
	pageChain := middlewareNames(s.pageChain())

	var pages, others []string
	err := s.router.Walk(func(method string, route string, _ http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		key := method + " " + route
		if runsThePageChain(middlewareNames(middlewares), pageChain) {
			pages = append(pages, key)
			return nil
		}
		others = append(others, key)
		t.Run(key, func(t *testing.T) {
			cookies, id := danglingPointerCookies(t, s)
			request := withCookies(guardRequest(method, route), cookies)
			require.Equal(t, route, s.router.RouteFor(request), "the request reaches the route it was built for")

			rr := httptest.NewRecorder()
			s.router.ServeHTTP(rr, request)

			assert.Empty(t, rr.Header().Values("Set-Cookie"), "answered %d", rr.Code)
			assert.Zero(t, backend.loadsOf(id), "the browser session the cookie names is not loaded")
		})
		return nil
	})
	require.NoError(t, err)

	assert.Contains(t, pages, "GET /auth/authorize", "a page route is told by its chain")
	for _, route := range []string{"GET /static/*", "HEAD /static/*", "GET /favicon.ico", "GET /health",
		"GET /openapi.yaml", "GET /client/logo/{clientIdentifier}", "GET /certs", "POST /auth/token",
		"POST /auth/revoke", "POST /auth/introspect", "GET /api/public/settings", "GET /brand-assets/{id}"} {
		assert.Contains(t, others, route, "the guard reaches every branch outside the page branch")
	}

	// A static directory is the 404 page, a page answer, drawn behind the page branch's chain.
	directory := httptest.NewRecorder()
	s.router.ServeHTTP(directory, httptest.NewRequest(http.MethodGet, "/static/favicon", nil))
	assert.Equal(t, http.StatusNotFound, directory.Code)
	assert.Equal(t, "no-store", directory.Header().Get("Cache-Control"), "a static directory is a page answer")
}

// A page request with the same cookies still clears the dangling pointer, as before #825: the
// answer is no-store, the browser session no longer holds the pointer, and the chunked cookie store's
// leftover is deleted. The router's 405 for a path under a page group, GET /auth/token, is a page
// answer and does the same.
func TestRegisterRoutes_APageRequestStillClearsTheDanglingPointer(t *testing.T) {
	for _, request := range []struct {
		method, target string
		status         int
	}{
		{http.MethodGet, "/", http.StatusFound},
		{http.MethodGet, "/auth/token", http.StatusMethodNotAllowed},
	} {
		t.Run(request.method+" "+request.target, func(t *testing.T) {
			database := newRoutingDatabase(t)
			database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, endedUserSession).
				Return(nil, nil).Once()
			s, backend := newBrowserSessionTestServer(t, database)
			cookies, id := danglingPointerCookies(t, s)

			rr := httptest.NewRecorder()
			s.router.ServeHTTP(rr, withCookies(httptest.NewRequest(request.method, request.target, nil), cookies))

			require.Equal(t, request.status, rr.Code, rr.Body.String())
			assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
			assert.Equal(t, "no-cache", rr.Header().Get("Pragma"))
			assert.Positive(t, backend.loadsOf(id), "the page branch loads the browser session")
			database.AssertCalled(t, "GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, endedUserSession)

			deleted := false
			for _, cookie := range rr.Result().Cookies() {
				if cookie.Name == oldChunkedCookie && cookie.MaxAge < 0 {
					deleted = true
				}
			}
			assert.True(t, deleted, "the chunked cookie store's leftover is deleted: %q", rr.Header().Values("Set-Cookie"))

			after := withCookies(httptest.NewRequest(http.MethodGet, "/", nil), cookies[:1])
			session, err := s.sessionStore.Get(after, sessionkeys.AuthServerSessionName)
			require.NoError(t, err)
			assert.Equal(t, id, session.ID, "the browser session itself stays")
			assert.NotContains(t, session.Values, sessionkeys.SessionIdentifier, "the pointer is removed")
		})
	}
}

// An answer outside the page branch that is written in a language takes it from the request alone:
// its ui_locales query parameter, else its Accept-Language, else English. A sign-in in progress in
// the same browser, whose authorize request asked for French, no longer chooses it. The error page a
// client logo answers a storage fault with is one such answer.
func TestRegisterRoutes_AnErrorPageOutsideThePageBranchIsInTheLanguageTheRequestAsks(t *testing.T) {
	database := newRoutingDatabase(t)
	database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "shop").
		Return(nil, errors.New("the database is down"))
	s, _ := newBrowserSessionTestServer(t, database)

	signIn := httptest.NewRecorder()
	require.NoError(t, ceremony.NewStore(s.sessionStore, sessionkeys.AuthServerSessionName).AddAuthContext(signIn,
		httptest.NewRequest(http.MethodGet, "/auth/authorize", nil),
		&ceremony.AuthContext{
			AuthState:  ceremony.AuthStateLevel1Password,
			CeremonyId: ceremony.NewId(),
			ClientId:   routesTestClientId,
			UILocales:  []string{"fr"},
		}))
	cookies := signIn.Result().Cookies()
	require.Len(t, cookies, 1)

	for _, request := range []struct {
		name, target, acceptLanguage, title string
	}{
		{"its ui_locales", "/client/logo/shop?ui_locales=es", "de", "Algo salió mal"},
		{"its Accept-Language", "/client/logo/shop", "de", "Etwas ist schiefgelaufen"},
		{"English", "/client/logo/shop", "", "Something went wrong"},
	} {
		t.Run(request.name, func(t *testing.T) {
			r := withCookies(httptest.NewRequest(http.MethodGet, request.target, nil), cookies)
			if request.acceptLanguage != "" {
				r.Header.Set("Accept-Language", request.acceptLanguage)
			}
			rr := httptest.NewRecorder()
			s.router.ServeHTTP(rr, r)

			require.Equal(t, http.StatusInternalServerError, rr.Code)
			assert.Contains(t, rr.Body.String(), `<h1 class="auth-title">`+request.title+`</h1>`)
			assert.NotContains(t, rr.Body.String(), "Une erreur est survenue", "not the sign-in's French")
		})
	}
}
