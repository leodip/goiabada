package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/sessionkeys"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/sessionstore/sessiontest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// staleBackend is the in-memory backend with every row read back a minute past its last access, so
// every request finds the session past the touch threshold, and its touches counted.
type staleBackend struct {
	*sessiontest.MemoryBackend
	mu      sync.Mutex
	touches int
}

func (b *staleBackend) Load(ctx context.Context, id string) (*sessionstore.Record, error) {
	record, err := b.MemoryBackend.Load(ctx, id)
	if err != nil {
		return nil, err
	}
	record.LastAccessed = time.Now().UTC().Add(-time.Minute)
	return record, nil
}

func (b *staleBackend) Touch(ctx context.Context, id string, authenticated bool) (time.Time, error) {
	b.mu.Lock()
	b.touches++
	b.mu.Unlock()
	return b.MemoryBackend.Touch(ctx, id, authenticated)
}

// A request on the page branch that finds a signed-in session stale touches it and sends its cookie
// again with the row's new expiry; the same request on the files, protocol and API branches reads
// the session, as the session identifier on the context shows, and neither touches it nor sends a
// cookie (#743 decisions 8 and 9).
func TestInitMiddleware_OnlyThePageBranchRefreshesTheSessionAndSendsItsCookie(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetSettingsById", mock.Anything, nilTx, int64(1)).Return(&record.Settings{Id: 1}, nil).Maybe()
	database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "the-user-session").
		Return(&record.UserSession{Id: 1, UserId: 1, SessionIdentifier: "the-user-session"}, nil).Maybe()
	database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(&record.User{Id: 1}, nil).Maybe()

	backend := &staleBackend{MemoryBackend: sessiontest.NewMemoryBackend()}
	s := newStaticBranchTestServer(database)
	s.sessionStore = newTestSessionStoreOver(backend)
	branches := s.initMiddleware()

	signedInSessionIdentifier := ""
	probe := func(w http.ResponseWriter, r *http.Request) {
		session, err := s.sessionStore.Get(r, sessionkeys.AuthServerSessionName)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		signedInSessionIdentifier, _ = session.Values[sessionkeys.SessionIdentifier].(string)
		w.WriteHeader(http.StatusOK)
	}
	branches.pages.Get("/probe/page", probe)
	branches.files.Get("/probe/file", probe)
	branches.protocol.Get("/probe/protocol", probe)
	branches.token.Get("/probe/token", probe)
	branches.revoke.Get("/probe/revoke", probe)
	branches.introspect.Get("/probe/introspect", probe)
	branches.api.Get("/api/probe", probe)

	// A signed-in session, saved as a sign-in saves it.
	saveReq := httptest.NewRequest(http.MethodGet, "/", nil)
	saveRec := httptest.NewRecorder()
	session, err := s.sessionStore.Get(saveReq, sessionkeys.AuthServerSessionName)
	require.NoError(t, err)
	session.Values[sessionkeys.SessionIdentifier] = "the-user-session"
	require.NoError(t, s.sessionStore.Save(saveReq, saveRec, session))
	saved := saveRec.Result().Cookies()
	require.Len(t, saved, 1)
	sessionCookie := saved[0]
	id, err := s.sessionStore.OpenCookie(sessionkeys.AuthServerSessionName, sessionCookie.Value)
	require.NoError(t, err)

	serve := func(target string) []*http.Cookie {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.AddCookie(sessionCookie)
		rec := httptest.NewRecorder()
		signedInSessionIdentifier = ""
		s.router.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code, target)
		assert.Equal(t, "the-user-session", signedInSessionIdentifier, "%s reads the session", target)
		var cookies []*http.Cookie
		for _, cookie := range rec.Result().Cookies() {
			if cookie.Name == sessionCookie.Name {
				cookies = append(cookies, cookie)
			}
		}
		return cookies
	}

	for _, target := range []string{"/probe/file", "/probe/protocol", "/probe/token", "/probe/revoke",
		"/probe/introspect", "/api/probe"} {
		cookies := serve(target)
		assert.Empty(t, cookies, "%s sends no session cookie", target)
		assert.Zero(t, backend.touches, "%s does not touch the session", target)
	}

	cookies := serve("/probe/page")
	assert.Equal(t, 1, backend.touches, "the page request touches the stale session")
	require.Len(t, cookies, 1, "and sends its cookie again")
	reissuedId, err := s.sessionStore.OpenCookie(sessionkeys.AuthServerSessionName, cookies[0].Value)
	require.NoError(t, err)
	assert.Equal(t, id, reissuedId, "naming the same session")
	row, err := backend.MemoryBackend.Load(context.Background(), id)
	require.NoError(t, err)
	assert.InDelta(t, time.Until(row.ExpiresAt).Seconds(), cookies[0].MaxAge, 2,
		"with the row's new expiry as its Max-Age")
	assert.InDelta(t, 3600, cookies[0].MaxAge, 2, "an hour, the in-memory backend's lifetime")
}

// Every answer on the page branch is no-store, whatever exit writes it: the refresh can send the
// session cookie again on any of them, and no answer that carries it may be stored by a shared cache
// (#743 decision 9). A page handler that writes no header of its own, and the 405 the router answers
// GET /auth/token with behind the /auth group's chain, both carry the reissued cookie under
// Cache-Control: no-store and Pragma: no-cache. A 405 is heuristically cacheable (RFC 9110 section
// 15.5.6), and Set-Cookie does not stop a cache storing it (RFC 9111 section 7.3).
func TestRegisterRoutes_EveryPageBranchAnswerCarryingARefreshedCookieIsNoStore(t *testing.T) {
	database := newRoutingDatabase(t)
	database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "the-user-session").
		Return(&record.UserSession{Id: 1, UserId: 1, SessionIdentifier: "the-user-session"}, nil).Maybe()
	database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(&record.User{Id: 1}, nil).Maybe()

	backend := &staleBackend{MemoryBackend: sessiontest.NewMemoryBackend()}
	s := newStaticBranchTestServer(database)
	s.sessionStore = newTestSessionStoreOver(backend)
	s.registerRoutes()

	saveReq := httptest.NewRequest(http.MethodGet, "/", nil)
	saveRec := httptest.NewRecorder()
	session, err := s.sessionStore.Get(saveReq, sessionkeys.AuthServerSessionName)
	require.NoError(t, err)
	session.Values[sessionkeys.SessionIdentifier] = "the-user-session"
	require.NoError(t, s.sessionStore.Save(saveReq, saveRec, session))
	saved := saveRec.Result().Cookies()
	require.Len(t, saved, 1)
	sessionCookie := saved[0]

	for _, request := range []struct {
		method, target string
		status         int
	}{
		{http.MethodGet, "/auth/token", http.StatusMethodNotAllowed},
		{http.MethodPut, "/auth/pwd", http.StatusMethodNotAllowed},
		{http.MethodGet, "/", http.StatusFound},
	} {
		touchesBefore := backend.touches
		req := httptest.NewRequest(request.method, request.target, nil)
		req.AddCookie(sessionCookie)
		rec := httptest.NewRecorder()
		s.router.ServeHTTP(rec, req)

		require.Equal(t, request.status, rec.Code, "%s %s", request.method, request.target)
		assert.Equal(t, touchesBefore+1, backend.touches, "%s %s touches the stale session", request.method, request.target)
		var reissued []*http.Cookie
		for _, cookie := range rec.Result().Cookies() {
			if cookie.Name == sessionCookie.Name {
				reissued = append(reissued, cookie)
			}
		}
		require.Len(t, reissued, 1, "%s %s sends the session cookie again", request.method, request.target)
		assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"), "%s %s", request.method, request.target)
		assert.Equal(t, "no-cache", rec.Header().Get("Pragma"), "%s %s", request.method, request.target)
	}
}
