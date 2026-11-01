package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/sessionkeys"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/sessionstore/sessiontest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// newSessionIdentifierTestStore is the browser session store as the auth server builds it, over an
// in-memory backend: the removal of a dangling pointer is a conditional write, and only a real store
// shows what it leaves stored.
func newSessionIdentifierTestStore(t *testing.T) *sessionstore.ConditionalStore {
	t.Helper()
	backend := sessiontest.NewMemoryBackend()
	store, err := sessionstore.NewServerSideStore(backend, sessionkeys.SessionIdentifier, false,
		sessionstore.PersistentCookie, sessionstore.KeyPair{
			AuthenticationKey: []byte("12345678901234567890123456789012"),
			EncryptionKey:     []byte("abcdefghijklmnopqrstuvwxyz123456"),
		}, nil)
	require.NoError(t, err)
	conditional, err := sessionstore.NewConditionalStore(store, backend)
	require.NoError(t, err)
	return conditional
}

// seedBrowserSession stores a browser session holding values and answers the cookies naming it.
func seedBrowserSession(t *testing.T, store *sessionstore.ConditionalStore, values map[string]any) []*http.Cookie {
	t.Helper()
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	sess, err := store.Get(req, sessionkeys.AuthServerSessionName)
	require.NoError(t, err)
	for k, v := range values {
		sess.Values[k] = v
	}
	require.NoError(t, store.Save(req, rr, sess))
	return rr.Result().Cookies()
}

// browserRequest is a request of the browser holding cookies.
func browserRequest(cookies []*http.Cookie) *http.Request {
	req := httptest.NewRequest("GET", "/", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return req
}

// writeBrowserSessionMeanwhile is another request of the same browser changing its session: change is
// applied to the values it reads, and the whole session saved, or deleted when change asks for it.
func writeBrowserSessionMeanwhile(t *testing.T, store *sessionstore.ConditionalStore, cookies []*http.Cookie,
	change func(sess *sessionstore.Session)) {
	t.Helper()
	req := browserRequest(cookies)
	sess, err := store.Get(req, sessionkeys.AuthServerSessionName)
	require.NoError(t, err)
	change(sess)
	require.NoError(t, store.Save(req, httptest.NewRecorder(), sess))
}

// storedBrowserSession is the browser session as the browser's next request reads it.
func storedBrowserSession(t *testing.T, store *sessionstore.ConditionalStore, cookies []*http.Cookie) map[string]any {
	t.Helper()
	sess, err := store.Get(browserRequest(cookies), sessionkeys.AuthServerSessionName)
	require.NoError(t, err)
	return sess.Values
}

// unreadableSessionStore is a browser session store whose read fails, so no write can follow it.
type unreadableSessionStore struct {
	t   *testing.T
	err error
}

func (s unreadableSessionStore) Get(*http.Request, string) (*sessionstore.Session, error) {
	return nil, s.err
}

func (s unreadableSessionStore) ChangeAndSave(*http.Request, http.ResponseWriter, *sessionstore.Session,
	func(map[string]any) error) error {
	s.t.Error("a session that could not be read must not be written")
	return nil
}

func TestSessionIdentifier(t *testing.T) {
	t.Run("Session store error", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)

		middleware := SessionIdentifier(unreadableSessionStore{t: t, err: errors.New("session store error")}, mockDB, PageFaults())

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()

		middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rr, req)

		assert.Equal(t, http.StatusInternalServerError, rr.Code)
	})

	t.Run("No session identifier", func(t *testing.T) {
		store := newSessionIdentifierTestStore(t)
		mockDB := datamocks.NewDatabase(t)

		middleware := SessionIdentifier(store, mockDB, PageFaults())

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()

		var present, userPresent bool
		middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, present = reqctx.SessionIdentifierFrom(r.Context())
			_, userPresent = reqctx.SessionUserIdFrom(r.Context())
		})).ServeHTTP(rr, req)

		assert.False(t, present)
		assert.False(t, userPresent)
		assert.Empty(t, rr.Result().Cookies(), "a session holding no pointer is not written")
	})

	t.Run("Valid session identifier", func(t *testing.T) {
		store := newSessionIdentifierTestStore(t)
		mockDB := datamocks.NewDatabase(t)
		cookies := seedBrowserSession(t, store, map[string]any{sessionkeys.SessionIdentifier: "valid-session-id"})

		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "valid-session-id").
			Return(&record.UserSession{UserId: 42}, nil).Once()

		middleware := SessionIdentifier(store, mockDB, PageFaults())

		rr := httptest.NewRecorder()

		var contextSessionIdentifier string
		var present bool
		var contextUserId int64
		var userPresent bool
		middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			contextSessionIdentifier, present = reqctx.SessionIdentifierFrom(r.Context())
			contextUserId, userPresent = reqctx.SessionUserIdFrom(r.Context())
		})).ServeHTTP(rr, browserRequest(cookies))

		assert.True(t, present)
		assert.Equal(t, "valid-session-id", contextSessionIdentifier)
		assert.True(t, userPresent, "the session's user rides with its identifier, so it is not read again")
		assert.Equal(t, int64(42), contextUserId)
		assert.Equal(t, "valid-session-id", storedBrowserSession(t, store, cookies)[sessionkeys.SessionIdentifier])
	})

	t.Run("Invalid session identifier", func(t *testing.T) {
		store := newSessionIdentifierTestStore(t)
		mockDB := datamocks.NewDatabase(t)
		cookies := seedBrowserSession(t, store, map[string]any{sessionkeys.SessionIdentifier: "invalid-session-id"})

		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "invalid-session-id").Return(nil, nil)

		middleware := SessionIdentifier(store, mockDB, PageFaults())

		rr := httptest.NewRecorder()

		var present bool
		var cached any
		var getErr error
		middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, present = reqctx.SessionIdentifierFrom(r.Context())
			sess, err := store.Get(r, sessionkeys.AuthServerSessionName)
			if err != nil {
				getErr = err
				return
			}
			cached = sess.Values[sessionkeys.SessionIdentifier]
		})).ServeHTTP(rr, browserRequest(cookies))

		require.NoError(t, getErr)
		assert.False(t, present)
		assert.Nil(t, cached, "the request's own session must not hold the dangling pointer either")
		assert.NotContains(t, storedBrowserSession(t, store, cookies), sessionkeys.SessionIdentifier)
	})

	t.Run("Invalid session identifier preserves other session values", func(t *testing.T) {
		store := newSessionIdentifierTestStore(t)
		mockDB := datamocks.NewDatabase(t)
		cookies := seedBrowserSession(t, store, map[string]any{
			sessionkeys.SessionIdentifier: "invalid-session-id",
			sessionkeys.AuthContexts:      `{"authState":"level1_password"}`,
		})

		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "invalid-session-id").Return(nil, nil)

		middleware := SessionIdentifier(store, mockDB, PageFaults())

		middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(httptest.NewRecorder(), browserRequest(cookies))

		values := storedBrowserSession(t, store, cookies)
		assert.Equal(t, `{"authState":"level1_password"}`, values[sessionkeys.AuthContexts])
		assert.NotContains(t, values, sessionkeys.SessionIdentifier)
	})

	t.Run("Database error", func(t *testing.T) {
		store := newSessionIdentifierTestStore(t)
		mockDB := datamocks.NewDatabase(t)
		cookies := seedBrowserSession(t, store, map[string]any{sessionkeys.SessionIdentifier: "error-session-id"})

		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "error-session-id").Return(nil, errors.New("database error"))

		middleware := SessionIdentifier(store, mockDB, PageFaults())

		rr := httptest.NewRecorder()

		middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rr, browserRequest(cookies))

		assert.Equal(t, http.StatusInternalServerError, rr.Code)
	})
}

// The removal of a dangling pointer writes only that removal onto the browser session as it is stored
// when it writes, not the copy its request read when it began (#579 decision 5). Each case holds the
// request inside its read of the user session, where another request of the same browser writes.
func TestSessionIdentifier_RemovingADanglingPointerKeepsWhatAnotherRequestWroteMeanwhile(t *testing.T) {
	t.Run("a ceremony started meanwhile is kept", func(t *testing.T) {
		store := newSessionIdentifierTestStore(t)
		mockDB := datamocks.NewDatabase(t)
		cookies := seedBrowserSession(t, store, map[string]any{
			sessionkeys.SessionIdentifier: "gone-session-id",
			sessionkeys.AuthContexts:      "ceremony A",
		})

		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "gone-session-id").
			Run(func(mock.Arguments) {
				writeBrowserSessionMeanwhile(t, store, cookies, func(sess *sessionstore.Session) {
					sess.Values[sessionkeys.AuthContexts] = "ceremony B"
				})
			}).Return(nil, nil).Once()

		rr := httptest.NewRecorder()
		reached := false
		SessionIdentifier(store, mockDB, PageFaults())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			reached = true
		})).ServeHTTP(rr, browserRequest(cookies))

		require.True(t, reached, rr.Body.String())
		values := storedBrowserSession(t, store, cookies)
		assert.Equal(t, "ceremony B", values[sessionkeys.AuthContexts],
			"the removal must not put back the ceremony its request began with")
		assert.NotContains(t, values, sessionkeys.SessionIdentifier)
	})

	t.Run("a pointer to a newer user session written meanwhile is kept", func(t *testing.T) {
		store := newSessionIdentifierTestStore(t)
		mockDB := datamocks.NewDatabase(t)
		cookies := seedBrowserSession(t, store, map[string]any{sessionkeys.SessionIdentifier: "gone-session-id"})

		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "gone-session-id").
			Run(func(mock.Arguments) {
				writeBrowserSessionMeanwhile(t, store, cookies, func(sess *sessionstore.Session) {
					sess.Values[sessionkeys.SessionIdentifier] = "new-session-id"
				})
			}).Return(nil, nil).Once()

		rr := httptest.NewRecorder()
		var present bool
		SessionIdentifier(store, mockDB, PageFaults())(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			_, present = reqctx.SessionIdentifierFrom(r.Context())
		})).ServeHTTP(rr, browserRequest(cookies))

		assert.False(t, present)
		assert.Empty(t, rr.Result().Cookies(), "a session no longer holding the dangling pointer is not written")
		assert.Equal(t, "new-session-id", storedBrowserSession(t, store, cookies)[sessionkeys.SessionIdentifier],
			"only the dangling pointer is removed, never the one that replaced it")
	})

	t.Run("a session signed out meanwhile is not put back", func(t *testing.T) {
		store := newSessionIdentifierTestStore(t)
		mockDB := datamocks.NewDatabase(t)
		cookies := seedBrowserSession(t, store, map[string]any{
			sessionkeys.SessionIdentifier: "gone-session-id",
			sessionkeys.AuthContexts:      "ceremony A",
		})

		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "gone-session-id").
			Run(func(mock.Arguments) {
				writeBrowserSessionMeanwhile(t, store, cookies, func(sess *sessionstore.Session) {
					sess.Options.MaxAge = -1
				})
			}).Return(nil, nil).Once()

		rr := httptest.NewRecorder()
		var present bool
		reached := false
		SessionIdentifier(store, mockDB, PageFaults())(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			reached = true
			_, present = reqctx.SessionIdentifierFrom(r.Context())
		})).ServeHTTP(rr, browserRequest(cookies))

		require.True(t, reached, "a pointer gone with its session is removed, which is no fault: %s", rr.Body.String())
		assert.False(t, present)
		assert.Empty(t, rr.Result().Cookies(), "a gone session must not be put back")
		assert.Empty(t, storedBrowserSession(t, store, cookies), "a gone session must not be put back")
	})
}
