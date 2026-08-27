package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/sessionstore"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestMiddlewareCookieReset(t *testing.T) {
	const testSessionName = "test-session"

	t.Run("No error", func(t *testing.T) {
		mockStore := new(mocks_sessionstore.Store)
		mockStore.On("Get", mock.Anything, testSessionName).Return(&sessions.Session{}, nil)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
		middleware := MiddlewareCookieReset(mockStore, testSessionName)

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()

		middleware(handler).ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		mockStore.AssertExpectations(t)
	})

	t.Run("Decode error", func(t *testing.T) {
		mockStore := new(mocks_sessionstore.Store)
		decodeErr := securecookie.MultiError{securecookie.ErrMacInvalid}
		mockStore.On("Get", mock.Anything, testSessionName).Return(nil, decodeErr)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
		middleware := MiddlewareCookieReset(mockStore, testSessionName)

		req := httptest.NewRequest("GET", "/test", nil)
		rr := httptest.NewRecorder()

		middleware(handler).ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, "/test", rr.Header().Get("Location"))

		cookies := rr.Result().Cookies()
		assert.Len(t, cookies, 1)
		assert.Equal(t, testSessionName, cookies[0].Name)
		assert.True(t, cookies[0].Expires.Before(time.Now()))
		assert.Equal(t, -1, cookies[0].MaxAge)
		assert.Equal(t, "/", cookies[0].Path)

		mockStore.AssertExpectations(t)
	})

	t.Run("Non-decode error", func(t *testing.T) {
		mockStore := new(mocks_sessionstore.Store)
		mockStore.On("Get", mock.Anything, testSessionName).Return(nil, errors.New("non-decode error"))

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
		middleware := MiddlewareCookieReset(mockStore, testSessionName)

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()

		middleware(handler).ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Len(t, rr.Result().Cookies(), 0)

		mockStore.AssertExpectations(t)
	})
}

// TestMiddlewareCookieReset_StaleCookies covers the half of this middleware that exists
// because of #266: a browser arriving with the chunked cookie store's leftovers has to be
// told to drop them, here, because nothing else ever will again.
//
// Over a real ServerSideStore rather than the mock the cases above use. The names, the
// attributes and the decision about which names are safe to delete all come from the
// store, and a mock cannot get any of them wrong in an interesting way.
func TestMiddlewareCookieReset_StaleCookies(t *testing.T) {
	const sessionName = "authserver"

	newStore := func(secure bool) *sessionstore.ServerSideStore {
		return sessionstore.NewServerSideStore(
			newNoRowsBackend(), "SessionIdentifier", secure,
			[]byte("12345678901234567890123456789012"),
			[]byte("abcdefghijklmnopqrstuvwxyz123456"))
	}

	run := func(t *testing.T, store *sessionstore.ServerSideStore, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest("GET", "/auth/authorize", nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		reached := false
		MiddlewareCookieReset(store, sessionName)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			reached = true
		})).ServeHTTP(rr, req)
		assert.True(t, reached, "the request must still reach the handler")
		return rr
	}

	t.Run("Deletes only the chunk cookies the request actually carries", func(t *testing.T) {
		rr := run(t, newStore(false),
			&http.Cookie{Name: sessionName + "-chunk-0", Value: "leftover"},
			&http.Cookie{Name: sessionName + "-chunk-3", Value: "leftover"})

		names := deletedCookieNames(t, rr)
		assert.ElementsMatch(t, []string{sessionName + "-chunk-0", sessionName + "-chunk-3"}, names,
			"a deletion is emitted for each leftover present, and for no name that is absent")

		for _, c := range rr.Result().Cookies() {
			assert.Equal(t, -1, c.MaxAge)
			assert.Equal(t, "/", c.Path, "a deletion on the wrong path deletes nothing")
		}
	})

	t.Run("Writes nothing when the browser carries no leftovers", func(t *testing.T) {
		// This is what makes the purge first-contact rather than per-request: the browser
		// drops them on the first response and never sends them again, so every request
		// after that must be free of Set-Cookie.
		rr := run(t, newStore(false))
		assert.Empty(t, rr.Result().Cookies())
	})

	t.Run("On https the bare name is a leftover and the prefixed one is the live cookie", func(t *testing.T) {
		store := newStore(true)
		rr := run(t, store,
			&http.Cookie{Name: sessionName, Value: "the old master cookie"},
			&http.Cookie{Name: "__Host-" + sessionName, Value: "not decodable, but live"})

		names := deletedCookieNames(t, rr)
		assert.Contains(t, names, sessionName)
		assert.NotContains(t, names, "__Host-"+sessionName,
			"the prefixed cookie is this store's own and must never be purged as a leftover")

		for _, c := range rr.Result().Cookies() {
			assert.True(t, c.Secure, "a __Host- deployment's deletions are Secure like its cookies")
		}
	})

	t.Run("On plain http the bare name is the live cookie and is left alone", func(t *testing.T) {
		// The inverse of the case above, and the reason StaleCookieNames is a function on
		// the store rather than a constant list: deleting the bare name here would delete
		// the session the very same response is writing.
		rr := run(t, newStore(false), &http.Cookie{Name: sessionName, Value: "not decodable, but live"})
		assert.NotContains(t, deletedCookieNames(t, rr), sessionName)
	})
}

// TestMiddlewareCookieReset_DecodeErrorNamesThePhysicalCookie pins the other defect #266
// introduced here. The deletion used to be built from the logical session name with no
// Secure attribute, which on https names a cookie the browser does not have and would be
// refused even with the right name.
func TestMiddlewareCookieReset_DecodeErrorNamesThePhysicalCookie(t *testing.T) {
	const sessionName = "authserver"

	store := &decodeFailingStore{ServerSideStore: sessionstore.NewServerSideStore(
		newNoRowsBackend(), "SessionIdentifier", true,
		[]byte("12345678901234567890123456789012"),
		[]byte("abcdefghijklmnopqrstuvwxyz123456"))}

	req := httptest.NewRequest("GET", "/auth/authorize", nil)
	rr := httptest.NewRecorder()
	MiddlewareCookieReset(store, sessionName)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("a request whose cookie cannot be decoded must be answered here")
	})).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)

	cookies := rr.Result().Cookies()
	assert.Len(t, cookies, 1)
	assert.Equal(t, "__Host-"+sessionName, cookies[0].Name)
	assert.True(t, cookies[0].Secure, "a browser refuses a __Host- cookie that is not Secure")
	assert.Equal(t, -1, cookies[0].MaxAge)
}

// deletedCookieNames reads through Result(), never the live header map: a middleware that
// commits its status with WriteHeader is exactly where the two disagree.
func deletedCookieNames(t *testing.T, rr *httptest.ResponseRecorder) []string {
	t.Helper()
	var names []string
	for _, c := range rr.Result().Cookies() {
		names = append(names, c.Name)
	}
	return names
}

// decodeFailingStore is a ServerSideStore whose Get answers the way a store answers a
// cookie it cannot decode. ServerSideStore itself never does, by design: it answers an
// undecodable cookie with a fresh session. The branch is still reachable, because this
// middleware takes sessions.Store and any store may report a decode failure, and what it
// must get right when it fires is naming the physical cookie, which on https is prefixed.
type decodeFailingStore struct {
	*sessionstore.ServerSideStore
}

func (s *decodeFailingStore) Get(*http.Request, string) (*sessions.Session, error) {
	return nil, securecookie.MultiError{securecookie.ErrMacInvalid}
}

// noRowsBackend answers "there is no such session" to everything, which is all these cases
// need: none of them reaches storage on purpose.
type noRowsBackend struct{}

func newNoRowsBackend() sessionstore.Backend { return noRowsBackend{} }

func (noRowsBackend) Load(context.Context, string) (*sessionstore.Record, error) {
	return nil, sessionstore.ErrNotFound
}

func (noRowsBackend) Create(context.Context, string, []byte, bool) (time.Time, error) {
	return time.Now().UTC().Add(time.Hour), nil
}

func (noRowsBackend) Update(context.Context, string, []byte, bool) (time.Time, error) {
	return time.Time{}, sessionstore.ErrNotFound
}

func (noRowsBackend) Touch(context.Context, string, bool) (time.Time, error) {
	return time.Time{}, sessionstore.ErrNotFound
}

func (noRowsBackend) Delete(context.Context, string) error { return nil }
