package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestMiddlewareCors(t *testing.T) {
	tests := []struct {
		name          string
		path          string
		origin        string
		expectedAllow bool
		setupMock     func(*mocks_data.Database)
	}{
		{
			name:          "Allow CORS for openid-configuration",
			path:          "/.well-known/openid-configuration",
			origin:        "http://example.com",
			expectedAllow: true,
			setupMock:     func(db *mocks_data.Database) {},
		},
		{
			name:          "Allow CORS for certs",
			path:          "/certs",
			origin:        "http://example.com",
			expectedAllow: true,
			setupMock:     func(db *mocks_data.Database) {},
		},
		{
			name:          "Allow CORS for auth/token with valid origin",
			path:          "/auth/token",
			origin:        "http://allowed.com",
			expectedAllow: true,
			setupMock: func(db *mocks_data.Database) {
				db.On("WebOriginExists", mock.Anything, "http://allowed.com").Return(true, nil)
			},
		},
		{
			name:          "Allow CORS for auth/logout with valid origin",
			path:          "/auth/logout",
			origin:        "http://allowed.com",
			expectedAllow: true,
			setupMock: func(db *mocks_data.Database) {
				db.On("WebOriginExists", mock.Anything, "http://allowed.com").Return(true, nil)
			},
		},
		{
			name:          "Allow CORS for userinfo with valid origin",
			path:          "/userinfo",
			origin:        "http://allowed.com",
			expectedAllow: true,
			setupMock: func(db *mocks_data.Database) {
				db.On("WebOriginExists", mock.Anything, "http://allowed.com").Return(true, nil)
			},
		},
		{
			name:          "Disallow CORS for auth/token with invalid origin",
			path:          "/auth/token",
			origin:        "http://disallowed.com",
			expectedAllow: false,
			setupMock: func(db *mocks_data.Database) {
				db.On("WebOriginExists", mock.Anything, "http://disallowed.com").Return(false, nil)
			},
		},
		{
			name:          "Disallow CORS for auth/logout with invalid origin",
			path:          "/auth/logout",
			origin:        "http://disallowed.com",
			expectedAllow: false,
			setupMock: func(db *mocks_data.Database) {
				db.On("WebOriginExists", mock.Anything, "http://disallowed.com").Return(false, nil)
			},
		},
		{
			name:          "Disallow CORS for userinfo with invalid origin",
			path:          "/userinfo",
			origin:        "http://disallowed.com",
			expectedAllow: false,
			setupMock: func(db *mocks_data.Database) {
				db.On("WebOriginExists", mock.Anything, "http://disallowed.com").Return(false, nil)
			},
		},
		{
			name:          "Disallow CORS for unknown path",
			path:          "/unknown",
			origin:        "http://example.com",
			expectedAllow: false,
			setupMock:     func(db *mocks_data.Database) {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := mocks_data.NewDatabase(t)
			tt.setupMock(db)

			handler := MiddlewareCors(db)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest("OPTIONS", tt.path, nil)
			req.Header.Set("Origin", tt.origin)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if tt.expectedAllow {
				assert.Equal(t, tt.origin, rr.Header().Get("Access-Control-Allow-Origin"))
			} else {
				assert.Empty(t, rr.Header().Get("Access-Control-Allow-Origin"))
			}
		})
	}
}

// The gated paths consult WebOriginExists and nothing else. GetAllWebOrigins read every row in the
// table on every CORS-checked request, with no cache; the method here is an index lookup on the
// UNIQUE (origin, client_id) migration 000034 adds. A strict mock is what pins which method runs:
// the assertion below fails if the middleware goes back to scanning, and mocks_data.NewDatabase(t)
// fails the test on any call that was not registered (#250).
func TestMiddlewareCors_ConsultsWebOriginExistsAndNotAScan(t *testing.T) {
	db := mocks_data.NewDatabase(t)
	db.On("WebOriginExists", mock.Anything, "http://allowed.com").Return(true, nil).Once()

	handler := MiddlewareCors(db)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("OPTIONS", "/userinfo", nil)
	req.Header.Set("Origin", "http://allowed.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	db.AssertExpectations(t)
	db.AssertNotCalled(t, "GetAllWebOrigins", mock.Anything)
}

// An unreadable list is not an empty one, and it is not a permissive one either. A database error
// answering true here would let script on any origin read a token or userinfo response, so the
// only safe answer is false. Nothing else in this file covers this path (#250).
func TestMiddlewareCors_ADatabaseErrorFailsClosed(t *testing.T) {
	db := mocks_data.NewDatabase(t)
	db.On("WebOriginExists", mock.Anything, "http://allowed.com").
		Return(false, errors.New("the database is unreachable")).Once()

	handler := MiddlewareCors(db)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("OPTIONS", "/auth/token", nil)
	req.Header.Set("Origin", "http://allowed.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Empty(t, rr.Result().Header.Get("Access-Control-Allow-Origin"))
	db.AssertExpectations(t)
}

// A preflight has to say how long it may be cached. cors@v1.2.2 emits Access-Control-Max-Age only
// when maxAge > 0, so with no value set the header never shipped and every browser fell back to
// its own short default, re-preflighting roughly every five seconds and paying for a lookup each
// time.
//
// Read through Result().Header rather than the recorder's live map: the live map shows a header
// that was set even if the response never carried it, which is how a test of a header can be
// green about bytes that do not exist.
func TestMiddlewareCors_APreflightIsCacheable(t *testing.T) {
	db := mocks_data.NewDatabase(t)
	db.On("WebOriginExists", mock.Anything, "http://allowed.com").Return(true, nil)

	handler := MiddlewareCors(db)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("OPTIONS", "/userinfo", nil)
	req.Header.Set("Origin", "http://allowed.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, "600", rr.Result().Header.Get("Access-Control-Max-Age"))
}
