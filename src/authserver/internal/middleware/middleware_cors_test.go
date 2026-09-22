package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
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
			name:          "Allow CORS for openid-configuration with trailing slash",
			path:          "/.well-known/openid-configuration/",
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
			name:          "Allow CORS for certs with trailing slash",
			path:          "/certs/",
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
				db.On("WebOriginExists", mock.Anything, mock.Anything, "http://allowed.com").Return(true, nil)
			},
		},
		{
			name:          "Allow CORS for auth/token with trailing slash and valid origin",
			path:          "/auth/token/",
			origin:        "http://allowed.com",
			expectedAllow: true,
			setupMock: func(db *mocks_data.Database) {
				db.On("WebOriginExists", mock.Anything, mock.Anything, "http://allowed.com").Return(true, nil)
			},
		},
		{
			name:          "Allow CORS for auth/logout with valid origin",
			path:          "/auth/logout",
			origin:        "http://allowed.com",
			expectedAllow: true,
			setupMock: func(db *mocks_data.Database) {
				db.On("WebOriginExists", mock.Anything, mock.Anything, "http://allowed.com").Return(true, nil)
			},
		},
		{
			name:          "Allow CORS for auth/logout with trailing slash and valid origin",
			path:          "/auth/logout/",
			origin:        "http://allowed.com",
			expectedAllow: true,
			setupMock: func(db *mocks_data.Database) {
				db.On("WebOriginExists", mock.Anything, mock.Anything, "http://allowed.com").Return(true, nil)
			},
		},
		{
			name:          "Allow CORS for userinfo with valid origin",
			path:          "/userinfo",
			origin:        "http://allowed.com",
			expectedAllow: true,
			setupMock: func(db *mocks_data.Database) {
				db.On("WebOriginExists", mock.Anything, mock.Anything, "http://allowed.com").Return(true, nil)
			},
		},
		{
			name:          "Allow CORS for userinfo with trailing slash and valid origin",
			path:          "/userinfo/",
			origin:        "http://allowed.com",
			expectedAllow: true,
			setupMock: func(db *mocks_data.Database) {
				db.On("WebOriginExists", mock.Anything, mock.Anything, "http://allowed.com").Return(true, nil)
			},
		},
		{
			name:          "Disallow CORS for auth/token with invalid origin",
			path:          "/auth/token",
			origin:        "http://disallowed.com",
			expectedAllow: false,
			setupMock: func(db *mocks_data.Database) {
				db.On("WebOriginExists", mock.Anything, mock.Anything, "http://disallowed.com").Return(false, nil)
			},
		},
		{
			name:          "Disallow CORS for auth/logout with invalid origin",
			path:          "/auth/logout",
			origin:        "http://disallowed.com",
			expectedAllow: false,
			setupMock: func(db *mocks_data.Database) {
				db.On("WebOriginExists", mock.Anything, mock.Anything, "http://disallowed.com").Return(false, nil)
			},
		},
		{
			name:          "Disallow CORS for userinfo with invalid origin",
			path:          "/userinfo",
			origin:        "http://disallowed.com",
			expectedAllow: false,
			setupMock: func(db *mocks_data.Database) {
				db.On("WebOriginExists", mock.Anything, mock.Anything, "http://disallowed.com").Return(false, nil)
			},
		},
		{
			name:          "Disallow CORS for unknown path",
			path:          "/unknown",
			origin:        "http://example.com",
			expectedAllow: false,
			setupMock:     func(db *mocks_data.Database) {},
		},
		{
			name:          "Disallow CORS for root path",
			path:          "/",
			origin:        "http://example.com",
			expectedAllow: false,
			setupMock:     func(db *mocks_data.Database) {},
		},
		{
			name:          "Disallow CORS for path below auth/token",
			path:          "/auth/token/foo",
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
	db.On("WebOriginExists", mock.Anything, mock.Anything, "http://allowed.com").Return(true, nil).Once()

	handler := MiddlewareCors(db)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("OPTIONS", "/userinfo", nil)
	req.Header.Set("Origin", "http://allowed.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	db.AssertExpectations(t)
	db.AssertNotCalled(t, "GetAllWebOrigins", mock.Anything, mock.Anything)
}

// An unreadable list is not an empty one, and it is not a permissive one either. A database error
// answering true here would let script on any origin read a token or userinfo response, so the
// only safe answer is false. Nothing else in this file covers this path (#250).
func TestMiddlewareCors_ADatabaseErrorFailsClosed(t *testing.T) {
	db := mocks_data.NewDatabase(t)
	db.On("WebOriginExists", mock.Anything, mock.Anything, "http://allowed.com").
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
	db.On("WebOriginExists", mock.Anything, mock.Anything, "http://allowed.com").Return(true, nil)

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

// Seam 4 of #386 for the CORS middleware, stage 7.
//
// MiddlewareCors is the one consumer in this batch whose port is reached from a middleware rather
// than a handler, and the one where dropping the request's context would be worse than slow: the
// preflight decision is made inside AllowOriginFunc, which has the request in scope and nothing
// else, so a WebOriginExists issued on context.Background() would keep answering for a browser
// that has already gone away.
//
// chi's request id is on this request's context and on no other, so a middleware that passed
// context.Background() matches nothing and the strict mock reports an unexpected call.

const corsPropagatedRequestId = "goiabada/req-cors-propagation-1"

func corsRequestCarryingId(path, origin string) *http.Request {
	req := httptest.NewRequest("OPTIONS", path, nil)
	req.Header.Set("Origin", origin)
	req.Header.Set("Access-Control-Request-Method", "GET")
	return req.WithContext(context.WithValue(req.Context(), chimiddleware.RequestIDKey, corsPropagatedRequestId))
}

func theCorsRequestsContext() interface{} {
	return mock.MatchedBy(func(ctx context.Context) bool {
		return chimiddleware.GetReqID(ctx) == corsPropagatedRequestId
	})
}

// The accept arm: the origin lookup on a gated path is issued on behalf of the preflight that
// asked for it.
func TestMiddlewareCors_ChecksTheOriginUnderTheRequestsContext(t *testing.T) {
	db := mocks_data.NewDatabase(t)
	db.On("WebOriginExists", theCorsRequestsContext(), mock.Anything, "http://allowed.com").
		Return(true, nil).Once()

	handler := MiddlewareCors(db)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, corsRequestCarryingId("/userinfo", "http://allowed.com"))

	assert.Equal(t, "http://allowed.com", rr.Header().Get("Access-Control-Allow-Origin"))
	db.AssertExpectations(t)
}

// The reject arm: the discovery URL is allowed by the path alone, so the origin port is never
// reached and there is no context to get wrong. It is the arm that stops the accept arm passing
// on a middleware that consults the database unconditionally.
func TestMiddlewareCors_AnUngatedPathReachesNoOriginPort(t *testing.T) {
	db := mocks_data.NewDatabase(t)

	handler := MiddlewareCors(db)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, corsRequestCarryingId("/.well-known/openid-configuration", "http://anywhere.com"))

	assert.Equal(t, "http://anywhere.com", rr.Header().Get("Access-Control-Allow-Origin"))
	db.AssertNotCalled(t, "WebOriginExists", mock.Anything, mock.Anything, mock.Anything)
}
