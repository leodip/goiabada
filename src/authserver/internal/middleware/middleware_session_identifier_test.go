package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/sessionkeys"
	"github.com/leodip/goiabada/core/sessionstore"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestMiddlewareSessionIdentifier(t *testing.T) {
	t.Run("Session store error", func(t *testing.T) {
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)

		mockSessionStore.On("Get", mock.Anything, sessionkeys.AuthServerSessionName).Return(nil, errors.New("session store error"))

		middleware := MiddlewareSessionIdentifier(mockSessionStore, mockDB)

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()

		middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rr, req)

		assert.Equal(t, http.StatusInternalServerError, rr.Code)
	})

	t.Run("No session identifier", func(t *testing.T) {
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)

		session := sessionstore.NewSession(mockSessionStore, sessionkeys.AuthServerSessionName)
		mockSessionStore.On("Get", mock.Anything, sessionkeys.AuthServerSessionName).Return(session, nil)

		middleware := MiddlewareSessionIdentifier(mockSessionStore, mockDB)

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()

		var present bool
		middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, present = reqctx.SessionIdentifierFrom(r.Context())
		})).ServeHTTP(rr, req)

		assert.False(t, present)
	})

	t.Run("Valid session identifier", func(t *testing.T) {
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)

		session := sessionstore.NewSession(mockSessionStore, sessionkeys.AuthServerSessionName)
		session.Values[sessionkeys.SessionKeySessionIdentifier] = "valid-session-id"
		mockSessionStore.On("Get", mock.Anything, sessionkeys.AuthServerSessionName).Return(session, nil)

		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "valid-session-id").Return(&models.UserSession{}, nil)

		middleware := MiddlewareSessionIdentifier(mockSessionStore, mockDB)

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()

		var contextSessionIdentifier string
		var present bool
		middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			contextSessionIdentifier, present = reqctx.SessionIdentifierFrom(r.Context())
		})).ServeHTTP(rr, req)

		assert.True(t, present)
		assert.Equal(t, "valid-session-id", contextSessionIdentifier)
	})

	t.Run("Invalid session identifier", func(t *testing.T) {
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)

		session := sessionstore.NewSession(mockSessionStore, sessionkeys.AuthServerSessionName)
		session.Values[sessionkeys.SessionKeySessionIdentifier] = "invalid-session-id"
		mockSessionStore.On("Get", mock.Anything, sessionkeys.AuthServerSessionName).Return(session, nil)

		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "invalid-session-id").Return(nil, nil)
		mockSessionStore.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		middleware := MiddlewareSessionIdentifier(mockSessionStore, mockDB)

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()

		var present bool
		middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, present = reqctx.SessionIdentifierFrom(r.Context())
		})).ServeHTTP(rr, req)

		assert.False(t, present)
	})

	t.Run("Invalid session identifier preserves other session values", func(t *testing.T) {
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)

		session := sessionstore.NewSession(mockSessionStore, sessionkeys.AuthServerSessionName)
		session.Values[sessionkeys.SessionKeySessionIdentifier] = "invalid-session-id"
		session.Values[sessionkeys.SessionKeyAuthContext] = `{"authState":"level1_password"}`
		mockSessionStore.On("Get", mock.Anything, sessionkeys.AuthServerSessionName).Return(session, nil)

		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "invalid-session-id").Return(nil, nil)
		mockSessionStore.On("Save", mock.Anything, mock.Anything, mock.MatchedBy(func(s *sessionstore.Session) bool {
			// Verify session identifier was removed but auth context was preserved
			_, hasSessionId := s.Values[sessionkeys.SessionKeySessionIdentifier]
			authContext, hasAuthContext := s.Values[sessionkeys.SessionKeyAuthContext]
			return !hasSessionId && hasAuthContext && authContext == `{"authState":"level1_password"}`
		})).Return(nil)

		middleware := MiddlewareSessionIdentifier(mockSessionStore, mockDB)

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()

		middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rr, req)

		// Verify the session still has auth context after middleware runs
		assert.Equal(t, `{"authState":"level1_password"}`, session.Values[sessionkeys.SessionKeyAuthContext])
		assert.Nil(t, session.Values[sessionkeys.SessionKeySessionIdentifier])
	})

	t.Run("Database error", func(t *testing.T) {
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)

		session := sessionstore.NewSession(mockSessionStore, sessionkeys.AuthServerSessionName)
		session.Values[sessionkeys.SessionKeySessionIdentifier] = "error-session-id"
		mockSessionStore.On("Get", mock.Anything, sessionkeys.AuthServerSessionName).Return(session, nil)

		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "error-session-id").Return(nil, errors.New("database error"))

		middleware := MiddlewareSessionIdentifier(mockSessionStore, mockDB)

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()

		middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rr, req)

		assert.Equal(t, http.StatusInternalServerError, rr.Code)
	})
}
