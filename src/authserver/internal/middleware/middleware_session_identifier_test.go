package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/constants"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/models"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestMiddlewareSessionIdentifier(t *testing.T) {
	t.Run("Session store error", func(t *testing.T) {
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)

		mockSessionStore.On("Get", mock.Anything, constants.AuthServerSessionName).Return(nil, errors.New("session store error"))

		middleware := MiddlewareSessionIdentifier(mockSessionStore, mockDB)

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()

		middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rr, req)

		assert.Equal(t, http.StatusInternalServerError, rr.Code)
	})

	t.Run("No session identifier", func(t *testing.T) {
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)

		session := sessions.NewSession(mockSessionStore, constants.AuthServerSessionName)
		mockSessionStore.On("Get", mock.Anything, constants.AuthServerSessionName).Return(session, nil)

		middleware := MiddlewareSessionIdentifier(mockSessionStore, mockDB)

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()

		var contextSessionIdentifier interface{}
		middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			contextSessionIdentifier = r.Context().Value(constants.ContextKeySessionIdentifier)
		})).ServeHTTP(rr, req)

		assert.Nil(t, contextSessionIdentifier)
	})

	t.Run("Valid session identifier", func(t *testing.T) {
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)

		session := sessions.NewSession(mockSessionStore, constants.AuthServerSessionName)
		session.Values[constants.SessionKeySessionIdentifier] = "valid-session-id"
		mockSessionStore.On("Get", mock.Anything, constants.AuthServerSessionName).Return(session, nil)

		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, "valid-session-id").Return(&models.UserSession{}, nil)

		middleware := MiddlewareSessionIdentifier(mockSessionStore, mockDB)

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()

		var contextSessionIdentifier string
		middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			contextSessionIdentifier = r.Context().Value(constants.ContextKeySessionIdentifier).(string)
		})).ServeHTTP(rr, req)

		assert.Equal(t, "valid-session-id", contextSessionIdentifier)
	})

	t.Run("Invalid session identifier", func(t *testing.T) {
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)

		session := sessions.NewSession(mockSessionStore, constants.AuthServerSessionName)
		session.Values[constants.SessionKeySessionIdentifier] = "invalid-session-id"
		mockSessionStore.On("Get", mock.Anything, constants.AuthServerSessionName).Return(session, nil)

		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, "invalid-session-id").Return(nil, nil)
		mockSessionStore.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		middleware := MiddlewareSessionIdentifier(mockSessionStore, mockDB)

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()

		var contextSessionIdentifier interface{}
		middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			contextSessionIdentifier = r.Context().Value(constants.ContextKeySessionIdentifier)
		})).ServeHTTP(rr, req)

		assert.Nil(t, contextSessionIdentifier)
	})

	t.Run("Database error", func(t *testing.T) {
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)

		session := sessions.NewSession(mockSessionStore, constants.AuthServerSessionName)
		session.Values[constants.SessionKeySessionIdentifier] = "error-session-id"
		mockSessionStore.On("Get", mock.Anything, constants.AuthServerSessionName).Return(session, nil)

		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, "error-session-id").Return(nil, errors.New("database error"))

		middleware := MiddlewareSessionIdentifier(mockSessionStore, mockDB)

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()

		middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rr, req)

		assert.Equal(t, http.StatusInternalServerError, rr.Code)
	})
}
