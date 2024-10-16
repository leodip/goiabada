package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/constants"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestMiddlewareRateLimiter(t *testing.T) {
	t.Run("Rate limit by session identifier", func(t *testing.T) {
		mockStore := new(mocks_sessionstore.Store)
		mockSession := &sessions.Session{
			Values: make(map[interface{}]interface{}),
		}
		mockSession.Values[constants.SessionKeySessionIdentifier] = "test-session-id"

		mockStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		handler := MiddlewareRateLimiter(mockStore, 2, 1)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		for i := 0; i < 3; i++ {
			req := httptest.NewRequest("GET", "/", nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if i < 2 {
				assert.Equal(t, http.StatusOK, w.Code)
			} else {
				assert.Equal(t, http.StatusTooManyRequests, w.Code)
			}
		}
	})

	t.Run("Rate limit by auth context hash", func(t *testing.T) {
		mockStore := new(mocks_sessionstore.Store)
		mockSession := &sessions.Session{
			Values: make(map[interface{}]interface{}),
		}
		mockSession.Values[constants.SessionKeyAuthContext] = `{"user_id": 123}`

		mockStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		handler := MiddlewareRateLimiter(mockStore, 2, 1)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		for i := 0; i < 3; i++ {
			req := httptest.NewRequest("GET", "/", nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if i < 2 {
				assert.Equal(t, http.StatusOK, w.Code)
			} else {
				assert.Equal(t, http.StatusTooManyRequests, w.Code)
			}
		}
	})

	t.Run("Rate limit by IP when session retrieval fails", func(t *testing.T) {
		mockStore := new(mocks_sessionstore.Store)
		mockStore.On("Get", mock.Anything, constants.SessionName).Return(nil, errors.New("session retrieval failed"))

		handler := MiddlewareRateLimiter(mockStore, 2, 1)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		for i := 0; i < 3; i++ {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = "192.0.2.1:1234"
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if i < 2 {
				assert.Equal(t, http.StatusOK, w.Code)
			} else {
				assert.Equal(t, http.StatusTooManyRequests, w.Code)
			}
		}
	})

	t.Run("Rate limit resets after window", func(t *testing.T) {
		mockStore := new(mocks_sessionstore.Store)
		mockSession := &sessions.Session{
			Values: make(map[interface{}]interface{}),
		}
		mockSession.Values[constants.SessionKeySessionIdentifier] = "test-session-id"

		mockStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		handler := MiddlewareRateLimiter(mockStore, 2, 1)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		for i := 0; i < 2; i++ {
			req := httptest.NewRequest("GET", "/", nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
		}

		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusTooManyRequests, w.Code)

		time.Sleep(1100 * time.Millisecond)

		req = httptest.NewRequest("GET", "/", nil)
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}
