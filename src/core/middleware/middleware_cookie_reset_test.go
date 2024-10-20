package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/constants"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestMiddlewareCookieReset(t *testing.T) {
	t.Run("No error", func(t *testing.T) {
		mockStore := new(mocks_sessionstore.Store)
		mockStore.On("Get", mock.Anything, constants.SessionName).Return(&sessions.Session{}, nil)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
		middleware := MiddlewareCookieReset(mockStore)

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()

		middleware(handler).ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		mockStore.AssertExpectations(t)
	})

	t.Run("Decode error", func(t *testing.T) {
		mockStore := new(mocks_sessionstore.Store)
		decodeErr := securecookie.MultiError{securecookie.ErrMacInvalid}
		mockStore.On("Get", mock.Anything, constants.SessionName).Return(nil, decodeErr)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
		middleware := MiddlewareCookieReset(mockStore)

		req := httptest.NewRequest("GET", "/test", nil)
		rr := httptest.NewRecorder()

		middleware(handler).ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, "/test", rr.Header().Get("Location"))

		cookies := rr.Result().Cookies()
		assert.Len(t, cookies, 1)
		assert.Equal(t, constants.SessionName, cookies[0].Name)
		assert.True(t, cookies[0].Expires.Before(time.Now()))
		assert.Equal(t, -1, cookies[0].MaxAge)
		assert.Equal(t, "/", cookies[0].Path)

		mockStore.AssertExpectations(t)
	})

	t.Run("Non-decode error", func(t *testing.T) {
		mockStore := new(mocks_sessionstore.Store)
		mockStore.On("Get", mock.Anything, constants.SessionName).Return(nil, errors.New("non-decode error"))

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
		middleware := MiddlewareCookieReset(mockStore)

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()

		middleware(handler).ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Len(t, rr.Result().Cookies(), 0)

		mockStore.AssertExpectations(t)
	})
}
