package handlerhelpers

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"

	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
)

func TestGetAuthContext(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockStore := mocks_sessionstore.NewStore(t)
		helper := NewAuthHelper(mockStore)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		sess := sessions.NewSession(mockStore, constants.SessionName)
		authContext := &oauth.AuthContext{ClientId: "test-client"}
		jsonData, _ := json.Marshal(authContext)
		sess.Values[constants.SessionKeyAuthContext] = string(jsonData)

		mockStore.On("Get", req, constants.SessionName).Return(sess, nil)

		result, err := helper.GetAuthContext(req)

		assert.NoError(t, err)
		assert.Equal(t, authContext.ClientId, result.ClientId)
		mockStore.AssertExpectations(t)
	})

	t.Run("SessionError", func(t *testing.T) {
		mockStore := mocks_sessionstore.NewStore(t)
		helper := NewAuthHelper(mockStore)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		mockStore.On("Get", req, constants.SessionName).Return(nil, assert.AnError)

		result, err := helper.GetAuthContext(req)

		assert.Error(t, err)
		assert.Nil(t, result)
		mockStore.AssertExpectations(t)
	})

	t.Run("NoAuthContext", func(t *testing.T) {
		mockStore := mocks_sessionstore.NewStore(t)
		helper := NewAuthHelper(mockStore)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		sess := sessions.NewSession(mockStore, constants.SessionName)

		mockStore.On("Get", req, constants.SessionName).Return(sess, nil)

		result, err := helper.GetAuthContext(req)

		assert.Error(t, err)
		assert.Nil(t, result)
		mockStore.AssertExpectations(t)
	})

	t.Run("UnmarshalError", func(t *testing.T) {
		mockStore := mocks_sessionstore.NewStore(t)
		helper := NewAuthHelper(mockStore)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		sess := sessions.NewSession(mockStore, constants.SessionName)
		sess.Values[constants.SessionKeyAuthContext] = "invalid json"

		mockStore.On("Get", req, constants.SessionName).Return(sess, nil)

		result, err := helper.GetAuthContext(req)

		assert.Error(t, err)
		assert.Nil(t, result)
		mockStore.AssertExpectations(t)
	})
}

func TestGetLoggedInSubject(t *testing.T) {
	helper := NewAuthHelper(nil)

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		jwtInfo := oauth.JwtInfo{
			IdToken: &oauth.JwtToken{
				Claims: map[string]interface{}{"sub": "test-subject"},
			},
		}
		ctx := context.WithValue(req.Context(), constants.ContextKeyJwtInfo, jwtInfo)
		req = req.WithContext(ctx)

		subject := helper.GetLoggedInSubject(req)

		assert.Equal(t, "test-subject", subject)
	})

	t.Run("NoJwtInfo", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)

		subject := helper.GetLoggedInSubject(req)

		assert.Empty(t, subject)
	})

	t.Run("InvalidJwtInfo", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		ctx := context.WithValue(req.Context(), constants.ContextKeyJwtInfo, "invalid")
		req = req.WithContext(ctx)

		// Capture log output
		var buf bytes.Buffer
		log.SetOutput(&buf)
		defer log.SetOutput(os.Stderr)

		subject := helper.GetLoggedInSubject(req)

		assert.Empty(t, subject)
		assert.Contains(t, buf.String(), "ERROR unable to cast jwtInfo")
	})

	t.Run("NoIdToken", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		jwtInfo := oauth.JwtInfo{}
		ctx := context.WithValue(req.Context(), constants.ContextKeyJwtInfo, jwtInfo)
		req = req.WithContext(ctx)

		subject := helper.GetLoggedInSubject(req)

		assert.Empty(t, subject)
	})
}

func TestSaveAuthContext(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockStore := mocks_sessionstore.NewStore(t)
		helper := NewAuthHelper(mockStore)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		sess := sessions.NewSession(mockStore, constants.SessionName)
		authContext := &oauth.AuthContext{ClientId: "test-client"}

		mockStore.On("Get", req, constants.SessionName).Return(sess, nil)
		mockStore.On("Save", req, w, sess).Return(nil)

		err := helper.SaveAuthContext(w, req, authContext)

		assert.NoError(t, err)
		assert.Contains(t, sess.Values, constants.SessionKeyAuthContext)
		mockStore.AssertExpectations(t)
	})

	t.Run("SessionError", func(t *testing.T) {
		mockStore := mocks_sessionstore.NewStore(t)
		helper := NewAuthHelper(mockStore)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		authContext := &oauth.AuthContext{ClientId: "test-client"}

		mockStore.On("Get", req, constants.SessionName).Return(nil, assert.AnError)

		err := helper.SaveAuthContext(w, req, authContext)

		assert.Error(t, err)
		mockStore.AssertExpectations(t)
	})

	t.Run("SaveError", func(t *testing.T) {
		mockStore := mocks_sessionstore.NewStore(t)
		helper := NewAuthHelper(mockStore)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		sess := sessions.NewSession(mockStore, constants.SessionName)
		authContext := &oauth.AuthContext{ClientId: "test-client"}

		mockStore.On("Get", req, constants.SessionName).Return(sess, nil)
		mockStore.On("Save", req, w, sess).Return(assert.AnError)

		err := helper.SaveAuthContext(w, req, authContext)

		assert.Error(t, err)
		mockStore.AssertExpectations(t)
	})
}

func TestClearAuthContext(t *testing.T) {

	t.Run("Success", func(t *testing.T) {
		mockStore := mocks_sessionstore.NewStore(t)
		helper := NewAuthHelper(mockStore)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		sess := sessions.NewSession(mockStore, constants.SessionName)
		sess.Values[constants.SessionKeyAuthContext] = "test-context"

		mockStore.On("Get", req, constants.SessionName).Return(sess, nil)
		mockStore.On("Save", req, w, sess).Return(nil)

		err := helper.ClearAuthContext(w, req)

		assert.NoError(t, err)
		assert.NotContains(t, sess.Values, constants.SessionKeyAuthContext)
		mockStore.AssertExpectations(t)
	})

	t.Run("SessionError", func(t *testing.T) {
		mockStore := mocks_sessionstore.NewStore(t)
		helper := NewAuthHelper(mockStore)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()

		mockStore.On("Get", req, constants.SessionName).Return(nil, assert.AnError)

		err := helper.ClearAuthContext(w, req)

		assert.Error(t, err)
		mockStore.AssertExpectations(t)
	})

	t.Run("SaveError", func(t *testing.T) {
		mockStore := mocks_sessionstore.NewStore(t)
		helper := NewAuthHelper(mockStore)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		sess := sessions.NewSession(mockStore, constants.SessionName)

		mockStore.On("Get", req, constants.SessionName).Return(sess, nil)
		mockStore.On("Save", req, w, sess).Return(assert.AnError)

		err := helper.ClearAuthContext(w, req)

		assert.Error(t, err)
		mockStore.AssertExpectations(t)
	})
}
