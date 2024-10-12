package accounthandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
)

func TestHandleAccountLogoutGet_IdTokenExists(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockDB := mocks_data.NewDatabase(t)

	mockSession := &sessions.Session{
		Values: make(map[interface{}]interface{}),
		Options: &sessions.Options{
			MaxAge: 1,
		},
	}
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
	mockSessionStore.On("Save", mock.Anything, mock.Anything, mockSession).Return(nil)

	encryptionKey := []byte("test_encryption_key_000000000000")
	clientSecret := "client_secret"
	encryptedSecret, err := encryption.EncryptText(clientSecret, encryptionKey)
	assert.Nil(t, err)

	client := &models.Client{
		ClientIdentifier:      constants.AdminConsoleClientIdentifier,
		ClientSecretEncrypted: encryptedSecret,
	}
	mockDB.On("GetClientByClientIdentifier", mock.Anything, constants.AdminConsoleClientIdentifier).Return(client, nil)

	req, _ := http.NewRequest("GET", "/account/logout", nil)
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, &models.Settings{
		AESEncryptionKey: encryptionKey,
	}))
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, oauth.JwtInfo{
		IdToken: &oauth.JwtToken{
			TokenBase64: "test_token",
			Claims: jwt.MapClaims{
				"sub": uuid.New().String(),
			},
		},
	}))

	rr := httptest.NewRecorder()

	handler := HandleAccountLogoutGet(mockHttpHelper, mockSessionStore, mockDB)
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)

	redirectURL, _ := url.Parse(rr.Header().Get("Location"))
	assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/logout", redirectURL.Scheme+"://"+redirectURL.Host+redirectURL.Path)

	query := redirectURL.Query()
	assert.NotEmpty(t, query.Get("id_token_hint"))
	assert.Equal(t, config.Get().BaseURL, query.Get("post_logout_redirect_uri"))
	assert.Equal(t, constants.AdminConsoleClientIdentifier, query.Get("client_id"))
	assert.NotEmpty(t, query.Get("state"))

	mockSessionStore.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAccountLogoutGet_IdTokenDoesNotExist(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockDB := mocks_data.NewDatabase(t)

	mockSession := &sessions.Session{
		Values: make(map[interface{}]interface{}),
		Options: &sessions.Options{
			MaxAge: 1,
		},
	}
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
	mockSessionStore.On("Save", mock.Anything, mock.Anything, mockSession).Return(nil)

	req, _ := http.NewRequest("GET", "/account/logout", nil)
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, &models.Settings{}))
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, oauth.JwtInfo{}))

	rr := httptest.NewRecorder()

	handler := HandleAccountLogoutGet(mockHttpHelper, mockSessionStore, mockDB)
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, config.Get().BaseURL, rr.Header().Get("Location"))

	mockSessionStore.AssertExpectations(t)
	mockDB.AssertNotCalled(t, "GetClientByClientIdentifier")
}
