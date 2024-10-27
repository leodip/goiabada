package adminclienthandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
)

func TestHandleAdminClientAuthenticationGet(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockDB := mocks_data.NewDatabase(t)

	encryptionKey := []byte("test-encryption-key-000000000000")
	secret := "decrypted-secret"
	encryptedSecret, err := encryption.EncryptText(secret, encryptionKey)
	assert.Nil(t, err)

	client := &models.Client{
		Id:                    1,
		ClientIdentifier:      "test-client",
		IsPublic:              false,
		ClientSecretEncrypted: encryptedSecret,
	}

	mockDB.On("GetClientById", mock.Anything, int64(1)).Return(client, nil)

	mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_clients_authentication.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		clientData, ok := data["client"].(struct {
			ClientId            int64
			ClientIdentifier    string
			IsPublic            bool
			ClientSecret        string
			IsSystemLevelClient bool
		})
		return ok &&
			clientData.ClientId == 1 &&
			clientData.ClientIdentifier == "test-client" &&
			!clientData.IsPublic &&
			clientData.ClientSecret == "decrypted-secret" &&
			!clientData.IsSystemLevelClient
	})).Return(nil)

	handler := HandleAdminClientAuthenticationGet(mockHttpHelper, mockSessionStore, mockDB)

	req, _ := http.NewRequest("GET", "/admin/clients/1/authentication", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("clientId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, &models.Settings{
		AESEncryptionKey: encryptionKey,
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAdminClientAuthenticationGet_SavedSuccessfully(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockDB := mocks_data.NewDatabase(t)

	encryptionKey := []byte("test-encryption-key-000000000000")
	secret := "decrypted-secret"
	encryptedSecret, err := encryption.EncryptText(secret, encryptionKey)
	assert.Nil(t, err)

	client := &models.Client{
		Id:                    1,
		ClientIdentifier:      "test-client",
		IsPublic:              false,
		ClientSecretEncrypted: encryptedSecret,
	}

	mockDB.On("GetClientById", mock.Anything, int64(1)).Return(client, nil)

	mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
	mockSession.AddFlash("true", "savedSuccessfully")
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
	mockSessionStore.On("Save", mock.Anything, mock.Anything, mockSession).Return(nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_clients_authentication.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		clientData, ok := data["client"].(struct {
			ClientId            int64
			ClientIdentifier    string
			IsPublic            bool
			ClientSecret        string
			IsSystemLevelClient bool
		})
		return ok &&
			clientData.ClientId == 1 &&
			clientData.ClientIdentifier == "test-client" &&
			!clientData.IsPublic &&
			clientData.ClientSecret == "decrypted-secret" &&
			!clientData.IsSystemLevelClient &&
			data["savedSuccessfully"] == true
	})).Return(nil)

	handler := HandleAdminClientAuthenticationGet(mockHttpHelper, mockSessionStore, mockDB)

	req, _ := http.NewRequest("GET", "/admin/clients/1/authentication", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("clientId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, &models.Settings{
		AESEncryptionKey: encryptionKey,
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAdminClientGenerateNewSecretGet(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)

	mockHttpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.MatchedBy(func(data interface{}) bool {
		result, ok := data.(map[string]string)
		return ok &&
			len(result) == 1 &&
			len(result["NewSecret"]) == 60
	})).Return()

	handler := HandleAdminClientGenerateNewSecretGet(mockHttpHelper)

	req, _ := http.NewRequest("GET", "/admin/clients/generate-new-secret", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
}

func TestHandleAdminClientAuthenticationPost(t *testing.T) {
	t.Run("Change from public to confidential", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		encryptionKey := []byte("test-encryption-key-000000000000")
		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			IsPublic:         true,
		}

		mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("test-subject")
		mockDB.On("GetClientById", mock.Anything, int64(1)).Return(client, nil)

		mockDB.On("UpdateClient", mock.Anything, mock.MatchedBy(func(c *models.Client) bool {
			return c.Id == 1 && c.IsPublic == false && len(c.ClientSecretEncrypted) > 0
		})).Return(nil)

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
		mockSessionStore.On("Save", mock.Anything, mock.Anything, mockSession).Return(nil)

		mockAuditLogger.On("Log", constants.AuditUpdatedClientAuthentication, mock.Anything).Return(nil)

		handler := HandleAdminClientAuthenticationPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

		form := url.Values{}
		form.Add("publicConfidential", "confidential")
		form.Add("clientSecret", strings.Repeat("a", 60))
		req, _ := http.NewRequest("POST", "/admin/clients/1/authentication", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("clientId", "1")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, &models.Settings{
			AESEncryptionKey: encryptionKey,
		}))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.Get().BaseURL+"/admin/clients/1/authentication", rr.Header().Get("Location"))

		mockHttpHelper.AssertExpectations(t)
		mockSessionStore.AssertExpectations(t)
		mockAuthHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockAuditLogger.AssertExpectations(t)
	})

	t.Run("Change from confidential to public", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			IsPublic:         false,
		}

		mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("test-subject")
		mockDB.On("GetClientById", mock.Anything, int64(1)).Return(client, nil)

		mockDB.On("UpdateClient", mock.Anything, mock.MatchedBy(func(c *models.Client) bool {
			return c.Id == 1 && c.IsPublic == true && c.ClientSecretEncrypted == nil && c.ClientCredentialsEnabled == false
		})).Return(nil)

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
		mockSessionStore.On("Save", mock.Anything, mock.Anything, mockSession).Return(nil)

		mockAuditLogger.On("Log", constants.AuditUpdatedClientAuthentication, mock.Anything).Return(nil)

		handler := HandleAdminClientAuthenticationPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

		form := url.Values{}
		form.Add("publicConfidential", "public")
		req, _ := http.NewRequest("POST", "/admin/clients/1/authentication", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("clientId", "1")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, &models.Settings{}))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.Get().BaseURL+"/admin/clients/1/authentication", rr.Header().Get("Location"))

		mockHttpHelper.AssertExpectations(t)
		mockSessionStore.AssertExpectations(t)
		mockAuthHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockAuditLogger.AssertExpectations(t)
	})

	t.Run("System level client", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		encryptionKey := []byte("test-encryption-key-000000000000")
		client := &models.Client{
			Id:               1,
			ClientIdentifier: constants.AdminConsoleClientIdentifier,
			IsPublic:         false,
		}

		mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("test-subject")
		mockDB.On("GetClientById", mock.Anything, int64(1)).Return(client, nil)

		mockDB.On("UpdateClient", mock.Anything, mock.MatchedBy(func(c *models.Client) bool {
			return c.Id == 1 && c.IsPublic == false && len(c.ClientSecretEncrypted) > 0
		})).Return(nil)

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
		mockSessionStore.On("Save", mock.Anything, mock.Anything, mockSession).Return(nil)

		mockAuditLogger.On("Log", constants.AuditUpdatedClientAuthentication, mock.Anything).Return(nil)

		handler := HandleAdminClientAuthenticationPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

		form := url.Values{}
		form.Add("clientSecret", strings.Repeat("a", 60))
		req, _ := http.NewRequest("POST", "/admin/clients/1/authentication", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("clientId", "1")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, &models.Settings{
			AESEncryptionKey: encryptionKey,
		}))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.Get().BaseURL+"/admin/clients/1/authentication", rr.Header().Get("Location"))

		mockHttpHelper.AssertExpectations(t)
		mockSessionStore.AssertExpectations(t)
		mockAuthHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockAuditLogger.AssertExpectations(t)
	})

	t.Run("Invalid client secret", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			IsPublic:         false,
		}

		mockDB.On("GetClientById", mock.Anything, int64(1)).Return(client, nil)

		mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_clients_authentication.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Invalid client secret. Please generate a new one."
		})).Return(nil)

		handler := HandleAdminClientAuthenticationPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

		form := url.Values{}
		form.Add("publicConfidential", "confidential")
		form.Add("clientSecret", "short-secret")
		req, _ := http.NewRequest("POST", "/admin/clients/1/authentication", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("clientId", "1")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, &models.Settings{
			AESEncryptionKey: []byte("test-encryption-key-000000000000"),
		}))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		mockHttpHelper.AssertExpectations(t)
		mockSessionStore.AssertExpectations(t)
		mockAuthHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockAuditLogger.AssertNotCalled(t, "Log")
	})
}
