package handlers

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_oauth "github.com/leodip/goiabada/core/oauth/mocks"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"

	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestHandleAccountLogoutGet(t *testing.T) {
	t.Run("No id token hint given", func(t *testing.T) {

		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		handler := HandleAccountLogoutGet(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

		req, _ := http.NewRequest("GET", "/logout", nil)
		rr := httptest.NewRecorder()

		settings := &models.Settings{}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		httpHelper.On("GetFromUrlQueryOrFormPost", req, "id_token_hint").Return("")
		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/logout_consent.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			_, hasCsrfField := data["csrfField"]
			return hasCsrfField
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		httpHelper.AssertExpectations(t)
	})

	t.Run("No postLogoutRedirectURI given", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutGet(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

		req, _ := http.NewRequest("GET", "/logout?id_token_hint=sometoken", nil)
		rr := httptest.NewRecorder()

		settings := &models.Settings{}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		httpHelper.On("GetFromUrlQueryOrFormPost", req, "id_token_hint").Return("sometoken")
		httpHelper.On("GetFromUrlQueryOrFormPost", req, "post_logout_redirect_uri").Return("")
		httpHelper.On("RenderTemplate", rr, req, "/layouts/no_menu_layout.html", "/auth_error.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			title, hasTitle := data["title"].(string)
			error, hasError := data["error"].(string)
			return hasTitle && title == "Logout error" &&
				hasError && error == "The post_logout_redirect_uri parameter is required. This parameter must match one of the redirect URIs that was registered for this client."
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		httpHelper.AssertExpectations(t)
	})

	t.Run("Fails to decode idTokenHint", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutGet(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

		idTokenHint := "This is not base64!"
		req, _ := http.NewRequest("GET", "/logout?id_token_hint="+url.QueryEscape(idTokenHint)+"&post_logout_redirect_uri=http://example.com&client_id=someclientid", nil)
		rr := httptest.NewRecorder()

		settings := &models.Settings{
			AESEncryptionKey: []byte("some_encryption_key0000000000000"),
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "id_token_hint").Return(idTokenHint)
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "post_logout_redirect_uri").Return("http://example.com")
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "client_id").Return("someclientid")

		database.On("GetClientByClientIdentifier", mock.Anything, "someclientid").Return(&models.Client{
			ClientSecretEncrypted: []byte("encrypted_secret"),
		}, nil)

		httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/no_menu_layout.html", "/auth_error.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			errorMsg, ok := data["error"].(string)
			return ok && strings.Contains(errorMsg, "Failed to base64 decode the id_token_hint")
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		httpHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Fails to decrypt idTokenHint", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutGet(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

		aesEncryptionKey := []byte("some_encryption_key0000000000000")
		clientSecret := "some_client_secret"
		clientSecretEncrypted, err := encryption.EncryptText(clientSecret, aesEncryptionKey)
		assert.Nil(t, err)

		idTokenHint := base64.StdEncoding.EncodeToString([]byte("some_encrypted_token"))
		req, _ := http.NewRequest("GET", "/logout?id_token_hint="+url.QueryEscape(idTokenHint)+"&post_logout_redirect_uri=http://example.com&client_id=someclientid", nil)
		rr := httptest.NewRecorder()

		settings := &models.Settings{
			AESEncryptionKey: aesEncryptionKey,
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		client := &models.Client{
			ClientSecretEncrypted: clientSecretEncrypted,
		}

		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "id_token_hint").Return(idTokenHint)
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "post_logout_redirect_uri").Return("http://example.com")
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "client_id").Return("someclientid")

		database.On("GetClientByClientIdentifier", mock.Anything, "someclientid").Return(client, nil)

		httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/no_menu_layout.html", "/auth_error.html",
			mock.MatchedBy(func(bind map[string]interface{}) bool {
				errorMsg, ok := bind["error"].(string)
				return ok && strings.Contains(errorMsg, "Failed to decrypt the id_token_hint")
			})).Return(nil).Once()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		httpHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Token parser fails to validate id token", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutGet(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

		aesEncryptionKey := []byte("some_encryption_key0000000000000")
		clientSecret := "some_client_secret"
		clientSecretEncrypted, _ := encryption.EncryptText(clientSecret, aesEncryptionKey)

		idTokenHint := "some_id_token"
		clientSecretPadded := clientSecret + strings.Repeat("0", 32-len(clientSecret))
		idTokenHintEncrypted, _ := encryption.EncryptText(idTokenHint, []byte(clientSecretPadded))
		idTokenHintEncryptedBase64 := base64.StdEncoding.EncodeToString(idTokenHintEncrypted)

		req, _ := http.NewRequest("GET", "/logout?id_token_hint="+url.QueryEscape(idTokenHintEncryptedBase64)+"&post_logout_redirect_uri=http://example.com&client_id=someclientid", nil)
		rr := httptest.NewRecorder()

		settings := &models.Settings{
			AESEncryptionKey: aesEncryptionKey,
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		client := &models.Client{
			ClientSecretEncrypted: clientSecretEncrypted,
		}

		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "id_token_hint").Return(idTokenHintEncryptedBase64)
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "post_logout_redirect_uri").Return("http://example.com")
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "client_id").Return("someclientid")

		database.On("GetClientByClientIdentifier", mock.Anything, "someclientid").Return(client, nil)

		tokenParser.On("DecodeAndValidateTokenString", mock.Anything, idTokenHint, (*rsa.PublicKey)(nil)).
			Return(nil, errors.New("some error")).Once()

		httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/no_menu_layout.html", "/auth_error.html",
			mock.MatchedBy(func(bind map[string]interface{}) bool {
				errorMsg, ok := bind["error"].(string)
				return ok && strings.Contains(errorMsg, "The id_token_hint parameter is invalid: some error")
			})).Return(nil).Once()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		httpHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		tokenParser.AssertExpectations(t)
	})

	t.Run("Issuer does not match", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutGet(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

		aesEncryptionKey := []byte("some_encryption_key0000000000000")
		clientSecret := "some_client_secret"
		clientSecretEncrypted, _ := encryption.EncryptText(clientSecret, aesEncryptionKey)

		idTokenHint := "some_id_token"
		clientSecretPadded := clientSecret + strings.Repeat("0", 32-len(clientSecret))
		idTokenHintEncrypted, _ := encryption.EncryptText(idTokenHint, []byte(clientSecretPadded))
		idTokenHintEncryptedBase64 := base64.StdEncoding.EncodeToString(idTokenHintEncrypted)

		req, _ := http.NewRequest("GET", "/logout?id_token_hint="+url.QueryEscape(idTokenHintEncryptedBase64)+"&post_logout_redirect_uri=http://example.com&client_id=someclientid", nil)
		rr := httptest.NewRecorder()

		settings := &models.Settings{
			AESEncryptionKey: aesEncryptionKey,
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		client := &models.Client{
			ClientSecretEncrypted: clientSecretEncrypted,
			ClientIdentifier:      "someclientid",
		}

		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "id_token_hint").Return(idTokenHintEncryptedBase64)
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "post_logout_redirect_uri").Return("http://example.com")
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "client_id").Return("someclientid")

		database.On("GetClientByClientIdentifier", mock.Anything, "someclientid").Return(client, nil)

		mockIdToken := &oauth.JwtToken{
			Claims: map[string]interface{}{
				"iss": "http://wrong-issuer.com",
			},
		}

		tokenParser.On("DecodeAndValidateTokenString", mock.Anything, idTokenHint, (*rsa.PublicKey)(nil)).Return(mockIdToken, nil)

		originalAuthServerBaseUrl := config.Get().BaseURL
		config.Get().BaseURL = "http://correct-issuer.com"
		defer func() {
			config.Get().BaseURL = originalAuthServerBaseUrl
		}()

		httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/no_menu_layout.html", "/auth_error.html",
			mock.MatchedBy(func(bind map[string]interface{}) bool {
				errorMsg, ok := bind["error"].(string)
				return ok && strings.Contains(errorMsg, "The id_token_hint parameter is invalid: the iss claim does not match the issuer of this server.")
			})).Return(nil).Once()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		httpHelper.AssertExpectations(t)
		tokenParser.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Aud claim does not match any client", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutGet(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

		aesEncryptionKey := []byte("some_encryption_key0000000000000")
		clientSecret := "some_client_secret"
		clientSecretEncrypted, _ := encryption.EncryptText(clientSecret, aesEncryptionKey)

		idTokenHint := "some_id_token"
		clientSecretPadded := clientSecret + strings.Repeat("0", 32-len(clientSecret))
		idTokenHintEncrypted, _ := encryption.EncryptText(idTokenHint, []byte(clientSecretPadded))
		idTokenHintEncryptedBase64 := base64.StdEncoding.EncodeToString(idTokenHintEncrypted)

		req, _ := http.NewRequest("GET", "/logout?id_token_hint="+url.QueryEscape(idTokenHintEncryptedBase64)+"&post_logout_redirect_uri=http://example.com&client_id=someclientid", nil)
		rr := httptest.NewRecorder()

		settings := &models.Settings{
			AESEncryptionKey: aesEncryptionKey,
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		client := &models.Client{
			ClientSecretEncrypted: clientSecretEncrypted,
			ClientIdentifier:      "someclientid",
		}

		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "id_token_hint").Return(idTokenHintEncryptedBase64)
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "post_logout_redirect_uri").Return("http://example.com")
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "client_id").Return("someclientid")

		database.On("GetClientByClientIdentifier", mock.Anything, "someclientid").Return(client, nil)

		config.Get().BaseURL = "http://correct-issuer.com"
		mockIdToken := &oauth.JwtToken{
			Claims: map[string]interface{}{
				"iss": config.Get().BaseURL,
				"aud": "non_existent_client_id",
			},
		}

		tokenParser.On("DecodeAndValidateTokenString", mock.Anything, idTokenHint, (*rsa.PublicKey)(nil)).Return(mockIdToken, nil)
		database.On("GetClientByClientIdentifier", mock.Anything, "non_existent_client_id").Return(nil, nil)

		httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/no_menu_layout.html", "/auth_error.html",
			mock.MatchedBy(func(bind map[string]interface{}) bool {
				errorMsg, ok := bind["error"].(string)
				return ok && strings.Contains(errorMsg, "Invalid client: non_existent_client_id")
			})).Return(nil).Once()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		httpHelper.AssertExpectations(t)
		tokenParser.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Post logout redirect URI not authorized", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutGet(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

		aesEncryptionKey := []byte("some_encryption_key0000000000000")
		clientSecret := "some_client_secret"
		clientSecretEncrypted, _ := encryption.EncryptText(clientSecret, aesEncryptionKey)

		idTokenHint := "some_id_token"
		clientSecretPadded := clientSecret + strings.Repeat("0", 32-len(clientSecret))
		idTokenHintEncrypted, _ := encryption.EncryptText(idTokenHint, []byte(clientSecretPadded))
		idTokenHintEncryptedBase64 := base64.StdEncoding.EncodeToString(idTokenHintEncrypted)

		unauthorizedRedirectURI := "http://unauthorized-redirect.com"
		req, _ := http.NewRequest("GET", "/logout?id_token_hint="+url.QueryEscape(idTokenHintEncryptedBase64)+"&post_logout_redirect_uri="+url.QueryEscape(unauthorizedRedirectURI)+"&client_id=someclientid", nil)
		rr := httptest.NewRecorder()

		settings := &models.Settings{
			AESEncryptionKey: aesEncryptionKey,
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		client := &models.Client{
			ClientSecretEncrypted: clientSecretEncrypted,
			ClientIdentifier:      "someclientid",
		}

		httpHelper.On("GetFromUrlQueryOrFormPost", req, "id_token_hint").Return(idTokenHintEncryptedBase64)
		httpHelper.On("GetFromUrlQueryOrFormPost", req, "post_logout_redirect_uri").Return(unauthorizedRedirectURI)
		httpHelper.On("GetFromUrlQueryOrFormPost", req, "client_id").Return("someclientid")

		database.On("GetClientByClientIdentifier", mock.Anything, "someclientid").Return(client, nil)

		config.Get().BaseURL = "http://correct-issuer.com"
		mockIdToken := &oauth.JwtToken{
			Claims: map[string]interface{}{
				"iss": config.Get().BaseURL,
				"aud": "someclientid",
			},
		}

		tokenParser.On("DecodeAndValidateTokenString", mock.Anything, idTokenHint, (*rsa.PublicKey)(nil)).Return(mockIdToken, nil)

		database.On("ClientLoadRedirectURIs", mock.Anything, client).Run(func(args mock.Arguments) {
			client := args.Get(1).(*models.Client)
			client.RedirectURIs = []models.RedirectURI{
				{URI: "http://authorized-redirect.com"},
			}
		}).Return(nil)

		httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/no_menu_layout.html", "/auth_error.html",
			mock.MatchedBy(func(bind map[string]interface{}) bool {
				errorMsg, ok := bind["error"].(string)
				return ok && strings.Contains(errorMsg, "Invalid post_logout_redirect_uri")
			})).Return(nil).Once()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		httpHelper.AssertExpectations(t)
		tokenParser.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("SessionIdentifier exists but sid claim is missing from ID token", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutGet(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

		aesEncryptionKey := []byte("some_encryption_key0000000000000")
		clientSecret := "some_client_secret"
		clientSecretEncrypted, _ := encryption.EncryptText(clientSecret, aesEncryptionKey)

		idTokenHint := "some_id_token"
		clientSecretPadded := clientSecret + strings.Repeat("0", 32-len(clientSecret))
		idTokenHintEncrypted, _ := encryption.EncryptText(idTokenHint, []byte(clientSecretPadded))
		idTokenHintEncryptedBase64 := base64.StdEncoding.EncodeToString(idTokenHintEncrypted)

		req, _ := http.NewRequest("GET", "/logout?id_token_hint="+url.QueryEscape(idTokenHintEncryptedBase64)+"&post_logout_redirect_uri=http://example.com&client_id=someclientid", nil)
		rr := httptest.NewRecorder()

		settings := &models.Settings{
			AESEncryptionKey: aesEncryptionKey,
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		ctx = context.WithValue(ctx, constants.ContextKeySessionIdentifier, "existing-session-id")
		req = req.WithContext(ctx)

		client := &models.Client{
			ClientSecretEncrypted: clientSecretEncrypted,
			ClientIdentifier:      "someclientid",
		}

		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "id_token_hint").Return(idTokenHintEncryptedBase64)
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "post_logout_redirect_uri").Return("http://example.com")
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "client_id").Return("someclientid")

		database.On("GetClientByClientIdentifier", mock.Anything, "someclientid").Return(client, nil)

		config.Get().BaseURL = "http://correct-issuer.com"
		mockIdToken := &oauth.JwtToken{
			Claims: map[string]interface{}{
				"iss": config.Get().BaseURL,
				"aud": "someclientid",
				// Note: 'sid' claim is intentionally missing
			},
		}

		tokenParser.On("DecodeAndValidateTokenString", mock.Anything, idTokenHint, (*rsa.PublicKey)(nil)).Return(mockIdToken, nil)

		database.On("ClientLoadRedirectURIs", mock.Anything, client).Run(func(args mock.Arguments) {
			client := args.Get(1).(*models.Client)
			client.RedirectURIs = []models.RedirectURI{
				{URI: "http://example.com"},
			}
		}).Return(nil)

		httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
			return err != nil && err.Error() == "Invalid session identifier in id_token_hint"
		})).Return(nil).Once()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		httpHelper.AssertExpectations(t)
		tokenParser.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Sid claim does not match", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutGet(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

		aesEncryptionKey := []byte("some_encryption_key0000000000000")
		clientSecret := "some_client_secret"
		clientSecretEncrypted, _ := encryption.EncryptText(clientSecret, aesEncryptionKey)

		idTokenHint := "some_id_token"
		clientSecretPadded := clientSecret + strings.Repeat("0", 32-len(clientSecret))
		idTokenHintEncrypted, _ := encryption.EncryptText(idTokenHint, []byte(clientSecretPadded))
		idTokenHintEncryptedBase64 := base64.StdEncoding.EncodeToString(idTokenHintEncrypted)

		req, _ := http.NewRequest("GET", "/logout?id_token_hint="+url.QueryEscape(idTokenHintEncryptedBase64)+"&post_logout_redirect_uri=http://example.com&client_id=someclientid", nil)
		rr := httptest.NewRecorder()

		settings := &models.Settings{AESEncryptionKey: aesEncryptionKey}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		ctx = context.WithValue(ctx, constants.ContextKeySessionIdentifier, "existing-session-id")
		req = req.WithContext(ctx)

		client := &models.Client{ClientSecretEncrypted: clientSecretEncrypted, ClientIdentifier: "someclientid"}
		database.On("GetClientByClientIdentifier", mock.Anything, "someclientid").Return(client, nil)

		config.Get().BaseURL = "http://correct-issuer.com"
		mockIdToken := &oauth.JwtToken{
			Claims: map[string]interface{}{
				"iss": config.Get().BaseURL,
				"aud": "someclientid",
				"sid": "some-other-session-id",
			},
		}

		tokenParser.On("DecodeAndValidateTokenString", mock.Anything, idTokenHint, (*rsa.PublicKey)(nil)).Return(mockIdToken, nil)

		database.On("ClientLoadRedirectURIs", mock.Anything, client).Run(func(args mock.Arguments) {
			client := args.Get(1).(*models.Client)
			client.RedirectURIs = []models.RedirectURI{{URI: "http://example.com"}}
		}).Return(nil)

		httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
			return err != nil && err.Error() == "Invalid session identifier in id_token_hint"
		})).Return(nil).Once()

		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "id_token_hint").Return(idTokenHintEncryptedBase64)
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "post_logout_redirect_uri").Return("http://example.com")
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "client_id").Return("someclientid")

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		httpHelper.AssertExpectations(t)
		tokenParser.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Successful logout with DeleteUserSession call", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutGet(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

		aesEncryptionKey := []byte("some_encryption_key0000000000000")
		clientSecret := "some_client_secret"
		clientSecretEncrypted, _ := encryption.EncryptText(clientSecret, aesEncryptionKey)

		idTokenHint := "some_id_token"
		clientSecretPadded := clientSecret + strings.Repeat("0", 32-len(clientSecret))
		idTokenHintEncrypted, _ := encryption.EncryptText(idTokenHint, []byte(clientSecretPadded))
		idTokenHintEncryptedBase64 := base64.StdEncoding.EncodeToString(idTokenHintEncrypted)

		sessionIdentifier := "existing-session-id"
		req, _ := http.NewRequest("GET", "/logout?id_token_hint="+url.QueryEscape(idTokenHintEncryptedBase64)+"&post_logout_redirect_uri=http://example.com&client_id=someclientid&state=abc123", nil)
		rr := httptest.NewRecorder()

		settings := &models.Settings{
			AESEncryptionKey: aesEncryptionKey,
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		ctx = context.WithValue(ctx, constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		client := &models.Client{
			Id:                    1,
			ClientSecretEncrypted: clientSecretEncrypted,
			ClientIdentifier:      "someclientid",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "someclientid").Return(client, nil)

		config.Get().BaseURL = "http://correct-issuer.com"
		mockIdToken := &oauth.JwtToken{
			Claims: map[string]interface{}{
				"iss": config.Get().BaseURL,
				"aud": "someclientid",
				"sid": sessionIdentifier,
			},
		}

		tokenParser.On("DecodeAndValidateTokenString", mock.Anything, idTokenHint, (*rsa.PublicKey)(nil)).Return(mockIdToken, nil)

		database.On("ClientLoadRedirectURIs", mock.Anything, client).Run(func(args mock.Arguments) {
			client := args.Get(1).(*models.Client)
			client.RedirectURIs = []models.RedirectURI{
				{URI: "http://example.com"},
			}
		}).Return(nil)

		userSession := &models.UserSession{
			Id:     1,
			UserId: 123,
			Clients: []models.UserSessionClient{
				{
					Id:       1,
					ClientId: 1,
					Client:   *client,
				},
			},
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(userSession, nil)
		database.On("UserSessionLoadClients", mock.Anything, userSession).Return(nil)
		database.On("UserSessionClientsLoadClients", mock.Anything, userSession.Clients).Return(nil)
		database.On("DeleteUserSessionClient", mock.Anything, int64(1)).Return(nil)
		database.On("DeleteUserSession", mock.Anything, int64(1)).Return(nil)

		auditLogger.On("Log", constants.AuditDeletedUserSessionClient, mock.Anything).Return()
		auditLogger.On("Log", constants.AuditLogout, mock.Anything).Return()

		mockSession := &sessions.Session{
			Values: make(map[interface{}]interface{}),
		}
		httpSession.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
		httpSession.On("Save", mock.Anything, mock.Anything, mockSession).Return(nil)

		authHelper.On("GetLoggedInSubject", mock.Anything).Return("user-123")

		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "id_token_hint").Return(idTokenHintEncryptedBase64)
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "post_logout_redirect_uri").Return("http://example.com")
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "client_id").Return("someclientid")
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "state").Return("abc-123")

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Contains(t, rr.Header().Get("Location"), "http://example.com?sid="+sessionIdentifier+"&state=abc-123")

		httpHelper.AssertExpectations(t)
		tokenParser.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		httpSession.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})
}

func TestPadClientSecret(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Empty string",
			input:    "",
			expected: strings.Repeat("0", 32),
		},
		{
			name:     "String shorter than 32 characters",
			input:    "short",
			expected: "short" + strings.Repeat("0", 27),
		},
		{
			name:     "String exactly 32 characters",
			input:    "12345678901234567890123456789012",
			expected: "12345678901234567890123456789012",
		},
		{
			name:     "String longer than 32 characters",
			input:    "123456789012345678901234567890123456",
			expected: "123456789012345678901234567890123456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := padClientSecret(tt.input)
			if result != tt.expected {
				t.Errorf("padClientSecret(%q) = %q, want %q", tt.input, result, tt.expected)
			}
			if len(result) < 32 {
				t.Errorf("padClientSecret(%q) returned a string shorter than 32 characters", tt.input)
			}
		})
	}
}

func TestDecryptIDTokenHint(t *testing.T) {
	t.Run("Successful decryption", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		settings := &models.Settings{
			AESEncryptionKey: []byte("some_encryption_key0000000000000"),
		}

		clientSecret := "test_secret"
		clientSecretEncrypted, _ := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)

		client := &models.Client{
			ClientSecretEncrypted: clientSecretEncrypted,
		}

		database.On("GetClientByClientIdentifier", mock.Anything, "test_client").Return(client, nil)

		idTokenHint := "test_token"
		clientSecretPadded := padClientSecret(clientSecret)
		encryptedToken, _ := encryption.EncryptText(idTokenHint, []byte(clientSecretPadded)[:32])
		encodedToken := base64.StdEncoding.EncodeToString(encryptedToken)

		result, err := decryptIDTokenHint(encodedToken, "test_client", database, settings)

		assert.NoError(t, err)
		assert.Equal(t, idTokenHint, result)
	})

	t.Run("Invalid client", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		settings := &models.Settings{
			AESEncryptionKey: []byte("some_encryption_key0000000000000"),
		}

		database.On("GetClientByClientIdentifier", mock.Anything, "invalid_client").Return(nil, nil)

		_, err := decryptIDTokenHint("encoded_token", "invalid_client", database, settings)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Invalid client")
	})

	t.Run("Invalid base64 encoding", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		settings := &models.Settings{
			AESEncryptionKey: []byte("some_encryption_key0000000000000"),
		}

		client := &models.Client{
			ClientSecretEncrypted: []byte("encrypted_secret"),
		}

		database.On("GetClientByClientIdentifier", mock.Anything, "test_client").Return(client, nil)

		_, err := decryptIDTokenHint("invalid_base64", "test_client", database, settings)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Failed to base64 decode the id_token_hint")
	})

	t.Run("Decryption failure", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		settings := &models.Settings{
			AESEncryptionKey: []byte("some_encryption_key0000000000000"),
		}

		clientSecret := "test_secret"
		clientSecretEncrypted, _ := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)

		client := &models.Client{
			ClientSecretEncrypted: clientSecretEncrypted,
		}

		database.On("GetClientByClientIdentifier", mock.Anything, "test_client").Return(client, nil)

		invalidEncryptedToken := []byte("invalid_encrypted_token")
		encodedToken := base64.StdEncoding.EncodeToString(invalidEncryptedToken)

		_, err := decryptIDTokenHint(encodedToken, "test_client", database, settings)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Failed to decrypt the id_token_hint")
	})
}

func TestValidateClientAndRedirectURI(t *testing.T) {
	t.Run("Valid client and redirect URI", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		idToken := &oauth.JwtToken{
			Claims: map[string]interface{}{
				"aud": "test_client",
			},
		}
		postLogoutRedirectURI := "https://example.com/logout"
		clientId := "test_client"

		client := &models.Client{
			ClientIdentifier: "test_client",
			RedirectURIs: []models.RedirectURI{
				{URI: "https://example.com/logout"},
			},
		}

		database.On("GetClientByClientIdentifier", mock.Anything, "test_client").Return(client, nil)
		database.On("ClientLoadRedirectURIs", mock.Anything, client).Run(func(args mock.Arguments) {
			// RedirectURIs are already set, so we don't need to do anything here
		}).Return(nil)

		result, err := validateClientAndRedirectURI(idToken, postLogoutRedirectURI, database, clientId)

		assert.NoError(t, err)
		assert.Equal(t, client, result)
	})

	t.Run("Missing aud claim", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		idToken := &oauth.JwtToken{
			Claims: map[string]interface{}{},
		}
		postLogoutRedirectURI := "https://example.com/logout"
		clientId := "test_client"

		_, err := validateClientAndRedirectURI(idToken, postLogoutRedirectURI, database, clientId)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "The aud claim is missing in id_token_hint")
	})

	t.Run("Invalid client", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		idToken := &oauth.JwtToken{
			Claims: map[string]interface{}{
				"aud": "invalid_client",
			},
		}
		postLogoutRedirectURI := "https://example.com/logout"
		clientId := "invalid_client"

		database.On("GetClientByClientIdentifier", mock.Anything, "invalid_client").Return(nil, nil)

		_, err := validateClientAndRedirectURI(idToken, postLogoutRedirectURI, database, clientId)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Invalid client: invalid_client")
	})

	t.Run("Mismatched client_id", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		idToken := &oauth.JwtToken{
			Claims: map[string]interface{}{
				"aud": "test_client",
			},
		}
		postLogoutRedirectURI := "https://example.com/logout"
		clientId := "different_client"

		// Set up mock for GetClientByClientIdentifier
		client := &models.Client{
			ClientIdentifier: "test_client",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test_client").Return(client, nil)

		_, err := validateClientAndRedirectURI(idToken, postLogoutRedirectURI, database, clientId)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "The client_id parameter does not match the aud claim in id_token_hint")
	})

	t.Run("Invalid redirect URI", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		idToken := &oauth.JwtToken{
			Claims: map[string]interface{}{
				"aud": "test_client",
			},
		}
		postLogoutRedirectURI := "https://example.com/invalid"
		clientId := "test_client"

		client := &models.Client{
			ClientIdentifier: "test_client",
			RedirectURIs: []models.RedirectURI{
				{URI: "https://example.com/logout"},
			},
		}

		database.On("GetClientByClientIdentifier", mock.Anything, "test_client").Return(client, nil)
		database.On("ClientLoadRedirectURIs", mock.Anything, client).Run(func(args mock.Arguments) {
			// RedirectURIs are already set, so we don't need to do anything here
		}).Return(nil)

		_, err := validateClientAndRedirectURI(idToken, postLogoutRedirectURI, database, clientId)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Invalid post_logout_redirect_uri")
	})
}

func TestHandleExistingSessionOnLogout(t *testing.T) {
	t.Run("Invalid session identifier", func(t *testing.T) {
		r := &http.Request{}
		sessionIdentifier := "test-session"
		idToken := &oauth.JwtToken{
			Claims: map[string]interface{}{
				"sid": "different-session",
			},
		}
		client := &models.Client{}
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)

		err := handleExistingSessionOnLogout(r, sessionIdentifier, idToken, client, database, auditLogger, authHelper)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Invalid session identifier in id_token_hint")
	})

	t.Run("Session not found", func(t *testing.T) {
		r := &http.Request{}
		sessionIdentifier := "test-session"
		idToken := &oauth.JwtToken{
			Claims: map[string]interface{}{
				"sid": "test-session",
			},
		}
		client := &models.Client{}
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(nil, nil)

		err := handleExistingSessionOnLogout(r, sessionIdentifier, idToken, client, database, auditLogger, authHelper)

		assert.NoError(t, err) // The function should not return an error if the session is not found
		database.AssertExpectations(t)
	})

	t.Run("Delete user session client", func(t *testing.T) {
		r := &http.Request{}
		sessionIdentifier := "test-session"
		idToken := &oauth.JwtToken{
			Claims: map[string]interface{}{
				"sid": "test-session",
			},
		}
		client := &models.Client{
			ClientIdentifier: "test-client",
		}
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)

		userSession := &models.UserSession{
			Id:     1,
			UserId: 123,
			Clients: []models.UserSessionClient{
				{
					Id: 1,
					Client: models.Client{
						ClientIdentifier: "test-client",
					},
				},
				{
					Id: 2,
					Client: models.Client{
						ClientIdentifier: "other-client",
					},
				},
			},
		}

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(userSession, nil)
		database.On("UserSessionLoadClients", mock.Anything, userSession).Return(nil)
		database.On("UserSessionClientsLoadClients", mock.Anything, userSession.Clients).Return(nil)
		database.On("DeleteUserSessionClient", mock.Anything, int64(1)).Return(nil)
		// We don't expect DeleteUserSession to be called in this case

		authHelper.On("GetLoggedInSubject", mock.Anything).Return("user-123")

		auditLogger.On("Log", constants.AuditDeletedUserSessionClient, mock.Anything).Return()

		err := handleExistingSessionOnLogout(r, sessionIdentifier, idToken, client, database, auditLogger, authHelper)

		assert.NoError(t, err)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("Delete entire user session", func(t *testing.T) {
		r := &http.Request{}
		sessionIdentifier := "test-session"
		idToken := &oauth.JwtToken{
			Claims: map[string]interface{}{
				"sid": "test-session",
			},
		}
		client := &models.Client{
			ClientIdentifier: "test-client",
		}
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)

		userSession := &models.UserSession{
			Id:     1,
			UserId: 123,
			Clients: []models.UserSessionClient{
				{
					Id: 1,
					Client: models.Client{
						ClientIdentifier: "test-client",
					},
				},
			},
		}

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(userSession, nil)
		database.On("UserSessionLoadClients", mock.Anything, userSession).Return(nil)
		database.On("UserSessionClientsLoadClients", mock.Anything, userSession.Clients).Return(nil)
		database.On("DeleteUserSessionClient", mock.Anything, int64(1)).Return(nil)
		database.On("DeleteUserSession", mock.Anything, int64(1)).Return(nil)

		authHelper.On("GetLoggedInSubject", mock.Anything).Return("user-123")

		auditLogger.On("Log", constants.AuditDeletedUserSessionClient, mock.Anything).Return()
		auditLogger.On("Log", constants.AuditLogout, mock.Anything).Return()

		err := handleExistingSessionOnLogout(r, sessionIdentifier, idToken, client, database, auditLogger, authHelper)

		assert.NoError(t, err)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("Client not found in user session", func(t *testing.T) {
		r := &http.Request{}
		sessionIdentifier := "test-session"
		idToken := &oauth.JwtToken{
			Claims: map[string]interface{}{
				"sid": "test-session",
			},
		}
		client := &models.Client{
			ClientIdentifier: "test-client",
		}
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)

		userSession := &models.UserSession{
			Id:     1,
			UserId: 123,
			Clients: []models.UserSessionClient{
				{
					Id: 1,
					Client: models.Client{
						ClientIdentifier: "other-client",
					},
				},
			},
		}

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(userSession, nil)
		database.On("UserSessionLoadClients", mock.Anything, userSession).Return(nil)
		database.On("UserSessionClientsLoadClients", mock.Anything, userSession.Clients).Return(nil)

		err := handleExistingSessionOnLogout(r, sessionIdentifier, idToken, client, database, auditLogger, authHelper)

		assert.NoError(t, err) // The function should not return an error if the client is not found in the session
		database.AssertExpectations(t)
		auditLogger.AssertNotCalled(t, "Log")
		authHelper.AssertNotCalled(t, "GetLoggedInSubject")
	})
}

func TestHandleAccountLogoutPost(t *testing.T) {
	origAuthServerBaseUrl := config.Get().BaseURL
	config.Get().BaseURL = "http://localhost:8080"
	defer func() { config.Get().BaseURL = origAuthServerBaseUrl }()

	t.Run("Successful logout", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutPost(httpHelper, httpSession, authHelper, database, auditLogger)

		req, err := http.NewRequest("POST", "/logout", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		sessionIdentifier := "test-session"
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		mockSession := &sessions.Session{
			Values: make(map[interface{}]interface{}),
		}
		httpSession.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
		httpSession.On("Save", mock.Anything, mock.Anything, mockSession).Return(nil)

		userSession := &models.UserSession{
			Id:     1,
			UserId: 123,
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(userSession, nil)

		loggedInSubject := "user-123"
		authHelper.On("GetLoggedInSubject", mock.Anything).Return(loggedInSubject)

		auditLogger.On("Log", constants.AuditLogout, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userId"] == int64(123) &&
				details["sessionIdentifier"] == sessionIdentifier &&
				details["loggedInUser"] == loggedInSubject
		})).Return()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.Get().BaseURL, rr.Header().Get("Location"))

		httpSession.AssertExpectations(t)
		database.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("Session not found", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutPost(httpHelper, httpSession, authHelper, database, auditLogger)

		req, err := http.NewRequest("POST", "/logout", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		sessionIdentifier := "test-session"
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		mockSession := &sessions.Session{
			Values: make(map[interface{}]interface{}),
		}
		httpSession.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
		httpSession.On("Save", mock.Anything, mock.Anything, mockSession).Return(nil)

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(nil, nil)

		authHelper.On("GetLoggedInSubject", mock.Anything).Return("user-123")

		auditLogger.On("Log", constants.AuditLogout, mock.Anything).Return()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.Get().BaseURL, rr.Header().Get("Location"))

		httpSession.AssertExpectations(t)
		database.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("Session store error", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutPost(httpHelper, httpSession, authHelper, database, auditLogger)

		req, err := http.NewRequest("POST", "/logout", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		sessionError := errors.New("session store error")
		httpSession.On("Get", mock.Anything, constants.SessionName).Return(nil, sessionError)

		httpHelper.On("InternalServerError",
			mock.Anything,
			mock.Anything,
			mock.MatchedBy(func(err error) bool {
				return err.Error() == "session store error"
			}),
		).Run(func(args mock.Arguments) {
			w := args.Get(0).(http.ResponseWriter)
			w.WriteHeader(http.StatusInternalServerError)
		}).Return()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusInternalServerError, rr.Code)
		httpSession.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
	})

	t.Run("Session save error", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutPost(httpHelper, httpSession, authHelper, database, auditLogger)

		req, err := http.NewRequest("POST", "/logout", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		mockSession := &sessions.Session{
			Values: make(map[interface{}]interface{}),
		}
		httpSession.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
		httpSession.On("Save", mock.Anything, mock.Anything, mockSession).Return(errors.New("session save error"))

		httpHelper.On("InternalServerError",
			mock.AnythingOfType("*httptest.ResponseRecorder"),
			mock.AnythingOfType("*http.Request"),
			mock.MatchedBy(func(err error) bool {
				return err.Error() == "session save error"
			}),
		).Return()

		handler.ServeHTTP(rr, req)

		httpSession.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
	})
}
