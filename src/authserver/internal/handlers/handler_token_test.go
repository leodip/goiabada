package handlers

import (
	"database/sql"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_oauth "github.com/leodip/goiabada/core/oauth/mocks"
	mocks_users "github.com/leodip/goiabada/core/user/mocks"
	mocks_validators "github.com/leodip/goiabada/core/validators/mocks"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/validators"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestHandleTokenPost(t *testing.T) {
	t.Run("ParseForm gives error", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		userSessionManager := mocks_users.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		tokenValidator := mocks_validators.NewTokenValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleTokenPost(httpHelper, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger)

		req, _ := http.NewRequest("POST", "/token", nil)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		httpHelper.On("JsonError", rr, req, mock.AnythingOfType("*errors.errorString")).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
	})

	t.Run("ValidateTokenRequest gives error", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		userSessionManager := mocks_users.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		tokenValidator := mocks_validators.NewTokenValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleTokenPost(httpHelper, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger)

		formData := "grant_type=authorization_code&code=test_code&redirect_uri=http://example.com&client_id=test_client"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		validationError := customerrors.NewErrorDetailWithHttpStatusCode("invalid_request", "Validation error", http.StatusBadRequest)

		tokenValidator.On("ValidateTokenRequest", req.Context(), mock.AnythingOfType("*validators.ValidateTokenRequestInput")).
			Return(nil, validationError)

		httpHelper.On("JsonError", rr, req, validationError).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		tokenValidator.AssertExpectations(t)
	})

	t.Run("Authorization_code GenerateTokenResponseForAuthCode gives error", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		userSessionManager := mocks_users.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		tokenValidator := mocks_validators.NewTokenValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleTokenPost(httpHelper, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger)

		formData := "grant_type=authorization_code&code=test_code&redirect_uri=http://example.com&client_id=test_client"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		mockCode := &models.Code{Id: 1, Used: false}
		validationResult := &validators.ValidateTokenRequestResult{CodeEntity: mockCode}

		tokenValidator.On("ValidateTokenRequest", req.Context(), mock.AnythingOfType("*validators.ValidateTokenRequestInput")).
			Return(validationResult, nil)

		tokenIssuer.On("GenerateTokenResponseForAuthCode", req.Context(), mockCode).
			Return(nil, customerrors.NewErrorDetailWithHttpStatusCode("server_error", "Failed to generate token", http.StatusInternalServerError))

		httpHelper.On("InternalServerError",
			mock.Anything,
			mock.Anything,
			mock.MatchedBy(func(err *customerrors.ErrorDetail) bool {
				return err.GetCode() == "server_error" && err.GetDescription() == "Failed to generate token"
			})).
			Return().Once()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		tokenValidator.AssertExpectations(t)
		tokenIssuer.AssertExpectations(t)
	})

	t.Run("Authorization_code UpdateCode gives error", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		userSessionManager := mocks_users.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		tokenValidator := mocks_validators.NewTokenValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleTokenPost(httpHelper, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger)

		formData := "grant_type=authorization_code&code=test_code&redirect_uri=http://example.com&client_id=test_client"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		mockCode := &models.Code{Id: 1, Used: false}
		validationResult := &validators.ValidateTokenRequestResult{CodeEntity: mockCode}

		tokenValidator.On("ValidateTokenRequest", req.Context(), mock.AnythingOfType("*validators.ValidateTokenRequestInput")).
			Return(validationResult, nil)

		tokenIssuer.On("GenerateTokenResponseForAuthCode", req.Context(), mockCode).
			Return(&oauth.TokenResponse{}, nil)

		database.On("UpdateCode", (*sql.Tx)(nil), mock.AnythingOfType("*models.Code")).
			Return(customerrors.NewErrorDetailWithHttpStatusCode("server_error", "Failed to update code", http.StatusInternalServerError))

		httpHelper.On("InternalServerError",
			mock.Anything,
			mock.Anything,
			mock.MatchedBy(func(err error) bool {
				return strings.Contains(err.Error(), "Failed to update code")
			}),
		).Return().Once()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		tokenValidator.AssertExpectations(t)
		tokenIssuer.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Authorization_code successful flow", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		userSessionManager := mocks_users.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		tokenValidator := mocks_validators.NewTokenValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleTokenPost(httpHelper, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger)

		formData := "grant_type=authorization_code&code=test_code&redirect_uri=http://example.com&client_id=test_client"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		mockCode := &models.Code{Id: 1, Used: false}
		validationResult := &validators.ValidateTokenRequestResult{CodeEntity: mockCode}

		tokenValidator.On("ValidateTokenRequest", req.Context(), mock.AnythingOfType("*validators.ValidateTokenRequestInput")).
			Return(validationResult, nil)

		mockTokenResponse := &oauth.TokenResponse{
			AccessToken: "access_token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}
		tokenIssuer.On("GenerateTokenResponseForAuthCode", req.Context(), mockCode).
			Return(mockTokenResponse, nil)

		database.On("UpdateCode", (*sql.Tx)(nil), mock.AnythingOfType("*models.Code")).
			Return(nil)

		auditLogger.On("Log", "token_issued_authorization_code_response", mock.MatchedBy(func(details map[string]interface{}) bool {
			codeId, ok := details["codeId"].(int64)
			return ok && codeId == mockCode.Id
		})).Return()

		httpHelper.On("EncodeJson", rr, req, mockTokenResponse).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		tokenValidator.AssertExpectations(t)
		tokenIssuer.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)

		assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
		assert.Equal(t, "no-cache", rr.Header().Get("Pragma"))
	})

	t.Run("Client_credentials successful flow", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		userSessionManager := mocks_users.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		tokenValidator := mocks_validators.NewTokenValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleTokenPost(httpHelper, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger)

		formData := "grant_type=client_credentials&client_id=test_client&client_secret=test_secret&scope=test_scope"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		mockClient := &models.Client{Id: 1, ClientIdentifier: "test_client"}
		validationResult := &validators.ValidateTokenRequestResult{
			Client: mockClient,
			Scope:  "test_scope",
		}

		tokenValidator.On("ValidateTokenRequest", req.Context(), mock.AnythingOfType("*validators.ValidateTokenRequestInput")).
			Return(validationResult, nil)

		mockTokenResponse := &oauth.TokenResponse{
			AccessToken: "access_token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}
		tokenIssuer.On("GenerateTokenResponseForClientCred", req.Context(), mockClient, "test_scope").
			Return(mockTokenResponse, nil)

		auditLogger.On("Log", "token_issued_client_credentials_response", mock.MatchedBy(func(details map[string]interface{}) bool {
			clientId, ok := details["clientId"].(int64)
			return ok && clientId == mockClient.Id
		})).Return()

		httpHelper.On("EncodeJson", rr, req, mockTokenResponse).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		tokenValidator.AssertExpectations(t)
		tokenIssuer.AssertExpectations(t)
		auditLogger.AssertExpectations(t)

		assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
		assert.Equal(t, "no-cache", rr.Header().Get("Pragma"))
	})

	t.Run("Refresh_token and token is revoked", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		userSessionManager := mocks_users.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		tokenValidator := mocks_validators.NewTokenValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleTokenPost(httpHelper, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger)

		formData := "grant_type=refresh_token&refresh_token=test_refresh_token"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		mockRefreshToken := &models.RefreshToken{Id: 1, Revoked: true}
		validationResult := &validators.ValidateTokenRequestResult{RefreshToken: mockRefreshToken}

		tokenValidator.On("ValidateTokenRequest", req.Context(), mock.AnythingOfType("*validators.ValidateTokenRequestInput")).
			Return(validationResult, nil)

		httpHelper.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.(*customerrors.ErrorDetail).GetCode() == "invalid_grant" &&
				err.(*customerrors.ErrorDetail).GetDescription() == "This refresh token has been revoked."
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		tokenValidator.AssertExpectations(t)
	})

	t.Run("Refresh_token UpdateRefreshToken gives error", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		userSessionManager := mocks_users.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		tokenValidator := mocks_validators.NewTokenValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleTokenPost(httpHelper, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger)

		formData := "grant_type=refresh_token&refresh_token=test_refresh_token"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		mockRefreshToken := &models.RefreshToken{Id: 1, Revoked: false}
		validationResult := &validators.ValidateTokenRequestResult{
			RefreshToken: mockRefreshToken,
			CodeEntity:   &models.Code{},
		}

		tokenValidator.On("ValidateTokenRequest", req.Context(), mock.AnythingOfType("*validators.ValidateTokenRequestInput")).
			Return(validationResult, nil)

		database.On("UpdateRefreshToken", (*sql.Tx)(nil), mock.AnythingOfType("*models.RefreshToken")).
			Return(customerrors.NewErrorDetailWithHttpStatusCode("server_error", "Failed to update refresh token", http.StatusInternalServerError))

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "Failed to update refresh token")
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		tokenValidator.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Refresh_token GenerateTokenResponseForRefresh gives error", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		userSessionManager := mocks_users.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		tokenValidator := mocks_validators.NewTokenValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleTokenPost(httpHelper, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger)

		formData := "grant_type=refresh_token&refresh_token=test_refresh_token"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		mockRefreshToken := &models.RefreshToken{Id: 1, Revoked: false}
		mockCode := &models.Code{Id: 1}
		validationResult := &validators.ValidateTokenRequestResult{
			RefreshToken:     mockRefreshToken,
			CodeEntity:       mockCode,
			RefreshTokenInfo: &oauth.JwtToken{},
		}

		tokenValidator.On("ValidateTokenRequest", req.Context(), mock.AnythingOfType("*validators.ValidateTokenRequestInput")).
			Return(validationResult, nil)

		database.On("UpdateRefreshToken", (*sql.Tx)(nil), mock.AnythingOfType("*models.RefreshToken")).
			Return(nil)

		tokenIssuer.On("GenerateTokenResponseForRefresh", req.Context(), mock.AnythingOfType("*oauth.GenerateTokenForRefreshInput")).
			Return(nil, customerrors.NewErrorDetailWithHttpStatusCode("server_error", "Failed to generate token", http.StatusInternalServerError))

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "Failed to generate token")
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		tokenValidator.AssertExpectations(t)
		database.AssertExpectations(t)
		tokenIssuer.AssertExpectations(t)
	})

	t.Run("Refresh_token with SessionIdentifier bumps user session", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		userSessionManager := mocks_users.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		tokenValidator := mocks_validators.NewTokenValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleTokenPost(httpHelper, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger)

		formData := "grant_type=refresh_token&refresh_token=test_refresh_token"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		mockSessionIdentifier := "test_session_identifier"
		mockClientId := int64(123)
		mockUserId := int64(456)
		mockCodeId := int64(789)
		mockRefreshTokenJti := "test_jti"

		mockRefreshToken := &models.RefreshToken{
			Id:                1,
			Revoked:           false,
			SessionIdentifier: mockSessionIdentifier,
			RefreshTokenJti:   mockRefreshTokenJti,
			Code: models.Code{
				Id:       mockCodeId,
				ClientId: mockClientId,
			},
		}
		mockCode := &models.Code{Id: mockCodeId, ClientId: mockClientId}
		validationResult := &validators.ValidateTokenRequestResult{
			RefreshToken:     mockRefreshToken,
			CodeEntity:       mockCode,
			RefreshTokenInfo: &oauth.JwtToken{},
		}

		tokenValidator.On("ValidateTokenRequest", req.Context(), mock.AnythingOfType("*validators.ValidateTokenRequestInput")).
			Return(validationResult, nil)

		database.On("UpdateRefreshToken", (*sql.Tx)(nil), mock.AnythingOfType("*models.RefreshToken")).
			Return(nil)

		mockTokenResponse := &oauth.TokenResponse{
			AccessToken:  "new_access_token",
			RefreshToken: "new_refresh_token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		}
		tokenIssuer.On("GenerateTokenResponseForRefresh", req.Context(), mock.AnythingOfType("*oauth.GenerateTokenForRefreshInput")).
			Return(mockTokenResponse, nil)

		mockUserSession := &models.UserSession{
			Id:     1,
			UserId: mockUserId,
		}
		// For refresh token flow, empty strings are passed (no step-up authentication)
		userSessionManager.On("BumpUserSession", req, mockSessionIdentifier, mockClientId, "", "").
			Return(mockUserSession, nil)

		auditLogger.On("Log", constants.AuditBumpedUserSession, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userId"] == mockUserId && details["clientId"] == mockClientId
		})).Return()

		auditLogger.On("Log", constants.AuditTokenIssuedRefreshTokenResponse, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["codeId"] == mockCodeId && details["refreshTokenJti"] == mockRefreshTokenJti
		})).Return()

		httpHelper.On("EncodeJson", rr, req, mockTokenResponse).Return()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
		assert.Equal(t, "no-cache", rr.Header().Get("Pragma"))

		httpHelper.AssertExpectations(t)
		tokenValidator.AssertExpectations(t)
		database.AssertExpectations(t)
		tokenIssuer.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("Refresh_token success path without session", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		userSessionManager := mocks_users.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		tokenValidator := mocks_validators.NewTokenValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleTokenPost(httpHelper, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger)

		formData := "grant_type=refresh_token&refresh_token=test_refresh_token"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		mockClientId := int64(123)
		mockCodeId := int64(789)
		mockRefreshTokenJti := "test_jti"

		mockRefreshToken := &models.RefreshToken{
			Id:              1,
			Revoked:         false,
			RefreshTokenJti: mockRefreshTokenJti,
			Code: models.Code{
				Id:       mockCodeId,
				ClientId: mockClientId,
			},
		}
		mockCode := &models.Code{Id: mockCodeId, ClientId: mockClientId}
		validationResult := &validators.ValidateTokenRequestResult{
			RefreshToken:     mockRefreshToken,
			CodeEntity:       mockCode,
			RefreshTokenInfo: &oauth.JwtToken{},
		}

		tokenValidator.On("ValidateTokenRequest", req.Context(), mock.AnythingOfType("*validators.ValidateTokenRequestInput")).
			Return(validationResult, nil)

		database.On("UpdateRefreshToken", (*sql.Tx)(nil), mock.AnythingOfType("*models.RefreshToken")).
			Return(nil)

		mockTokenResponse := &oauth.TokenResponse{
			AccessToken:  "new_access_token",
			RefreshToken: "new_refresh_token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		}
		tokenIssuer.On("GenerateTokenResponseForRefresh", req.Context(), mock.AnythingOfType("*oauth.GenerateTokenForRefreshInput")).
			Return(mockTokenResponse, nil)

		auditLogger.On("Log", constants.AuditTokenIssuedRefreshTokenResponse, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["codeId"] == mockCodeId && details["refreshTokenJti"] == mockRefreshTokenJti
		})).Return()

		httpHelper.On("EncodeJson", rr, req, mockTokenResponse).Return()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
		assert.Equal(t, "no-cache", rr.Header().Get("Pragma"))

		httpHelper.AssertExpectations(t)
		tokenValidator.AssertExpectations(t)
		database.AssertExpectations(t)
		tokenIssuer.AssertExpectations(t)
		auditLogger.AssertExpectations(t)

		// Ensure that BumpUserSession was not called
		userSessionManager.AssertNotCalled(t, "BumpUserSession")
	})

	t.Run("Unsupported_grant_type", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		userSessionManager := mocks_users.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		tokenValidator := mocks_validators.NewTokenValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleTokenPost(httpHelper, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger)

		formData := "grant_type=unsupported_type&client_id=test_client&client_secret=test_secret"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		// Mock the ValidateTokenRequest to return a result (even though it's not used in this case)
		tokenValidator.On("ValidateTokenRequest", req.Context(), mock.AnythingOfType("*validators.ValidateTokenRequestInput")).
			Return(&validators.ValidateTokenRequestResult{}, nil)

		// Expect a JSON error response for unsupported grant type
		httpHelper.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
			if customErr, ok := err.(*customerrors.ErrorDetail); ok {
				return customErr.GetCode() == "unsupported_grant_type" &&
					customErr.GetDescription() == "Unsupported grant_type." &&
					customErr.GetHttpStatusCode() == http.StatusBadRequest
			}
			return false
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		tokenValidator.AssertExpectations(t)

		// Ensure that other methods were not called
		database.AssertNotCalled(t, "UpdateRefreshToken")
		tokenIssuer.AssertNotCalled(t, "GenerateTokenResponseForAuthCode")
		tokenIssuer.AssertNotCalled(t, "GenerateTokenResponseForClientCred")
		tokenIssuer.AssertNotCalled(t, "GenerateTokenResponseForRefresh")
		userSessionManager.AssertNotCalled(t, "BumpUserSession")
		auditLogger.AssertNotCalled(t, "Log")
	})
}

func TestParseBasicAuth(t *testing.T) {
	t.Run("Empty header returns false", func(t *testing.T) {
		clientId, clientSecret, ok := parseBasicAuth("")
		assert.False(t, ok)
		assert.Empty(t, clientId)
		assert.Empty(t, clientSecret)
	})

	t.Run("Non-Basic scheme returns false", func(t *testing.T) {
		clientId, clientSecret, ok := parseBasicAuth("Bearer some-token")
		assert.False(t, ok)
		assert.Empty(t, clientId)
		assert.Empty(t, clientSecret)
	})

	t.Run("Invalid base64 returns false", func(t *testing.T) {
		clientId, clientSecret, ok := parseBasicAuth("Basic not-valid-base64!")
		assert.False(t, ok)
		assert.Empty(t, clientId)
		assert.Empty(t, clientSecret)
	})

	t.Run("Missing colon separator returns false", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("nocolon"))
		clientId, clientSecret, ok := parseBasicAuth("Basic " + encoded)
		assert.False(t, ok)
		assert.Empty(t, clientId)
		assert.Empty(t, clientSecret)
	})

	t.Run("Valid credentials are parsed correctly", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("my-client-id:my-secret"))
		clientId, clientSecret, ok := parseBasicAuth("Basic " + encoded)
		assert.True(t, ok)
		assert.Equal(t, "my-client-id", clientId)
		assert.Equal(t, "my-secret", clientSecret)
	})

	t.Run("Password with colons is parsed correctly", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("client:pass:with:colons"))
		clientId, clientSecret, ok := parseBasicAuth("Basic " + encoded)
		assert.True(t, ok)
		assert.Equal(t, "client", clientId)
		assert.Equal(t, "pass:with:colons", clientSecret)
	})

	t.Run("Empty password is valid", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("client:"))
		clientId, clientSecret, ok := parseBasicAuth("Basic " + encoded)
		assert.True(t, ok)
		assert.Equal(t, "client", clientId)
		assert.Equal(t, "", clientSecret)
	})

	t.Run("Empty client_id with password is valid", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte(":secret"))
		clientId, clientSecret, ok := parseBasicAuth("Basic " + encoded)
		assert.True(t, ok)
		assert.Equal(t, "", clientId)
		assert.Equal(t, "secret", clientSecret)
	})

	t.Run("Special characters in credentials", func(t *testing.T) {
		// Test with special chars that might cause issues
		encoded := base64.StdEncoding.EncodeToString([]byte("client+id@example.com:p@ss=word&special!"))
		clientId, clientSecret, ok := parseBasicAuth("Basic " + encoded)
		assert.True(t, ok)
		assert.Equal(t, "client+id@example.com", clientId)
		assert.Equal(t, "p@ss=word&special!", clientSecret)
	})

	t.Run("Unicode characters in credentials", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("клиент:密码"))
		clientId, clientSecret, ok := parseBasicAuth("Basic " + encoded)
		assert.True(t, ok)
		assert.Equal(t, "клиент", clientId)
		assert.Equal(t, "密码", clientSecret)
	})

	t.Run("Lowercase basic prefix is rejected", func(t *testing.T) {
		// RFC 7617 says the scheme is case-insensitive, but we're strict here
		// This documents the current behavior
		encoded := base64.StdEncoding.EncodeToString([]byte("client:secret"))
		clientId, clientSecret, ok := parseBasicAuth("basic " + encoded)
		assert.False(t, ok)
		assert.Empty(t, clientId)
		assert.Empty(t, clientSecret)
	})

	t.Run("Extra whitespace after Basic is handled", func(t *testing.T) {
		// Extra space should cause base64 decode to fail or produce wrong result
		encoded := base64.StdEncoding.EncodeToString([]byte("client:secret"))
		clientId, clientSecret, ok := parseBasicAuth("Basic  " + encoded) // two spaces
		// The extra space becomes part of the base64 string, likely causing decode failure
		assert.False(t, ok)
		assert.Empty(t, clientId)
		assert.Empty(t, clientSecret)
	})

	t.Run("Missing space after Basic is rejected", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("client:secret"))
		clientId, clientSecret, ok := parseBasicAuth("Basic" + encoded) // no space
		assert.False(t, ok)
		assert.Empty(t, clientId)
		assert.Empty(t, clientSecret)
	})

	t.Run("Very long credentials", func(t *testing.T) {
		longClientId := strings.Repeat("a", 1000)
		longSecret := strings.Repeat("b", 1000)
		encoded := base64.StdEncoding.EncodeToString([]byte(longClientId + ":" + longSecret))
		clientId, clientSecret, ok := parseBasicAuth("Basic " + encoded)
		assert.True(t, ok)
		assert.Equal(t, longClientId, clientId)
		assert.Equal(t, longSecret, clientSecret)
	})
}

func TestExtractClientCredentials(t *testing.T) {
	t.Run("Basic auth only - credentials extracted from header", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("basic-client:basic-secret"))
		req, _ := http.NewRequest("POST", "/token", strings.NewReader("grant_type=client_credentials"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Basic "+encoded)
		_ = req.ParseForm()

		clientId, clientSecret, usedBasicAuth, err := extractClientCredentials(req)
		assert.NoError(t, err)
		assert.Equal(t, "basic-client", clientId)
		assert.Equal(t, "basic-secret", clientSecret)
		assert.True(t, usedBasicAuth)
	})

	t.Run("POST body only - credentials extracted from form", func(t *testing.T) {
		formData := "grant_type=client_credentials&client_id=post-client&client_secret=post-secret"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		_ = req.ParseForm()

		clientId, clientSecret, usedBasicAuth, err := extractClientCredentials(req)
		assert.NoError(t, err)
		assert.Equal(t, "post-client", clientId)
		assert.Equal(t, "post-secret", clientSecret)
		assert.False(t, usedBasicAuth)
	})

	t.Run("Both methods provided - returns error", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("basic-client:basic-secret"))
		formData := "grant_type=client_credentials&client_id=post-client&client_secret=post-secret"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Basic "+encoded)
		_ = req.ParseForm()

		clientId, clientSecret, usedBasicAuth, err := extractClientCredentials(req)
		assert.Error(t, err)
		assert.Empty(t, clientId)
		assert.Empty(t, clientSecret)
		assert.False(t, usedBasicAuth)

		errDetail, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_request", errDetail.GetCode())
		assert.Contains(t, errDetail.GetDescription(), "multiple authentication methods")
	})

	t.Run("No credentials provided - returns empty values", func(t *testing.T) {
		formData := "grant_type=authorization_code&code=test"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		_ = req.ParseForm()

		clientId, clientSecret, usedBasicAuth, err := extractClientCredentials(req)
		assert.NoError(t, err)
		assert.Empty(t, clientId)
		assert.Empty(t, clientSecret)
		assert.False(t, usedBasicAuth)
	})

	t.Run("Basic auth with client_id in POST but no client_secret - allowed", func(t *testing.T) {
		// This is allowed because only client_secret in POST triggers the conflict
		encoded := base64.StdEncoding.EncodeToString([]byte("basic-client:basic-secret"))
		formData := "grant_type=client_credentials&client_id=post-client"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Basic "+encoded)
		_ = req.ParseForm()

		clientId, clientSecret, usedBasicAuth, err := extractClientCredentials(req)
		assert.NoError(t, err)
		assert.Equal(t, "basic-client", clientId)
		assert.Equal(t, "basic-secret", clientSecret)
		assert.True(t, usedBasicAuth)
	})

	t.Run("Invalid Basic auth header falls back to POST body", func(t *testing.T) {
		// Malformed Basic auth should be ignored, not cause an error
		formData := "grant_type=client_credentials&client_id=post-client&client_secret=post-secret"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Basic invalid-base64!")
		_ = req.ParseForm()

		clientId, clientSecret, usedBasicAuth, err := extractClientCredentials(req)
		assert.NoError(t, err)
		assert.Equal(t, "post-client", clientId)
		assert.Equal(t, "post-secret", clientSecret)
		assert.False(t, usedBasicAuth)
	})

	t.Run("Bearer token header does not interfere with POST body", func(t *testing.T) {
		// A Bearer token should not be treated as Basic auth
		formData := "grant_type=client_credentials&client_id=post-client&client_secret=post-secret"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer some-access-token")
		_ = req.ParseForm()

		clientId, clientSecret, usedBasicAuth, err := extractClientCredentials(req)
		assert.NoError(t, err)
		assert.Equal(t, "post-client", clientId)
		assert.Equal(t, "post-secret", clientSecret)
		assert.False(t, usedBasicAuth)
	})

	t.Run("Empty client_secret in POST body is not considered authentication", func(t *testing.T) {
		// Empty string for client_secret should not trigger the "multiple methods" error
		encoded := base64.StdEncoding.EncodeToString([]byte("basic-client:basic-secret"))
		formData := "grant_type=client_credentials&client_id=post-client&client_secret="
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Basic "+encoded)
		_ = req.ParseForm()

		clientId, clientSecret, usedBasicAuth, err := extractClientCredentials(req)
		assert.NoError(t, err)
		assert.Equal(t, "basic-client", clientId)
		assert.Equal(t, "basic-secret", clientSecret)
		assert.True(t, usedBasicAuth)
	})

	t.Run("Public client - only client_id in POST, no secret", func(t *testing.T) {
		formData := "grant_type=authorization_code&client_id=public-client&code=auth-code"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		_ = req.ParseForm()

		clientId, clientSecret, usedBasicAuth, err := extractClientCredentials(req)
		assert.NoError(t, err)
		assert.Equal(t, "public-client", clientId)
		assert.Equal(t, "", clientSecret)
		assert.False(t, usedBasicAuth)
	})
}
