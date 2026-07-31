package handlers

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"net/url"
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

		// Code is claimed successfully, but token generation then fails.
		database.On("MarkCodeAsUsed", (*sql.Tx)(nil), mockCode.Id).Return(true, nil)

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

	t.Run("Authorization_code MarkCodeAsUsed gives error", func(t *testing.T) {
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

		// Claiming the code errors out. Tokens must NOT be generated.
		database.On("MarkCodeAsUsed", (*sql.Tx)(nil), mockCode.Id).
			Return(false, customerrors.NewErrorDetailWithHttpStatusCode("server_error", "Failed to mark code as used", http.StatusInternalServerError))

		httpHelper.On("InternalServerError",
			mock.Anything,
			mock.Anything,
			mock.MatchedBy(func(err error) bool {
				return strings.Contains(err.Error(), "Failed to mark code as used")
			}),
		).Return().Once()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		tokenValidator.AssertExpectations(t)
		database.AssertExpectations(t)
		// Token generation must not happen when the claim fails.
		tokenIssuer.AssertNotCalled(t, "GenerateTokenResponseForAuthCode", mock.Anything, mock.Anything)
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
		// Code is claimed atomically before minting; only the winner proceeds.
		database.On("MarkCodeAsUsed", (*sql.Tx)(nil), mockCode.Id).Return(true, nil)

		tokenIssuer.On("GenerateTokenResponseForAuthCode", req.Context(), mockCode).
			Return(mockTokenResponse, nil)

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

// TestHandleTokenPost_AuthCodeReuse_RevokeFailureReturns500 verifies the
// failure path of the RFC 6749 §4.1.2 revocation flow: when the validator
// signals auth-code reuse but the transactional revoke fails, the handler
// MUST return 500 (not invalid_grant) so the client never sees a response
// that looks like a clean denial while linked tokens may still be live.
// It must also skip the audit log, which fires only after a successful commit.
func TestHandleTokenPost_AuthCodeReuse_RevokeFailureReturns500(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	userSessionManager := mocks_users.NewUserSessionManager(t)
	database := mocks_data.NewDatabase(t)
	tokenIssuer := mocks_oauth.NewTokenIssuer(t)
	tokenValidator := mocks_validators.NewTokenValidator(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleTokenPost(httpHelper, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger)

	formData := "grant_type=authorization_code&code=replayed&redirect_uri=http://example.com&client_id=test_client"
	req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	reusedCode := &models.Code{
		Id:                42,
		ClientId:          7,
		UserId:            13,
		SessionIdentifier: "sid-reused",
	}
	reuseErr := &customerrors.AuthCodeReusedError{
		Detail: customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant", "Code is invalid.", http.StatusBadRequest),
		Code:   reusedCode,
	}

	tokenValidator.On("ValidateTokenRequest", req.Context(), mock.AnythingOfType("*validators.ValidateTokenRequestInput")).
		Return(nil, reuseErr)

	database.On("BeginTransaction").Return((*sql.Tx)(nil), nil).Once()

	dbErr := errors.New("connection refused")
	database.On("GetRefreshTokensBySessionIdentifier", (*sql.Tx)(nil), "sid-reused").
		Return(nil, dbErr).Once()

	database.On("RollbackTransaction", (*sql.Tx)(nil)).Return(nil).Once()

	httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
		return err != nil && strings.Contains(err.Error(), "connection refused")
	})).Return().Once()

	handler.ServeHTTP(rr, req)

	httpHelper.AssertExpectations(t)
	tokenValidator.AssertExpectations(t)
	database.AssertExpectations(t)

	// Audit log must NOT fire when revocation fails: it is reserved for the
	// post-commit success path where revokedJtis are real.
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything)
	// invalid_grant response must NOT be sent: the client gets 500 instead.
	httpHelper.AssertNotCalled(t, "JsonError", mock.Anything, mock.Anything, mock.Anything)
}

// TestHandleTokenPost_AuthCodeReuse_BeginTransactionFailureReturns500 covers
// the earliest failure point: BeginTransaction itself errors. The handler
// must still surface a 500 and skip both the audit log and the JsonError.
func TestHandleTokenPost_AuthCodeReuse_BeginTransactionFailureReturns500(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	userSessionManager := mocks_users.NewUserSessionManager(t)
	database := mocks_data.NewDatabase(t)
	tokenIssuer := mocks_oauth.NewTokenIssuer(t)
	tokenValidator := mocks_validators.NewTokenValidator(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleTokenPost(httpHelper, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger)

	formData := "grant_type=authorization_code&code=replayed&redirect_uri=http://example.com&client_id=test_client"
	req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	reuseErr := &customerrors.AuthCodeReusedError{
		Detail: customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant", "Code is invalid.", http.StatusBadRequest),
		Code: &models.Code{
			Id:                7,
			SessionIdentifier: "sid-reused",
		},
	}

	tokenValidator.On("ValidateTokenRequest", req.Context(), mock.AnythingOfType("*validators.ValidateTokenRequestInput")).
		Return(nil, reuseErr)

	beginErr := errors.New("tx begin failed")
	database.On("BeginTransaction").Return((*sql.Tx)(nil), beginErr).Once()

	httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
		return err != nil && strings.Contains(err.Error(), "tx begin failed")
	})).Return().Once()

	handler.ServeHTTP(rr, req)

	httpHelper.AssertExpectations(t)
	tokenValidator.AssertExpectations(t)
	database.AssertExpectations(t)

	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything)
	httpHelper.AssertNotCalled(t, "JsonError", mock.Anything, mock.Anything, mock.Anything)
}

// TestHandleTokenPost_AuthCode_ConcurrentDoubleSpendLoses verifies the #77 fix:
// when two requests race to redeem the same code, the loser (whose atomic claim
// via MarkCodeAsUsed returns false) is rejected with invalid_grant. Crucially it
// must NOT mint tokens and must NOT run the session-wide reuse cascade (no
// BeginTransaction, no session teardown, no reuse audit) — that cascade running
// concurrently with the winner's mint on the same session rows is what deadlocks
// the winner. A genuine *later* replay is still cascaded by the sequential-reuse
// path (covered by the integration CodeReuse_* tests).
func TestHandleTokenPost_AuthCode_ConcurrentDoubleSpendLoses(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	userSessionManager := mocks_users.NewUserSessionManager(t)
	database := mocks_data.NewDatabase(t)
	tokenIssuer := mocks_oauth.NewTokenIssuer(t)
	tokenValidator := mocks_validators.NewTokenValidator(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleTokenPost(httpHelper, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger)

	formData := "grant_type=authorization_code&code=raced&redirect_uri=http://example.com&client_id=test_client"
	req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	racedCode := &models.Code{
		Id:                42,
		ClientId:          7,
		UserId:            13,
		SessionIdentifier: "sid-raced",
	}
	validationResult := &validators.ValidateTokenRequestResult{CodeEntity: racedCode}

	tokenValidator.On("ValidateTokenRequest", req.Context(), mock.AnythingOfType("*validators.ValidateTokenRequestInput")).
		Return(validationResult, nil)

	// This request loses the race: the code was already claimed concurrently.
	database.On("MarkCodeAsUsed", (*sql.Tx)(nil), racedCode.Id).Return(false, nil)

	httpHelper.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
		detail, ok := err.(*customerrors.ErrorDetail)
		return ok && detail.GetCode() == "invalid_grant"
	})).Return().Once()

	handler.ServeHTTP(rr, req)

	httpHelper.AssertExpectations(t)
	tokenValidator.AssertExpectations(t)
	database.AssertExpectations(t)

	// The loser must not mint tokens, and must not run the reuse cascade: no
	// transaction, no session teardown, no reuse audit.
	tokenIssuer.AssertNotCalled(t, "GenerateTokenResponseForAuthCode", mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "BeginTransaction")
	database.AssertNotCalled(t, "DeleteUserSession", mock.Anything, mock.Anything)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything)
}

// TestNormalizeScope is the exhaustive table for the helper, which is a pure string function, so
// every other layer's scope tests can stay thin.
//
// The last three rows are what step 3's wiring tests build on: normalizeScope cannot distinguish a
// whitespace-only scope from an omitted one, and does not try to. Both yield "", and the CALLER
// separates them by also looking at the raw value.
func TestNormalizeScope(t *testing.T) {
	testCases := []struct {
		name  string
		input string
		want  string
	}{
		{"collapses a double space", "billing-api:read  billing-api:write", "billing-api:read billing-api:write"},
		{"collapses a tab", "billing-api:read\tbilling-api:write", "billing-api:read billing-api:write"},
		{"collapses a newline", "billing-api:read\nbilling-api:write", "billing-api:read billing-api:write"},
		{"trims leading", " billing-api:read", "billing-api:read"},
		{"trims trailing", "billing-api:read ", "billing-api:read"},
		{"trims both", "  billing-api:read  ", "billing-api:read"},
		{"trims and collapses mixed whitespace", " billing-api:read \t  billing-api:write\t", "billing-api:read billing-api:write"},
		{"drops an exact duplicate", "billing-api:read billing-api:read", "billing-api:read"},
		{"drops a later duplicate, preserving first-occurrence order", "billing-api:read billing-api:write billing-api:read", "billing-api:read billing-api:write"},
		{"spaces only becomes empty", "   ", ""},
		{"tab only becomes empty", "\t", ""},
		{"empty stays empty", "", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, normalizeScope(tc.input))
		})
	}
}

// TestGrantTypeConsumesScope pins which grant types the provided-but-empty rejection applies to.
// The authorization_code row is the one that matters: it never reads the scope parameter, so
// rejecting on it would break a valid token exchange.
func TestGrantTypeConsumesScope(t *testing.T) {
	testCases := []struct {
		grantType string
		want      bool
	}{
		{"client_credentials", true},
		{"refresh_token", true},
		{"password", true},
		{"authorization_code", false},
		{"", false},
		{"urn:ietf:params:oauth:grant-type:device_code", false},
	}

	for _, tc := range testCases {
		t.Run(tc.grantType, func(t *testing.T) {
			assert.Equal(t, tc.want, grantTypeConsumesScope(tc.grantType))
		})
	}
}

// TestHandleTokenPost_ScopeNormalizationWiring is step 3 of the normalization work: it proves the
// handler actually calls normalizeScope and passes its OUTPUT to the validator, which the pure
// unit table above cannot show.
//
// The validator is mocked with mock.MatchedBy so the scope it receives is captured rather than
// merely type-checked. Every accepting row returns a validation error afterwards, because what is
// under test is the input handed over, not what happens next.
func TestHandleTokenPost_ScopeNormalizationWiring(t *testing.T) {
	// omittedScope distinguishes "no scope parameter in the form" from "scope=<something>".
	const omittedScope = "\x00omitted\x00"

	testCases := []struct {
		name      string
		grantType string
		rawScope  string
		// wantScope is what the validator must receive. Only read when wantValidatorCalled.
		wantScope           string
		wantValidatorCalled bool
	}{
		{
			name:                "tab-separated scopes are collapsed",
			grantType:           "client_credentials",
			rawScope:            "billing-api:read\tbilling-api:write",
			wantScope:           "billing-api:read billing-api:write",
			wantValidatorCalled: true,
		},
		{
			name:                "surrounding whitespace is trimmed",
			grantType:           "client_credentials",
			rawScope:            "  billing-api:read  ",
			wantScope:           "billing-api:read",
			wantValidatorCalled: true,
		},
		{
			name:                "a duplicate scope is dropped",
			grantType:           "client_credentials",
			rawScope:            "billing-api:read billing-api:read",
			wantScope:           "billing-api:read",
			wantValidatorCalled: true,
		},
		{
			name:                "whitespace-only is rejected before the validator, client credentials",
			grantType:           "client_credentials",
			rawScope:            "   ",
			wantValidatorCalled: false,
		},
		{
			name:                "whitespace-only is rejected before the validator, refresh",
			grantType:           "refresh_token",
			rawScope:            "   ",
			wantValidatorCalled: false,
		},
		{
			// Accept-to-reject change. ROPC currently treats a whitespace-only scope as absent and
			// issues an "openid" token, so this row is the one behaviour regression the
			// normalization work introduces, on a deprecated grant receiving malformed input.
			name:                "whitespace-only is rejected before the validator, ROPC",
			grantType:           "password",
			rawScope:            "   ",
			wantValidatorCalled: false,
		},
		{
			// LOAD-BEARING: fails if someone applies the rejection to every grant type. The
			// authorization code grant never reads the scope parameter, so a malformed one must be
			// ignored rather than break an otherwise valid exchange.
			name:                "whitespace-only is ignored for the authorization code grant",
			grantType:           "authorization_code",
			rawScope:            "   ",
			wantScope:           "",
			wantValidatorCalled: true,
		},
		{
			// LOAD-BEARING: fails if someone implements the rejection as "empty scope is invalid"
			// rather than "provided-but-empty is invalid". An omitted scope must still reach the
			// validator as "", which is what selects the client credentials all-permissions branch.
			name:                "an omitted scope still reaches the validator as empty",
			grantType:           "client_credentials",
			rawScope:            omittedScope,
			wantScope:           "",
			wantValidatorCalled: true,
		},
		{
			// LOAD-BEARING, and distinct from the row above: this one encodes an explicitly empty
			// `scope=` in the form body, which is a DIFFERENT wire format from omitting the
			// parameter even though PostForm.Get returns "" for both. Verified: Set("scope", "")
			// encodes as `scope=`, where Has("scope") is true and Get("scope") is "".
			//
			// Decision 15 and the release note both promise `scope=` keeps working, because plenty
			// of HTTP clients serialize empty values and rejecting them would break integrations
			// for no security gain. Switching the rejection's presence test to PostForm.Has would
			// honour omission while newly rejecting this, and the row above would not notice. Do
			// not merge these two rows.
			name:                "an explicitly empty scope= is treated as omitted",
			grantType:           "client_credentials",
			rawScope:            "",
			wantScope:           "",
			wantValidatorCalled: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
			userSessionManager := mocks_users.NewUserSessionManager(t)
			database := mocks_data.NewDatabase(t)
			tokenIssuer := mocks_oauth.NewTokenIssuer(t)
			tokenValidator := mocks_validators.NewTokenValidator(t)
			auditLogger := mocks_audit.NewAuditLogger(t)

			handler := HandleTokenPost(httpHelper, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger)

			form := url.Values{"grant_type": {tc.grantType}, "client_id": {"test_client"}}
			if tc.rawScope != omittedScope {
				form.Set("scope", tc.rawScope)
			}

			req, _ := http.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()

			if tc.wantValidatorCalled {
				// Capture what the handler passed. Returning an error keeps the test focused on
				// the input rather than on downstream token issuance.
				validationError := customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
					"stop here", http.StatusBadRequest)
				tokenValidator.On("ValidateTokenRequest", req.Context(), mock.MatchedBy(
					func(input *validators.ValidateTokenRequestInput) bool {
						return input.Scope == tc.wantScope
					})).Return(nil, validationError).Once()
				httpHelper.On("JsonError", rr, req, validationError).Return()

				handler.ServeHTTP(rr, req)

				// AssertExpectations is what proves the scope matched: an input whose Scope differed
				// would not satisfy MatchedBy, so the expectation would go unmet.
				tokenValidator.AssertExpectations(t)
				httpHelper.AssertExpectations(t)
				return
			}

			// Rejected before the validator runs. mocks_validators.NewTokenValidator(t) fails the
			// test if ValidateTokenRequest is called with no expectation registered, so registering
			// none is the assertion that it was not reached.
			var rejection *customerrors.ErrorDetail
			httpHelper.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
				detail, ok := err.(*customerrors.ErrorDetail)
				if !ok {
					return false
				}
				rejection = detail
				return true
			})).Return()

			handler.ServeHTTP(rr, req)

			httpHelper.AssertExpectations(t)
			if assert.NotNil(t, rejection, "the handler should have rejected the request") {
				assert.Equal(t, "invalid_scope", rejection.GetCode())
				assert.Equal(t, http.StatusBadRequest, rejection.GetHttpStatusCode())
				assert.Contains(t, rejection.GetDescription(), "provided but contains no scopes")
			}
		})
	}
}

// TestHandleTokenPost_ScopeDenialAudit covers the audit half of the #104 work.
//
// Before this, a successful client credentials issuance logged only clientId, so there was no
// record of which scopes were granted to whom, and a denial logged nothing at all. Exploitation of
// the cross-resource escalation therefore cannot be reconstructed for any period before the fix.
//
// Deliberately thin on WHICH requests are denied, since stage 1's validator table owns that. What
// these four cases pin is that a denial reaches the audit logger, that the predicate is not gated on
// grant type, and that there is exactly one call site.
func TestHandleTokenPost_ScopeDenialAudit(t *testing.T) {
	newHandler := func(t *testing.T) (*mocks_handlerhelpers.HttpHelper, *mocks_validators.TokenValidator,
		*mocks_oauth.TokenIssuer, *mocks_audit.AuditLogger, http.HandlerFunc) {
		t.Helper()
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		userSessionManager := mocks_users.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		tokenValidator := mocks_validators.NewTokenValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		return httpHelper, tokenValidator, tokenIssuer, auditLogger,
			HandleTokenPost(httpHelper, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger)
	}

	// Rows 1 and 2 differ ONLY in grant type. Row 2 fails if a GrantType check is ever added to the
	// predicate, which would leave ROPC scope probing unlogged despite being the identical signal.
	for _, tc := range []struct {
		name      string
		grantType string
		form      string
		wantScope string
	}{
		{
			name:      "client credentials scope denial is audited",
			grantType: "client_credentials",
			form:      "grant_type=client_credentials&client_id=test_client&client_secret=s&scope=reports-api:read",
			wantScope: "reports-api:read",
		},
		{
			name:      "ROPC scope denial is audited too",
			grantType: "password",
			form:      "grant_type=password&client_id=test_client&username=u&password=p&scope=reports-api:read",
			wantScope: "reports-api:read",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper, tokenValidator, _, auditLogger, handler := newHandler(t)

			req, _ := http.NewRequest("POST", "/token", strings.NewReader(tc.form))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()

			denial := customerrors.NewErrorDetailWithHttpStatusCode("invalid_scope",
				"Permission to access scope 'reports-api:read' is not granted to the client.",
				http.StatusBadRequest)
			tokenValidator.On("ValidateTokenRequest", req.Context(),
				mock.AnythingOfType("*validators.ValidateTokenRequestInput")).Return(nil, denial)

			auditLogger.On("Log", constants.AuditTokenScopeDenied, mock.MatchedBy(
				func(details map[string]interface{}) bool {
					return details["clientIdentifier"] == "test_client" &&
						details["grantType"] == tc.grantType &&
						details["scope"] == tc.wantScope
				})).Return()

			httpHelper.On("JsonError", rr, req, denial).Return()

			handler.ServeHTTP(rr, req)

			auditLogger.AssertExpectations(t)
			httpHelper.AssertExpectations(t)
		})
	}

	// Row 3 asserts the ABSENCE of an event, which looks like an oversight and is not: it is the
	// guard against reintroducing an unauthenticated audit row. The provided-but-empty rejection
	// fires before the client is authenticated, so auditing it would let anyone forge rows against a
	// legitimate client. A second call site there passes every other row and fails only this one.
	t.Run("the provided-but-empty rejection emits no audit event", func(t *testing.T) {
		httpHelper, tokenValidator, _, auditLogger, handler := newHandler(t)

		form := url.Values{
			"grant_type": {"client_credentials"},
			"client_id":  {"test_client"},
			"scope":      {"   "},
		}
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		var rejection *customerrors.ErrorDetail
		httpHelper.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
			detail, ok := err.(*customerrors.ErrorDetail)
			if !ok {
				return false
			}
			rejection = detail
			return true
		})).Return()

		// No auditLogger expectation is registered, and none is registered on the validator either.
		// mocks_audit.NewAuditLogger(t) fails the test if Log is called without a matching
		// expectation, so registering nothing IS the assertion.
		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything)
		tokenValidator.AssertNotCalled(t, "ValidateTokenRequest", mock.Anything, mock.Anything)
		if assert.NotNil(t, rejection) {
			assert.Equal(t, "invalid_scope", rejection.GetCode())
		}
	})

	// Row 4: the forensic field on the success path. Nothing asserted this payload's shape before.
	t.Run("successful issuance records the scope", func(t *testing.T) {
		httpHelper, tokenValidator, tokenIssuer, auditLogger, handler := newHandler(t)

		form := "grant_type=client_credentials&client_id=test_client&client_secret=s&scope=billing-api:read"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		mockClient := &models.Client{Id: 42, ClientIdentifier: "test_client"}
		tokenValidator.On("ValidateTokenRequest", req.Context(),
			mock.AnythingOfType("*validators.ValidateTokenRequestInput")).
			Return(&validators.ValidateTokenRequestResult{Client: mockClient, Scope: "billing-api:read"}, nil)

		tokenResponse := &oauth.TokenResponse{AccessToken: "at", TokenType: "Bearer", ExpiresIn: 3600}
		tokenIssuer.On("GenerateTokenResponseForClientCred", req.Context(), mockClient, "billing-api:read").
			Return(tokenResponse, nil)

		auditLogger.On("Log", constants.AuditTokenIssuedClientCredentialsResponse, mock.MatchedBy(
			func(details map[string]interface{}) bool {
				clientId, ok := details["clientId"].(int64)
				return ok && clientId == mockClient.Id && details["scope"] == "billing-api:read"
			})).Return()

		httpHelper.On("EncodeJson", rr, req, tokenResponse).Return()

		handler.ServeHTTP(rr, req)

		auditLogger.AssertExpectations(t)
		tokenIssuer.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
	})
}

// TestHandleTokenPost_ROPC_IgnoresBrowserSession pins that the HANDLER never forwards a
// session identifier from the request into a password grant.
//
// Scope note: the token issuer is mocked here, so this proves the handoff and nothing about
// the tokens themselves. That neither generated token carries a sid is proven separately, in
// core/oauth's TestGenerateTokenResponseForROPC and TestGenerateTokenResponseForRefreshROPC.
// Neither half substitutes for the other.
//
// This closes a real leak rather than guarding a hypothetical. MiddlewareSessionIdentifier
// is mounted globally with router.Use, so a browser cookie's session lands in the request
// context even on /auth/token. The handler used to copy that into ROPCGrantInput, and the
// shared ROPC input builder forwarded it into ID-token generation. A password grant for
// user B, made while the browser happened to be logged in as user A, therefore received an
// ID token carrying A's session identifier.
//
// The fix was structural: ROPCGrantInput no longer has the field, so this test asserts the
// handler builds an input the type cannot even express a session on, with a session
// identifier deliberately present in the context to prove it is ignored rather than merely
// absent (#106).
func TestHandleTokenPost_ROPC_IgnoresBrowserSession(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	userSessionManager := mocks_users.NewUserSessionManager(t)
	database := mocks_data.NewDatabase(t)
	tokenIssuer := mocks_oauth.NewTokenIssuer(t)
	tokenValidator := mocks_validators.NewTokenValidator(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	handler := HandleTokenPost(httpHelper, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger)

	form := "grant_type=password&client_id=test_client&username=u&password=p&scope=openid"
	req, _ := http.NewRequest("POST", "/token", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// A DIFFERENT user's browser session, present exactly as the global middleware would
	// leave it. Nothing in a password grant may consume this.
	req = req.WithContext(context.WithValue(req.Context(),
		constants.ContextKeySessionIdentifier, "some-other-users-browser-session"))
	rr := httptest.NewRecorder()

	client := &models.Client{Id: 1, ClientIdentifier: "test_client"}
	user := &models.User{Id: 42, Subject: uuid.New(), AuthStateGeneration: 7}

	tokenValidator.On("ValidateTokenRequest", mock.Anything,
		mock.AnythingOfType("*validators.ValidateTokenRequestInput")).
		Return(&validators.ValidateTokenRequestResult{Client: client, User: user, Scope: "openid"}, nil)

	var captured *oauth.ROPCGrantInput
	tokenIssuer.On("GenerateTokenResponseForROPC", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*oauth.ROPCGrantInput) }).
		Return(&oauth.ROPCGrantResponse{AccessToken: "at", TokenType: "Bearer"}, nil)

	auditLogger.On("Log", constants.AuditTokenIssuedROPCResponse, mock.Anything).Return()
	httpHelper.On("EncodeJson", rr, mock.Anything, mock.Anything).Return()

	handler.ServeHTTP(rr, req)

	require.NotNil(t, captured, "GenerateTokenResponseForROPC was never called")
	assert.Equal(t, client, captured.Client)
	assert.Equal(t, user, captured.User)
	// The generation travels on the validated User snapshot, which is what the issuer stamps
	// initial ROPC tokens from (#106 decision 13).
	assert.EqualValues(t, 7, captured.User.AuthStateGeneration)
}

// TestHandleTokenPost_SupersededRefreshTokenIsSurfaced is the handler-layer smoke case for
// the generation boundary (#106 stage 3). Deliberately thin: the comparison logic is owned
// exhaustively by TestValidateTokenRequest_AuthStateGeneration in the validator package, and
// the validator is a mock here, so this can only show that the handler passes the rejection
// through to the client rather than swallowing it or turning it into a 500.
//
// It also pins that neither audit branch fires. The generation rejection is invalid_grant,
// which is not ErrUserDisabled and not invalid_scope, so a superseded refresh token must not
// be recorded as either. Stage 5 adds the event that does cover this.
func TestHandleTokenPost_SupersededRefreshTokenIsSurfaced(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	userSessionManager := mocks_users.NewUserSessionManager(t)
	database := mocks_data.NewDatabase(t)
	tokenIssuer := mocks_oauth.NewTokenIssuer(t)
	tokenValidator := mocks_validators.NewTokenValidator(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleTokenPost(httpHelper, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger)

	formData := "grant_type=refresh_token&refresh_token=superseded&client_id=test_client"
	req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	// The exact error the validator's two refresh branches return on a generation mismatch.
	supersededErr := customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
		"The refresh token is invalid because it was superseded.", http.StatusBadRequest)

	tokenValidator.On("ValidateTokenRequest", req.Context(), mock.AnythingOfType("*validators.ValidateTokenRequestInput")).
		Return(nil, supersededErr)

	httpHelper.On("JsonError", rr, req, supersededErr).Return().Once()

	handler.ServeHTTP(rr, req)

	httpHelper.AssertExpectations(t)
	tokenValidator.AssertExpectations(t)
	httpHelper.AssertNotCalled(t, "InternalServerError", mock.Anything, mock.Anything, mock.Anything)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything)
}
