package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_test "github.com/leodip/goiabada/core/mocks"
	mocks_oauth "github.com/leodip/goiabada/core/oauth/mocks"
)

func TestHandleIssueGet(t *testing.T) {
	t.Run("Error when getting GetAuthContext", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		req, err := http.NewRequest("GET", "/auth/issue", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		expectedError := &customerrors.ErrorDetail{} // Create an appropriate error
		authHelper.On("GetAuthContext", mock.Anything).Return(nil, expectedError)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err == expectedError
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("Unexpected AuthState", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		req, err := http.NewRequest("GET", "/auth/issue", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateInitial, // Unexpected state
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "authContext.AuthState is not ready_to_issue_code"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("Successfully issues a code", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		req, err := http.NewRequest("GET", "/auth/issue", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		// Mock auth context - note: ResponseType "code" means authorization code flow, not implicit
		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateReadyToIssueCode,
			ClientId:     "test-client",
			UserId:       123,
			ResponseMode: "query",
			ResponseType: "code",
			RedirectURI:  "https://example.com/callback",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		// Mock code creation
		mockCode := &models.Code{
			Id:          1,
			Code:        "test-code",
			ClientId:    1,
			RedirectURI: "https://example.com/callback",
			State:       "test-state",
		}
		codeIssuer.On("CreateAuthCode", mock.MatchedBy(func(input *oauth.CreateCodeInput) bool {
			return input.AuthContext == *authContext
		})).Return(mockCode, nil)

		// Mock audit logging
		auditLogger.On("Log", constants.AuditCreatedAuthCode, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userId"] == int64(123) && details["clientId"] == int64(1) && details["codeId"] == int64(1)
		})).Return()

		// Mock clearing auth context
		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		// Execute the handler
		handler.ServeHTTP(rr, req)

		// Assertions
		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, "https://example.com/callback?code=test-code&state=test-state", rr.Header().Get("Location"))

		// Verify that all expected actions were performed
		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		codeIssuer.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})
}

func TestIsImplicitFlow(t *testing.T) {
	tests := []struct {
		name         string
		responseType string
		expected     bool
	}{
		// Implicit flow response types (should return true)
		{
			name:         "token only",
			responseType: "token",
			expected:     true,
		},
		{
			name:         "id_token only",
			responseType: "id_token",
			expected:     true,
		},
		{
			name:         "id_token token",
			responseType: "id_token token",
			expected:     true,
		},
		{
			name:         "token id_token (reversed order)",
			responseType: "token id_token",
			expected:     true,
		},
		// Authorization code flow (should return false)
		{
			name:         "code only",
			responseType: "code",
			expected:     false,
		},
		{
			name:         "empty response type",
			responseType: "",
			expected:     false,
		},
		// Hybrid flows (contain code, should return false)
		{
			name:         "code token (hybrid)",
			responseType: "code token",
			expected:     false,
		},
		{
			name:         "code id_token (hybrid)",
			responseType: "code id_token",
			expected:     false,
		},
		{
			name:         "code id_token token (hybrid)",
			responseType: "code id_token token",
			expected:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := oauth.ParseResponseType(tt.responseType).IsImplicitFlow()
			assert.Equal(t, tt.expected, result, "IsImplicitFlow(%q) = %v, want %v", tt.responseType, result, tt.expected)
		})
	}
}

func TestHandleIssueGet_ImplicitFlow(t *testing.T) {
	t.Run("Implicit flow with token response type", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		req, err := http.NewRequest("GET", "/auth/issue", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:      oauth.AuthStateReadyToIssueCode,
			ClientId:       "test-client",
			UserId:         123,
			ResponseMode:   "fragment",
			ResponseType:   "token",
			RedirectURI:    "https://example.com/callback",
			Scope:          "openid",
			State:          "test-state",
			Nonce:          "test-nonce",
			AcrLevel:       "urn:goiabada:pwd",
			AuthMethods:    "pwd",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		// Mock client lookup
		mockClient := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			Enabled:          true,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(mockClient, nil)

		// Mock user lookup
		mockUser := &models.User{
			Id:      123,
			Subject: uuid.MustParse("11111111-1111-1111-1111-111111111111"),
			Email:   "test@example.com",
			Enabled: true,
		}
		database.On("GetUserById", mock.Anything, int64(123)).Return(mockUser, nil)

		// Mock token generation
		tokenResponse := &oauth.ImplicitGrantResponse{
			AccessToken: "access-token-123",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
			Scope:       "openid",
		}
		tokenIssuer.On("GenerateTokenResponseForImplicit", mock.Anything, mock.MatchedBy(func(input *oauth.ImplicitGrantInput) bool {
			return input.Client.Id == int64(1) && input.User.Id == int64(123) && input.Scope == "openid"
		}), true, false).Return(tokenResponse, nil)

		// Mock audit logging
		auditLogger.On("Log", constants.AuditTokenIssuedImplicitResponse, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userId"] == int64(123) && details["clientId"] == int64(1) && details["issueAccessToken"] == true && details["issueIdToken"] == false
		})).Return()

		// Mock clearing auth context
		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		location := rr.Header().Get("Location")
		assert.Contains(t, location, "https://example.com/callback#")
		assert.Contains(t, location, "access_token=access-token-123")
		assert.Contains(t, location, "token_type=Bearer")
		assert.Contains(t, location, "expires_in=3600")
		assert.Contains(t, location, "state=test-state")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		tokenIssuer.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("Implicit flow with id_token response type", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		req, err := http.NewRequest("GET", "/auth/issue", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:      oauth.AuthStateReadyToIssueCode,
			ClientId:       "test-client",
			UserId:         123,
			ResponseMode:   "fragment",
			ResponseType:   "id_token",
			RedirectURI:    "https://example.com/callback",
			Scope:          "openid",
			State:          "test-state",
			Nonce:          "test-nonce",
			AcrLevel:       "urn:goiabada:pwd",
			AuthMethods:    "pwd",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		mockClient := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			Enabled:          true,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(mockClient, nil)

		mockUser := &models.User{
			Id:      123,
			Subject: uuid.MustParse("11111111-1111-1111-1111-111111111111"),
			Email:   "test@example.com",
			Enabled: true,
		}
		database.On("GetUserById", mock.Anything, int64(123)).Return(mockUser, nil)

		tokenResponse := &oauth.ImplicitGrantResponse{
			IdToken: "id-token-123",
			Scope:   "openid",
		}
		tokenIssuer.On("GenerateTokenResponseForImplicit", mock.Anything, mock.MatchedBy(func(input *oauth.ImplicitGrantInput) bool {
			return input.Client.Id == int64(1) && input.User.Id == int64(123) && input.Nonce == "test-nonce"
		}), false, true).Return(tokenResponse, nil)

		auditLogger.On("Log", constants.AuditTokenIssuedImplicitResponse, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["issueAccessToken"] == false && details["issueIdToken"] == true
		})).Return()

		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		location := rr.Header().Get("Location")
		assert.Contains(t, location, "https://example.com/callback#")
		assert.Contains(t, location, "id_token=id-token-123")
		assert.Contains(t, location, "state=test-state")
		assert.NotContains(t, location, "access_token=")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		tokenIssuer.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("Implicit flow with id_token token response type", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		req, err := http.NewRequest("GET", "/auth/issue", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:      oauth.AuthStateReadyToIssueCode,
			ClientId:       "test-client",
			UserId:         123,
			ResponseMode:   "fragment",
			ResponseType:   "id_token token",
			RedirectURI:    "https://example.com/callback",
			Scope:          "openid",
			State:          "test-state",
			Nonce:          "test-nonce",
			AcrLevel:       "urn:goiabada:pwd",
			AuthMethods:    "pwd",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		mockClient := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			Enabled:          true,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(mockClient, nil)

		mockUser := &models.User{
			Id:      123,
			Subject: uuid.MustParse("11111111-1111-1111-1111-111111111111"),
			Email:   "test@example.com",
			Enabled: true,
		}
		database.On("GetUserById", mock.Anything, int64(123)).Return(mockUser, nil)

		tokenResponse := &oauth.ImplicitGrantResponse{
			AccessToken: "access-token-123",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
			IdToken:     "id-token-123",
			Scope:       "openid",
		}
		tokenIssuer.On("GenerateTokenResponseForImplicit", mock.Anything, mock.MatchedBy(func(input *oauth.ImplicitGrantInput) bool {
			return input.Client.Id == int64(1) && input.User.Id == int64(123)
		}), true, true).Return(tokenResponse, nil)

		auditLogger.On("Log", constants.AuditTokenIssuedImplicitResponse, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["issueAccessToken"] == true && details["issueIdToken"] == true
		})).Return()

		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		location := rr.Header().Get("Location")
		assert.Contains(t, location, "https://example.com/callback#")
		assert.Contains(t, location, "access_token=access-token-123")
		assert.Contains(t, location, "id_token=id-token-123")
		assert.Contains(t, location, "token_type=Bearer")
		assert.Contains(t, location, "expires_in=3600")
		assert.Contains(t, location, "state=test-state")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		tokenIssuer.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("Implicit flow uses consented scope when available", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		req, err := http.NewRequest("GET", "/auth/issue", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:      oauth.AuthStateReadyToIssueCode,
			ClientId:       "test-client",
			UserId:         123,
			ResponseType:   "token",
			RedirectURI:    "https://example.com/callback",
			Scope:          "openid profile email",
			ConsentedScope: "openid profile", // User consented to less
			State:          "test-state",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		mockClient := &models.Client{Id: 1, ClientIdentifier: "test-client", Enabled: true}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(mockClient, nil)

		mockUser := &models.User{Id: 123, Subject: uuid.MustParse("11111111-1111-1111-1111-111111111111")}
		database.On("GetUserById", mock.Anything, int64(123)).Return(mockUser, nil)

		tokenResponse := &oauth.ImplicitGrantResponse{
			AccessToken: "access-token-123",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
			Scope:       "openid profile",
		}
		tokenIssuer.On("GenerateTokenResponseForImplicit", mock.Anything, mock.MatchedBy(func(input *oauth.ImplicitGrantInput) bool {
			return input.Scope == "openid profile" // Should use consented scope
		}), true, false).Return(tokenResponse, nil)

		auditLogger.On("Log", constants.AuditTokenIssuedImplicitResponse, mock.Anything).Return()
		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		location := rr.Header().Get("Location")
		assert.Contains(t, location, "scope=openid+profile")

		tokenIssuer.AssertExpectations(t)
	})

	t.Run("Implicit flow error - client not found", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		req, err := http.NewRequest("GET", "/auth/issue", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateReadyToIssueCode,
			ClientId:     "unknown-client",
			UserId:       123,
			ResponseType: "token",
			RedirectURI:  "https://example.com/callback",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		database.On("GetClientByClientIdentifier", mock.Anything, "unknown-client").Return(nil, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err != nil && strings.Contains(err.Error(), "client unknown-client not found")
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Implicit flow error - user not found", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		req, err := http.NewRequest("GET", "/auth/issue", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateReadyToIssueCode,
			ClientId:     "test-client",
			UserId:       999,
			ResponseType: "token",
			RedirectURI:  "https://example.com/callback",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		mockClient := &models.Client{Id: 1, ClientIdentifier: "test-client", Enabled: true}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(mockClient, nil)

		database.On("GetUserById", mock.Anything, int64(999)).Return(nil, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err != nil && strings.Contains(err.Error(), "user 999 not found")
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Implicit flow error - token generation fails", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		req, err := http.NewRequest("GET", "/auth/issue", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateReadyToIssueCode,
			ClientId:     "test-client",
			UserId:       123,
			ResponseType: "token",
			RedirectURI:  "https://example.com/callback",
			Scope:        "openid",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		mockClient := &models.Client{Id: 1, ClientIdentifier: "test-client", Enabled: true}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(mockClient, nil)

		mockUser := &models.User{Id: 123, Subject: uuid.MustParse("11111111-1111-1111-1111-111111111111")}
		database.On("GetUserById", mock.Anything, int64(123)).Return(mockUser, nil)

		tokenError := errors.New("token generation failed")
		tokenIssuer.On("GenerateTokenResponseForImplicit", mock.Anything, mock.Anything, true, false).Return(nil, tokenError)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err == tokenError
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		tokenIssuer.AssertExpectations(t)
	})
}

func TestIssueImplicitTokens(t *testing.T) {
	t.Run("Access token only", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/auth/issue", nil)

		tokenResponse := &oauth.ImplicitGrantResponse{
			AccessToken: "access-token-123",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
			Scope:       "openid",
		}

		err := issueImplicitTokens(w, r, "https://example.com/callback", "test-state", tokenResponse)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, w.Code)
		location := w.Header().Get("Location")
		assert.Contains(t, location, "https://example.com/callback#")
		assert.Contains(t, location, "access_token=access-token-123")
		assert.Contains(t, location, "token_type=Bearer")
		assert.Contains(t, location, "expires_in=3600")
		assert.Contains(t, location, "scope=openid")
		assert.Contains(t, location, "state=test-state")
		assert.NotContains(t, location, "id_token=")
	})

	t.Run("ID token only", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/auth/issue", nil)

		tokenResponse := &oauth.ImplicitGrantResponse{
			IdToken: "id-token-123",
			Scope:   "openid",
		}

		err := issueImplicitTokens(w, r, "https://example.com/callback", "test-state", tokenResponse)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, w.Code)
		location := w.Header().Get("Location")
		assert.Contains(t, location, "https://example.com/callback#")
		assert.Contains(t, location, "id_token=id-token-123")
		assert.Contains(t, location, "scope=openid")
		assert.Contains(t, location, "state=test-state")
		assert.NotContains(t, location, "access_token=")
		assert.NotContains(t, location, "token_type=")
		assert.NotContains(t, location, "expires_in=")
	})

	t.Run("Both access token and ID token", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/auth/issue", nil)

		tokenResponse := &oauth.ImplicitGrantResponse{
			AccessToken: "access-token-123",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
			IdToken:     "id-token-123",
			Scope:       "openid profile",
		}

		err := issueImplicitTokens(w, r, "https://example.com/callback", "test-state", tokenResponse)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, w.Code)
		location := w.Header().Get("Location")
		assert.Contains(t, location, "https://example.com/callback#")
		assert.Contains(t, location, "access_token=access-token-123")
		assert.Contains(t, location, "token_type=Bearer")
		assert.Contains(t, location, "expires_in=3600")
		assert.Contains(t, location, "id_token=id-token-123")
		assert.Contains(t, location, "state=test-state")
	})

	t.Run("No state parameter", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/auth/issue", nil)

		tokenResponse := &oauth.ImplicitGrantResponse{
			AccessToken: "access-token-123",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}

		err := issueImplicitTokens(w, r, "https://example.com/callback", "", tokenResponse)

		assert.NoError(t, err)
		location := w.Header().Get("Location")
		assert.Contains(t, location, "https://example.com/callback#")
		assert.Contains(t, location, "access_token=access-token-123")
		assert.NotContains(t, location, "state=")
	})

	t.Run("State with whitespace only", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/auth/issue", nil)

		tokenResponse := &oauth.ImplicitGrantResponse{
			AccessToken: "access-token-123",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}

		err := issueImplicitTokens(w, r, "https://example.com/callback", "   ", tokenResponse)

		assert.NoError(t, err)
		location := w.Header().Get("Location")
		assert.NotContains(t, location, "state=")
	})

	t.Run("No scope in response", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/auth/issue", nil)

		tokenResponse := &oauth.ImplicitGrantResponse{
			AccessToken: "access-token-123",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}

		err := issueImplicitTokens(w, r, "https://example.com/callback", "test-state", tokenResponse)

		assert.NoError(t, err)
		location := w.Header().Get("Location")
		assert.NotContains(t, location, "scope=")
	})
}

func TestHandleIssueGet_ImplicitFlow_DatabaseErrors(t *testing.T) {
	t.Run("Implicit flow error - database error on client lookup", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		req, err := http.NewRequest("GET", "/auth/issue", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateReadyToIssueCode,
			ClientId:     "test-client",
			UserId:       123,
			ResponseType: "token",
			RedirectURI:  "https://example.com/callback",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		dbError := errors.New("database connection failed")
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(nil, dbError)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err == dbError
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Implicit flow error - database error on user lookup", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		req, err := http.NewRequest("GET", "/auth/issue", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateReadyToIssueCode,
			ClientId:     "test-client",
			UserId:       123,
			ResponseType: "token",
			RedirectURI:  "https://example.com/callback",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		mockClient := &models.Client{Id: 1, ClientIdentifier: "test-client", Enabled: true}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(mockClient, nil)

		dbError := errors.New("user database error")
		database.On("GetUserById", mock.Anything, int64(123)).Return(nil, dbError)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err == dbError
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Implicit flow error - clear auth context fails", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		req, err := http.NewRequest("GET", "/auth/issue", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateReadyToIssueCode,
			ClientId:     "test-client",
			UserId:       123,
			ResponseType: "token",
			RedirectURI:  "https://example.com/callback",
			Scope:        "openid",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		mockClient := &models.Client{Id: 1, ClientIdentifier: "test-client", Enabled: true}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(mockClient, nil)

		mockUser := &models.User{Id: 123, Subject: uuid.MustParse("11111111-1111-1111-1111-111111111111")}
		database.On("GetUserById", mock.Anything, int64(123)).Return(mockUser, nil)

		tokenResponse := &oauth.ImplicitGrantResponse{
			AccessToken: "access-token-123",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}
		tokenIssuer.On("GenerateTokenResponseForImplicit", mock.Anything, mock.Anything, true, false).Return(tokenResponse, nil)

		auditLogger.On("Log", constants.AuditTokenIssuedImplicitResponse, mock.Anything).Return()

		clearError := errors.New("failed to clear auth context")
		authHelper.On("ClearAuthContext", rr, req).Return(clearError)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err == clearError
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})
}

func TestIsImplicitFlow_EdgeCases(t *testing.T) {
	tests := []struct {
		name         string
		responseType string
		expected     bool
	}{
		// Edge cases
		{
			name:         "multiple spaces between tokens",
			responseType: "id_token  token",
			expected:     true,
		},
		{
			name:         "leading space",
			responseType: " token",
			expected:     true,
		},
		{
			name:         "trailing space",
			responseType: "token ",
			expected:     true,
		},
		{
			name:         "all whitespace",
			responseType: "   ",
			expected:     false,
		},
		{
			name:         "tab character",
			responseType: "token\tid_token",
			expected:     true,
		},
		{
			name:         "newline character",
			responseType: "token\nid_token",
			expected:     true,
		},
		{
			name:         "unknown response type",
			responseType: "unknown",
			expected:     false,
		},
		{
			name:         "partial match - tokens",
			responseType: "tokens",
			expected:     false,
		},
		{
			name:         "partial match - id_tokens",
			responseType: "id_tokens",
			expected:     false,
		},
		{
			name:         "case sensitivity - TOKEN",
			responseType: "TOKEN",
			expected:     false, // OAuth is case-sensitive
		},
		{
			name:         "case sensitivity - ID_TOKEN",
			responseType: "ID_TOKEN",
			expected:     false, // OAuth is case-sensitive
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := oauth.ParseResponseType(tt.responseType).IsImplicitFlow()
			assert.Equal(t, tt.expected, result, "IsImplicitFlow(%q) = %v, want %v", tt.responseType, result, tt.expected)
		})
	}
}

func TestIssueAuthCode(t *testing.T) {
	t.Run("Query response mode", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/auth/issue", nil)
		code := &models.Code{
			Code:        "test_code",
			RedirectURI: "https://example.com/callback",
			State:       "test_state",
		}

		err := issueAuthCode(w, r, nil, code, "query")

		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "https://example.com/callback?code=test_code&state=test_state", w.Header().Get("Location"))
	})

	t.Run("Fragment response mode", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/auth/issue", nil)
		code := &models.Code{
			Code:        "test_code",
			RedirectURI: "https://example.com/callback",
			State:       "test_state",
		}

		err := issueAuthCode(w, r, nil, code, "fragment")

		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "https://example.com/callback#code=test_code&state=test_state", w.Header().Get("Location"))
	})

	t.Run("Form post response mode", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/auth/issue", nil)
		code := &models.Code{
			Code:        "test_code",
			RedirectURI: "https://example.com/callback",
			State:       "test_state",
		}

		templateFS := &mocks_test.TestFS{
			FileContents: map[string]string{
				"form_post.html": `<form method="post" action="{{.redirectURI}}">
					<input type="hidden" name="code" value="{{.code}}">
					<input type="hidden" name="state" value="{{.state}}">
				</form>`,
			},
		}

		err := issueAuthCode(w, r, templateFS, code, "form_post")

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), `<form method="post" action="https://example.com/callback">`)
		assert.Contains(t, w.Body.String(), `<input type="hidden" name="code" value="test_code">`)
		assert.Contains(t, w.Body.String(), `<input type="hidden" name="state" value="test_state">`)
	})

	t.Run("Default to query response mode", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/auth/issue", nil)
		code := &models.Code{
			Code:        "test_code",
			RedirectURI: "https://example.com/callback",
			State:       "test_state",
		}

		err := issueAuthCode(w, r, nil, code, "")

		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "https://example.com/callback?code=test_code&state=test_state", w.Header().Get("Location"))
	})

	t.Run("Error parsing template", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/auth/issue", nil)
		code := &models.Code{
			Code:        "test_code",
			RedirectURI: "https://example.com/callback",
			State:       "test_state",
		}

		templateFS := &mocks_test.TestFS{
			FileContents: map[string]string{
				"form_post.html": `{{.InvalidTemplate`,
			},
		}

		err := issueAuthCode(w, r, templateFS, code, "form_post")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unable to parse template")
	})
}
