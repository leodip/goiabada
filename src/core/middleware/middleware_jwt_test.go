package middleware

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mock_handler_helpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mock_oauth "github.com/leodip/goiabada/core/oauth/mocks"
	mock_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
)

// Mock HTTP client
type mockHTTPClient struct {
	mock.Mock
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	args := m.Called(req)
	return args.Get(0).(*http.Response), args.Error(1)
}

func TestJwtAuthorizationHeaderToContext_ValidBearerToken(t *testing.T) {
	const testSessionName = "test-session"
	mockTokenParser := new(mock_oauth.TokenParser)
	mockAuthHelper := new(mock_handler_helpers.AuthHelper)

	middleware := NewMiddlewareJwt(nil, testSessionName, mockTokenParser, mockAuthHelper, nil, "http://localhost:9090", "http://localhost:9091", "", "")

	expectedToken := &oauth.JwtToken{
		TokenBase64: "validtoken",
		Claims: map[string]interface{}{
			"sub": "user",
		},
	}
	mockTokenParser.On("DecodeAndValidateTokenString", "validtoken", mock.Anything, true).
		Return(expectedToken, nil)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer validtoken")

	rr := httptest.NewRecorder()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Context().Value(constants.ContextKeyBearerToken)
		assert.NotNil(t, token)
		assert.IsType(t, oauth.JwtToken{}, token)
		assert.Equal(t, "validtoken", token.(oauth.JwtToken).TokenBase64)
		assert.Equal(t, "user", token.(oauth.JwtToken).Claims["sub"])
	})

	handler := middleware.JwtAuthorizationHeaderToContext()(nextHandler)
	handler.ServeHTTP(rr, req)

	mockTokenParser.AssertExpectations(t)
}

func TestJwtAuthorizationHeaderToContext_InvalidBearerToken(t *testing.T) {
	const testSessionName = "test-session"
	mockTokenParser := new(mock_oauth.TokenParser)
	mockAuthHelper := new(mock_handler_helpers.AuthHelper)

	middleware := NewMiddlewareJwt(nil, testSessionName, mockTokenParser, mockAuthHelper, nil, "http://localhost:9090", "http://localhost:9091", "", "")

	mockTokenParser.On("DecodeAndValidateTokenString", "invalidtoken", mock.Anything, true).
		Return(nil, assert.AnError)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer invalidtoken")

	rr := httptest.NewRecorder()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Context().Value(constants.ContextKeyBearerToken)
		assert.Nil(t, token)
	})

	handler := middleware.JwtAuthorizationHeaderToContext()(nextHandler)
	handler.ServeHTTP(rr, req)

	mockTokenParser.AssertExpectations(t)
}

func TestJwtAuthorizationHeaderToContext_NoBearerToken(t *testing.T) {
	const testSessionName = "test-session"
	mockTokenParser := new(mock_oauth.TokenParser)
	mockAuthHelper := new(mock_handler_helpers.AuthHelper)

	middleware := NewMiddlewareJwt(nil, testSessionName, mockTokenParser, mockAuthHelper, nil, "http://localhost:9090", "http://localhost:9091", "", "")

	req := httptest.NewRequest("GET", "/", nil)

	rr := httptest.NewRecorder()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Context().Value(constants.ContextKeyBearerToken)
		assert.Nil(t, token)
	})

	handler := middleware.JwtAuthorizationHeaderToContext()(nextHandler)
	handler.ServeHTTP(rr, req)
}

func TestJwtAuthorizationHeaderToContext_InvalidAuthorizationHeader(t *testing.T) {
	const testSessionName = "test-session"
	mockTokenParser := new(mock_oauth.TokenParser)
	mockAuthHelper := new(mock_handler_helpers.AuthHelper)

	middleware := NewMiddlewareJwt(nil, testSessionName, mockTokenParser, mockAuthHelper, nil, "http://localhost:9090", "http://localhost:9091", "", "")

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "NotBearer token")

	rr := httptest.NewRecorder()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Context().Value(constants.ContextKeyBearerToken)
		assert.Nil(t, token)
	})

	handler := middleware.JwtAuthorizationHeaderToContext()(nextHandler)
	handler.ServeHTTP(rr, req)
}

func TestJwtSessionHandler_ValidSession(t *testing.T) {
    const testSessionName = "test-session"
    mockTokenParser := new(mock_oauth.TokenParser)
    mockAuthHelper := new(mock_handler_helpers.AuthHelper)
    mockSessionStore := new(mock_sessionstore.Store)

    middleware := NewMiddlewareJwt(mockSessionStore, testSessionName, mockTokenParser, mockAuthHelper, nil, "http://localhost:9090", "http://localhost:9091", "", "")

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	session := &sessions.Session{
		Values: map[interface{}]interface{}{
			constants.SessionKeyJwt: oauth.TokenResponse{
				AccessToken: "validtoken",
			},
		},
	}

	mockSessionStore.On("Get", mock.Anything, testSessionName).Return(session, nil)

	expectedToken := &oauth.JwtToken{
		TokenBase64: "validtoken",
		Claims: map[string]interface{}{
			"iss": "https://example.com",
		},
	}
	mockTokenParser.On("DecodeAndValidateTokenString", "validtoken", mock.Anything, true).Return(expectedToken, nil)

	expectedJwtInfo := &oauth.JwtInfo{
		TokenResponse: oauth.TokenResponse{AccessToken: "validtoken"},
		AccessToken:   expectedToken,
	}
	mockTokenParser.On("DecodeAndValidateTokenResponse", mock.AnythingOfType("*oauth.TokenResponse")).Return(expectedJwtInfo, nil)

	settings := &models.Settings{Issuer: "https://example.com"}
	ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
	req = req.WithContext(ctx)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate that JwtInfo is set in the context
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		assert.True(t, ok, "JwtInfo should be set in the context")
		assert.NotNil(t, jwtInfo, "JwtInfo should not be nil")

		// Validate the contents of JwtInfo
		assert.Equal(t, "validtoken", jwtInfo.TokenResponse.AccessToken)
		assert.Equal(t, "validtoken", jwtInfo.AccessToken.TokenBase64)
		assert.Equal(t, "https://example.com", jwtInfo.AccessToken.GetStringClaim("iss"))

		// Compare the struct values, not the pointers
		assert.Equal(t, *expectedJwtInfo, jwtInfo, "JwtInfo in context should match expected JwtInfo")
	})

	handler := middleware.JwtSessionHandler()(nextHandler)
	handler.ServeHTTP(rr, req)

	mockSessionStore.AssertExpectations(t)
	mockTokenParser.AssertExpectations(t)
}

func TestJwtSessionHandler_InvalidSession(t *testing.T) {
    const testSessionName = "test-session"
    mockTokenParser := new(mock_oauth.TokenParser)
    mockAuthHelper := new(mock_handler_helpers.AuthHelper)
    mockSessionStore := new(mock_sessionstore.Store)

    middleware := NewMiddlewareJwt(mockSessionStore, testSessionName, mockTokenParser, mockAuthHelper, nil, "http://localhost:9090", "http://localhost:9091", "", "")

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	mockSessionStore.On("Get", mock.Anything, testSessionName).Return(nil, assert.AnError)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Next handler should not be called")
	})

	handler := middleware.JwtSessionHandler()(nextHandler)
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	mockSessionStore.AssertExpectations(t)
}

func TestJwtSessionHandler_NoJwtInSession(t *testing.T) {
    const testSessionName = "test-session"
    mockTokenParser := new(mock_oauth.TokenParser)
    mockAuthHelper := new(mock_handler_helpers.AuthHelper)
    mockSessionStore := new(mock_sessionstore.Store)

    middleware := NewMiddlewareJwt(mockSessionStore, testSessionName, mockTokenParser, mockAuthHelper, nil, "http://localhost:9090", "http://localhost:9091", "", "")

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	session := &sessions.Session{
		Values: map[interface{}]interface{}{},
	}

	mockSessionStore.On("Get", mock.Anything, testSessionName).Return(session, nil)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwtInfo := r.Context().Value(constants.ContextKeyJwtInfo)
		assert.Nil(t, jwtInfo, "JwtInfo should not be set in the context")
	})

	handler := middleware.JwtSessionHandler()(nextHandler)
	handler.ServeHTTP(rr, req)

	mockSessionStore.AssertExpectations(t)
}

func TestJwtSessionHandler_InvalidTokenInSession(t *testing.T) {
    const testSessionName = "test-session"
    mockTokenParser := new(mock_oauth.TokenParser)
    mockAuthHelper := new(mock_handler_helpers.AuthHelper)
    mockSessionStore := new(mock_sessionstore.Store)

    middleware := NewMiddlewareJwt(mockSessionStore, testSessionName, mockTokenParser, mockAuthHelper, nil, "http://localhost:9090", "http://localhost:9091", "", "")

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	session := &sessions.Session{
		Values: map[interface{}]interface{}{
			constants.SessionKeyJwt: oauth.TokenResponse{
				AccessToken: "invalidtoken",
			},
		},
	}

	mockSessionStore.On("Get", mock.Anything, testSessionName).Return(session, nil)
	mockTokenParser.On("DecodeAndValidateTokenString", "invalidtoken", mock.Anything, true).Return(nil, assert.AnError)

	// Mock session save after failed refresh attempt
	mockSessionStore.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	settings := &models.Settings{Issuer: "https://example.com"}
	ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
	req = req.WithContext(ctx)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwtInfo := r.Context().Value(constants.ContextKeyJwtInfo)
		assert.Nil(t, jwtInfo, "JwtInfo should not be set in the context")
	})

	handler := middleware.JwtSessionHandler()(nextHandler)
	handler.ServeHTTP(rr, req)

	mockSessionStore.AssertExpectations(t)
	mockTokenParser.AssertExpectations(t)
    // no database expectations

	// Check that the JWT was removed from the session
	assert.Nil(t, session.Values[constants.SessionKeyJwt], "JWT should be removed from session")
}

func TestJwtSessionHandler_InvalidIssuer(t *testing.T) {
    const testSessionName = "test-session"
    mockTokenParser := new(mock_oauth.TokenParser)
    mockAuthHelper := new(mock_handler_helpers.AuthHelper)
    mockSessionStore := new(mock_sessionstore.Store)

    middleware := NewMiddlewareJwt(mockSessionStore, testSessionName, mockTokenParser, mockAuthHelper, nil, "http://localhost:9090", "http://localhost:9091", "", "")

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	session := &sessions.Session{
		Values: map[interface{}]interface{}{
			constants.SessionKeyJwt: oauth.TokenResponse{
				AccessToken: "validtoken",
			},
		},
	}

	mockSessionStore.On("Get", mock.Anything, testSessionName).Return(session, nil)

	expectedToken := &oauth.JwtToken{
		TokenBase64: "validtoken",
		Claims: map[string]interface{}{
			"iss": "https://invalid-issuer.com",
		},
	}
	mockTokenParser.On("DecodeAndValidateTokenString", "validtoken", mock.Anything, true).Return(expectedToken, nil)

	mockTokenParser.On("DecodeAndValidateTokenResponse", mock.AnythingOfType("*oauth.TokenResponse")).Return(&oauth.JwtInfo{
		TokenResponse: oauth.TokenResponse{AccessToken: "validtoken"},
		AccessToken:   expectedToken,
	}, nil)

	// Add expectation for Save when the session is cleared
	mockSessionStore.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	settings := &models.Settings{Issuer: "https://example.com"}
	ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
	req = req.WithContext(ctx)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Next handler should not be called")
	})

	handler := middleware.JwtSessionHandler()(nextHandler)
	handler.ServeHTTP(rr, req)

	// Verify redirected to root
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, "/", rr.Header().Get("Location"))

	// Verify session was cleared
	_, exists := session.Values[constants.SessionKeyJwt]
	assert.False(t, exists, "JWT should be removed from session")

	mockSessionStore.AssertExpectations(t)
	mockTokenParser.AssertExpectations(t)
}

func TestJwtSessionHandler_ValidRefreshToken(t *testing.T) {
    const testSessionName = "test-session"
    mockTokenParser := new(mock_oauth.TokenParser)
    mockAuthHelper := new(mock_handler_helpers.AuthHelper)
    mockSessionStore := new(mock_sessionstore.Store)
    mockHTTPClient := &mockHTTPClient{}

    // Create middleware with mocked dependencies and client credentials
    middleware := NewMiddlewareJwt(mockSessionStore, testSessionName, mockTokenParser, mockAuthHelper, mockHTTPClient, "http://localhost:9090", "http://localhost:9091", "admin-console-client", "secret123")

	// Create test request
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	// Setup initial session
	initialSession := &sessions.Session{
		Values: map[interface{}]interface{}{
			constants.SessionKeyJwt: oauth.TokenResponse{
				AccessToken:  "invalidtoken",
				RefreshToken: "validrefreshtoken",
			},
		},
	}

	// Mock session store
	mockSessionStore.On("Get", mock.Anything, testSessionName).Return(initialSession, nil)
	mockSessionStore.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	// Mock token parser
	mockTokenParser.On("DecodeAndValidateTokenString", "invalidtoken", mock.Anything, true).Return(nil, errors.New("invalid token")).Once()

	mockTokenParser.On("DecodeAndValidateTokenResponse", mock.MatchedBy(func(tr *oauth.TokenResponse) bool {
		// Validate the TokenResponse
		return tr != nil &&
			tr.AccessToken == "newvalidtoken" &&
			tr.RefreshToken == "newrefreshtoken" &&
			tr.TokenType == "Bearer" &&
			tr.ExpiresIn == 3600
	})).Return(&oauth.JwtInfo{
		TokenResponse: oauth.TokenResponse{AccessToken: "newvalidtoken"},
		AccessToken: &oauth.JwtToken{
			TokenBase64: "newvalidtoken",
			Claims: map[string]interface{}{
				"iss": "https://example.com",
			},
		},
	}, nil).Once()

    // Setup context with settings
    settings := &models.Settings{
        Issuer: "https://example.com",
    }
	ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
	req = req.WithContext(ctx)

	// Mock HTTP client for token refresh
	mockHTTPClient.On("Do", mock.AnythingOfType("*http.Request")).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body: io.NopCloser(strings.NewReader(`{
			"access_token": "newvalidtoken",
			"token_type": "Bearer",
			"expires_in": 3600,
			"refresh_token": "newrefreshtoken"
		}`)),
	}, nil)

	// Create next handler
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		assert.True(t, ok, "JwtInfo should be set in the context")
		assert.NotNil(t, jwtInfo, "JwtInfo should not be nil")
		assert.Equal(t, "newvalidtoken", jwtInfo.TokenResponse.AccessToken)
	})

	// Run the middleware
	handler := middleware.JwtSessionHandler()(nextHandler)
	handler.ServeHTTP(rr, req)

	// Assert expectations
	mockSessionStore.AssertExpectations(t)
	mockTokenParser.AssertExpectations(t)
    // no database expectations
	mockHTTPClient.AssertExpectations(t)

	// Additional assertions
	assert.Equal(t, http.StatusOK, rr.Code, "Handler returned wrong status code")
}

func TestRefreshToken_Success(t *testing.T) {
    const testSessionName = "test-session"
    mockTokenParser := new(mock_oauth.TokenParser)
    mockAuthHelper := new(mock_handler_helpers.AuthHelper)
    mockSessionStore := new(mock_sessionstore.Store)
    mockHTTPClient := &mockHTTPClient{}

    middleware := NewMiddlewareJwt(mockSessionStore, testSessionName, mockTokenParser, mockAuthHelper, mockHTTPClient, "http://localhost:9090", "http://localhost:9091", "admin-console-client", "secret123")

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	initialTokenResponse := &oauth.TokenResponse{
		AccessToken:  "oldaccesstoken",
		RefreshToken: "oldrefreshtoken",
	}

	session := &sessions.Session{
		Values: map[interface{}]interface{}{
			constants.SessionKeyJwt: *initialTokenResponse,
		},
	}

	mockSessionStore.On("Get", mock.Anything, testSessionName).Return(session, nil)
	mockSessionStore.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(nil)

    settings := &models.Settings{Issuer: "https://example.com"}
	ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
	req = req.WithContext(ctx)

	mockHTTPClient.On("Do", mock.AnythingOfType("*http.Request")).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body: io.NopCloser(strings.NewReader(`{
			"access_token": "newaccesstoken",
			"token_type": "Bearer",
			"expires_in": 3600,
			"refresh_token": "newrefreshtoken"
		}`)),
	}, nil)

	refreshed, err := middleware.refreshToken(rr, req, initialTokenResponse)

	assert.True(t, refreshed)
	assert.NoError(t, err)

	newTokenResponse, ok := session.Values[constants.SessionKeyJwt].(oauth.TokenResponse)
	assert.True(t, ok)
	assert.Equal(t, "newaccesstoken", newTokenResponse.AccessToken)
	assert.Equal(t, "newrefreshtoken", newTokenResponse.RefreshToken)

	mockSessionStore.AssertExpectations(t)
    // no database expectations
	mockHTTPClient.AssertExpectations(t)
}

func TestRefreshToken_NoRefreshToken(t *testing.T) {
    const testSessionName = "test-session"
    mockTokenParser := new(mock_oauth.TokenParser)
    mockAuthHelper := new(mock_handler_helpers.AuthHelper)
    mockSessionStore := new(mock_sessionstore.Store)
    mockHTTPClient := &mockHTTPClient{}

    middleware := NewMiddlewareJwt(mockSessionStore, testSessionName, mockTokenParser, mockAuthHelper, mockHTTPClient, "http://localhost:9090", "http://localhost:9091", "admin-console-client", "secret123")

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	tokenResponse := &oauth.TokenResponse{
		AccessToken: "oldaccesstoken",
		// No refresh token
	}

	refreshed, err := middleware.refreshToken(rr, req, tokenResponse)

	assert.False(t, refreshed)
	assert.NoError(t, err)
}

func TestRefreshToken_InvalidResponse(t *testing.T) {
	const testSessionName = "test-session"
	mockTokenParser := new(mock_oauth.TokenParser)
	mockAuthHelper := new(mock_handler_helpers.AuthHelper)
	mockSessionStore := new(mock_sessionstore.Store)
	mockHTTPClient := &mockHTTPClient{}

    middleware := NewMiddlewareJwt(mockSessionStore, testSessionName, mockTokenParser, mockAuthHelper, mockHTTPClient, "http://localhost:9090", "http://localhost:9091", "admin-console-client", "secret123")

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	tokenResponse := &oauth.TokenResponse{
		AccessToken:  "oldaccesstoken",
		RefreshToken: "oldrefreshtoken",
	}

    settings := &models.Settings{Issuer: "https://example.com"}
	ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
	req = req.WithContext(ctx)

	mockHTTPClient.On("Do", mock.AnythingOfType("*http.Request")).Return(&http.Response{
		StatusCode: http.StatusBadRequest,
		Body:       io.NopCloser(strings.NewReader(`{"error": "invalid_grant"}`)),
	}, nil)

	refreshed, err := middleware.refreshToken(rr, req, tokenResponse)

	assert.False(t, refreshed)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "error response from server")

	mockSessionStore.AssertExpectations(t)
    // no database expectations
	mockHTTPClient.AssertExpectations(t)
}

func TestRequiresScope_Authorized(t *testing.T) {
    const testSessionName = "test-session"
    mockTokenParser := new(mock_oauth.TokenParser)
    mockAuthHelper := new(mock_handler_helpers.AuthHelper)
    mockSessionStore := new(mock_sessionstore.Store)

    middleware := NewMiddlewareJwt(mockSessionStore, testSessionName, mockTokenParser, mockAuthHelper, nil, "http://localhost:9090", "http://localhost:9091", "", "")

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	jwtInfo := oauth.JwtInfo{
		TokenResponse: oauth.TokenResponse{AccessToken: "validtoken"},
	}
	ctx := req.Context()
	ctx = context.WithValue(ctx, constants.ContextKeyJwtInfo, jwtInfo)
	req = req.WithContext(ctx)

	mockAuthHelper.On("IsAuthorizedToAccessResource", jwtInfo, []string{"required:scope"}).Return(true)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	handler := middleware.RequiresScope([]string{"required:scope"})(next)
	handler.ServeHTTP(rr, req)

	assert.True(t, nextCalled, "Next handler should have been called")
	assert.Equal(t, http.StatusOK, rr.Code)
	mockAuthHelper.AssertExpectations(t)
}

func TestRequiresScope_Unauthorized(t *testing.T) {
    const testSessionName = "test-session"
    mockTokenParser := new(mock_oauth.TokenParser)
    mockAuthHelper := new(mock_handler_helpers.AuthHelper)
    mockSessionStore := new(mock_sessionstore.Store)

    middleware := NewMiddlewareJwt(mockSessionStore, testSessionName, mockTokenParser, mockAuthHelper, nil, "http://localhost:9090", "http://localhost:9091", "", "")

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	jwtInfo := oauth.JwtInfo{
		TokenResponse: oauth.TokenResponse{AccessToken: "validtoken"},
	}
	ctx := req.Context()
	ctx = context.WithValue(ctx, constants.ContextKeyJwtInfo, jwtInfo)
	req = req.WithContext(ctx)

	mockAuthHelper.On("IsAuthorizedToAccessResource", jwtInfo, []string{"required:scope"}).Return(false)
	mockAuthHelper.On("IsAuthenticated", jwtInfo).Return(true)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Next handler should not have been called")
	})

	handler := middleware.RequiresScope([]string{"required:scope"})(next)
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, "/unauthorized", rr.Header().Get("Location"))
	mockAuthHelper.AssertExpectations(t)
}

func TestRequiresScope_Unauthenticated(t *testing.T) {
    const testSessionName = "test-session"
    mockTokenParser := new(mock_oauth.TokenParser)
    mockAuthHelper := new(mock_handler_helpers.AuthHelper)
    mockSessionStore := new(mock_sessionstore.Store)

    middleware := NewMiddlewareJwt(mockSessionStore, testSessionName, mockTokenParser, mockAuthHelper, nil, "http://localhost:9090", "http://localhost:9091", "", "")

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	jwtInfo := oauth.JwtInfo{}
	ctx := req.Context()
	ctx = context.WithValue(ctx, constants.ContextKeyJwtInfo, jwtInfo)
	req = req.WithContext(ctx)

	mockAuthHelper.On("IsAuthorizedToAccessResource", jwtInfo, []string{"required:scope"}).Return(false)
	mockAuthHelper.On("IsAuthenticated", jwtInfo).Return(false)
	mockAuthHelper.On("RedirToAuthorize", mock.Anything, mock.Anything, constants.AdminConsoleClientIdentifier, mock.AnythingOfType("string"), mock.AnythingOfType("string")).Return(nil)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Next handler should not have been called")
	})

	handler := middleware.RequiresScope([]string{"required:scope"})(next)
	handler.ServeHTTP(rr, req)

	mockAuthHelper.AssertExpectations(t)
}

func TestRequiresScope_NoJwtInfo(t *testing.T) {
    const testSessionName = "test-session"
    mockTokenParser := new(mock_oauth.TokenParser)
    mockAuthHelper := new(mock_handler_helpers.AuthHelper)
    mockSessionStore := new(mock_sessionstore.Store)

    middleware := NewMiddlewareJwt(mockSessionStore, testSessionName, mockTokenParser, mockAuthHelper, nil, "http://localhost:9090", "http://localhost:9091", "", "")

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	mockAuthHelper.On("IsAuthorizedToAccessResource", oauth.JwtInfo{}, []string{"required:scope"}).Return(false)
	mockAuthHelper.On("IsAuthenticated", oauth.JwtInfo{}).Return(false)
	mockAuthHelper.On("RedirToAuthorize", mock.Anything, mock.Anything, constants.AdminConsoleClientIdentifier, mock.AnythingOfType("string"), mock.AnythingOfType("string")).Return(nil)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Next handler should not have been called")
	})

	handler := middleware.RequiresScope([]string{"required:scope"})(next)
	handler.ServeHTTP(rr, req)

	mockAuthHelper.AssertExpectations(t)
}

func TestRequiresScope_RedirectError(t *testing.T) {
    const testSessionName = "test-session"
    mockTokenParser := new(mock_oauth.TokenParser)
    mockAuthHelper := new(mock_handler_helpers.AuthHelper)
    mockSessionStore := new(mock_sessionstore.Store)

    middleware := NewMiddlewareJwt(mockSessionStore, testSessionName, mockTokenParser, mockAuthHelper, nil, "http://localhost:9090", "http://localhost:9091", "", "")

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	jwtInfo := oauth.JwtInfo{}
	ctx := req.Context()
	ctx = context.WithValue(ctx, constants.ContextKeyJwtInfo, jwtInfo)
	req = req.WithContext(ctx)

	mockAuthHelper.On("IsAuthorizedToAccessResource", jwtInfo, []string{"required:scope"}).Return(false)
	mockAuthHelper.On("IsAuthenticated", jwtInfo).Return(false)
	mockAuthHelper.On("RedirToAuthorize", mock.Anything, mock.Anything, constants.AdminConsoleClientIdentifier, mock.AnythingOfType("string"), mock.AnythingOfType("string")).Return(assert.AnError)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Next handler should not have been called")
	})

	handler := middleware.RequiresScope([]string{"required:scope"})(next)
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	mockAuthHelper.AssertExpectations(t)
}

func TestBuildScopeString(t *testing.T) {
	middleware := &MiddlewareJwt{}

	manageAccountScope := constants.AdminConsoleResourceIdentifier + ":" + constants.ManageAccountPermissionIdentifier
	manageAdminConsoleScope := constants.AdminConsoleResourceIdentifier + ":" + constants.ManageAdminConsolePermissionIdentifier

	tests := []struct {
		name     string
		input    []string
		expected string
	}{
		{
			name:     "Empty input",
			input:    []string{},
			expected: fmt.Sprintf("openid email %s %s", manageAccountScope, manageAdminConsoleScope),
		},
		{
			name:     "Single scope",
			input:    []string{"scope1"},
			expected: fmt.Sprintf("openid email scope1 %s %s", manageAccountScope, manageAdminConsoleScope),
		},
		{
			name:     "Multiple scopes",
			input:    []string{"scope1", "scope2", "scope3"},
			expected: fmt.Sprintf("openid email scope1 scope2 scope3 %s %s", manageAccountScope, manageAdminConsoleScope),
		},
		{
			name:     "With required scopes already included",
			input:    []string{"openid", "email", manageAccountScope, manageAdminConsoleScope},
			expected: fmt.Sprintf("openid email %s %s", manageAccountScope, manageAdminConsoleScope),
		},
		{
			name:     "Mixed case scopes",
			input:    []string{"Scope1", "SCOPE2", "scope3"},
			expected: fmt.Sprintf("openid email scope1 scope2 scope3 %s %s", manageAccountScope, manageAdminConsoleScope),
		},
		{
			name:     "Scopes with spaces",
			input:    []string{" scope1 ", " scope2 ", " scope3 "},
			expected: fmt.Sprintf("openid email scope1 scope2 scope3 %s %s", manageAccountScope, manageAdminConsoleScope),
		},
		{
			name:     "Duplicate scopes",
			input:    []string{"scope1", "scope2", "scope1", "scope2"},
			expected: fmt.Sprintf("openid email scope1 scope2 %s %s", manageAccountScope, manageAdminConsoleScope),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := middleware.buildScopeString(tt.input)
			// Sort both strings for reliable comparison since map iteration order is random
			expectedParts := strings.Fields(tt.expected)
			resultParts := strings.Fields(result)
			sort.Strings(expectedParts)
			sort.Strings(resultParts)
			assert.Equal(t, expectedParts, resultParts, "Scope strings should match after sorting")
		})
	}
}

func TestBuildScopeString_Consistency(t *testing.T) {
	middleware := &MiddlewareJwt{}

	manageAccountScope := constants.AdminConsoleResourceIdentifier + ":" + constants.ManageAccountPermissionIdentifier
	manageAdminConsoleScope := constants.AdminConsoleResourceIdentifier + ":" + constants.ManageAdminConsolePermissionIdentifier

	input := []string{"scope1", "scope2", "scope3"}
	expectedScopes := []string{
		"openid",
		"email",
		"scope1",
		"scope2",
		"scope3",
		manageAccountScope,
		manageAdminConsoleScope,
	}

	// Run the function multiple times to ensure consistent output
	for i := 0; i < 10; i++ {
		result := middleware.buildScopeString(input)
		resultParts := strings.Fields(result)
		sort.Strings(resultParts)

		// Create a sorted copy of expected scopes for comparison
		expectedSorted := make([]string, len(expectedScopes))
		copy(expectedSorted, expectedScopes)
		sort.Strings(expectedSorted)

		assert.Equal(t, expectedSorted, resultParts, "All results should be consistent")
	}
}

func TestBuildScopeString_LargeInput(t *testing.T) {
	middleware := &MiddlewareJwt{}

	manageAccountScope := constants.AdminConsoleResourceIdentifier + ":" + constants.ManageAccountPermissionIdentifier
	manageAdminConsoleScope := constants.AdminConsoleResourceIdentifier + ":" + constants.ManageAdminConsolePermissionIdentifier

	// Create a large input slice
	input := make([]string, 1000)
	for i := 0; i < 1000; i++ {
		input[i] = fmt.Sprintf("scope%d", i)
	}

	result := middleware.buildScopeString(input)
	resultParts := strings.Fields(result)

	// Check that the result contains required scopes
	requiredScopes := []string{"openid", "email", manageAccountScope, manageAdminConsoleScope}
	for _, scope := range requiredScopes {
		assert.Contains(t, resultParts, scope, "Result should contain required scope: "+scope)
	}

	// Check that the result contains all input scopes
	for _, scope := range input {
		assert.Contains(t, resultParts, scope, "Result should contain input scope: "+scope)
	}
}

func TestBuildScopeString_SpecialCharacters(t *testing.T) {
	middleware := &MiddlewareJwt{}

	manageAccountScope := constants.AdminConsoleResourceIdentifier + ":" + constants.ManageAccountPermissionIdentifier
	manageAdminConsoleScope := constants.AdminConsoleResourceIdentifier + ":" + constants.ManageAdminConsolePermissionIdentifier

	input := []string{"scope:with:colons", "scope-with-dashes", "scope_with_underscores", "scope.with.dots"}
	result := middleware.buildScopeString(input)
	resultParts := strings.Fields(result)

	expectedScopes := append(input, []string{
		"openid",
		"email",
		manageAccountScope,
		manageAdminConsoleScope,
	}...)

	for _, scope := range expectedScopes {
		assert.Contains(t, resultParts, scope, "Result should contain scope: "+scope)
	}
}
