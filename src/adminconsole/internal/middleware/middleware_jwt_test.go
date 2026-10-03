package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	coreconstants "github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	mock_middleware "github.com/leodip/goiabada/adminconsole/internal/middleware/mocks"
	mock_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
)

func TestJwtSessionHandler_InvalidSession(t *testing.T) {
	const testSessionName = "test-session"
	mockTokenParser := new(mock_middleware.TokenParser)
	mockAuthHelper := new(mock_middleware.AuthHelper)
	mockSessionStore := new(mock_sessionstore.Store)

	middleware := NewMiddlewareJwt(mockSessionStore, testSessionName, mockTokenParser, nil, mockAuthHelper, stubErrorRenderer{}, "http://localhost:9091", "")

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

func TestRequiresScope_Authorized(t *testing.T) {
	const testSessionName = "test-session"
	mockTokenParser := new(mock_middleware.TokenParser)
	mockAuthHelper := new(mock_middleware.AuthHelper)
	mockSessionStore := new(mock_sessionstore.Store)

	middleware := NewMiddlewareJwt(mockSessionStore, testSessionName, mockTokenParser, nil, mockAuthHelper, stubErrorRenderer{}, "http://localhost:9091", "")

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	jwtInfo := oauthclient.JwtInfo{
		TokenResponse: oauth.TokenResponse{AccessToken: "validtoken"},
	}
	ctx := req.Context()
	ctx = reqctx.WithJwtInfo(ctx, jwtInfo)
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
	mockTokenParser := new(mock_middleware.TokenParser)
	mockAuthHelper := new(mock_middleware.AuthHelper)
	mockSessionStore := new(mock_sessionstore.Store)

	middleware := NewMiddlewareJwt(mockSessionStore, testSessionName, mockTokenParser, nil, mockAuthHelper, stubErrorRenderer{}, "http://localhost:9091", "")

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	jwtInfo := oauthclient.JwtInfo{
		TokenResponse: oauth.TokenResponse{AccessToken: "validtoken"},
	}
	ctx := req.Context()
	ctx = reqctx.WithJwtInfo(ctx, jwtInfo)
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

// TestRequiresScope_Unauthenticated, _NoJwtInfo and _RedirectError construct with
// coreconstants.AdminConsoleClientIdentifier rather than "" on purpose: RequiresScope used to
// substitute that constant itself when the field was blank, so with "" these three asserted
// the substitution and nothing about the caller. The middleware no longer names any module's
// identity, and the argument here is what reaches RedirToAuthorize (#285).
func TestRequiresScope_Unauthenticated(t *testing.T) {
	const testSessionName = "test-session"
	mockTokenParser := new(mock_middleware.TokenParser)
	mockAuthHelper := new(mock_middleware.AuthHelper)
	mockSessionStore := new(mock_sessionstore.Store)

	middleware := NewMiddlewareJwt(mockSessionStore, testSessionName, mockTokenParser, nil, mockAuthHelper, stubErrorRenderer{}, "http://localhost:9091", coreconstants.AdminConsoleClientIdentifier)

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	jwtInfo := oauthclient.JwtInfo{}
	ctx := req.Context()
	ctx = reqctx.WithJwtInfo(ctx, jwtInfo)
	req = req.WithContext(ctx)

	mockAuthHelper.On("IsAuthorizedToAccessResource", jwtInfo, []string{"required:scope"}).Return(false)
	mockAuthHelper.On("IsAuthenticated", jwtInfo).Return(false)
	mockAuthHelper.On("RedirToAuthorize", mock.Anything, mock.Anything, coreconstants.AdminConsoleClientIdentifier, mock.AnythingOfType("string"), mock.AnythingOfType("string")).Return(nil)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Next handler should not have been called")
	})

	handler := middleware.RequiresScope([]string{"required:scope"})(next)
	handler.ServeHTTP(rr, req)

	mockAuthHelper.AssertExpectations(t)
}

func TestRequiresScope_NoJwtInfo(t *testing.T) {
	const testSessionName = "test-session"
	mockTokenParser := new(mock_middleware.TokenParser)
	mockAuthHelper := new(mock_middleware.AuthHelper)
	mockSessionStore := new(mock_sessionstore.Store)

	middleware := NewMiddlewareJwt(mockSessionStore, testSessionName, mockTokenParser, nil, mockAuthHelper, stubErrorRenderer{}, "http://localhost:9091", coreconstants.AdminConsoleClientIdentifier)

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	mockAuthHelper.On("IsAuthorizedToAccessResource", oauthclient.JwtInfo{}, []string{"required:scope"}).Return(false)
	mockAuthHelper.On("IsAuthenticated", oauthclient.JwtInfo{}).Return(false)
	mockAuthHelper.On("RedirToAuthorize", mock.Anything, mock.Anything, coreconstants.AdminConsoleClientIdentifier, mock.AnythingOfType("string"), mock.AnythingOfType("string")).Return(nil)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Next handler should not have been called")
	})

	handler := middleware.RequiresScope([]string{"required:scope"})(next)
	handler.ServeHTTP(rr, req)

	mockAuthHelper.AssertExpectations(t)
}

func TestRequiresScope_RedirectError(t *testing.T) {
	const testSessionName = "test-session"
	mockTokenParser := new(mock_middleware.TokenParser)
	mockAuthHelper := new(mock_middleware.AuthHelper)
	mockSessionStore := new(mock_sessionstore.Store)

	middleware := NewMiddlewareJwt(mockSessionStore, testSessionName, mockTokenParser, nil, mockAuthHelper, stubErrorRenderer{}, "http://localhost:9091", coreconstants.AdminConsoleClientIdentifier)

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	jwtInfo := oauthclient.JwtInfo{}
	ctx := req.Context()
	ctx = reqctx.WithJwtInfo(ctx, jwtInfo)
	req = req.WithContext(ctx)

	mockAuthHelper.On("IsAuthorizedToAccessResource", jwtInfo, []string{"required:scope"}).Return(false)
	mockAuthHelper.On("IsAuthenticated", jwtInfo).Return(false)
	mockAuthHelper.On("RedirToAuthorize", mock.Anything, mock.Anything, coreconstants.AdminConsoleClientIdentifier, mock.AnythingOfType("string"), mock.AnythingOfType("string")).Return(assert.AnError)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Next handler should not have been called")
	})

	handler := middleware.RequiresScope([]string{"required:scope"})(next)
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	mockAuthHelper.AssertExpectations(t)
}

// Where the console returns after sign-in is its own base URL and the request's path and query.
// It was the base URL and the request line as sent, and an absolute-form request line put a whole
// second URL after the base (#426).
func TestRequiresScope_ReturnsToTheBaseURLPlusPathAndQuery(t *testing.T) {
	testCases := []struct {
		name        string
		requestLine string
	}{
		{name: "origin form", requestLine: "/admin/users?page=2&query=a%26b"},
		{name: "absolute form naming another host", requestLine: "http://elsewhere.example/admin/users?page=2&query=a%26b"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			mockAuthHelper := new(mock_middleware.AuthHelper)
			middleware := NewMiddlewareJwt(new(mock_sessionstore.Store), "test-session", new(mock_middleware.TokenParser), nil, mockAuthHelper, stubErrorRenderer{}, "http://localhost:9091", coreconstants.AdminConsoleClientIdentifier)

			req := httptest.NewRequest("GET", testCase.requestLine, nil)
			require.Equal(t, testCase.requestLine, req.RequestURI, "the request line did not reach the request as sent")

			mockAuthHelper.On("IsAuthorizedToAccessResource", oauthclient.JwtInfo{}, []string{"required:scope"}).Return(false)
			mockAuthHelper.On("IsAuthenticated", oauthclient.JwtInfo{}).Return(false)
			mockAuthHelper.On("RedirToAuthorize", mock.Anything, mock.Anything, coreconstants.AdminConsoleClientIdentifier,
				mock.AnythingOfType("string"), "http://localhost:9091/admin/users?page=2&query=a%26b").Return(nil)

			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Error("Next handler should not have been called")
			})

			middleware.RequiresScope([]string{"required:scope"})(next).ServeHTTP(httptest.NewRecorder(), req)

			mockAuthHelper.AssertExpectations(t)
		})
	}
}

func TestBuildScopeString(t *testing.T) {
	middleware := &MiddlewareJwt{}

	manageAccountScope := coreconstants.AuthServerResourceIdentifier + ":" + coreconstants.ManageAccountPermissionIdentifier
	manageScope := coreconstants.AuthServerResourceIdentifier + ":" + coreconstants.ManagePermissionIdentifier

	tests := []struct {
		name     string
		input    []string
		expected string
	}{
		{
			name:     "Empty input",
			input:    []string{},
			expected: fmt.Sprintf("openid email profile %s %s", manageAccountScope, manageScope),
		},
		{
			name:     "Single scope",
			input:    []string{"scope1"},
			expected: fmt.Sprintf("openid email profile scope1 %s %s", manageAccountScope, manageScope),
		},
		{
			name:     "Multiple scopes",
			input:    []string{"scope1", "scope2", "scope3"},
			expected: fmt.Sprintf("openid email profile scope1 scope2 scope3 %s %s", manageAccountScope, manageScope),
		},
		{
			name:     "With required scopes already included",
			input:    []string{"openid", "email", manageAccountScope, manageScope},
			expected: fmt.Sprintf("openid email profile %s %s", manageAccountScope, manageScope),
		},
		{
			name:     "Mixed case scopes",
			input:    []string{"Scope1", "SCOPE2", "scope3"},
			expected: fmt.Sprintf("openid email profile scope1 scope2 scope3 %s %s", manageAccountScope, manageScope),
		},
		{
			name:     "Scopes with spaces",
			input:    []string{" scope1 ", " scope2 ", " scope3 "},
			expected: fmt.Sprintf("openid email profile scope1 scope2 scope3 %s %s", manageAccountScope, manageScope),
		},
		{
			name:     "Duplicate scopes",
			input:    []string{"scope1", "scope2", "scope1", "scope2"},
			expected: fmt.Sprintf("openid email profile scope1 scope2 %s %s", manageAccountScope, manageScope),
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

	manageAccountScope := coreconstants.AuthServerResourceIdentifier + ":" + coreconstants.ManageAccountPermissionIdentifier
	manageScope := coreconstants.AuthServerResourceIdentifier + ":" + coreconstants.ManagePermissionIdentifier

	input := []string{"scope1", "scope2", "scope3"}
	expectedScopes := []string{
		"openid",
		"email",
		"profile",
		"scope1",
		"scope2",
		"scope3",
		manageAccountScope,
		manageScope,
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

	manageAccountScope := coreconstants.AuthServerResourceIdentifier + ":" + coreconstants.ManageAccountPermissionIdentifier
	manageScope := coreconstants.AuthServerResourceIdentifier + ":" + coreconstants.ManagePermissionIdentifier

	// Create a large input slice
	input := make([]string, 1000)
	for i := 0; i < 1000; i++ {
		input[i] = fmt.Sprintf("scope%d", i)
	}

	result := middleware.buildScopeString(input)
	resultParts := strings.Fields(result)

	// Check that the result contains required scopes
	requiredScopes := []string{"openid", "email", manageAccountScope, manageScope}
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

	manageAccountScope := coreconstants.AuthServerResourceIdentifier + ":" + coreconstants.ManageAccountPermissionIdentifier
	manageScope := coreconstants.AuthServerResourceIdentifier + ":" + coreconstants.ManagePermissionIdentifier

	input := []string{"scope:with:colons", "scope-with-dashes", "scope_with_underscores", "scope.with.dots"}
	result := middleware.buildScopeString(input)
	resultParts := strings.Fields(result)

	expectedScopes := append(input, []string{
		"openid",
		"email",
		manageAccountScope,
		manageScope,
	}...)

	for _, scope := range expectedScopes {
		assert.Contains(t, resultParts, scope, "Result should contain scope: "+scope)
	}
}
