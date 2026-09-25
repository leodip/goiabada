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
	"sync"
	"testing"
	"time"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/adminconsole/internal/boundedread"
	"github.com/leodip/goiabada/adminconsole/internal/constants"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	coreconstants "github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	mock_middleware "github.com/leodip/goiabada/adminconsole/internal/middleware/mocks"
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

func TestJwtSessionHandler_InvalidSession(t *testing.T) {
	const testSessionName = "test-session"
	mockTokenParser := new(mock_middleware.TokenParser)
	mockAuthHelper := new(mock_middleware.AuthHelper)
	mockSessionStore := new(mock_sessionstore.Store)

	middleware := NewMiddlewareJwt(mockSessionStore, testSessionName, mockTokenParser, mockAuthHelper, stubErrorRenderer{}, nil, "http://localhost:9090", "http://localhost:9091", "", "")

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

func TestRefreshToken_NoRefreshToken(t *testing.T) {
	const testSessionName = "test-session"
	mockTokenParser := new(mock_middleware.TokenParser)
	mockAuthHelper := new(mock_middleware.AuthHelper)
	mockSessionStore := new(mock_sessionstore.Store)
	mockHTTPClient := &mockHTTPClient{}

	middleware := NewMiddlewareJwt(mockSessionStore, testSessionName, mockTokenParser, mockAuthHelper, stubErrorRenderer{}, mockHTTPClient, "http://localhost:9090", "http://localhost:9091", "admin-console-client", "secret123")

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	tokenResponse := &oauth.TokenResponse{
		AccessToken: "oldaccesstoken",
		// No refresh token
	}

	refreshed, refused, err := middleware.refreshToken(rr, req, *tokenResponse, verifiedStored)

	assert.Nil(t, refreshed)
	assert.NoError(t, refused, "no answer reached the parser")
	assert.NoError(t, err)
}

// The one path that used to panic. Every other refreshToken case either supplies a client or
// returns before one is reached, so this is the case that holds the guard: with credentials
// configured and a refresh token present, a nil HTTPClient used to log and then dereference on
// the next line, taking the process down on a request the caller was equipped to handle. It now
// fails closed, which is what the caller already does with a refresh error -- clear the session
// and carry on (#320).
//
// A restored log-then-continue branch fails this test by panicking rather than by an assertion,
// which needs no panic harness: a panic in a test is a failed test.
func TestRefreshToken_NilHTTPClientFailsClosed(t *testing.T) {
	const testSessionName = "test-session"
	mockTokenParser := new(mock_middleware.TokenParser)
	mockAuthHelper := new(mock_middleware.AuthHelper)
	mockSessionStore := new(mock_sessionstore.Store)

	// nil as the interface itself, not a typed nil behind it: a (*mockHTTPClient)(nil) would
	// pass the == nil guard and reach Do, which is a different thing to test.
	middleware := NewMiddlewareJwt(mockSessionStore, testSessionName, mockTokenParser, mockAuthHelper, stubErrorRenderer{}, nil, "http://localhost:9090", "http://localhost:9091", "admin-console-client", "secret123")

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	tokenResponse := &oauth.TokenResponse{
		AccessToken:  "oldaccesstoken",
		RefreshToken: "oldrefreshtoken",
	}

	refreshed, refused, err := middleware.refreshToken(rr, req, *tokenResponse, verifiedStored)

	assert.Nil(t, refreshed)
	assert.NoError(t, refused, "no answer reached the parser")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no http client is configured")
}

func TestRefreshToken_InvalidResponse(t *testing.T) {
	const testSessionName = "test-session"
	mockTokenParser := new(mock_middleware.TokenParser)
	mockAuthHelper := new(mock_middleware.AuthHelper)
	mockSessionStore := new(mock_sessionstore.Store)
	mockHTTPClient := &mockHTTPClient{}

	middleware := NewMiddlewareJwt(mockSessionStore, testSessionName, mockTokenParser, mockAuthHelper, stubErrorRenderer{}, mockHTTPClient, "http://localhost:9090", "http://localhost:9091", "admin-console-client", "secret123")

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	tokenResponse := &oauth.TokenResponse{
		AccessToken:  "oldaccesstoken",
		RefreshToken: "oldrefreshtoken",
	}

	mockHTTPClient.On("Do", mock.AnythingOfType("*http.Request")).Return(&http.Response{
		StatusCode: http.StatusBadRequest,
		Body:       io.NopCloser(strings.NewReader(`{"error": "invalid_grant"}`)),
	}, nil)

	refreshed, refused, err := middleware.refreshToken(rr, req, *tokenResponse, verifiedStored)

	assert.Nil(t, refreshed)
	assert.NoError(t, refused, "no answer reached the parser")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "error response from server")

	mockSessionStore.AssertExpectations(t)
	// no database expectations
	mockHTTPClient.AssertExpectations(t)
}

func TestRequiresScope_Authorized(t *testing.T) {
	const testSessionName = "test-session"
	mockTokenParser := new(mock_middleware.TokenParser)
	mockAuthHelper := new(mock_middleware.AuthHelper)
	mockSessionStore := new(mock_sessionstore.Store)

	middleware := NewMiddlewareJwt(mockSessionStore, testSessionName, mockTokenParser, mockAuthHelper, stubErrorRenderer{}, nil, "http://localhost:9090", "http://localhost:9091", "", "")

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	jwtInfo := oauthclient.JwtInfo{
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
	mockTokenParser := new(mock_middleware.TokenParser)
	mockAuthHelper := new(mock_middleware.AuthHelper)
	mockSessionStore := new(mock_sessionstore.Store)

	middleware := NewMiddlewareJwt(mockSessionStore, testSessionName, mockTokenParser, mockAuthHelper, stubErrorRenderer{}, nil, "http://localhost:9090", "http://localhost:9091", "", "")

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	jwtInfo := oauthclient.JwtInfo{
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

	middleware := NewMiddlewareJwt(mockSessionStore, testSessionName, mockTokenParser, mockAuthHelper, stubErrorRenderer{}, nil, "http://localhost:9090", "http://localhost:9091", coreconstants.AdminConsoleClientIdentifier, "")

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	jwtInfo := oauthclient.JwtInfo{}
	ctx := req.Context()
	ctx = context.WithValue(ctx, constants.ContextKeyJwtInfo, jwtInfo)
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

	middleware := NewMiddlewareJwt(mockSessionStore, testSessionName, mockTokenParser, mockAuthHelper, stubErrorRenderer{}, nil, "http://localhost:9090", "http://localhost:9091", coreconstants.AdminConsoleClientIdentifier, "")

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

	middleware := NewMiddlewareJwt(mockSessionStore, testSessionName, mockTokenParser, mockAuthHelper, stubErrorRenderer{}, nil, "http://localhost:9090", "http://localhost:9091", coreconstants.AdminConsoleClientIdentifier, "")

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	jwtInfo := oauthclient.JwtInfo{}
	ctx := req.Context()
	ctx = context.WithValue(ctx, constants.ContextKeyJwtInfo, jwtInfo)
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
			middleware := NewMiddlewareJwt(new(mock_sessionstore.Store), "test-session", new(mock_middleware.TokenParser),
				mockAuthHelper, stubErrorRenderer{}, nil,
				"http://localhost:9090", "http://localhost:9091", coreconstants.AdminConsoleClientIdentifier, "")

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

// =============================================================================
// The refresh grant's bounds, goal 9 of #338.
//
// refreshToken is the third of the three reads the admin console makes of the
// auth server, and it is a separate io.ReadAll that neither core/oauth case can
// observe. It is also one of the two grants decision 12 detaches from the
// browser's context, and that one is observable only here.
// =============================================================================

// countingRefreshBody serves a fixed body and records how much was read. Finite
// and larger than the cap: an unbounded read consumes all of it and parses
// cleanly, while the bound stops one byte past the cap and refuses the answer
// outright, so both the count and the outcome flip when the cap goes.
type countingRefreshBody struct {
	remaining []byte
	read      int64
}

func (b *countingRefreshBody) Read(p []byte) (int, error) {
	if len(b.remaining) == 0 {
		return 0, io.EOF
	}
	n := copy(p, b.remaining)
	b.remaining = b.remaining[n:]
	b.read += int64(n)
	return n, nil
}

func (b *countingRefreshBody) Close() error { return nil }

func oversizedRefreshResponse() *countingRefreshBody {
	prefix := `{"access_token":"newaccesstoken","refresh_token":"newrefreshtoken","scope":"`
	suffix := `"}`
	padding := oauthclient.MaxTokenResponseBytes + 1024 - len(prefix) - len(suffix)
	return &countingRefreshBody{remaining: []byte(prefix + strings.Repeat("x", padding) + suffix)}
}

func TestRefreshToken_RefusesAnAnswerOverTheCap(t *testing.T) {
	const testSessionName = "test-session"
	mockTokenParser := new(mock_middleware.TokenParser)
	mockAuthHelper := new(mock_middleware.AuthHelper)
	mockSessionStore := new(mock_sessionstore.Store)
	mockHTTPClient := &mockHTTPClient{}

	middleware := NewMiddlewareJwt(mockSessionStore, testSessionName, mockTokenParser,
		mockAuthHelper, stubErrorRenderer{},
		mockHTTPClient, "http://localhost:9090", "http://localhost:9091", "admin-console-client", "secret123")

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	body := oversizedRefreshResponse()
	mockHTTPClient.On("Do", mock.AnythingOfType("*http.Request")).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       body,
	}, nil)

	refreshed, refused, err := middleware.refreshToken(rr, req, oauth.TokenResponse{
		AccessToken:  "oldaccesstoken",
		RefreshToken: "oldrefreshtoken",
	}, verifiedStored)

	assert.Nil(t, refreshed)
	assert.NoError(t, refused, "no answer reached the parser")
	require.Error(t, err)
	assert.True(t, errors.Is(err, boundedread.ErrResponseTooLarge),
		"the answer is refused as oversized rather than reaching json.Unmarshal truncated: %v", err)
	assert.Equal(t, int64(oauthclient.MaxTokenResponseBytes)+1, body.read,
		"one byte past the cap is read, which is what makes the overrun detectable, and no more")

	// The session is reached only after the read and the parse succeed, so an
	// oversized answer never becomes the administrator's session.
	mockSessionStore.AssertNotCalled(t, "Save", mock.Anything, mock.Anything, mock.Anything)
	mockHTTPClient.AssertExpectations(t)
}

// recordingTransport reports what the outbound request's context looked like at
// the moment it was handed to the transport. That context is the only place
// decision 12 is observable: a plain r.Context() here is already cancelled and
// the round trip never leaves the process.
type recordingTransport struct {
	inner       http.RoundTripper
	mu          sync.Mutex
	hadDeadline bool
	deadline    time.Time
	ctxErr      error
	requestID   string
}

func (rt *recordingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rt.mu.Lock()
	rt.deadline, rt.hadDeadline = r.Context().Deadline()
	rt.ctxErr = r.Context().Err()
	rt.requestID = chimiddleware.GetReqID(r.Context())
	rt.mu.Unlock()
	return rt.inner.RoundTrip(r)
}

// refresh_token is single use: the auth server revokes the old token as part of
// issuing the new one, so a refresh abandoned because the browser went away leaves
// the console holding a revoked token and signs the administrator out on their next
// page load. The inbound request here is already cancelled, which is exactly that
// situation, and the refresh has to complete anyway.
//
// Completing means the new token is written down, not merely received, so the
// session read and write that follow the call are asserted here too: the real
// ServerSideStore passes the request's context straight to its backend and refuses
// both on a cancelled one, which would leave the administrator holding the revoked
// token with the replacement fetched and dropped. The store double cannot show that
// by failing -- it saves whatever the context says -- so the case reads the context
// the store was handed instead.
//
// A real httptest.Server rather than a mock client, because a cancelled context
// is refused by the transport and not by anything above it: a double that
// ignores the context would pass this with r.Context() restored (#338).
func TestJwtSessionHandler_RefreshesOnACancelledRequestContext(t *testing.T) {
	const testSessionName = "test-session"

	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.URL.Path != "/auth/token" || r.PostFormValue("grant_type") != "refresh_token" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"newaccesstoken","refresh_token":"newrefreshtoken"}`))
	}))
	defer authServer.Close()

	transport := &recordingTransport{inner: http.DefaultTransport}

	mockTokenParser := new(mock_middleware.TokenParser)
	mockAuthHelper := new(mock_middleware.AuthHelper)
	mockSessionStore := new(mock_sessionstore.Store)

	middleware := NewMiddlewareJwt(mockSessionStore, testSessionName, mockTokenParser,
		mockAuthHelper, stubErrorRenderer{},
		&http.Client{Transport: transport}, authServer.URL, "http://localhost:9091",
		"admin-console-client", "secret123")

	session := &sessionstore.Session{
		Values: map[string]any{
			constants.SessionKeyJwt: oauth.TokenResponse{
				AccessToken:  "oldaccesstoken",
				IdToken:      storedIDTokenRaw,
				RefreshToken: "oldrefreshtoken",
			},
			// Due: this is what sends the middleware down the refresh path.
			constants.SessionKeyJwtExpiresAt: time.Now().Add(10 * time.Second).Unix(),
		},
	}
	// The context each store call was handed, captured at the call: the handler cancels
	// the detached context on its way out, so reading it afterwards would show it done
	// whatever was passed. Get runs twice -- once on the browser's own request at the top
	// of the handler, then again on the detached one inside the refresh -- so these hold
	// the last call, and the deadline assertion below is what proves which one that was.
	var getCtxErr, saveCtxErr error
	var getDeadline, saveDeadline time.Time
	var getHadDeadline, saveHadDeadline bool
	var getRequestID, saveRequestID string
	mockSessionStore.On("Get", mock.Anything, testSessionName).Return(session, nil).
		Run(func(args mock.Arguments) {
			if req, ok := args.Get(0).(*http.Request); ok {
				getCtxErr = req.Context().Err()
				getDeadline, getHadDeadline = req.Context().Deadline()
				getRequestID = chimiddleware.GetReqID(req.Context())
			}
		})
	mockSessionStore.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(nil).
		Run(func(args mock.Arguments) {
			if req, ok := args.Get(0).(*http.Request); ok {
				saveCtxErr = req.Context().Err()
				saveDeadline, saveHadDeadline = req.Context().Deadline()
				saveRequestID = chimiddleware.GetReqID(req.Context())
			}
		})

	mockTokenParser.On("DecodeAndValidateStoredIDToken", mock.Anything, storedIDTokenRaw).
		Return(verifiedStored, nil)
	// The answer's validation is part of the refresh too: the old refresh token is spent by the
	// time it runs, and the parser may have to fetch the JWKS, so it runs on the detached context
	// under the same deadline as the call and the write (#427).
	var parseCtxErr error
	var parseDeadline time.Time
	var parseHadDeadline bool
	mockTokenParser.On("DecodeAndValidateRefreshResponse", mock.Anything, mock.Anything, verifiedStored).
		Run(func(args mock.Arguments) {
			if ctx, ok := args.Get(0).(context.Context); ok {
				parseCtxErr = ctx.Err()
				parseDeadline, parseHadDeadline = ctx.Deadline()
			}
		}).
		Return(func(_ context.Context, tr *oauth.TokenResponse, previous *oauth.JwtToken) (*oauthclient.JwtInfo, error) {
			return &oauthclient.JwtInfo{TokenResponse: *tr, IdToken: previous}, nil
		})

	// The browser has gone: the inbound request's context is already done before
	// the handler runs. It carries a request id, which is the value the detachment is
	// required to keep: chi's RequestID middleware puts one on every inbound request in
	// both servers, and the installed slog handler lifts it off the context onto every
	// record. context.Background() would drop it, which is the whole reason decision 12
	// chose WithoutCancel over it.
	const wantRequestID = "the-inbound-request-id"
	ctx, cancel := context.WithCancel(
		context.WithValue(context.Background(), chimiddleware.RequestIDKey, wantRequestID))
	cancel()
	req := httptest.NewRequest("GET", "/", nil).WithContext(ctx)
	rr := httptest.NewRecorder()

	var reached bool
	middleware.JwtSessionHandler()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)

	assert.True(t, reached, "the chain continues")

	newTokenResponse, ok := session.Values[constants.SessionKeyJwt].(oauth.TokenResponse)
	require.True(t, ok, "the refresh completed and its result reached the session")
	assert.Equal(t, "newaccesstoken", newTokenResponse.AccessToken)
	assert.Equal(t, "newrefreshtoken", newTokenResponse.RefreshToken)

	transport.mu.Lock()
	defer transport.mu.Unlock()
	assert.NoError(t, transport.ctxErr,
		"the outbound request runs on a context detached from the browser's")
	require.True(t, transport.hadDeadline,
		"detached, but not unbounded: the deadline is what replaces the cancellation")
	// And it is the ten seconds decision 11 chose, not merely some deadline: recording only
	// that one exists leaves dividing the production value by ten green, and the value is the
	// whole of what bounds a peer that accepts the connection and never answers. The tolerance
	// covers the round trip against the local server, which is milliseconds (#338).
	assert.LessOrEqual(t, time.Until(transport.deadline), oauthclient.TokenExchangeTimeout,
		"bounded by TokenExchangeTimeout")
	assert.Greater(t, time.Until(transport.deadline), oauthclient.TokenExchangeTimeout-time.Second,
		"and by that value rather than by something shorter")

	// And the writing half. Receiving the token is not the point; recording it is, and the
	// store is the only thing that does. Handing it the browser's request leaves these two
	// calls refused by any store that honours the context, with the old token already
	// revoked by the auth server.
	assert.NoError(t, getCtxErr,
		"the session read after the refresh runs on the detached context too")
	assert.NoError(t, saveCtxErr,
		"and so does the save that records the new token")
	require.True(t, getHadDeadline, "the session read is bounded")
	require.True(t, saveHadDeadline, "and so is the save")

	// One budget, not three. Decision 14-b bounds the call and the write that records its
	// result as a single operation, so the store calls have to observe the same absolute
	// deadline the transport did -- not merely some deadline under ten seconds. Minting a
	// fresh ten second context after the token response satisfies every assertion above
	// and stretches the operation to nearly twenty, which is what these two refuse (#338).
	assert.True(t, transport.deadline.Equal(getDeadline),
		"the session read runs on the deadline the token call was given, not a fresh one")
	assert.True(t, transport.deadline.Equal(saveDeadline),
		"and so does the save: one deadline covers the call and the write together")
	assert.NoError(t, parseCtxErr, "the answer is validated on the detached context")
	require.True(t, parseHadDeadline, "which is bounded")
	assert.True(t, transport.deadline.Equal(parseDeadline),
		"by the same deadline as the call and the write it sits between")

	// The request id is the value WithoutCancel exists to keep. Every record these three
	// write is correlated by it, so context.Background() here would silence the refresh in
	// the operator's log exactly when it is being asked what happened to a session.
	assert.Equal(t, wantRequestID, transport.requestID,
		"the detached call keeps the request's values: request_id still reaches its records")
	assert.Equal(t, wantRequestID, getRequestID, "and the session read keeps them")
	assert.Equal(t, wantRequestID, saveRequestID, "and so does the save")
}
