package middleware

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	mock_middleware "github.com/leodip/goiabada/authserver/internal/middleware/mocks"
)

func TestJwtAuthorizationHeaderToContext_ValidBearerToken(t *testing.T) {
	mockTokenParser := new(mock_middleware.TokenParser)
	middleware := NewMiddlewareBearerToken(mockTokenParser)

	expectedToken := &oauth.JwtToken{
		TokenBase64: "validtoken",
		Claims: map[string]interface{}{
			"sub": "user",
			"typ": "Bearer",
			"aud": "authserver",
		},
	}
	mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "validtoken", true).
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
	mockTokenParser := new(mock_middleware.TokenParser)
	middleware := NewMiddlewareBearerToken(mockTokenParser)

	mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "invalidtoken", true).
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
	mockTokenParser := new(mock_middleware.TokenParser)
	middleware := NewMiddlewareBearerToken(mockTokenParser)

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
	mockTokenParser := new(mock_middleware.TokenParser)
	middleware := NewMiddlewareBearerToken(mockTokenParser)

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

// Tests for POST body access_token extraction (OIDC Core 1.0 Section 5.3.1)

func TestJwtAuthorizationHeaderToContext_ValidPostBodyToken(t *testing.T) {
	mockTokenParser := new(mock_middleware.TokenParser)
	middleware := NewMiddlewareBearerToken(mockTokenParser)

	expectedToken := &oauth.JwtToken{
		TokenBase64: "validposttoken",
		Claims: map[string]interface{}{
			"sub": "user",
			"typ": "Bearer",
			"aud": "authserver",
		},
	}
	mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "validposttoken", true).
		Return(expectedToken, nil)

	req := httptest.NewRequest("POST", "/userinfo", strings.NewReader("access_token=validposttoken"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Context().Value(constants.ContextKeyBearerToken)
		assert.NotNil(t, token)
		assert.IsType(t, oauth.JwtToken{}, token)
		assert.Equal(t, "validposttoken", token.(oauth.JwtToken).TokenBase64)
		assert.Equal(t, "user", token.(oauth.JwtToken).Claims["sub"])
	})

	handler := middleware.JwtAuthorizationHeaderToContext()(nextHandler)
	handler.ServeHTTP(rr, req)

	mockTokenParser.AssertExpectations(t)
}

func TestJwtAuthorizationHeaderToContext_InvalidPostBodyToken(t *testing.T) {
	mockTokenParser := new(mock_middleware.TokenParser)
	middleware := NewMiddlewareBearerToken(mockTokenParser)

	mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "invalidposttoken", true).
		Return(nil, assert.AnError)

	req := httptest.NewRequest("POST", "/userinfo", strings.NewReader("access_token=invalidposttoken"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Context().Value(constants.ContextKeyBearerToken)
		assert.Nil(t, token)
	})

	handler := middleware.JwtAuthorizationHeaderToContext()(nextHandler)
	handler.ServeHTTP(rr, req)

	mockTokenParser.AssertExpectations(t)
}

func TestJwtAuthorizationHeaderToContext_HeaderTakesPrecedenceOverPostBody(t *testing.T) {
	mockTokenParser := new(mock_middleware.TokenParser)
	middleware := NewMiddlewareBearerToken(mockTokenParser)

	expectedToken := &oauth.JwtToken{
		TokenBase64: "headertoken",
		Claims: map[string]interface{}{
			"sub": "headeruser",
			"typ": "Bearer",
			"aud": "authserver",
		},
	}
	// Only the header token should be validated, not the body token
	mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "headertoken", true).
		Return(expectedToken, nil)

	req := httptest.NewRequest("POST", "/userinfo", strings.NewReader("access_token=bodytoken"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer headertoken")

	rr := httptest.NewRecorder()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Context().Value(constants.ContextKeyBearerToken)
		assert.NotNil(t, token)
		assert.IsType(t, oauth.JwtToken{}, token)
		assert.Equal(t, "headertoken", token.(oauth.JwtToken).TokenBase64)
		assert.Equal(t, "headeruser", token.(oauth.JwtToken).Claims["sub"])
	})

	handler := middleware.JwtAuthorizationHeaderToContext()(nextHandler)
	handler.ServeHTTP(rr, req)

	mockTokenParser.AssertExpectations(t)
}

func TestJwtAuthorizationHeaderToContext_PostBodyIgnoredForGetRequest(t *testing.T) {
	mockTokenParser := new(mock_middleware.TokenParser)
	middleware := NewMiddlewareBearerToken(mockTokenParser)

	// GET request with access_token in query string should NOT extract the token
	req := httptest.NewRequest("GET", "/userinfo?access_token=gettoken", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Context().Value(constants.ContextKeyBearerToken)
		assert.Nil(t, token, "Token should not be extracted from GET request body/query")
	})

	handler := middleware.JwtAuthorizationHeaderToContext()(nextHandler)
	handler.ServeHTTP(rr, req)

	// Token parser should NOT be called for GET request with body token
	mockTokenParser.AssertNotCalled(t, "DecodeAndValidateTokenString",
		mock.Anything, mock.Anything, mock.Anything)
}

// A POST that carries the token only in its query is the one request where the two accessors
// disagree: ParseForm merges the URL query behind the body, so r.FormValue would return the query
// value here and put a token that has travelled in a request target into the context, while
// r.PostFormValue returns "" and the request goes on unauthenticated. RFC 6750 section 2.3 says the
// URI query method "has a high likelihood of being logged", and RFC 9700 section 4.3.2 makes it
// "Clients MUST NOT pass access tokens in a URI query parameter".
//
// The GET case above does not pin this: it is refused by the method check two branches earlier and
// never reaches the read at all. This is the case that fails if the accessor regresses (#333).
func TestJwtAuthorizationHeaderToContext_PostQueryTokenIgnored(t *testing.T) {
	mockTokenParser := new(mock_middleware.TokenParser)
	middleware := NewMiddlewareBearerToken(mockTokenParser)

	// A genuine form submission whose body does not carry the token, with the token in the query.
	req := httptest.NewRequest("POST", "/userinfo?access_token=querytoken", strings.NewReader("other_param=value"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Context().Value(constants.ContextKeyBearerToken)
		assert.Nil(t, token, "Token should not be extracted from the URL query of a POST")
	})

	handler := middleware.JwtAuthorizationHeaderToContext()(nextHandler)
	handler.ServeHTTP(rr, req)

	// Token parser should NOT be called for a token that arrived in the request target
	mockTokenParser.AssertNotCalled(t, "DecodeAndValidateTokenString",
		mock.Anything, mock.Anything, mock.Anything)
}

func TestJwtAuthorizationHeaderToContext_PostBodyIgnoredForWrongContentType(t *testing.T) {
	mockTokenParser := new(mock_middleware.TokenParser)
	middleware := NewMiddlewareBearerToken(mockTokenParser)

	req := httptest.NewRequest("POST", "/userinfo", strings.NewReader("access_token=jsontoken"))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Context().Value(constants.ContextKeyBearerToken)
		assert.Nil(t, token, "Token should not be extracted from POST with wrong Content-Type")
	})

	handler := middleware.JwtAuthorizationHeaderToContext()(nextHandler)
	handler.ServeHTTP(rr, req)

	// Token parser should NOT be called for wrong content type
	mockTokenParser.AssertNotCalled(t, "DecodeAndValidateTokenString",
		mock.Anything, mock.Anything, mock.Anything)
}

func TestJwtAuthorizationHeaderToContext_PostBodyEmptyAccessToken(t *testing.T) {
	mockTokenParser := new(mock_middleware.TokenParser)
	middleware := NewMiddlewareBearerToken(mockTokenParser)

	req := httptest.NewRequest("POST", "/userinfo", strings.NewReader("access_token="))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Context().Value(constants.ContextKeyBearerToken)
		assert.Nil(t, token, "Token should not be set for empty access_token")
	})

	handler := middleware.JwtAuthorizationHeaderToContext()(nextHandler)
	handler.ServeHTTP(rr, req)

	// Token parser should NOT be called for empty token
	mockTokenParser.AssertNotCalled(t, "DecodeAndValidateTokenString",
		mock.Anything, mock.Anything, mock.Anything)
}

func TestJwtAuthorizationHeaderToContext_PostBodyNoAccessTokenParameter(t *testing.T) {
	mockTokenParser := new(mock_middleware.TokenParser)
	middleware := NewMiddlewareBearerToken(mockTokenParser)

	req := httptest.NewRequest("POST", "/userinfo", strings.NewReader("other_param=value"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Context().Value(constants.ContextKeyBearerToken)
		assert.Nil(t, token, "Token should not be set when access_token parameter is missing")
	})

	handler := middleware.JwtAuthorizationHeaderToContext()(nextHandler)
	handler.ServeHTTP(rr, req)

	// Token parser should NOT be called when access_token is missing
	mockTokenParser.AssertNotCalled(t, "DecodeAndValidateTokenString",
		mock.Anything, mock.Anything, mock.Anything)
}

func TestJwtAuthorizationHeaderToContext_PostBodyContentTypeWithCharset(t *testing.T) {
	mockTokenParser := new(mock_middleware.TokenParser)
	middleware := NewMiddlewareBearerToken(mockTokenParser)

	expectedToken := &oauth.JwtToken{
		TokenBase64: "charsettoken",
		Claims: map[string]interface{}{
			"sub": "user",
			"typ": "Bearer",
			"aud": "authserver",
		},
	}
	mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "charsettoken", true).
		Return(expectedToken, nil)

	req := httptest.NewRequest("POST", "/userinfo", strings.NewReader("access_token=charsettoken"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")

	rr := httptest.NewRecorder()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Context().Value(constants.ContextKeyBearerToken)
		assert.NotNil(t, token)
		assert.Equal(t, "charsettoken", token.(oauth.JwtToken).TokenBase64)
	})

	handler := middleware.JwtAuthorizationHeaderToContext()(nextHandler)
	handler.ServeHTTP(rr, req)

	mockTokenParser.AssertExpectations(t)
}

func TestJwtAuthorizationHeaderToContext_PostBodyWithOtherParameters(t *testing.T) {
	mockTokenParser := new(mock_middleware.TokenParser)
	middleware := NewMiddlewareBearerToken(mockTokenParser)

	expectedToken := &oauth.JwtToken{
		TokenBase64: "tokenwithotherparams",
		Claims: map[string]interface{}{
			"sub": "user",
			"typ": "Bearer",
			"aud": "authserver",
		},
	}
	mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "tokenwithotherparams", true).
		Return(expectedToken, nil)

	req := httptest.NewRequest("POST", "/userinfo", strings.NewReader("param1=value1&access_token=tokenwithotherparams&param2=value2"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Context().Value(constants.ContextKeyBearerToken)
		assert.NotNil(t, token)
		assert.Equal(t, "tokenwithotherparams", token.(oauth.JwtToken).TokenBase64)
	})

	handler := middleware.JwtAuthorizationHeaderToContext()(nextHandler)
	handler.ServeHTTP(rr, req)

	mockTokenParser.AssertExpectations(t)
}

func TestJwtAuthorizationHeaderToContext_EmptyBearerTokenInHeader(t *testing.T) {
	mockTokenParser := new(mock_middleware.TokenParser)
	middleware := NewMiddlewareBearerToken(mockTokenParser)

	expectedToken := &oauth.JwtToken{
		TokenBase64: "fallbacktoken",
		Claims: map[string]interface{}{
			"sub": "user",
			"typ": "Bearer",
			"aud": "authserver",
		},
	}
	mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "fallbacktoken", true).
		Return(expectedToken, nil)

	// Empty Bearer token in header should fall back to POST body
	req := httptest.NewRequest("POST", "/userinfo", strings.NewReader("access_token=fallbacktoken"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer ")

	rr := httptest.NewRecorder()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Context().Value(constants.ContextKeyBearerToken)
		assert.NotNil(t, token)
		assert.Equal(t, "fallbacktoken", token.(oauth.JwtToken).TokenBase64)
	})

	handler := middleware.JwtAuthorizationHeaderToContext()(nextHandler)
	handler.ServeHTTP(rr, req)

	mockTokenParser.AssertExpectations(t)
}

func TestJwtAuthorizationHeaderToContext_PutRequestIgnoresPostBody(t *testing.T) {
	mockTokenParser := new(mock_middleware.TokenParser)
	middleware := NewMiddlewareBearerToken(mockTokenParser)

	// PUT request should NOT extract token from body
	req := httptest.NewRequest("PUT", "/userinfo", strings.NewReader("access_token=puttoken"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Context().Value(constants.ContextKeyBearerToken)
		assert.Nil(t, token, "Token should not be extracted from PUT request body")
	})

	handler := middleware.JwtAuthorizationHeaderToContext()(nextHandler)
	handler.ServeHTTP(rr, req)

	// Token parser should NOT be called for PUT request
	mockTokenParser.AssertNotCalled(t, "DecodeAndValidateTokenString",
		mock.Anything, mock.Anything, mock.Anything)
}

// TestJwtAuthorizationHeaderToContext_TokenKindAndAudience is the bearer table of #401: a validly
// signed token reaches the context only when it is an access token (typ Bearer) whose aud names
// authserver. Every refused row still calls the next handler, with nothing in the context, which is
// how the route comes to answer as it does for a token that does not parse.
//
// The aud rows use the shapes the real parser hands over. It decodes into jwt.MapClaims, so the
// []string issuance writes for two audiences arrives as []interface{}; []string is kept as a row
// because it is the in-process shape.
func TestJwtAuthorizationHeaderToContext_TokenKindAndAudience(t *testing.T) {
	tests := []struct {
		name      string
		typ       interface{} // nil leaves the claim out
		aud       interface{} // nil leaves the claim out
		admitted  bool
		wantInLog string
	}{
		{name: "access token, aud a string", typ: "Bearer", aud: "authserver", admitted: true},
		{name: "access token, aud a parsed array", typ: "Bearer", aud: []interface{}{"authserver", "resource1"}, admitted: true},
		{name: "access token, aud an in-process array", typ: "Bearer", aud: []string{"resource1", "authserver"}, admitted: true},

		{name: "session refresh token", typ: "Refresh", aud: "authserver", wantInLog: "not an access token"},
		{name: "offline refresh token", typ: "Offline", aud: "authserver", wantInLog: "not an access token"},
		{name: "ID token, no typ", typ: nil, aud: "authserver", wantInLog: "not an access token"},
		{name: "typ ID", typ: "ID", aud: "authserver", wantInLog: "not an access token"},
		{name: "typ lowercase bearer", typ: "bearer", aud: "authserver", wantInLog: "not an access token"},
		{name: "typ a number", typ: 1, aud: "authserver", wantInLog: "not an access token"},

		{name: "aud absent", typ: "Bearer", aud: nil, wantInLog: "does not name this server's resource"},
		{name: "aud another resource", typ: "Bearer", aud: "resource1", wantInLog: "does not name this server's resource"},
		{name: "aud the issuer URL", typ: "Bearer", aud: "https://auth.example.com", wantInLog: "does not name this server's resource"},
		{name: "aud an array without authserver", typ: "Bearer", aud: []interface{}{"resource1", "resource2"}, wantInLog: "does not name this server's resource"},
		{name: "aud an empty array", typ: "Bearer", aud: []interface{}{}, wantInLog: "does not name this server's resource"},
		{name: "aud an array with a non-string beside authserver", typ: "Bearer", aud: []interface{}{"authserver", 7}, wantInLog: "aud is malformed"},
		// jwt/v5 reads an aud of any other type as no audience at all rather than an error.
		{name: "aud a number", typ: "Bearer", aud: 7, wantInLog: "does not name this server's resource"},
		{name: "aud a prefix of authserver", typ: "Bearer", aud: "authserve", wantInLog: "does not name this server's resource"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logs := testutil.CaptureSlog(t)
			mockTokenParser := new(mock_middleware.TokenParser)
			middleware := NewMiddlewareBearerToken(mockTokenParser)

			claims := map[string]interface{}{"sub": "user"}
			if tc.typ != nil {
				claims["typ"] = tc.typ
			}
			if tc.aud != nil {
				claims["aud"] = tc.aud
			}
			mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "the-signed-token", true).
				Return(&oauth.JwtToken{TokenBase64: "the-signed-token", Claims: claims}, nil)

			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("Authorization", "Bearer the-signed-token")

			nextCalled := false
			var tokenInContext interface{}
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				tokenInContext = r.Context().Value(constants.ContextKeyBearerToken)
			})

			middleware.JwtAuthorizationHeaderToContext()(nextHandler).ServeHTTP(httptest.NewRecorder(), req)

			assert.True(t, nextCalled, "the next handler runs either way; the route decides the answer")
			mockTokenParser.AssertExpectations(t)

			if tc.admitted {
				require.NotNil(t, tokenInContext)
				assert.Equal(t, "the-signed-token", tokenInContext.(oauth.JwtToken).TokenBase64)
				assert.Empty(t, logs.Records(), "an admitted token writes no record")
				return
			}

			assert.Nil(t, tokenInContext, "a refused token must not reach the context")
			records := logs.Records()
			require.Len(t, records, 1, "one record per refusal")
			assert.Equal(t, slog.LevelWarn, records[0].Level)
			assert.Contains(t, records[0].Message, tc.wantInLog)
			assert.NotContains(t, logs.Text(), "the-signed-token", "the record carries no token material")
		})
	}
}

// The form-body read of OIDC Core 1.0 section 5.3.1 reaches the same check: a refresh token sent
// as access_token is refused like one sent in the header.
func TestJwtAuthorizationHeaderToContext_PostBodyRefreshTokenRefused(t *testing.T) {
	mockTokenParser := new(mock_middleware.TokenParser)
	middleware := NewMiddlewareBearerToken(mockTokenParser)

	mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "refreshtoken", true).
		Return(&oauth.JwtToken{TokenBase64: "refreshtoken", Claims: map[string]interface{}{
			"sub": "user",
			"typ": "Refresh",
			"aud": "https://auth.example.com",
		}}, nil)

	req := httptest.NewRequest("POST", "/userinfo", strings.NewReader("access_token=refreshtoken"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	nextCalled := false
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		assert.Nil(t, r.Context().Value(constants.ContextKeyBearerToken))
	})

	middleware.JwtAuthorizationHeaderToContext()(nextHandler).ServeHTTP(httptest.NewRecorder(), req)

	assert.True(t, nextCalled)
	mockTokenParser.AssertExpectations(t)
}
