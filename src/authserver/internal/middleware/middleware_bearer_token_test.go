package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mock_middleware "github.com/leodip/goiabada/authserver/internal/middleware/mocks"
)

func TestJwtAuthorizationHeaderToContext_ValidBearerToken(t *testing.T) {
	mockTokenParser := new(mock_middleware.TokenParser)
	middleware := NewMiddlewareBearerToken(mockTokenParser)

	expectedToken := &oauth.JwtToken{
		TokenBase64: "validtoken",
		Claims: map[string]interface{}{
			"sub": "user",
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
