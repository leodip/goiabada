package middleware

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/middleware/mocks"
)

// These tests drive JwtAuthorizationHeaderToContext alone, on the API surface, and own how it reads
// the two methods RFC 6750 sections 2.1 and 2.2 define: what counts as a presented credential, which
// token is validated, and what reaches the context. The whole chain on both surfaces, with the exact
// challenge and body of every refusal, is bearer_guard_chain_test.go's; the refusals here pin only
// the status and the API code, which is deliberate.

// parseGuardResult is what one request through the parse guard produced.
type parseGuardResult struct {
	rr         *httptest.ResponseRecorder
	nextCalled bool
	token      oauth.JwtToken
	present    bool
}

// serveParseGuard runs req through the API surface's parse guard with parser, recording whether the
// next handler ran and what it found in the context.
func serveParseGuard(parser tokenParser, req *http.Request) parseGuardResult {
	var result parseGuardResult
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result.nextCalled = true
		result.token, result.present = reqctx.BearerTokenFrom(r.Context())
	})
	result.rr = httptest.NewRecorder()
	NewBearerTokenForAPI(parser).JwtAuthorizationHeaderToContext()(next).ServeHTTP(result.rr, req)
	return result
}

// accessToken is a token the parse guard admits: typ Bearer, aud authserver.
func accessToken(tokenBase64 string) *oauth.JwtToken {
	return &oauth.JwtToken{TokenBase64: tokenBase64, Claims: map[string]interface{}{
		"sub": "user",
		"typ": "Bearer",
		"aud": "authserver",
	}}
}

// requireAdmitted asserts the request reached the next handler carrying tokenBase64.
func requireAdmitted(t *testing.T, result parseGuardResult, tokenBase64 string) {
	t.Helper()
	require.True(t, result.nextCalled, "the next handler must run: %s", result.rr.Body.String())
	require.True(t, result.present, "the token must reach the context")
	assert.Equal(t, tokenBase64, result.token.TokenBase64)
}

// requirePassedThroughEmpty asserts the request reached the next handler with no token, which is
// how a request presenting no credential continues to the scope guard.
func requirePassedThroughEmpty(t *testing.T, result parseGuardResult) {
	t.Helper()
	require.True(t, result.nextCalled, "no credential passes through: %s", result.rr.Body.String())
	assert.False(t, result.present, "nothing reaches the context")
}

// requireRefused asserts the parse guard answered status with the API code, and the next handler
// never ran.
func requireRefused(t *testing.T, result parseGuardResult, status int, apiCode string) {
	t.Helper()
	assert.False(t, result.nextCalled, "a refused request must not reach the next handler")
	require.Equal(t, status, result.rr.Code, result.rr.Body.String())
	var body api.ErrorResponse
	require.NoError(t, json.Unmarshal(result.rr.Body.Bytes(), &body))
	assert.Equal(t, apiCode, body.ErrorCode)
}

func assertParserNotCalled(t *testing.T, parser *middlewaremocks.TokenParser) {
	t.Helper()
	parser.AssertNotCalled(t, "DecodeAndValidateTokenString", mock.Anything, mock.Anything, mock.Anything)
}

func TestJwtAuthorizationHeaderToContext_ValidBearerToken(t *testing.T) {
	parser := new(middlewaremocks.TokenParser)
	parser.On("DecodeAndValidateTokenString", mock.Anything, "validtoken", true).Return(accessToken("validtoken"), nil)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer validtoken")

	result := serveParseGuard(parser, req)
	requireAdmitted(t, result, "validtoken")
	assert.Equal(t, "user", result.token.Claims["sub"])
	parser.AssertExpectations(t)
}

// RFC 6750 section 2.1's credentials are `"Bearer" 1*SP b64token`, ABNF whose quoted string is case
// insensitive (RFC 5234 section 2.3), and resource servers MUST support the method. Before #435
// only "Bearer " matched and every other spelling read as no credential at all.
func TestJwtAuthorizationHeaderToContext_TheSchemeIsCaseInsensitive(t *testing.T) {
	for _, header := range []string{"bearer tok", "BEARER tok", "bEaReR tok", "Bearer   tok"} {
		t.Run(header, func(t *testing.T) {
			parser := new(middlewaremocks.TokenParser)
			parser.On("DecodeAndValidateTokenString", mock.Anything, "tok", true).Return(accessToken("tok"), nil)

			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("Authorization", header)

			requireAdmitted(t, serveParseGuard(parser, req), "tok")
			parser.AssertExpectations(t)
		})
	}
}

func TestJwtAuthorizationHeaderToContext_InvalidBearerToken(t *testing.T) {
	logs := logtest.CaptureSlog(t)
	parser := new(middlewaremocks.TokenParser)
	parser.On("DecodeAndValidateTokenString", mock.Anything, "invalidtoken", true).Return(nil, assert.AnError)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer invalidtoken")

	requireRefused(t, serveParseGuard(parser, req), http.StatusUnauthorized, "INVALID_TOKEN")
	parser.AssertExpectations(t)

	records := logs.Records()
	require.Len(t, records, 1, "one record per refusal")
	assert.Equal(t, slog.LevelWarn, records[0].Level)
	assert.Contains(t, records[0].Message, "did not validate")
	assert.NotContains(t, logs.Text(), "invalidtoken", "the record carries no token material")
}

func TestJwtAuthorizationHeaderToContext_NoBearerToken(t *testing.T) {
	parser := new(middlewaremocks.TokenParser)
	requirePassedThroughEmpty(t, serveParseGuard(parser, httptest.NewRequest("GET", "/", nil)))
	assertParserNotCalled(t, parser)
}

// Another scheme presents no bearer credential, so it passes through for the scope guard to answer
// as a request carrying none. "Bearerx" is another scheme, not Bearer without its space.
func TestJwtAuthorizationHeaderToContext_AnotherSchemeIsNoCredential(t *testing.T) {
	for _, header := range []string{"NotBearer token", "Basic dXNlcjpwYXNz", "Bearertoken", "Bearer\ttoken"} {
		t.Run(header, func(t *testing.T) {
			parser := new(middlewaremocks.TokenParser)
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("Authorization", header)

			requirePassedThroughEmpty(t, serveParseGuard(parser, req))
			assertParserNotCalled(t, parser)
		})
	}
}

// The Bearer scheme with nothing after it, or only spaces, presents a credential that is empty. It
// is refused as an invalid token rather than read as absent, since the client did send one.
func TestJwtAuthorizationHeaderToContext_EmptyBearerTokenInHeader(t *testing.T) {
	for _, header := range []string{"Bearer", "Bearer ", "bearer    "} {
		t.Run(header, func(t *testing.T) {
			parser := new(middlewaremocks.TokenParser)
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("Authorization", header)

			requireRefused(t, serveParseGuard(parser, req), http.StatusUnauthorized, "INVALID_TOKEN")
			assertParserNotCalled(t, parser)
		})
	}
}

// Tests for POST body access_token extraction (RFC 6750 section 2.2, OIDC Core 1.0 section 5.3.1)

func TestJwtAuthorizationHeaderToContext_ValidPostBodyToken(t *testing.T) {
	parser := new(middlewaremocks.TokenParser)
	parser.On("DecodeAndValidateTokenString", mock.Anything, "validposttoken", true).Return(accessToken("validposttoken"), nil)

	req := httptest.NewRequest("POST", "/userinfo", strings.NewReader("access_token=validposttoken"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	requireAdmitted(t, serveParseGuard(parser, req), "validposttoken")
	parser.AssertExpectations(t)
}

func TestJwtAuthorizationHeaderToContext_InvalidPostBodyToken(t *testing.T) {
	parser := new(middlewaremocks.TokenParser)
	parser.On("DecodeAndValidateTokenString", mock.Anything, "invalidposttoken", true).Return(nil, assert.AnError)

	req := httptest.NewRequest("POST", "/userinfo", strings.NewReader("access_token=invalidposttoken"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	requireRefused(t, serveParseGuard(parser, req), http.StatusUnauthorized, "INVALID_TOKEN")
	parser.AssertExpectations(t)
}

// RFC 6750 section 2: "Clients MUST NOT use more than one method to transmit the token in each
// request", and section 3.1 names such a request invalid_request, which SHOULD be answered 400.
// Before #435 the header silently won. Neither token is validated: the request is refused for its
// shape, whatever either token is. An empty header token counts as a method used, as it does alone.
func TestJwtAuthorizationHeaderToContext_HeaderAndBodyTogetherAreInvalidRequest(t *testing.T) {
	for _, tc := range []struct{ name, header, body string }{
		{"two tokens", "Bearer headertoken", "access_token=bodytoken"},
		{"the same token twice", "Bearer tok", "access_token=tok"},
		{"an empty header token", "Bearer ", "access_token=fallbacktoken"},
		{"an empty body token", "Bearer headertoken", "access_token="},
		{"a lowercase scheme", "bearer headertoken", "access_token=bodytoken"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parser := new(middlewaremocks.TokenParser)
			req := httptest.NewRequest("POST", "/userinfo", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Authorization", tc.header)

			requireRefused(t, serveParseGuard(parser, req), http.StatusBadRequest, "INVALID_REQUEST")
			assertParserNotCalled(t, parser)
		})
	}
}

// RFC 6750 section 3.1 names a request that "repeats the same parameter" invalid_request. Before
// #435 the first access_token silently won. Refused before either copy is validated, and before the
// two-method check, so a repeated body parameter is reported as what it is whatever the header holds.
func TestJwtAuthorizationHeaderToContext_ARepeatedAccessTokenIsInvalidRequest(t *testing.T) {
	for _, tc := range []struct{ name, header, body string }{
		{"two different tokens", "", "access_token=one&access_token=two"},
		{"the same token twice", "", "access_token=tok&access_token=tok"},
		{"a token and an empty copy", "", "access_token=tok&access_token="},
		{"repeated beside a header token", "Bearer headertoken", "access_token=one&access_token=two"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parser := new(middlewaremocks.TokenParser)
			req := httptest.NewRequest("POST", "/userinfo", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}

			result := serveParseGuard(parser, req)
			requireRefused(t, result, http.StatusBadRequest, "INVALID_REQUEST")
			var body api.ErrorResponse
			require.NoError(t, json.Unmarshal(result.rr.Body.Bytes(), &body))
			assert.Equal(t, "The access_token parameter must be sent once.", body.ErrorDescription)
			assertParserNotCalled(t, parser)
		})
	}
}

// The Authorization header carries one credentials production (RFC 9110 section 11.6.2), not a
// list, so section 5.3 forbids a second field line and RFC 6750 section 3.1 names a request that "is
// otherwise malformed" invalid_request. Before #435 the first line won: a Bearer token behind a
// Basic line read as no credential, and a second token behind a Bearer line was never seen. Refused
// before either line is read, whatever the schemes, and before the body's own checks.
func TestJwtAuthorizationHeaderToContext_ARepeatedAuthorizationHeaderIsInvalidRequest(t *testing.T) {
	for _, tc := range []struct {
		name  string
		lines []string
		body  string
	}{
		{name: "two Bearer tokens", lines: []string{"Bearer one", "Bearer two"}},
		{name: "the same Bearer token twice", lines: []string{"Bearer tok", "Bearer tok"}},
		{name: "a Basic line, then a Bearer line", lines: []string{"Basic dXNlcjpwYXNz", "Bearer tok"}},
		{name: "a Bearer line, then a Basic line", lines: []string{"Bearer tok", "Basic dXNlcjpwYXNz"}},
		{name: "two Basic lines", lines: []string{"Basic dXNlcjpwYXNz", "Basic dXNlcjpwYXNz"}},
		{name: "two Bearer tokens beside a repeated body token", lines: []string{"Bearer one", "Bearer two"},
			body: "access_token=three&access_token=four"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := logtest.CaptureSlog(t)
			parser := new(middlewaremocks.TokenParser)
			req := httptest.NewRequest("GET", "/userinfo", nil)
			if tc.body != "" {
				req = httptest.NewRequest("POST", "/userinfo", strings.NewReader(tc.body))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			for _, line := range tc.lines {
				req.Header.Add("Authorization", line)
			}

			result := serveParseGuard(parser, req)
			requireRefused(t, result, http.StatusBadRequest, "INVALID_REQUEST")
			var body api.ErrorResponse
			require.NoError(t, json.Unmarshal(result.rr.Body.Bytes(), &body))
			assert.Equal(t, "The Authorization header must be sent once.", body.ErrorDescription)
			assertParserNotCalled(t, parser)

			records := logs.Records()
			require.Len(t, records, 1, "one record per refusal")
			assert.Equal(t, slog.LevelWarn, records[0].Level)
			assert.Contains(t, records[0].Message, "authorization header was repeated")
		})
	}
}

// A form body that does not parse is refused as invalid_request before either method is looked at:
// RFC 6750 section 3.1 names a request that "is otherwise malformed" invalid_request. url.ParseQuery
// keeps the pairs it could read, so before this a valid header beside a malformed body carrying a
// second token was admitted as though one method had been used, and a body token beside a malformed
// pair passed through as no credential at all. A body cut at the request-body limit is the same
// refusal, as it is at the token endpoint (#426). Nothing is validated, whatever either token is.
//
// A form media type whose parameters do not parse is the same refusal, in any case: ParseForm
// reports it, whether it read the body (a parameter with no value) or not (a parameter given twice
// with two values). Passed over instead, the body beside a valid header would go unread.
func TestJwtAuthorizationHeaderToContext_ABodyThatDoesNotParseIsInvalidRequest(t *testing.T) {
	for _, tc := range []struct {
		name, header, contentType, body string
		limit                           int64
	}{
		{name: "a valid header beside a malformed body carrying a token", header: "Bearer headertoken", body: "access_token=bodytoken&junk=%GG"},
		{name: "a valid header beside a malformed body carrying no token", header: "Bearer headertoken", body: "junk=%GG"},
		{name: "a body token beside a malformed pair", body: "access_token=bodytoken&junk=%GG"},
		{name: "a malformed token pair", body: "access_token=%GG"},
		{name: "a malformed body and no credential", body: "%GG"},
		{name: "a body cut at the request-body limit", header: "Bearer headertoken", body: "access_token=" + strings.Repeat("a", 64), limit: 16},
		{name: "a form media type with a parameter that has no value", header: "Bearer headertoken",
			contentType: "application/x-www-form-urlencoded; charset", body: "access_token=bodytoken"},
		{name: "a form media type in capitals with a parameter that has no value", header: "Bearer headertoken",
			contentType: "APPLICATION/X-WWW-FORM-URLENCODED; charset", body: "access_token=bodytoken"},
		{name: "a form media type with one parameter given two values", header: "Bearer headertoken",
			contentType: "Application/X-WWW-Form-Urlencoded; charset=utf-8; charset=latin1", body: "access_token=bodytoken"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := logtest.CaptureSlog(t)
			parser := new(middlewaremocks.TokenParser)
			req := httptest.NewRequest("POST", "/userinfo", strings.NewReader(tc.body))
			contentType := tc.contentType
			if contentType == "" {
				contentType = "application/x-www-form-urlencoded"
			}
			req.Header.Set("Content-Type", contentType)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			if tc.limit > 0 {
				req.Body = http.MaxBytesReader(httptest.NewRecorder(), req.Body, tc.limit)
			}

			result := serveParseGuard(parser, req)
			requireRefused(t, result, http.StatusBadRequest, "INVALID_REQUEST")
			var body api.ErrorResponse
			require.NoError(t, json.Unmarshal(result.rr.Body.Bytes(), &body))
			assert.Equal(t, "The request body could not be parsed.", body.ErrorDescription)
			assertParserNotCalled(t, parser)

			records := logs.Records()
			require.Len(t, records, 1, "one record per refusal")
			assert.Equal(t, slog.LevelWarn, records[0].Level)
			assert.Contains(t, records[0].Message, "could not be parsed")
		})
	}
}

// A Basic header beside a body token is one bearer method, not two: Basic is not a way of sending a
// bearer token.
func TestJwtAuthorizationHeaderToContext_BasicHeaderBesideABodyTokenIsOneMethod(t *testing.T) {
	parser := new(middlewaremocks.TokenParser)
	parser.On("DecodeAndValidateTokenString", mock.Anything, "bodytoken", true).Return(accessToken("bodytoken"), nil)

	req := httptest.NewRequest("POST", "/userinfo", strings.NewReader("access_token=bodytoken"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")

	requireAdmitted(t, serveParseGuard(parser, req), "bodytoken")
	parser.AssertExpectations(t)
}

func TestJwtAuthorizationHeaderToContext_PostBodyIgnoredForGetRequest(t *testing.T) {
	parser := new(middlewaremocks.TokenParser)

	// GET request with access_token in query string should NOT extract the token
	req := httptest.NewRequest("GET", "/userinfo?access_token=gettoken", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	requirePassedThroughEmpty(t, serveParseGuard(parser, req))
	assertParserNotCalled(t, parser)
}

// A POST that carries the token only in its query is the one request where the two accessors
// disagree: ParseForm merges the URL query behind the body, so r.Form would hold the query value
// here and put a token that has travelled in a request target into the context, while r.PostForm
// does not and the request goes on unauthenticated. RFC 6750 section 2.3 says the URI query method
// "has a high likelihood of being logged", and RFC 9700 section 4.3.2 makes it "Clients MUST NOT
// pass access tokens in a URI query parameter".
//
// The GET case above does not pin this: it is refused by the method check and never reaches the
// read at all. This is the case that fails if the accessor regresses (#333).
func TestJwtAuthorizationHeaderToContext_PostQueryTokenIgnored(t *testing.T) {
	parser := new(middlewaremocks.TokenParser)

	// A genuine form submission whose body does not carry the token, with the token in the query.
	req := httptest.NewRequest("POST", "/userinfo?access_token=querytoken", strings.NewReader("other_param=value"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	requirePassedThroughEmpty(t, serveParseGuard(parser, req))
	assertParserNotCalled(t, parser)
}

// A query token is no method this server supports, so a header token beside one is one method, not
// two, and is admitted.
func TestJwtAuthorizationHeaderToContext_HeaderBesideAQueryTokenIsOneMethod(t *testing.T) {
	parser := new(middlewaremocks.TokenParser)
	parser.On("DecodeAndValidateTokenString", mock.Anything, "headertoken", true).Return(accessToken("headertoken"), nil)

	req := httptest.NewRequest("POST", "/userinfo?access_token=querytoken", strings.NewReader("other_param=value"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer headertoken")

	requireAdmitted(t, serveParseGuard(parser, req), "headertoken")
	parser.AssertExpectations(t)
}

func TestJwtAuthorizationHeaderToContext_PostBodyIgnoredForWrongContentType(t *testing.T) {
	parser := new(middlewaremocks.TokenParser)

	req := httptest.NewRequest("POST", "/userinfo", strings.NewReader("access_token=jsontoken"))
	req.Header.Set("Content-Type", "application/json")

	requirePassedThroughEmpty(t, serveParseGuard(parser, req))
	assertParserNotCalled(t, parser)
}

// An access_token parameter supplied empty is a presented token, empty, and refused as invalid
// without reaching the parser; before #435 it read as absent.
func TestJwtAuthorizationHeaderToContext_PostBodyEmptyAccessToken(t *testing.T) {
	parser := new(middlewaremocks.TokenParser)

	req := httptest.NewRequest("POST", "/userinfo", strings.NewReader("access_token="))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	requireRefused(t, serveParseGuard(parser, req), http.StatusUnauthorized, "INVALID_TOKEN")
	assertParserNotCalled(t, parser)
}

func TestJwtAuthorizationHeaderToContext_PostBodyNoAccessTokenParameter(t *testing.T) {
	parser := new(middlewaremocks.TokenParser)

	req := httptest.NewRequest("POST", "/userinfo", strings.NewReader("other_param=value"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	requirePassedThroughEmpty(t, serveParseGuard(parser, req))
	assertParserNotCalled(t, parser)
}

func TestJwtAuthorizationHeaderToContext_PostBodyContentTypeWithCharset(t *testing.T) {
	parser := new(middlewaremocks.TokenParser)
	parser.On("DecodeAndValidateTokenString", mock.Anything, "charsettoken", true).Return(accessToken("charsettoken"), nil)

	req := httptest.NewRequest("POST", "/userinfo", strings.NewReader("access_token=charsettoken"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")

	requireAdmitted(t, serveParseGuard(parser, req), "charsettoken")
	parser.AssertExpectations(t)
}

// A media type is case-insensitive (RFC 9110 section 8.3.1), and net/http's ParseForm reads the body
// of every spelling mime.ParseMediaType normalizes to the form type. The guard must see a body token
// in exactly those bodies, or a second token sent in one beside the header is never looked at and
// the header is admitted, which is what a media type in capitals did before (#435). Each spelling is
// sent beside a header token, refused as two methods, and alone, admitted.
//
// The dotted capital I is the row strings.EqualFold would get wrong: strings.ToLower, which mime
// applies, folds it to i, and ParseForm reads the body. The two Content-Type field lines are read as
// ParseForm reads them, through Header.Get, so the first decides.
func TestJwtAuthorizationHeaderToContext_EverySpellingOfTheFormMediaTypeIsAForm(t *testing.T) {
	for _, tc := range []struct {
		name         string
		contentTypes []string
	}{
		{"in capitals", []string{"APPLICATION/X-WWW-FORM-URLENCODED"}},
		{"in mixed case with a charset", []string{"Application/X-Www-Form-Urlencoded; charset=UTF-8"}},
		{"with space around the type", []string{" application/x-www-form-urlencoded ; charset=utf-8"}},
		{"with a dotted capital I", []string{"applİcation/x-www-form-urlencoded"}},
		{"in capitals, first of two Content-Type lines", []string{"APPLICATION/X-WWW-FORM-URLENCODED", "application/json"}},
	} {
		newRequest := func(t *testing.T) *http.Request {
			req := httptest.NewRequest("POST", "/userinfo", strings.NewReader("access_token=bodytoken"))
			req.Header["Content-Type"] = tc.contentTypes
			require.NoError(t, req.ParseForm(), "net/http reads this body as a form")
			require.Equal(t, "bodytoken", req.PostForm.Get("access_token"))
			// The guard parses the body itself; hand it one it has not seen.
			fresh := httptest.NewRequest("POST", "/userinfo", strings.NewReader("access_token=bodytoken"))
			fresh.Header["Content-Type"] = tc.contentTypes
			return fresh
		}

		t.Run(tc.name+", beside a header token", func(t *testing.T) {
			parser := new(middlewaremocks.TokenParser)
			req := newRequest(t)
			req.Header.Set("Authorization", "Bearer headertoken")

			result := serveParseGuard(parser, req)
			requireRefused(t, result, http.StatusBadRequest, "INVALID_REQUEST")
			var body api.ErrorResponse
			require.NoError(t, json.Unmarshal(result.rr.Body.Bytes(), &body))
			assert.Equal(t, "The access token must be sent by one method only.", body.ErrorDescription)
			assertParserNotCalled(t, parser)
		})

		t.Run(tc.name+", alone", func(t *testing.T) {
			parser := new(middlewaremocks.TokenParser)
			parser.On("DecodeAndValidateTokenString", mock.Anything, "bodytoken", true).Return(accessToken("bodytoken"), nil)

			requireAdmitted(t, serveParseGuard(parser, newRequest(t)), "bodytoken")
			parser.AssertExpectations(t)
		})
	}
}

func TestJwtAuthorizationHeaderToContext_PostBodyWithOtherParameters(t *testing.T) {
	parser := new(middlewaremocks.TokenParser)
	parser.On("DecodeAndValidateTokenString", mock.Anything, "tokenwithotherparams", true).Return(accessToken("tokenwithotherparams"), nil)

	req := httptest.NewRequest("POST", "/userinfo", strings.NewReader("param1=value1&access_token=tokenwithotherparams&param2=value2"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	requireAdmitted(t, serveParseGuard(parser, req), "tokenwithotherparams")
	parser.AssertExpectations(t)
}

func TestJwtAuthorizationHeaderToContext_PutRequestIgnoresPostBody(t *testing.T) {
	parser := new(middlewaremocks.TokenParser)

	// PUT request should NOT extract token from body
	req := httptest.NewRequest("PUT", "/userinfo", strings.NewReader("access_token=puttoken"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	requirePassedThroughEmpty(t, serveParseGuard(parser, req))
	assertParserNotCalled(t, parser)
}

// TestJwtAuthorizationHeaderToContext_TokenKindAndAudience is the bearer table of #401: a validly
// signed token reaches the context only when it is an access token (typ Bearer) whose aud names
// authserver. Every refused row is answered 401 invalid_token by the guard itself, exactly as a
// token that does not parse, and the next handler never runs (#435).
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
			logs := logtest.CaptureSlog(t)
			parser := new(middlewaremocks.TokenParser)

			claims := map[string]interface{}{"sub": "user"}
			if tc.typ != nil {
				claims["typ"] = tc.typ
			}
			if tc.aud != nil {
				claims["aud"] = tc.aud
			}
			parser.On("DecodeAndValidateTokenString", mock.Anything, "the-signed-token", true).
				Return(&oauth.JwtToken{TokenBase64: "the-signed-token", Claims: claims}, nil)

			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("Authorization", "Bearer the-signed-token")

			result := serveParseGuard(parser, req)
			parser.AssertExpectations(t)

			if tc.admitted {
				requireAdmitted(t, result, "the-signed-token")
				assert.Empty(t, logs.Records(), "an admitted token writes no record")
				return
			}

			requireRefused(t, result, http.StatusUnauthorized, "INVALID_TOKEN")
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
	parser := new(middlewaremocks.TokenParser)
	parser.On("DecodeAndValidateTokenString", mock.Anything, "refreshtoken", true).
		Return(&oauth.JwtToken{TokenBase64: "refreshtoken", Claims: map[string]interface{}{
			"sub": "user",
			"typ": "Refresh",
			"aud": "https://auth.example.com",
		}}, nil)

	req := httptest.NewRequest("POST", "/userinfo", strings.NewReader("access_token=refreshtoken"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	requireRefused(t, serveParseGuard(parser, req), http.StatusUnauthorized, "INVALID_TOKEN")
	parser.AssertExpectations(t)
}
