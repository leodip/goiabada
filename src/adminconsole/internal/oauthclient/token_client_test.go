package oauthclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// TokenClient
//
// ExchangeCode is the admin console's entire authorization-code exchange:
// handler_auth_callback.go calls it with the code the auth server just
// redirected back with, and what it returns becomes the administrator's
// session. The client is built once with the token URL, the client id and the
// secret, so the callback names none of them (#338, #441).
//
// The seam is the token URL, which is an httptest.Server here, the same shape
// newJwksServer uses. These cases pass a nil client and so take the configured
// default; the injected-client seam in token_client_bounds_test.go is where the
// read bound, the deadline and the detachment are observed instead.
// =============================================================================

// recordedRequest is what the fake token endpoint saw.
type recordedRequest struct {
	method      string
	path        string
	contentType string
	form        url.Values
}

// requestRecorder guards it. The handler runs on the server's own goroutine and
// the assertions run on the test's, and a socket is not a synchronisation edge
// the race detector can see, so the mutex is what makes this safe under the
// race leg rather than the ordering of the exchange.
type requestRecorder struct {
	mu   sync.Mutex
	seen recordedRequest
}

func (rr *requestRecorder) put(seen recordedRequest) {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	rr.seen = seen
}

func (rr *requestRecorder) snapshot() recordedRequest {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	return rr.seen
}

// newTokenEndpoint starts a server answering every request with the given
// status and body, and returns the token URL on it alongside the one request it
// recorded.
func newTokenEndpoint(t *testing.T, status int, body string) (string, *requestRecorder) {
	t.Helper()
	recorder := &requestRecorder{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		form, err := url.ParseQuery(string(raw))
		assert.NoError(t, err)

		recorder.put(recordedRequest{
			method:      r.Method,
			path:        r.URL.Path,
			contentType: r.Header.Get("Content-Type"),
			form:        form,
		})

		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server.URL + "/auth/token", recorder
}

// exchangeAgainst builds a client for tokenURL with a nil HTTP client and exchanges
// throwaway values: the cases using it are about the answer, not the request.
func exchangeAgainst(tokenURL string) (*oauth.TokenResponse, error) {
	return NewTokenClient(tokenURL, "ci", "cs", nil).
		ExchangeCode(context.Background(), "c", "r", "cv")
}

// -----------------------------------------------------------------------------
// The request
// -----------------------------------------------------------------------------

func TestExchangeCode_PostsTheFormTheTokenEndpointExpects(t *testing.T) {
	tokenURL, recorder := newTokenEndpoint(t, http.StatusOK, `{}`)

	_, err := NewTokenClient(tokenURL, "the-client-id", "the-client-secret", nil).ExchangeCode(
		context.Background(),
		"the-code",
		"https://console.example.com/auth/callback",
		"the-code-verifier",
	)
	require.NoError(t, err)

	seen := recorder.snapshot()
	assert.Equal(t, http.MethodPost, seen.method)
	assert.Equal(t, "/auth/token", seen.path, "posted to the token URL the client was built with")
	assert.Equal(t, "application/x-www-form-urlencoded", seen.contentType)

	// Every value differs from every other, so a transposed pair fails here
	// rather than passing on a shared fixture string. The client id and the secret
	// come from construction and the other three from the call.
	assert.Equal(t, "authorization_code", seen.form.Get("grant_type"))
	assert.Equal(t, "the-code", seen.form.Get("code"))
	assert.Equal(t, "https://console.example.com/auth/callback", seen.form.Get("redirect_uri"))
	assert.Equal(t, "the-client-id", seen.form.Get("client_id"))
	assert.Equal(t, "the-client-secret", seen.form.Get("client_secret"))
	assert.Equal(t, "the-code-verifier", seen.form.Get("code_verifier"))

	// Exactly those six: a parameter added without a test is what this catches.
	keys := make([]string, 0, len(seen.form))
	for key := range seen.form {
		keys = append(keys, key)
	}
	assert.ElementsMatch(t, []string{
		"grant_type", "code", "redirect_uri", "client_id", "client_secret", "code_verifier",
	}, keys)
}

// -----------------------------------------------------------------------------
// The response
// -----------------------------------------------------------------------------

func TestExchangeCode_DecodesEveryTokenResponseField(t *testing.T) {
	tokenURL, _ := newTokenEndpoint(t, http.StatusOK, `{
		"access_token": "the-access-token",
		"id_token": "the-id-token",
		"token_type": "Bearer",
		"expires_in": 300,
		"refresh_token": "the-refresh-token",
		"refresh_expires_in": 1200,
		"scope": "openid email profile"
	}`)

	tokenResponse, err := exchangeAgainst(tokenURL)
	require.NoError(t, err)
	require.NotNil(t, tokenResponse)

	// Field by field rather than against a struct literal: a field added to
	// oauth.TokenResponse later leaves a gap here that reads as a gap.
	assert.Equal(t, "the-access-token", tokenResponse.AccessToken)
	assert.Equal(t, "the-id-token", tokenResponse.IdToken)
	assert.Equal(t, "Bearer", tokenResponse.TokenType)
	assert.Equal(t, int64(300), tokenResponse.ExpiresIn)
	assert.Equal(t, "the-refresh-token", tokenResponse.RefreshToken)
	assert.Equal(t, int64(1200), tokenResponse.RefreshExpiresIn)
	assert.Equal(t, "openid email profile", tokenResponse.Scope)
}

// The benign member of the parse-failure class. It is here so the case below
// cannot be read as "any short body is refused": {} is short and is accepted.
func TestExchangeCode_AcceptsAnEmptyJSONObject(t *testing.T) {
	tokenURL, _ := newTokenEndpoint(t, http.StatusOK, `{}`)

	tokenResponse, err := exchangeAgainst(tokenURL)

	require.NoError(t, err)
	require.NotNil(t, tokenResponse)
	assert.Equal(t, oauth.TokenResponse{}, *tokenResponse)
}

// Refused by the json.Unmarshal error check and by nothing else: the endpoint
// answers 200 and is live, so neither the status gate nor the transport can be
// what fails this.
func TestExchangeCode_RejectsAnEmptyBody(t *testing.T) {
	testCases := []struct {
		name string
		body string
	}{
		{"no body at all", ""},
		{"whitespace only", "   "},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tokenURL, _ := newTokenEndpoint(t, http.StatusOK, tc.body)

			tokenResponse, err := exchangeAgainst(tokenURL)

			require.Error(t, err)
			assert.Contains(t, err.Error(), "unexpected end of JSON input")
			assert.Nil(t, tokenResponse)
		})
	}
}

// Refused by client.Do. The server is started and then closed, so the URL is
// well formed and the host is real: only the listener is gone, which is the one
// thing that differs from the cases above. It is not a refusal: nothing answered.
func TestExchangeCode_ErrorsWhenTheEndpointIsUnreachable(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	tokenURL := server.URL + "/auth/token"
	server.Close()

	tokenResponse, err := exchangeAgainst(tokenURL)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "error sending request")
	var refusal *TokenEndpointError
	assert.False(t, errors.As(err, &refusal), "an endpoint that never answered did not refuse anything")
	assert.Nil(t, tokenResponse)
}

// -----------------------------------------------------------------------------
// The refusal, decision 3 of #441
//
// Anything but a 200 from /auth/token is one error type, whichever grant asked:
// the status, and the answer's error and error_description (RFC 6749 section
// 5.2), each conformed to Appendix A's error_description characters and bounded
// at 512 bytes. The raw body is never part of it, because what this error says
// is logged, and the body is up to a mebibyte of text from the peer.
// -----------------------------------------------------------------------------

// Refused by the status check and by nothing else: this body is valid JSON and
// unmarshals cleanly into a zero oauth.TokenResponse, so with the status gate
// removed the call would succeed.
func TestExchangeCode_ARefusalCarriesTheStatusTheErrorAndItsDescription(t *testing.T) {
	tokenURL, _ := newTokenEndpoint(t, http.StatusBadRequest,
		`{"error":"invalid_grant","error_description":"the code has expired"}`)

	tokenResponse, err := exchangeAgainst(tokenURL)

	require.Error(t, err)
	assert.Nil(t, tokenResponse)

	var refusal *TokenEndpointError
	require.True(t, errors.As(err, &refusal), "a caller can match the refusal: %v", err)
	assert.Equal(t, http.StatusBadRequest, refusal.StatusCode)
	assert.Equal(t, "invalid_grant", refusal.ErrorCode)
	assert.Equal(t, "the code has expired", refusal.ErrorDescription)
	assert.Equal(t,
		"the auth server's token endpoint answered 400 (invalid_grant: the code has expired)",
		err.Error())
}

// The message drops what the answer did not carry rather than printing an empty
// slot for it.
func TestExchangeCode_ARefusalMessageNamesOnlyWhatTheAnswerCarried(t *testing.T) {
	testCases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{
			name:   "an error and no description",
			status: http.StatusUnauthorized,
			body:   `{"error":"invalid_client"}`,
			want:   "the auth server's token endpoint answered 401 (invalid_client)",
		},
		{
			name:   "a description and no error",
			status: http.StatusBadRequest,
			body:   `{"error_description":"no grant type"}`,
			want:   "the auth server's token endpoint answered 400 (no grant type)",
		},
		{
			name:   "an empty JSON object",
			status: http.StatusInternalServerError,
			body:   `{}`,
			want:   "the auth server's token endpoint answered 500",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tokenURL, _ := newTokenEndpoint(t, tc.status, tc.body)

			_, err := exchangeAgainst(tokenURL)

			require.Error(t, err)
			assert.Equal(t, tc.want, err.Error())
		})
	}
}

// A body that is not the RFC 6749 error object -- a proxy's HTML page, a stack trace --
// is refused on its status alone, and none of its text reaches the message. Before
// #441 the whole body was the message.
func TestExchangeCode_ARefusalNeverCarriesTheRawBody(t *testing.T) {
	testCases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{
			name:   "not JSON",
			status: http.StatusBadGateway,
			body:   "<html><body>upstream secret-peer-text</body></html>",
			want:   "the auth server's token endpoint answered 502",
		},
		{
			name:   "JSON with members beyond the two",
			status: http.StatusBadRequest,
			body:   `{"error":"invalid_grant","trace":"secret-peer-text"}`,
			want:   "the auth server's token endpoint answered 400 (invalid_grant)",
		},
		{
			name:   "JSON whose error is not a string",
			status: http.StatusBadRequest,
			body:   `{"error":{"nested":"secret-peer-text"}}`,
			want:   "the auth server's token endpoint answered 400",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tokenURL, _ := newTokenEndpoint(t, tc.status, tc.body)

			_, err := exchangeAgainst(tokenURL)

			require.Error(t, err)
			var refusal *TokenEndpointError
			require.True(t, errors.As(err, &refusal))
			assert.Equal(t, tc.status, refusal.StatusCode)
			assert.Equal(t, tc.want, err.Error())
			assert.NotContains(t, err.Error(), "secret-peer-text")
		})
	}
}

// Both values are the peer's text and both are conformed: a forbidden character
// becomes '?' and the result stops at 512 bytes, the last three of them "...".
// The description here carries a newline, which would split a log line, and runs
// to 600 bytes, so neither reaches the message whole.
func TestExchangeCode_ARefusalIsConformedAndBounded(t *testing.T) {
	description := "line one\nline two " + strings.Repeat("x", 600)
	tokenURL, _ := newTokenEndpoint(t, http.StatusBadRequest,
		`{"error":"invalid\"grant","error_description":"line one\nline two `+strings.Repeat("x", 600)+`"}`)

	_, err := exchangeAgainst(tokenURL)

	require.Error(t, err)
	var refusal *TokenEndpointError
	require.True(t, errors.As(err, &refusal))

	// '"' is outside Appendix A's error_description set, as is the newline.
	assert.Equal(t, "invalid?grant", refusal.ErrorCode)

	// "line one?line two " is 18 bytes, so 491 x's fill the 509 before the ellipsis.
	wantDescription := "line one?line two " + strings.Repeat("x", 491) + "..."
	require.Len(t, wantDescription, 512)
	assert.Equal(t, wantDescription, refusal.ErrorDescription)

	assert.NotContains(t, err.Error(), "\n", "the newline the peer sent does not split a log line")
	assert.NotContains(t, err.Error(), description, "the description does not reach the message whole")
	assert.Equal(t, "the auth server's token endpoint answered 400 (invalid?grant: "+wantDescription+")",
		err.Error())
}
