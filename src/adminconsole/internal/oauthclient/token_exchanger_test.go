package oauthclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// TokenExchanger
//
// ExchangeCodeForTokens is the admin console's entire authorization-code
// exchange: handler_auth_callback.go calls it with the code the auth server
// just redirected back with, and what it returns becomes the administrator's
// session. Until these cases it had no test anywhere, so everything below is
// written against the behaviour that ships today rather than against an
// intended one (#338).
//
// The seam is the tokenEndpoint argument, which is an httptest.Server here,
// the same shape newJwksServer uses above. These cases pass a nil client and so
// take the configured default; the injected-client seam below them, in
// token_exchanger_bounds_test.go, is where the read bound and the deadline are
// observed instead.
// =============================================================================

// recordedRequest is what the fake token endpoint saw.
type recordedRequest struct {
	method      string
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
// status and body, and returns its URL alongside the one request it recorded.
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
			contentType: r.Header.Get("Content-Type"),
			form:        form,
		})

		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server.URL, recorder
}

// -----------------------------------------------------------------------------
// The request
// -----------------------------------------------------------------------------

func TestExchangeCodeForTokens_PostsTheFormTheTokenEndpointExpects(t *testing.T) {
	endpoint, recorder := newTokenEndpoint(t, http.StatusOK, `{}`)

	_, err := NewTokenExchanger(nil).ExchangeCodeForTokens(
		context.Background(),
		"the-code",
		"https://console.example.com/auth/callback",
		"the-client-id",
		"the-client-secret",
		"the-code-verifier",
		endpoint,
	)
	require.NoError(t, err)

	seen := recorder.snapshot()
	assert.Equal(t, http.MethodPost, seen.method)
	assert.Equal(t, "application/x-www-form-urlencoded", seen.contentType)

	// Every value differs from every other, so a transposed pair fails here
	// rather than passing on a shared fixture string.
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

func TestExchangeCodeForTokens_DecodesEveryTokenResponseField(t *testing.T) {
	endpoint, _ := newTokenEndpoint(t, http.StatusOK, `{
		"access_token": "the-access-token",
		"id_token": "the-id-token",
		"token_type": "Bearer",
		"expires_in": 300,
		"refresh_token": "the-refresh-token",
		"refresh_expires_in": 1200,
		"scope": "openid email profile"
	}`)

	tokenResponse, err := NewTokenExchanger(nil).ExchangeCodeForTokens(
		context.Background(),
		"c", "r", "ci", "cs", "cv", endpoint,
	)
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
func TestExchangeCodeForTokens_AcceptsAnEmptyJSONObject(t *testing.T) {
	endpoint, _ := newTokenEndpoint(t, http.StatusOK, `{}`)

	tokenResponse, err := NewTokenExchanger(nil).ExchangeCodeForTokens(
		context.Background(),
		"c", "r", "ci", "cs", "cv", endpoint,
	)

	require.NoError(t, err)
	require.NotNil(t, tokenResponse)
	assert.Equal(t, oauth.TokenResponse{}, *tokenResponse)
}

// Refused by the json.Unmarshal error check and by nothing else: the endpoint
// answers 200 and is live, so neither the status gate nor the transport can be
// what fails this.
func TestExchangeCodeForTokens_RejectsAnEmptyBody(t *testing.T) {
	testCases := []struct {
		name string
		body string
	}{
		{"no body at all", ""},
		{"whitespace only", "   "},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			endpoint, _ := newTokenEndpoint(t, http.StatusOK, tc.body)

			tokenResponse, err := NewTokenExchanger(nil).ExchangeCodeForTokens(
				context.Background(), "c", "r", "ci", "cs", "cv", endpoint,
			)

			require.Error(t, err)
			assert.Contains(t, err.Error(), "unexpected end of JSON input")
			assert.Nil(t, tokenResponse)
		})
	}
}

// Refused by the status check and by nothing else: this body is valid JSON and
// unmarshals cleanly into a zero oauth.TokenResponse, so with the status gate removed
// the call would succeed.
func TestExchangeCodeForTokens_ReturnsTheBodyOfANon200(t *testing.T) {
	endpoint, _ := newTokenEndpoint(t, http.StatusBadRequest,
		`{"error":"invalid_grant","error_description":"the code has expired"}`)

	tokenResponse, err := NewTokenExchanger(nil).ExchangeCodeForTokens(
		context.Background(),
		"c", "r", "ci", "cs", "cv", endpoint,
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_grant")
	assert.Contains(t, err.Error(), "the code has expired")
	assert.Nil(t, tokenResponse)
}

// Refused by client.Do. The server is started and then closed, so the URL is
// well formed and the host is real: only the listener is gone, which is the one
// thing that differs from the cases above.
func TestExchangeCodeForTokens_ErrorsWhenTheEndpointIsUnreachable(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	endpoint := server.URL
	server.Close()

	tokenResponse, err := NewTokenExchanger(nil).ExchangeCodeForTokens(
		context.Background(),
		"c", "r", "ci", "cs", "cv", endpoint,
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "error sending request")
	assert.Nil(t, tokenResponse)
}
