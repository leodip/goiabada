package oauthclient

import (
	"context"
	"encoding/json"
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
// session. Refresh is the JWT middleware's refresh grant, sent when the stored
// access token is due. ClientCredentials is the grant SessionTokenSource caches,
// the bearer the console's browser-session storage presents. The client is built
// once with the token URL, the client id and the secret, so no caller names any
// of them (#338, #441).
//
// The three grants share the transport, the read bound and the refusal, so the
// cases about those run once per grant, over grants below. What differs, the form
// each posts, Refresh's kept refresh token and the client-credentials refusal's
// client id and remedy, has cases of its own.
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

// grant is one of the token client's grants, sent with throwaway values: the cases
// running over grants are about the answer, not the request. refusalSuffix is what
// the grant appends to the shared refusal's message, which only client_credentials
// does: it names the client the token was refused for (#266, #441 decision 3).
type grant struct {
	name          string
	send          func(ctx context.Context, c *TokenClient) (*oauth.TokenResponse, error)
	refusalSuffix string
}

var grants = []grant{
	{name: "authorization_code", send: func(ctx context.Context, c *TokenClient) (*oauth.TokenResponse, error) {
		return c.ExchangeCode(ctx, "c", "r", "cv")
	}},
	{name: "refresh_token", send: func(ctx context.Context, c *TokenClient) (*oauth.TokenResponse, error) {
		return c.Refresh(ctx, "rt")
	}},
	{name: "client_credentials", send: func(ctx context.Context, c *TokenClient) (*oauth.TokenResponse, error) {
		return c.ClientCredentials(ctx, "s")
	}, refusalSuffix: ` for client_id "ci"`},
}

// singleUseGrants are the two grants the auth server spends as it answers, which is
// what detaches them from their caller's cancellation. client_credentials spends
// nothing, so it keeps its caller's.
var singleUseGrants = grants[:2]

// sendAgainst builds a client for tokenURL with a nil HTTP client and sends g.
func (g grant) sendAgainst(tokenURL string) (*oauth.TokenResponse, error) {
	return g.send(context.Background(), NewTokenClient(tokenURL, "ci", "cs", nil, nil))
}

// exchangeAgainst is the authorization-code grant's sendAgainst, for the cases about
// what only the exchange answers.
func exchangeAgainst(tokenURL string) (*oauth.TokenResponse, error) {
	return grants[0].sendAgainst(tokenURL)
}

// formKeys is the set of parameter names a form carried.
func formKeys(form url.Values) []string {
	keys := make([]string, 0, len(form))
	for key := range form {
		keys = append(keys, key)
	}
	return keys
}

// -----------------------------------------------------------------------------
// The request
// -----------------------------------------------------------------------------

func TestExchangeCode_PostsTheFormTheTokenEndpointExpects(t *testing.T) {
	tokenURL, recorder := newTokenEndpoint(t, http.StatusOK, `{}`)

	_, err := NewTokenClient(tokenURL, "the-client-id", "the-client-secret", nil, nil).ExchangeCode(
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
	assert.ElementsMatch(t, []string{
		"grant_type", "code", "redirect_uri", "client_id", "client_secret", "code_verifier",
	}, formKeys(seen.form))
}

// The refresh grant's form is RFC 6749 section 6's, with the client authenticated in
// the body as every grant of this client does (#441 decision 7). It is the form the
// middleware posted before #441, parameter for parameter.
func TestRefresh_PostsTheFormTheTokenEndpointExpects(t *testing.T) {
	tokenURL, recorder := newTokenEndpoint(t, http.StatusOK, `{}`)

	_, err := NewTokenClient(tokenURL, "the-client-id", "the-client-secret", nil, nil).
		Refresh(context.Background(), "the-refresh-token")
	require.NoError(t, err)

	seen := recorder.snapshot()
	assert.Equal(t, http.MethodPost, seen.method)
	assert.Equal(t, "/auth/token", seen.path, "posted to the token URL the client was built with")
	assert.Equal(t, "application/x-www-form-urlencoded", seen.contentType)

	assert.Equal(t, "refresh_token", seen.form.Get("grant_type"))
	assert.Equal(t, "the-refresh-token", seen.form.Get("refresh_token"))
	assert.Equal(t, "the-client-id", seen.form.Get("client_id"))
	assert.Equal(t, "the-client-secret", seen.form.Get("client_secret"))

	// Exactly those four: no scope, so the grant is the one originally granted.
	assert.ElementsMatch(t, []string{
		"grant_type", "refresh_token", "client_id", "client_secret",
	}, formKeys(seen.form))
}

// The client-credentials grant's form is RFC 6749 section 4.4.2's, with the scope the
// caller asks for and the client authenticated in the body (#441 decision 7). It is the
// form SessionTokenSource posted before #441, parameter for parameter.
func TestClientCredentials_PostsTheFormTheTokenEndpointExpects(t *testing.T) {
	tokenURL, recorder := newTokenEndpoint(t, http.StatusOK, `{"access_token":"at"}`)

	_, err := NewTokenClient(tokenURL, "the-client-id", "the-client-secret", nil, nil).
		ClientCredentials(context.Background(), "the-resource:the-permission")
	require.NoError(t, err)

	seen := recorder.snapshot()
	assert.Equal(t, http.MethodPost, seen.method)
	assert.Equal(t, "/auth/token", seen.path, "posted to the token URL the client was built with")
	assert.Equal(t, "application/x-www-form-urlencoded", seen.contentType)

	assert.Equal(t, "client_credentials", seen.form.Get("grant_type"))
	assert.Equal(t, "the-client-id", seen.form.Get("client_id"))
	assert.Equal(t, "the-client-secret", seen.form.Get("client_secret"))
	assert.Equal(t, "the-resource:the-permission", seen.form.Get("scope"))

	assert.ElementsMatch(t, []string{
		"grant_type", "client_id", "client_secret", "scope",
	}, formKeys(seen.form))
}

// -----------------------------------------------------------------------------
// The response
// -----------------------------------------------------------------------------

func TestTokenClient_DecodesEveryTokenResponseField(t *testing.T) {
	for _, g := range grants {
		t.Run(g.name, func(t *testing.T) {
			tokenURL, _ := newTokenEndpoint(t, http.StatusOK, `{
				"access_token": "the-access-token",
				"id_token": "the-id-token",
				"token_type": "Bearer",
				"expires_in": 300,
				"refresh_token": "the-refresh-token",
				"refresh_expires_in": 1200,
				"scope": "openid email profile"
			}`)

			tokenResponse, err := g.sendAgainst(tokenURL)
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
		})
	}
}

// RFC 6749 section 6: the auth server "MAY issue a new refresh token, in which case
// the client MUST discard the old refresh token". One that issues none leaves the old
// one the client's, and returning the answer as it came would have the caller store
// it away as empty and sign the administrator out at the next refresh.
// golang.org/x/oauth2 keeps it the same way (#427, #441 decision 2).
func TestRefresh_KeepsTheOldRefreshTokenWhenTheAnswerCarriesNone(t *testing.T) {
	testCases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "the answer issues a new one, which replaces the old",
			body: `{"access_token":"the-new-access-token","refresh_token":"the-new-refresh-token"}`,
			want: "the-new-refresh-token",
		},
		{
			name: "the answer has no refresh_token member",
			body: `{"access_token":"the-new-access-token"}`,
			want: "the-old-refresh-token",
		},
		{
			name: "the answer's refresh_token is empty",
			body: `{"access_token":"the-new-access-token","refresh_token":""}`,
			want: "the-old-refresh-token",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tokenURL, _ := newTokenEndpoint(t, http.StatusOK, tc.body)

			tokenResponse, err := NewTokenClient(tokenURL, "ci", "cs", nil, nil).
				Refresh(context.Background(), "the-old-refresh-token")

			require.NoError(t, err)
			require.NotNil(t, tokenResponse)
			assert.Equal(t, "the-new-access-token", tokenResponse.AccessToken)
			assert.Equal(t, tc.want, tokenResponse.RefreshToken)
		})
	}
}

// The kept token is the refresh grant's alone: an exchange answering with none has
// no old one to keep, and the session it starts is simply not refreshable.
func TestExchangeCode_AnAnswerWithNoRefreshTokenStaysWithout(t *testing.T) {
	tokenURL, _ := newTokenEndpoint(t, http.StatusOK, `{"access_token":"the-access-token"}`)

	tokenResponse, err := exchangeAgainst(tokenURL)

	require.NoError(t, err)
	require.NotNil(t, tokenResponse)
	assert.Empty(t, tokenResponse.RefreshToken)
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
func TestTokenClient_RejectsAnEmptyBody(t *testing.T) {
	testCases := []struct {
		name string
		body string
	}{
		{"no body at all", ""},
		{"whitespace only", "   "},
	}

	for _, g := range grants {
		for _, tc := range testCases {
			t.Run(g.name+"/"+tc.name, func(t *testing.T) {
				tokenURL, _ := newTokenEndpoint(t, http.StatusOK, tc.body)

				tokenResponse, err := g.sendAgainst(tokenURL)

				require.Error(t, err)
				assert.Contains(t, err.Error(), "unexpected end of JSON input")
				assert.Nil(t, tokenResponse)
			})
		}
	}
}

// Refused by client.Do. The server is started and then closed, so the URL is
// well formed and the host is real: only the listener is gone, which is the one
// thing that differs from the cases above. It is not a refusal: nothing answered.
func TestTokenClient_ErrorsWhenTheEndpointIsUnreachable(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	tokenURL := server.URL + "/auth/token"
	server.Close()

	for _, g := range grants {
		t.Run(g.name, func(t *testing.T) {
			tokenResponse, err := g.sendAgainst(tokenURL)

			require.Error(t, err)
			assert.Contains(t, err.Error(), "error sending request")
			var refusal *TokenEndpointError
			assert.False(t, errors.As(err, &refusal), "an endpoint that never answered did not refuse anything")
			assert.Nil(t, tokenResponse)
		})
	}
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
func TestTokenClient_ARefusalCarriesTheStatusTheErrorAndItsDescription(t *testing.T) {
	for _, g := range grants {
		t.Run(g.name, func(t *testing.T) {
			tokenURL, _ := newTokenEndpoint(t, http.StatusBadRequest,
				`{"error":"invalid_grant","error_description":"the grant has expired"}`)

			tokenResponse, err := g.sendAgainst(tokenURL)

			require.Error(t, err)
			assert.Nil(t, tokenResponse)

			var refusal *TokenEndpointError
			require.True(t, errors.As(err, &refusal), "a caller can match the refusal: %v", err)
			assert.Equal(t, http.StatusBadRequest, refusal.StatusCode)
			assert.Equal(t, "invalid_grant", refusal.ErrorCode)
			assert.Equal(t, "the grant has expired", refusal.ErrorDescription)
			assert.Equal(t,
				"the auth server's token endpoint answered 400 (invalid_grant: the grant has expired)"+g.refusalSuffix,
				err.Error())
		})
	}
}

// The message drops what the answer did not carry rather than printing an empty
// slot for it.
func TestTokenClient_ARefusalMessageNamesOnlyWhatTheAnswerCarried(t *testing.T) {
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

	for _, g := range grants {
		for _, tc := range testCases {
			t.Run(g.name+"/"+tc.name, func(t *testing.T) {
				tokenURL, _ := newTokenEndpoint(t, tc.status, tc.body)

				_, err := g.sendAgainst(tokenURL)

				require.Error(t, err)
				assert.Equal(t, tc.want+g.refusalSuffix, err.Error())
			})
		}
	}
}

// A body that is not the RFC 6749 error object -- a proxy's HTML page, a stack trace --
// is refused on its status alone, and none of its text reaches the message. Before
// #441 the whole body was the message, for the refresh grant until slice 2.
func TestTokenClient_ARefusalNeverCarriesTheRawBody(t *testing.T) {
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

	for _, g := range grants {
		for _, tc := range testCases {
			t.Run(g.name+"/"+tc.name, func(t *testing.T) {
				tokenURL, _ := newTokenEndpoint(t, tc.status, tc.body)

				_, err := g.sendAgainst(tokenURL)

				require.Error(t, err)
				var refusal *TokenEndpointError
				require.True(t, errors.As(err, &refusal))
				assert.Equal(t, tc.status, refusal.StatusCode)
				assert.Equal(t, tc.want+g.refusalSuffix, err.Error())
				assert.NotContains(t, err.Error(), "secret-peer-text")
			})
		}
	}
}

// Both values are the peer's text and both are conformed: a forbidden character
// becomes '?' and the result stops at 512 bytes, the last three of them "...".
// The description here carries a newline, which would split a log line, and runs
// to 600 bytes, so neither reaches the message whole.
func TestTokenClient_ARefusalIsConformedAndBounded(t *testing.T) {
	description := "line one\nline two " + strings.Repeat("x", 600)

	for _, g := range grants {
		t.Run(g.name, func(t *testing.T) {
			tokenURL, _ := newTokenEndpoint(t, http.StatusBadRequest,
				`{"error":"invalid\"grant","error_description":"line one\nline two `+strings.Repeat("x", 600)+`"}`)

			_, err := g.sendAgainst(tokenURL)

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
			assert.Equal(t, "the auth server's token endpoint answered 400 (invalid?grant: "+wantDescription+")"+g.refusalSuffix,
				err.Error())
		})
	}
}

// The client-credentials refusal names the client and, for the two codes that mean the
// client is not provisioned for this grant, what to fix (#266, #441 decision 3).
//
// The deployment this protects is one where the seeded client lost what migration 000035
// provisions on it. The client id is no longer configurable (#285), but both halves stay
// editable from the admin console: an administrator can turn the client credentials flow
// off on `admin-console-client`, or take the browser-sessions permission away from it.
// Every admin console page then fails, and the way back in does not go through the admin
// console. The log line is the whole remedy an operator gets, so it is asserted rather
// than left to whoever reads the source next.
//
// unauthorized_client is client credentials being off on that client and invalid_scope
// is that client not holding the permission, which are the two refusals the token
// endpoint actually produces here.
func TestClientCredentials_ARefusalNamesTheClientAndTheRemedy(t *testing.T) {
	const scope = "the-resource:the-permission"

	refusal := func(code string) string {
		return `{"error":"` + code + `","error_description":"some description the endpoint chose"}`
	}

	// The client id is deliberately not `admin-console-client`, which is what production
	// passes: a message that hardcoded the identifier would satisfy an assertion on the
	// real one while carrying nothing the caller gave it.
	send := func(t *testing.T, status int, body string) error {
		t.Helper()
		tokenURL, _ := newTokenEndpoint(t, status, body)
		tokenResponse, err := NewTokenClient(tokenURL, "a-client-of-my-own", "the-secret", nil, nil).
			ClientCredentials(context.Background(), scope)
		require.Error(t, err)
		assert.Nil(t, tokenResponse)
		return err
	}

	for _, code := range []string{"unauthorized_client", "invalid_scope"} {
		t.Run(code, func(t *testing.T) {
			err := send(t, http.StatusBadRequest, refusal(code))

			assert.Equal(t,
				"the auth server's token endpoint answered 400 ("+code+": some description the endpoint chose)"+
					` for client_id "a-client-of-my-own", which needs the client credentials flow enabled`+
					" and the "+scope+" permission granted",
				err.Error())

			var endpointRefusal *TokenEndpointError
			require.True(t, errors.As(err, &endpointRefusal),
				"the client id and the remedy ride on the one refusal error, which a caller still matches")
			assert.Equal(t, code, endpointRefusal.ErrorCode)
		})
	}

	// A refusal that is not a provisioning fault must not send an operator to the Clients
	// page. It still names the code and the client, because both are useful either way.
	t.Run("server_error carries no remedy", func(t *testing.T) {
		err := send(t, http.StatusInternalServerError, refusal("server_error"))

		assert.Equal(t,
			"the auth server's token endpoint answered 500 (server_error: some description the endpoint chose)"+
				` for client_id "a-client-of-my-own"`,
			err.Error())
	})

	// A refusal with no JSON body at all still has to produce a message, since a proxy in
	// front of the auth server can answer before the token endpoint is reached.
	t.Run("a bodyless refusal still names the client", func(t *testing.T) {
		err := send(t, http.StatusBadGateway, "")

		assert.Equal(t, `the auth server's token endpoint answered 502 for client_id "a-client-of-my-own"`,
			err.Error())
	})

	// The remedy is keyed on the conformed code, so a code the peer dressed up does not
	// earn it, and a newline from the peer cannot forge a line in the console's log.
	t.Run("a forbidden rune in the error code earns no remedy and forges no line", func(t *testing.T) {
		err := send(t, http.StatusBadRequest, `{"error":"invalid_scope\nforged"}`)

		assert.NotContains(t, err.Error(), "\n")
		assert.NotContains(t, err.Error(), "permission granted")
		assert.Contains(t, err.Error(), `for client_id "a-client-of-my-own"`)
	})

	// Transport failures are not refusals: nothing answered, so there is no client to blame
	// and no remedy to give.
	t.Run("an unreachable endpoint is not a refusal", func(t *testing.T) {
		server := httptest.NewServer(http.NotFoundHandler())
		tokenURL := server.URL + "/auth/token"
		server.Close()

		_, err := NewTokenClient(tokenURL, "a-client-of-my-own", "the-secret", nil, nil).
			ClientCredentials(context.Background(), scope)

		require.Error(t, err)
		assert.NotContains(t, err.Error(), "a-client-of-my-own")
	})
}

// errTransportStops is what the failing transport below answers, so a case can ask whether the
// error the grant returns still carries it.
var errTransportStops = errors.New("the transport stops here")

// A failure before the answer is read, or of decoding it, keeps its cause in the error tree,
// so a caller can classify it with errors.Is and errors.As rather than by its text (pattern 7).
// The shared transport formatted these with %v, which kept the words and dropped the cause:
// a cancelled client-credentials caller was not errors.Is context.Canceled, where the
// transport it replaced had wrapped it (#441).
func TestTokenClient_KeepsTheCauseOfAFailure(t *testing.T) {
	for _, g := range grants {
		t.Run(g.name+"/a request that cannot be built", func(t *testing.T) {
			_, err := g.send(context.Background(), NewTokenClient("://no-scheme", "ci", "cs", nil, nil))

			var urlErr *url.Error
			require.ErrorAs(t, err, &urlErr)
		})

		t.Run(g.name+"/a transport failure", func(t *testing.T) {
			failing := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
				return nil, errTransportStops
			})}

			_, err := g.send(context.Background(), NewTokenClient(testTokenURL, "ci", "cs", failing, nil))

			require.ErrorIs(t, err, errTransportStops)
		})

		t.Run(g.name+"/an answer that is not JSON", func(t *testing.T) {
			tokenURL, _ := newTokenEndpoint(t, http.StatusOK, `{"access_token":`)

			_, err := g.sendAgainst(tokenURL)

			var syntaxErr *json.SyntaxError
			require.ErrorAs(t, err, &syntaxErr)
		})
	}

	// The one grant that keeps its caller's cancellation, so the one a cancelled caller fails.
	t.Run("client_credentials/a cancelled caller", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := NewTokenClient(testTokenURL, "ci", "cs", nil, nil).ClientCredentials(ctx, "s")

		require.ErrorIs(t, err, context.Canceled)
	})
}
