package apiclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Seam 6's other half: the client_credentials token source behind the browser session
// backend (#266).
//
// Nothing else in the change runs it. The store's tests replace the backend, the backend's
// tests replace the token source, and the endpoint's integration tests mint their own token,
// so a wrong grant, a missing scope, a token cached past its expiry or an error swallowed
// into an empty bearer would every one of them ship with all the planned cases green.

// tokenStub records the form each request carried and answers from a script.
type tokenStub struct {
	server *httptest.Server

	mu    sync.Mutex
	forms []url.Values
}

func newTokenStub(t *testing.T, answer func(w http.ResponseWriter, attempt int)) *tokenStub {
	t.Helper()

	stub := &tokenStub{}
	stub.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())

		stub.mu.Lock()
		stub.forms = append(stub.forms, r.PostForm)
		attempt := len(stub.forms)
		stub.mu.Unlock()

		answer(w, attempt)
	}))
	t.Cleanup(stub.server.Close)

	return stub
}

func (s *tokenStub) recorded() []url.Values {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]url.Values, len(s.forms))
	copy(out, s.forms)
	return out
}

// issues answers every request with a distinct access token and the given lifetime, so a
// case can tell a cached token from a freshly fetched one by its value.
func issues(expiresIn int64) func(http.ResponseWriter, int) {
	return func(w http.ResponseWriter, attempt int) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(oauth.TokenResponse{
			AccessToken: "token-" + string(rune('0'+attempt)),
			TokenType:   "Bearer",
			ExpiresIn:   expiresIn,
		})
	}
}

func newTestTokenSource(baseURL string) *SessionTokenSource {
	return NewSessionTokenSource(baseURL, "admin-console-client", "the-secret")
}

// TestSessionTokenSource_RequestsClientCredentialsWithTheNarrowScope is decision 16's shape
// on the wire. The scope matters most: holding this module's client secret must not be a way
// to drive the whole admin API with no user present, so the request asks for one permission
// and never one of the manage-* scopes.
func TestSessionTokenSource_RequestsClientCredentialsWithTheNarrowScope(t *testing.T) {
	stub := newTokenStub(t, issues(3600))
	source := newTestTokenSource(stub.server.URL)

	token, err := source.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "token-1", token)

	recorded := stub.recorded()
	require.Len(t, recorded, 1)
	assert.Equal(t, "client_credentials", recorded[0].Get("grant_type"))
	assert.Equal(t, "admin-console-client", recorded[0].Get("client_id"))
	assert.Equal(t, "the-secret", recorded[0].Get("client_secret"))
	assert.Equal(t,
		constants.AuthServerResourceIdentifier+":"+constants.BrowserSessionsPermissionIdentifier,
		recorded[0].Get("scope"))
}

// TestSessionTokenSource_PostsToTheTokenEndpoint. The base URL comes from configuration, and
// an operator writing it with a trailing slash is a matter of when rather than whether.
func TestSessionTokenSource_PostsToTheTokenEndpoint(t *testing.T) {
	for _, baseURL := range []string{"", "/"} {
		stub := newTokenStub(t, issues(3600))
		source := newTestTokenSource(stub.server.URL + baseURL)

		_, err := source.Token(context.Background())
		require.NoError(t, err)
		assert.Equal(t, stub.server.URL+"/auth/token", source.tokenURL)
	}
}

// TestSessionTokenSource_ReusesACachedToken is the whole reason this caches at all: the
// backend it feeds sits on the request path of every admin console page, and a token request
// per page would double the traffic between the two processes for no gain.
func TestSessionTokenSource_ReusesACachedToken(t *testing.T) {
	stub := newTokenStub(t, issues(3600))
	source := newTestTokenSource(stub.server.URL)

	first, err := source.Token(context.Background())
	require.NoError(t, err)
	second, err := source.Token(context.Background())
	require.NoError(t, err)

	assert.Equal(t, first, second)
	assert.Len(t, stub.recorded(), 1, "the second call must be answered from the cache")
}

// TestSessionTokenSource_RefetchesWithinTheExpiryMargin pins the margin rather than only the
// expiry. A token whose remaining life is inside the margin is treated as spent, so it can
// never expire between this check and the endpoint's own validation of it, which would cost
// a 401 and a retry for nothing.
func TestSessionTokenSource_RefetchesWithinTheExpiryMargin(t *testing.T) {
	// Ten seconds, well inside the thirty second margin, so the cache is never eligible.
	stub := newTokenStub(t, issues(10))
	source := newTestTokenSource(stub.server.URL)

	first, err := source.Token(context.Background())
	require.NoError(t, err)
	second, err := source.Token(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "token-1", first)
	assert.Equal(t, "token-2", second, "a token inside the margin is spent, not served again")
	assert.Len(t, stub.recorded(), 2)
}

// TestSessionTokenSource_InvalidateForcesARefetch is the half the backend's 401 path depends
// on. If Invalidate did not actually drop the cache, a revoked token would be presented over
// and over and the retry would refuse forever.
func TestSessionTokenSource_InvalidateForcesARefetch(t *testing.T) {
	stub := newTokenStub(t, issues(3600))
	source := newTestTokenSource(stub.server.URL)

	first, err := source.Token(context.Background())
	require.NoError(t, err)

	source.Invalidate()

	second, err := source.Token(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "token-1", first)
	assert.Equal(t, "token-2", second)
	assert.Len(t, stub.recorded(), 2)
}

// TestSessionTokenSource_ARefusalIsAnError. The alternative, an empty bearer with no error,
// would be presented on every session call and answered 401 on every one of them, which
// reads in a log as the endpoint refusing the admin console rather than as the token never
// having arrived.
func TestSessionTokenSource_ARefusalIsAnError(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			stub := newTokenStub(t, func(w http.ResponseWriter, _ int) { w.WriteHeader(status) })
			source := newTestTokenSource(stub.server.URL)

			token, err := source.Token(context.Background())
			require.Error(t, err)
			assert.Empty(t, token)
		})
	}
}

// TestSessionTokenSource_A200WithNoAccessTokenIsAnError covers what a status check alone lets
// through.
func TestSessionTokenSource_A200WithNoAccessTokenIsAnError(t *testing.T) {
	stub := newTokenStub(t, func(w http.ResponseWriter, _ int) {
		_ = json.NewEncoder(w).Encode(oauth.TokenResponse{TokenType: "Bearer", ExpiresIn: 3600})
	})
	source := newTestTokenSource(stub.server.URL)

	token, err := source.Token(context.Background())
	require.Error(t, err)
	assert.Empty(t, token)
}

// TestSessionTokenSource_AGarbageBodyIsAnError. Same reasoning: a body that is not a token
// response must not become an empty bearer.
func TestSessionTokenSource_AGarbageBodyIsAnError(t *testing.T) {
	stub := newTokenStub(t, func(w http.ResponseWriter, _ int) {
		_, _ = w.Write([]byte("not json"))
	})
	source := newTestTokenSource(stub.server.URL)

	_, err := source.Token(context.Background())
	require.Error(t, err)
}

// TestSessionTokenSource_AFailureDoesNotLeaveAStaleTokenCached. The token the failure
// replaced was one this source had already decided not to serve, so keeping it would mean
// serving it only on the failure path, which is the one place it is least likely to work.
func TestSessionTokenSource_AFailureDoesNotLeaveAStaleTokenCached(t *testing.T) {
	stub := newTokenStub(t, func(w http.ResponseWriter, attempt int) {
		if attempt == 1 {
			issues(10)(w, attempt)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	source := newTestTokenSource(stub.server.URL)

	first, err := source.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "token-1", first)

	// The second call is inside the margin, so it fetches, and the fetch fails.
	_, err = source.Token(context.Background())
	require.Error(t, err)

	third, err := source.Token(context.Background())
	require.Error(t, err, "the failure must not have left token-1 available to serve")
	assert.Empty(t, third)
	assert.Len(t, stub.recorded(), 3)
}
