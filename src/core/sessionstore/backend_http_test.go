package sessionstore

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/api"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Seam 6: the HTTP backend, which nothing else in this change executes.
//
// The store's own tests replace the backend with a fake and the endpoint's integration
// tests drive the handlers directly, so between them this file is the only thing that runs
// the adapter joining the two. A wrong path, an identifier that reaches the request target,
// a status mapped to the wrong outcome, an absent bearer header, a 401 that does not refresh
// or a retry spent on a failure that cannot be retried would every one of them ship with all
// the planned cases green (#266).

// recordedRequest is what the far end saw, which is most of what these cases assert.
type recordedRequest struct {
	method string
	path   string
	target string
	auth   string
	body   string
}

// stubEndpoint is an httptest.Server that records every request and answers from a script.
// The script is a function so a case can answer differently on the second attempt, which is
// how the retry and refresh cases are told apart from the ones that do neither.
type stubEndpoint struct {
	server *httptest.Server

	mu       sync.Mutex
	requests []recordedRequest
}

func newStubEndpoint(t *testing.T, answer func(w http.ResponseWriter, attempt int)) *stubEndpoint {
	t.Helper()

	stub := &stubEndpoint{}
	stub.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 0)
		buf := make([]byte, 1024)
		for {
			n, err := r.Body.Read(buf)
			body = append(body, buf[:n]...)
			if err != nil {
				break
			}
		}

		stub.mu.Lock()
		stub.requests = append(stub.requests, recordedRequest{
			method: r.Method,
			path:   r.URL.Path,
			target: r.URL.RequestURI(),
			auth:   r.Header.Get("Authorization"),
			body:   string(body),
		})
		attempt := len(stub.requests)
		stub.mu.Unlock()

		answer(w, attempt)
	}))
	t.Cleanup(stub.server.Close)

	return stub
}

func (s *stubEndpoint) recorded() []recordedRequest {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]recordedRequest, len(s.requests))
	copy(out, s.requests)
	return out
}

// stubTokens is a TokenSource that counts what was asked of it. Nothing here exercises a
// real client_credentials exchange: that is the admin console's own file, over its own
// httptest.Server, since it holds the credentials this package deliberately does not.
type stubTokens struct {
	mu          sync.Mutex
	token       string
	err         error
	handedOut   int
	invalidated int
}

func (s *stubTokens) Token(context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.handedOut++
	if s.err != nil {
		return "", s.err
	}
	return s.token, nil
}

func (s *stubTokens) Invalidate() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.invalidated++
	// A real source drops its cache here. This one answers with a token that says it was
	// refreshed, so a case can prove the retry used the new one rather than the old.
	s.token = "refreshed-token"
}

func newStubTokens() *stubTokens { return &stubTokens{token: "the-token"} }

// The identifier used throughout, long enough to be recognisable in a request target.
const httpTestSessionId = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func alwaysOK(body interface{}) func(http.ResponseWriter, int) {
	return func(w http.ResponseWriter, _ int) {
		w.Header().Set("Content-Type", "application/json")
		if body == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_ = json.NewEncoder(w).Encode(body)
	}
}

func alwaysStatus(status int) func(http.ResponseWriter, int) {
	return func(w http.ResponseWriter, _ int) { w.WriteHeader(status) }
}

// TestHTTPBackend_EachOperationHitsItsOwnPath covers the whole surface at once: the five
// operations, their method, and that each names its own endpoint. A backend that sent every
// call to the same path would round-trip perfectly against a stub that answers everything.
func TestHTTPBackend_EachOperationHitsItsOwnPath(t *testing.T) {
	expiresAt := time.Now().UTC().Add(time.Hour).Truncate(time.Second)

	cases := []struct {
		operation string
		answer    interface{}
		call      func(Backend) error
	}{
		{"load", api.SessionLoadResponse{Data: "ciphertext", ExpiresAt: expiresAt}, func(b Backend) error {
			_, err := b.Load(context.Background(), httpTestSessionId)
			return err
		}},
		{"create", api.SessionWriteResponse{ExpiresAt: expiresAt}, func(b Backend) error {
			_, err := b.Create(context.Background(), httpTestSessionId, []byte("ciphertext"), true)
			return err
		}},
		{"update", api.SessionWriteResponse{ExpiresAt: expiresAt}, func(b Backend) error {
			_, err := b.Update(context.Background(), httpTestSessionId, []byte("ciphertext"), true)
			return err
		}},
		{"touch", api.SessionWriteResponse{ExpiresAt: expiresAt}, func(b Backend) error {
			_, err := b.Touch(context.Background(), httpTestSessionId, false)
			return err
		}},
		{"delete", nil, func(b Backend) error {
			return b.Delete(context.Background(), httpTestSessionId)
		}},
	}

	for _, testCase := range cases {
		t.Run(testCase.operation, func(t *testing.T) {
			stub := newStubEndpoint(t, alwaysOK(testCase.answer))
			backend := NewHTTPBackend(stub.server.URL, newStubTokens())

			require.NoError(t, testCase.call(backend))

			recorded := stub.recorded()
			require.Len(t, recorded, 1)
			assert.Equal(t, http.MethodPost, recorded[0].method)
			assert.Equal(t, "/api/v1/sessions/"+testCase.operation, recorded[0].path)
			assert.Equal(t, "Bearer the-token", recorded[0].auth)
		})
	}
}

// TestHTTPBackend_TheIdentifierNeverReachesTheRequestTarget is the reason every operation is
// a POST with a body. A handle in a request line lands in the auth server's access log and
// in the log of every proxy in front of it, which is one of the arguments that decided the
// endpoint's shape.
func TestHTTPBackend_TheIdentifierNeverReachesTheRequestTarget(t *testing.T) {
	stub := newStubEndpoint(t, func(w http.ResponseWriter, _ int) {
		_ = json.NewEncoder(w).Encode(api.SessionLoadResponse{Data: "ciphertext"})
	})
	backend := NewHTTPBackend(stub.server.URL, newStubTokens())

	_, err := backend.Load(context.Background(), httpTestSessionId)
	require.NoError(t, err)
	_, err = backend.Create(context.Background(), httpTestSessionId, []byte("x"), false)
	require.NoError(t, err)
	_, err = backend.Update(context.Background(), httpTestSessionId, []byte("x"), false)
	require.NoError(t, err)
	_, err = backend.Touch(context.Background(), httpTestSessionId, false)
	require.NoError(t, err)
	require.NoError(t, backend.Delete(context.Background(), httpTestSessionId))

	recorded := stub.recorded()
	require.Len(t, recorded, 5)
	for _, request := range recorded {
		assert.NotContains(t, request.target, httpTestSessionId,
			"the session identifier must never appear in the request line")
		assert.Contains(t, request.body, httpTestSessionId,
			"it travels in the body instead, so the body must actually carry it")
	}
}

// TestHTTPBackend_LoadCarriesTheRecordBack proves the response is read rather than merely
// accepted: a backend that returned a zero Record on every 200 would pass every path case
// above and hand the store a session with no contents and a last-accessed at the zero time,
// which the store would then touch on every single read.
func TestHTTPBackend_LoadCarriesTheRecordBack(t *testing.T) {
	lastAccessed := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	expiresAt := time.Now().UTC().Add(time.Hour).Truncate(time.Second)

	stub := newStubEndpoint(t, alwaysOK(api.SessionLoadResponse{
		Data: "the-ciphertext", LastAccessed: lastAccessed, ExpiresAt: expiresAt,
	}))
	backend := NewHTTPBackend(stub.server.URL, newStubTokens())

	record, err := backend.Load(context.Background(), httpTestSessionId)
	require.NoError(t, err)
	assert.Equal(t, []byte("the-ciphertext"), record.Data)
	assert.True(t, lastAccessed.Equal(record.LastAccessed))
	assert.True(t, expiresAt.Equal(record.ExpiresAt))
}

// TestHTTPBackend_WriteOperationsCarryTheirArguments pins that data and the authenticated
// flag reach the wire. The flag is what decides which of the two lifetimes the auth server
// applies, so dropping it would silently give every admin console session the thirty minute
// pre-authentication window.
func TestHTTPBackend_WriteOperationsCarryTheirArguments(t *testing.T) {
	stub := newStubEndpoint(t, alwaysOK(api.SessionWriteResponse{ExpiresAt: time.Now().UTC()}))
	backend := NewHTTPBackend(stub.server.URL, newStubTokens())

	_, err := backend.Create(context.Background(), httpTestSessionId, []byte("the-ciphertext"), true)
	require.NoError(t, err)
	_, err = backend.Touch(context.Background(), httpTestSessionId, true)
	require.NoError(t, err)

	recorded := stub.recorded()
	require.Len(t, recorded, 2)

	var created api.SessionWriteRequest
	require.NoError(t, json.Unmarshal([]byte(recorded[0].body), &created))
	assert.Equal(t, httpTestSessionId, created.Id)
	assert.Equal(t, "the-ciphertext", created.Data)
	assert.True(t, created.Authenticated)

	var touched api.SessionTouchRequest
	require.NoError(t, json.Unmarshal([]byte(recorded[1].body), &touched))
	assert.True(t, touched.Authenticated)
}

// TestHTTPBackend_NotFoundIsErrNotFoundAndEverythingElseFailsClosed is decision 14 at the
// wire. 404 means the session is gone, which the store turns into a fresh session; any other
// refusal means the lookup could not be performed, which the middleware turns into a 500.
// Collapsing the second into the first would sign every administrator out for the duration
// of any interruption between the two processes.
func TestHTTPBackend_NotFoundIsErrNotFoundAndEverythingElseFailsClosed(t *testing.T) {
	t.Run("404 is ErrNotFound", func(t *testing.T) {
		stub := newStubEndpoint(t, alwaysStatus(http.StatusNotFound))
		backend := NewHTTPBackend(stub.server.URL, newStubTokens())

		_, err := backend.Load(context.Background(), httpTestSessionId)
		assert.ErrorIs(t, err, ErrNotFound)
	})

	for _, status := range []int{
		http.StatusBadRequest,
		http.StatusForbidden,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			stub := newStubEndpoint(t, alwaysStatus(status))
			backend := NewHTTPBackend(stub.server.URL, newStubTokens())

			_, err := backend.Load(context.Background(), httpTestSessionId)
			require.Error(t, err)
			assert.NotErrorIs(t, err, ErrNotFound,
				"a refusal that is not 404 must never read as a session that is gone")
		})
	}
}

// TestHTTPBackend_AGarbageBodyIsAnError covers the case a status check alone lets through: a
// 200 carrying something that is not the response this backend expects. Answering it as a
// session with empty contents would hand the store a decodable-looking blob of nothing.
func TestHTTPBackend_AGarbageBodyIsAnError(t *testing.T) {
	stub := newStubEndpoint(t, func(w http.ResponseWriter, _ int) {
		_, _ = w.Write([]byte("this is not json"))
	})
	backend := NewHTTPBackend(stub.server.URL, newStubTokens())

	_, err := backend.Load(context.Background(), httpTestSessionId)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrNotFound)
}

// TestHTTPBackend_ADroppedConnectionIsRetriedOnce is the reason the retry exists: an idle
// keep-alive connection closed by the far end is an ordinary event and should not reach an
// administrator as a 500.
func TestHTTPBackend_ADroppedConnectionIsRetriedOnce(t *testing.T) {
	stub := newStubEndpoint(t, func(w http.ResponseWriter, attempt int) {
		if attempt == 1 {
			// Hijack and close without writing anything, which is what a connection
			// dropped mid-request looks like from the client's side.
			hijacker, ok := w.(http.Hijacker)
			require.True(t, ok)
			conn, _, err := hijacker.Hijack()
			require.NoError(t, err)
			_ = conn.Close()
			return
		}
		_ = json.NewEncoder(w).Encode(api.SessionLoadResponse{Data: "ciphertext"})
	})
	backend := NewHTTPBackend(stub.server.URL, newStubTokens())

	record, err := backend.Load(context.Background(), httpTestSessionId)
	require.NoError(t, err)
	assert.Equal(t, []byte("ciphertext"), record.Data)
	assert.Len(t, stub.recorded(), 2, "one retry, and the second attempt is the one that succeeded")
}

// TestHTTPBackend_ASecondDroppedConnectionIsNotRetried is the other half. Without it the
// retry could be a loop and nothing would say so: an auth server that is down would be
// hammered by every admin console request rather than failing one of them.
func TestHTTPBackend_ASecondDroppedConnectionIsNotRetried(t *testing.T) {
	stub := newStubEndpoint(t, func(w http.ResponseWriter, _ int) {
		hijacker, ok := w.(http.Hijacker)
		require.True(t, ok)
		conn, _, err := hijacker.Hijack()
		require.NoError(t, err)
		_ = conn.Close()
	})
	backend := NewHTTPBackend(stub.server.URL, newStubTokens())

	_, err := backend.Load(context.Background(), httpTestSessionId)
	require.Error(t, err)
	assert.Len(t, stub.recorded(), 2, "the initial attempt and exactly one retry")
}

// TestHTTPBackend_A401DrivesExactlyOneRefresh covers the token half of the recovery: the
// endpoint refuses, the cached token is dropped, and the request goes again with a new one.
func TestHTTPBackend_A401DrivesExactlyOneRefresh(t *testing.T) {
	stub := newStubEndpoint(t, func(w http.ResponseWriter, attempt int) {
		if attempt == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(api.SessionLoadResponse{Data: "ciphertext"})
	})
	tokens := newStubTokens()
	backend := NewHTTPBackend(stub.server.URL, tokens)

	_, err := backend.Load(context.Background(), httpTestSessionId)
	require.NoError(t, err)

	recorded := stub.recorded()
	require.Len(t, recorded, 2)
	assert.Equal(t, "Bearer the-token", recorded[0].auth)
	assert.Equal(t, "Bearer refreshed-token", recorded[1].auth,
		"the retry must present the refreshed token, not the one that was just refused")
	assert.Equal(t, 1, tokens.invalidated)
}

// TestHTTPBackend_APersistent401StopsAfterOneRefresh is what keeps a misconfigured
// permission from becoming an infinite loop against the auth server's token endpoint.
func TestHTTPBackend_APersistent401StopsAfterOneRefresh(t *testing.T) {
	stub := newStubEndpoint(t, alwaysStatus(http.StatusUnauthorized))
	tokens := newStubTokens()
	backend := NewHTTPBackend(stub.server.URL, tokens)

	_, err := backend.Load(context.Background(), httpTestSessionId)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrNotFound)
	assert.Len(t, stub.recorded(), 2)
	assert.Equal(t, 1, tokens.invalidated, "exactly one refresh, however many 401s arrive")
}

// TestHTTPBackend_ATokenFailureIsNotRetried separates the two budgets. Asking a token source
// that just failed for another token produces the same failure, so spending the retry on it
// would double the cost of an outage and change nothing about its outcome.
func TestHTTPBackend_ATokenFailureIsNotRetried(t *testing.T) {
	stub := newStubEndpoint(t, alwaysOK(api.SessionLoadResponse{}))
	tokens := &stubTokens{err: errors.New("the token endpoint is down")}
	backend := NewHTTPBackend(stub.server.URL, tokens)

	_, err := backend.Load(context.Background(), httpTestSessionId)
	require.Error(t, err)
	assert.Empty(t, stub.recorded(), "no request can be sent without a token")
	assert.Equal(t, 1, tokens.handedOut)
}

// TestHTTPBackend_AnEmptyTokenIsRefusedBeforeTheWire. A source that answers "" without an
// error would otherwise send `Authorization: Bearer ` on every call and be answered 401 on
// every one of them, which reads in a log as the endpoint refusing the admin console rather
// than as the token never having arrived.
func TestHTTPBackend_AnEmptyTokenIsRefusedBeforeTheWire(t *testing.T) {
	stub := newStubEndpoint(t, alwaysOK(api.SessionLoadResponse{}))
	backend := NewHTTPBackend(stub.server.URL, &stubTokens{token: "   "})

	_, err := backend.Load(context.Background(), httpTestSessionId)
	require.Error(t, err)
	assert.Empty(t, stub.recorded())
}

// TestHTTPBackend_TrailingSlashInTheBaseURLDoesNotDoubleUp. The base URL comes from
// configuration, so an operator writing it with a trailing slash is a matter of when rather
// than whether, and a doubled slash is a 404 that would read as a missing session.
func TestHTTPBackend_TrailingSlashInTheBaseURLDoesNotDoubleUp(t *testing.T) {
	stub := newStubEndpoint(t, alwaysOK(api.SessionLoadResponse{}))
	backend := NewHTTPBackend(stub.server.URL+"/", newStubTokens())

	_, err := backend.Load(context.Background(), httpTestSessionId)
	require.NoError(t, err)

	recorded := stub.recorded()
	require.Len(t, recorded, 1)
	assert.Equal(t, "/api/v1/sessions/load", recorded[0].path)
	assert.False(t, strings.Contains(recorded[0].path, "//"))
}

// TestHTTPBackend_ACancelledContextIsNotRetried. The retry is for a connection that died on
// its own; a caller that has gone away is not owed a second attempt, and retrying one would
// keep working on behalf of a request that no longer exists.
func TestHTTPBackend_ACancelledContextIsNotRetried(t *testing.T) {
	stub := newStubEndpoint(t, alwaysOK(api.SessionLoadResponse{}))
	backend := NewHTTPBackend(stub.server.URL, newStubTokens())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := backend.Load(ctx, httpTestSessionId)
	require.Error(t, err)
	assert.Empty(t, stub.recorded())
}
