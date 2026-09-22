package apiclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/leodip/goiabada/adminconsole/internal/boundedread"
	"github.com/leodip/goiabada/core/api"
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

// The pair the read bound never had. This source reads the token endpoint's answer under
// maxSessionTokenResponseBytes, and an answer over it is refused rather than cut: a token
// response cut at the ceiling that happened to be balanced would decode with the access
// token missing, and would then arrive at the caller as the empty-bearer refusal above
// rather than as the oversized answer it was (#386 decision 4).
func TestSessionTokenSource_RefusesAnAnswerOverTheCap(t *testing.T) {
	stub := newTokenStub(t, func(w http.ResponseWriter, _ int) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(bytes.Repeat([]byte("x"), maxSessionTokenResponseBytes+1))
	})
	source := newTestTokenSource(stub.server.URL)

	token, err := source.Token(context.Background())

	require.Error(t, err)
	assert.True(t, errors.Is(err, boundedread.ErrResponseTooLarge),
		"the answer is refused as oversized rather than decoded from a prefix: %v", err)
	assert.Empty(t, token, "nothing is decoded out of an answer that was refused")
}

// And the boundary itself: an answer of exactly the cap is served. Without this the case
// above reads as "large answers are refused" rather than "answers over the cap are".
func TestSessionTokenSource_AcceptsAnAnswerOfExactlyTheCap(t *testing.T) {
	stub := newTokenStub(t, func(w http.ResponseWriter, _ int) {
		encoded, err := json.Marshal(oauth.TokenResponse{
			AccessToken: "at", TokenType: "Bearer", ExpiresIn: 300,
		})
		require.NoError(t, err)

		// Pad the one field of unbounded length until the answer is the cap to the byte.
		padded, err := json.Marshal(oauth.TokenResponse{
			AccessToken: "at", TokenType: "Bearer", ExpiresIn: 300,
			Scope: strings.Repeat("x", maxSessionTokenResponseBytes-len(encoded)-len(`,"scope":""`)),
		})
		require.NoError(t, err)
		require.Len(t, padded, maxSessionTokenResponseBytes)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(padded)
	})
	source := newTestTokenSource(stub.server.URL)

	token, err := source.Token(context.Background())

	require.NoError(t, err, "the cap is the largest accepted answer, not the first refused one")
	assert.Equal(t, "at", token)
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

// TestSessionTokenSource_ARefusalNamesTheClientAndTheRemedy pins decision 23.
//
// The deployment this protects is one where the seeded client lost what migration 000035
// provisions on it. The client id is no longer configurable (#285), but both halves stay
// editable from the admin console: an administrator can turn the client credentials flow off
// on `admin-console-client`, or take the browser-sessions permission away from it. Every
// admin console page then fails, and the way back in does not go through the admin console.
// The log line is the whole remedy an operator gets, so it is asserted rather than left to
// whoever reads the source next.
//
// unauthorized_client is client credentials being off on that client and invalid_scope is
// that client not holding the permission, which are the two refusals the token endpoint
// actually produces here.
func TestSessionTokenSource_ARefusalNamesTheClientAndTheRemedy(t *testing.T) {
	refuses := func(status int, code string) func(http.ResponseWriter, int) {
		return func(w http.ResponseWriter, _ int) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":             code,
				"error_description": "some description the endpoint chose",
			})
		}
	}

	permission := constants.AuthServerResourceIdentifier + ":" +
		constants.BrowserSessionsPermissionIdentifier

	for _, code := range []string{"unauthorized_client", "invalid_scope"} {
		t.Run(code, func(t *testing.T) {
			stub := newTokenStub(t, refuses(http.StatusBadRequest, code))
			source := NewSessionTokenSource(stub.server.URL, "a-client-of-my-own", "the-secret")

			_, err := source.Token(context.Background())
			require.Error(t, err)

			message := err.Error()
			assert.Contains(t, message, code,
				"the endpoint's error field is the difference between a diagnosable failure and a bare status")
			// The sentinel is deliberately not `admin-console-client`, which is what
			// production passes: a message that hardcoded the identifier would satisfy
			// an assertion on the real one while carrying nothing the caller gave it.
			assert.Contains(t, message, "a-client-of-my-own",
				"the client the token was refused for is what an operator has to go and fix")
			assert.Contains(t, message, permission,
				"the permission to grant")
			assert.Contains(t, message, "client credentials",
				"the switch to turn on")
		})
	}

	// A refusal that is not a provisioning fault must not send an operator to the Clients
	// page. It still names the code and the client, because both are useful either way.
	t.Run("server_error carries no remedy", func(t *testing.T) {
		stub := newTokenStub(t, refuses(http.StatusInternalServerError, "server_error"))
		source := NewSessionTokenSource(stub.server.URL, "a-client-of-my-own", "the-secret")

		_, err := source.Token(context.Background())
		require.Error(t, err)

		message := err.Error()
		assert.Contains(t, message, "server_error")
		assert.Contains(t, message, "a-client-of-my-own")
		assert.NotContains(t, message, permission,
			"a server_error is not a missing grant, and saying so would misdirect the repair")
	})

	// A refusal with no JSON body at all still has to produce a message, since a proxy in
	// front of the auth server can answer before the token endpoint is reached.
	t.Run("a bodyless refusal still names the client", func(t *testing.T) {
		stub := newTokenStub(t, func(w http.ResponseWriter, _ int) {
			w.WriteHeader(http.StatusBadGateway)
		})
		source := NewSessionTokenSource(stub.server.URL, "a-client-of-my-own", "the-secret")

		_, err := source.Token(context.Background())
		require.Error(t, err)

		message := err.Error()
		assert.Contains(t, message, "502")
		assert.Contains(t, message, "a-client-of-my-own")
		assert.NotContains(t, message, permission)
	})

	// The endpoint's error field arrives over the wire, so it is filtered on the way into a
	// log line exactly as the auth server filters it on the way out (RFC 6749 Appendix A.8).
	t.Run("a forbidden rune in the error code cannot forge a log line", func(t *testing.T) {
		stub := newTokenStub(t, refuses(http.StatusBadRequest, "bad\ncode"))
		source := NewSessionTokenSource(stub.server.URL, "a-client-of-my-own", "the-secret")

		_, err := source.Token(context.Background())
		require.Error(t, err)

		assert.NotContains(t, err.Error(), "\n",
			"a newline from the endpoint would forge a line in the admin console's log")
	})
}

// Seam "the client" (#373).
//
// The console reaches the auth server's three session lists through GetUserSessionsByUserId,
// GetClientSessionsByClientId and GetAccountSessions, and none of the three had ever had its
// real request path executed: the console's handler tests reach them only through hand-written
// stubs returning canned structs, so the URL each builds and the json.Unmarshal each performs
// ran nowhere. That decode is the one place a json tag renamed in core/api shows up as an empty
// field rather than as a compile error (#281 decision 6), and this table is deliberately
// written before the session response changes shape, so the proof exists before there is a
// rename to catch.
//
// The body is literal bytes rather than marshalled from the api structs: a body produced by the
// same tags it is meant to check proves nothing, which is the rule user_client_test.go already
// states for the user family.
//
// The presentation fields the session response used to carry -- startedAt,
// durationSinceStarted, lastAccessedAt, durationSinceLastAccessed and isValid -- are
// deliberately absent from both the body and the assertions. This table is about the contract
// that survives, so it must not need editing by the change it exists to protect.

// sessionUserAgent is what the JSON below must decode to, kept beside it in decoded form: the
// header carries a quote and a pair of angle brackets, so the two spellings differ by JSON's own
// escaping, and asserting the escaped one would pass on a client that never unescaped anything.
const sessionUserAgent = `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "odd" <build>`

// started is present and lastAccessed is null, so both arms of a *time.Time are read: the
// difference between a page printing "01 Jan 0001" and a page printing nothing.
const sessionBodyFields = `
	"id": 7,
	"sessionIdentifier": "a-session-identifier",
	"started": "2026-01-02T03:04:05Z",
	"lastAccessed": null,
	"ipAddress": "203.0.113.7",
	"deviceName": "Chrome 120",
	"deviceType": "Desktop",
	"deviceOS": "Linux",
	"userAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \"odd\" <build>",
	"userId": 42,
	"isCurrent": true,
	"clientIdentifiers": ["portal", "backoffice"]`

// servesSessions is `serves` with the whole request target recorded rather than the path alone,
// because GetClientSessionsByClientId assembles a query string by hand and that assembly is
// half of what this file covers. It is a second helper rather than a widened `serves` because
// that one has eleven callers, every one of them asserting against a path.
func servesSessions(t *testing.T, body string) (*AuthServerClient, func() (string, string)) {
	t.Helper()

	var gotURI, gotAuthorization string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURI = r.URL.RequestURI()
		gotAuthorization = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)

	return NewAuthServerClient(server.URL), func() (string, string) { return gotURI, gotAuthorization }
}

type sessionListMethod struct {
	name    string
	wantURI string
	call    func(c *AuthServerClient) ([]api.UserSessionDetailResponse, error)
}

func sessionListMethods() []sessionListMethod {
	return []sessionListMethod{
		{
			name:    "GetUserSessionsByUserId",
			wantURI: "/api/v1/admin/users/42/sessions",
			call: func(c *AuthServerClient) ([]api.UserSessionDetailResponse, error) {
				return c.GetUserSessionsByUserId(context.Background(), "an-access-token", 42)
			},
		},
		{
			name:    "GetClientSessionsByClientId",
			wantURI: "/api/v1/admin/clients/7/sessions?page=2&size=10",
			call: func(c *AuthServerClient) ([]api.UserSessionDetailResponse, error) {
				// The only one of the three answering an envelope rather than a bare list:
				// its sessions span users, so it carries their owners too. The users half is
				// decoded by its own case below, because the table's other two methods have
				// no such field to assert (#373).
				resp, err := c.GetClientSessionsByClientId(context.Background(), "an-access-token", 7, 2, 10)
				if err != nil {
					return nil, err
				}
				return resp.Sessions, nil
			},
		},
		{
			name:    "GetAccountSessions",
			wantURI: "/api/v1/account/sessions",
			call: func(c *AuthServerClient) ([]api.UserSessionDetailResponse, error) {
				return c.GetAccountSessions(context.Background(), "an-access-token")
			},
		},
	}
}

func TestAuthServerClient_SessionListsDecodeEveryFieldTheConsoleBinds(t *testing.T) {
	for _, method := range sessionListMethods() {
		t.Run(method.name, func(t *testing.T) {
			client, recorded := servesSessions(t, `{"sessions":[{`+sessionBodyFields+`}]}`)

			sessions, err := method.call(client)
			require.NoError(t, err)
			require.Len(t, sessions, 1)

			gotURI, gotAuthorization := recorded()
			assert.Equal(t, method.wantURI, gotURI)
			assert.Equal(t, "Bearer an-access-token", gotAuthorization)

			session := sessions[0]
			assert.Equal(t, int64(7), session.Id)
			assert.Equal(t, "a-session-identifier", session.SessionIdentifier)
			require.NotNil(t, session.Started)
			assert.Equal(t, time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC), session.Started.UTC())
			assert.Nil(t, session.LastAccessed)
			assert.Equal(t, "203.0.113.7", session.IpAddress)
			assert.Equal(t, "Chrome 120", session.DeviceName)
			assert.Equal(t, "Desktop", session.DeviceType)
			assert.Equal(t, "Linux", session.DeviceOS)
			assert.Equal(t, int64(42), session.UserId)
			assert.True(t, session.IsCurrent)
			assert.Equal(t, []string{"portal", "backoffice"}, session.ClientIdentifiers)

			// The raw header, byte for byte. It reaches the page as a tooltip, so a client
			// that repaired or truncated it would leave two sessions whose device labels read
			// alike indistinguishable (#281).
			assert.Equal(t, sessionUserAgent, session.UserAgent)
		})
	}
}

// A session created before the userAgent column existed carries an empty header, and the
// console must be handed that rather than a decoding failure: the field is required on the wire
// and present as an empty string, which #281 decision 7 accepted as permanent for pre-upgrade
// rows.
func TestAuthServerClient_SessionListsAcceptALegacyEmptyUserAgent(t *testing.T) {
	for _, method := range sessionListMethods() {
		t.Run(method.name, func(t *testing.T) {
			client, _ := servesSessions(t,
				`{"sessions":[{"id":7,"sessionIdentifier":"legacy","userAgent":"","userId":42}]}`)

			sessions, err := method.call(client)
			require.NoError(t, err)
			require.Len(t, sessions, 1)
			assert.Equal(t, "", sessions[0].UserAgent)
		})
	}
}

// GetClientSessionsByClientId assembles its query string by hand, `q := "?"` then `q += "&"`,
// and had no test at all. The neither case is the one that must produce a request target with
// no `?` in it: an absent query is what leaves the endpoint free to apply its own defaults,
// where `?page=0&size=0` would be asking it for page zero of nothing.
func TestAuthServerClient_GetClientSessionsByClientIdBuildsThePaginationQuery(t *testing.T) {
	for _, tc := range []struct {
		name    string
		page    int
		size    int
		wantURI string
	}{
		{"page and size", 2, 10, "/api/v1/admin/clients/7/sessions?page=2&size=10"},
		{"page only", 2, 0, "/api/v1/admin/clients/7/sessions?page=2"},
		{"size only", 0, 10, "/api/v1/admin/clients/7/sessions?size=10"},
		{"neither", 0, 0, "/api/v1/admin/clients/7/sessions"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, recorded := servesSessions(t, `{"sessions":[]}`)

			_, err := client.GetClientSessionsByClientId(context.Background(), "an-access-token", 7, tc.page, tc.size)
			require.NoError(t, err)

			gotURI, _ := recorded()
			assert.Equal(t, tc.wantURI, gotURI)
		})
	}
}

// The users half of the client sessions envelope, which no other session method carries. The
// console reads a session's owner out of this array instead of fetching a user per row, so a
// json tag renamed here reaches the page as two empty columns rather than as a compile error.
//
// Literal bytes again, and deliberately more than the five keys the endpoint sends: a decoder
// that refused an unknown field would break the console on the next field the auth server adds,
// and one that mapped by position rather than by name would pass the shorter body.
func TestAuthServerClient_ClientSessionsDecodeTheOwnersArray(t *testing.T) {
	client, _ := servesSessions(t, `{"sessions":[{`+sessionBodyFields+`}],"users":[
		{"id":42,"email":"jane@example.com","givenName":"Jane","middleName":"Q","familyName":"Doe"},
		{"id":43,"email":"sam@example.com","givenName":"Sam","middleName":"","familyName":"Reed",
		 "somethingAddedLater":"ignored"}]}`)

	resp, err := client.GetClientSessionsByClientId(context.Background(), "an-access-token", 7, 1, 50)
	require.NoError(t, err)
	require.Len(t, resp.Sessions, 1)
	require.Len(t, resp.Users, 2)

	assert.Equal(t, api.SessionOwnerResponse{
		Id: 42, Email: "jane@example.com", GivenName: "Jane", MiddleName: "Q", FamilyName: "Doe",
	}, resp.Users[0])
	assert.Equal(t, api.SessionOwnerResponse{
		Id: 43, Email: "sam@example.com", GivenName: "Sam", FamilyName: "Reed",
	}, resp.Users[1])

	// The array is what the session's userId resolves against, which is the whole reason it is
	// on the response.
	assert.Equal(t, int64(42), resp.Sessions[0].UserId)
}

// An endpoint that sent no users at all, which is what a body from before this field existed
// looks like. The console must be handed an empty lookup rather than a decoding failure: the
// page renders every row with its device and its timestamps and blank owner columns.
func TestAuthServerClient_ClientSessionsAcceptAnAbsentUsersArray(t *testing.T) {
	client, _ := servesSessions(t, `{"sessions":[{`+sessionBodyFields+`}]}`)

	resp, err := client.GetClientSessionsByClientId(context.Background(), "an-access-token", 7, 1, 50)
	require.NoError(t, err)
	require.Len(t, resp.Sessions, 1)
	assert.Empty(t, resp.Users)
}

// The two session deletes return only an error and still decode: a 200 carrying `success:false`
// is refused. Nothing else in this package behaves that way, the characterization rows answer
// both with `success:true`, and stage 11 moved the code holding the check onto the shared
// executor -- so this is the case that says the false arm survived the move (#386).
func TestAuthServerClient_ASessionDeleteRefusesASuccessFalseBody(t *testing.T) {
	testCases := []struct {
		name string
		call func(c *AuthServerClient) error
	}{
		{
			name: "DeleteUserSessionById",
			call: func(c *AuthServerClient) error {
				return c.DeleteUserSessionById(context.Background(), "an-access-token", 31)
			},
		},
		{
			name: "DeleteAccountSession",
			call: func(c *AuthServerClient) error {
				return c.DeleteAccountSession(context.Background(), "an-access-token", 31)
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Run("success false is refused", func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = w.Write([]byte(`{"success":false}`))
				}))
				t.Cleanup(server.Close)

				err := testCase.call(NewAuthServerClient(server.URL))

				require.Error(t, err, "a 200 the endpoint marked unsuccessful must not read as a deletion")
				assert.Contains(t, err.Error(), "success=false")
			})

			// The other half: without it a method that returned an error unconditionally would
			// pass the case above.
			t.Run("success true is the deletion", func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = w.Write([]byte(`{"success":true}`))
				}))
				t.Cleanup(server.Close)

				assert.NoError(t, testCase.call(NewAuthServerClient(server.URL)))
			})
		})
	}
}
