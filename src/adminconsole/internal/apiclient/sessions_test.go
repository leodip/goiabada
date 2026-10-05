package apiclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
// same tags it is meant to check proves nothing, which is the rule users_test.go already
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

	return NewAuthServerClient(server.URL, nil), func() (string, string) { return gotURI, gotAuthorization }
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

				err := testCase.call(NewAuthServerClient(server.URL, nil))

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

				assert.NoError(t, testCase.call(NewAuthServerClient(server.URL, nil)))
			})
		})
	}
}
