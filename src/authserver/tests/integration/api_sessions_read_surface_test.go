package integrationtests

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The endpoints seam for #373: what a caller actually receives from the three session lists.
//
// The other files in this directory each cover one endpoint and decode into the Go struct, which
// cannot see a key the struct no longer declares. Both claims here need the raw body or all three
// endpoints at once, so they live together.

// sessionPresentationKeys are the four pre-rendered strings and the constant isValid that the
// three lists published until #373. Each was derived from an instant in the same payload, in
// English, at the server, at the moment the request was served; isValid was set to true after
// every session for which it would have been false had already been skipped.
var sessionPresentationKeys = []string{
	`"startedAt"`,
	`"durationSinceStarted"`,
	`"lastAccessedAt"`,
	`"durationSinceLastAccessed"`,
	`"isValid"`,
}

// readBody returns the response body as a string, so a key can be looked for rather than decoded.
func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(raw)
}

// adminUserTokenReachingAllThree mints a user-bound access token through the authorization code
// flow, scoped to reach both admin session routes and the account one, and returns the token, the
// user it belongs to and the session the ceremony created, which is the session the token's sid
// names.
//
// A client_credentials admin token cannot stand in: sid is suppressed on that grant, so isCurrent
// is false everywhere under it, which is the other case below rather than this one.
func adminUserTokenReachingAllThree(t *testing.T) (string, *models.User, *models.UserSession) {
	t.Helper()

	scope := "openid " +
		constants.AuthServerResourceIdentifier + ":" + constants.ManagePermissionIdentifier + " " +
		constants.AuthServerResourceIdentifier + ":" + constants.ManageAccountPermissionIdentifier
	accessToken, user := createUserAccessTokenWithScope(t, scope)

	sid := extractSidClaim(t, accessToken)
	require.NotEmpty(t, sid, "a user-bound auth-code token must carry a sid claim")

	session, err := database.GetUserSessionBySessionIdentifier(nil, sid)
	require.NoError(t, err)
	require.NotNil(t, session, "the token's sid must name a live session")

	return accessToken, user, session
}

// TestAPISessionLists_PublishNoPresentationFields is decision 1 read off the wire. It asserts on
// the raw body rather than the decoded struct on purpose: once the fields left
// api.UserSessionDetailResponse every existing decode became blind to them, so a producer that
// went on emitting them would leave the whole suite green.
func TestAPISessionLists_PublishNoPresentationFields(t *testing.T) {
	accessToken, user, session := adminUserTokenReachingAllThree(t)

	testClient := &models.Client{
		ClientIdentifier:         "read-surface-client-" + fake.UUID()[:8],
		ClientSecretEncrypted:    []byte("encrypted-secret"),
		Description:              "Read Surface Client",
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
	}
	require.NoError(t, database.CreateClient(nil, testClient))
	defer func() { _ = database.DeleteClient(nil, testClient.Id) }()

	now := time.Now().UTC()
	require.NoError(t, database.CreateUserSessionClient(nil, &models.UserSessionClient{
		UserSessionId: session.Id,
		ClientId:      testClient.Id,
		Started:       now.Add(-time.Hour),
		LastAccessed:  now.Add(-5 * time.Minute),
	}))

	base := config.GetAuthServer().BaseURL
	for _, tc := range []struct {
		name string
		url  string
	}{
		{"admin user sessions", base + "/api/v1/admin/users/" + strconv.FormatInt(user.Id, 10) + "/sessions"},
		{"admin client sessions", base + "/api/v1/admin/clients/" + strconv.FormatInt(testClient.Id, 10) + "/sessions"},
		{"account sessions", base + "/api/v1/account/sessions"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := makeAPIRequest(t, "GET", tc.url, accessToken, nil)
			defer func() { _ = resp.Body.Close() }()

			require.Equal(t, http.StatusOK, resp.StatusCode)
			body := readBody(t, resp)

			for _, key := range sessionPresentationKeys {
				assert.NotContains(t, body, key, "the session list still publishes %s", key)
			}

			// The two survivors and the instants they were derived from are still there, so
			// an empty or errored body cannot be what passed the loop above.
			assert.Contains(t, body, `"isCurrent"`)
			assert.Contains(t, body, `"clientIdentifiers"`)
			assert.Contains(t, body, `"started"`)
			assert.Contains(t, body, `"lastAccessed"`)
		})
	}
}

// TestAPISessionLists_IsCurrentIsTrueOnAllThreeEndpoints is the case decision 1 exists for: the
// field was assigned at the account endpoint and nowhere else, so both admin endpoints answered a
// constant false and nothing failed. Reverting to that leaves this red on two of its three rows.
func TestAPISessionLists_IsCurrentIsTrueOnAllThreeEndpoints(t *testing.T) {
	accessToken, user, session := adminUserTokenReachingAllThree(t)

	testClient := &models.Client{
		ClientIdentifier:         "is-current-client-" + fake.UUID()[:8],
		ClientSecretEncrypted:    []byte("encrypted-secret"),
		Description:              "Is Current Client",
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
	}
	require.NoError(t, database.CreateClient(nil, testClient))
	defer func() { _ = database.DeleteClient(nil, testClient.Id) }()

	now := time.Now().UTC()
	require.NoError(t, database.CreateUserSessionClient(nil, &models.UserSessionClient{
		UserSessionId: session.Id,
		ClientId:      testClient.Id,
		Started:       now.Add(-time.Hour),
		LastAccessed:  now.Add(-5 * time.Minute),
	}))

	// A second live session for the same user, which the token does not name. Without it a
	// producer that set isCurrent true on every row would pass.
	other := createTestUserSession(t, user.Id, fake.UUID())
	defer func() { _ = database.DeleteUserSession(nil, other.Id) }()
	require.NoError(t, database.CreateUserSessionClient(nil, &models.UserSessionClient{
		UserSessionId: other.Id,
		ClientId:      testClient.Id,
		Started:       now.Add(-time.Hour),
		LastAccessed:  now.Add(-5 * time.Minute),
	}))

	base := config.GetAuthServer().BaseURL
	for _, tc := range []struct {
		name string
		url  string
	}{
		{"admin user sessions", base + "/api/v1/admin/users/" + strconv.FormatInt(user.Id, 10) + "/sessions"},
		{"admin client sessions", base + "/api/v1/admin/clients/" + strconv.FormatInt(testClient.Id, 10) + "/sessions"},
		{"account sessions", base + "/api/v1/account/sessions"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := makeAPIRequest(t, "GET", tc.url, accessToken, nil)
			defer func() { _ = resp.Body.Close() }()

			require.Equal(t, http.StatusOK, resp.StatusCode)

			var out api.GetUserSessionsResponse
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))

			byIdentifier := map[string]bool{}
			for _, s := range out.Sessions {
				byIdentifier[s.SessionIdentifier] = s.IsCurrent
			}

			isCurrent, present := byIdentifier[session.SessionIdentifier]
			require.True(t, present, "the caller's own session is missing from the list")
			assert.True(t, isCurrent, "the caller's own session must be marked current")

			wasCurrent, present := byIdentifier[other.SessionIdentifier]
			require.True(t, present, "the second session is missing from the list")
			assert.False(t, wasCurrent, "a session the token does not name must not be marked current")
		})
	}
}

// The other half of the same claim. sid is suppressed on client_credentials tokens, so an admin
// integration holding one has no session of its own, and every row must say so. An implementation
// comparing an empty claim against an empty identifier would mark rows current for a caller that
// has no session at all.
func TestAPIUserSessionsGet_AClientCredentialsTokenMarksNothingCurrent(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	require.Empty(t, extractSidClaim(t, accessToken), "a client_credentials token must carry no sid")

	testUser := &models.User{
		Subject:       fake.UUID(),
		Enabled:       true,
		Email:         uniqueEmail("nocurrent@sessions.test"),
		EmailVerified: true,
	}
	require.NoError(t, database.CreateUser(nil, testUser))
	defer func() { _ = database.DeleteUser(nil, testUser.Id) }()

	s1 := createTestUserSession(t, testUser.Id, fake.UUID())
	s2 := createTestUserSession(t, testUser.Id, fake.UUID())
	defer func() {
		_ = database.DeleteUserSession(nil, s1.Id)
		_ = database.DeleteUserSession(nil, s2.Id)
	}()

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/sessions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var out api.GetUserSessionsResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	require.Len(t, out.Sessions, 2)

	for _, s := range out.Sessions {
		assert.False(t, s.IsCurrent, "session %s marked current for a token with no sid", s.SessionIdentifier)
	}
}
