package integrationtests

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAPIClientSessionsGet_Success tests GET /api/v1/admin/clients/{id}/sessions happy path
func TestAPIClientSessionsGet_Success(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Create a client
	testClient := &models.Client{
		ClientIdentifier:         "test-client-sessions-" + fake.UUID()[:8],
		ClientSecretEncrypted:    []byte("encrypted-secret"),
		Description:              "Test Client for Sessions",
		Enabled:                  true,
		ConsentRequired:          false,
		IsPublic:                 false,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: false,
	}
	err := database.CreateClient(nil, testClient)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(nil, testClient.Id) }()

	// Create a user
	testUser := &models.User{
		Subject:       fake.UUID(),
		Enabled:       true,
		Email:         uniqueEmail("testuser@client-sessions-success.test"),
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err = database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteUser(nil, testUser.Id) }()

	// Create sessions
	s1 := createTestUserSession(t, testUser.Id, fake.UUID())
	s2 := createTestUserSession(t, testUser.Id, fake.UUID())
	defer func() {
		_ = database.DeleteUserSession(nil, s1.Id)
		_ = database.DeleteUserSession(nil, s2.Id)
	}()

	// Link sessions to client
	now := time.Now().UTC()
	usc1 := &models.UserSessionClient{UserSessionId: s1.Id, ClientId: testClient.Id, Started: now.Add(-time.Hour), LastAccessed: now.Add(-time.Minute * 5)}
	err = database.CreateUserSessionClient(nil, usc1)
	assert.NoError(t, err)
	usc2 := &models.UserSessionClient{UserSessionId: s2.Id, ClientId: testClient.Id, Started: now.Add(-time.Hour), LastAccessed: now.Add(-time.Minute * 5)}
	err = database.CreateUserSessionClient(nil, usc2)
	assert.NoError(t, err)

	// Call endpoint
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(testClient.Id, 10) + "/sessions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var out api.GetClientSessionsResponse
	err = json.NewDecoder(resp.Body).Decode(&out)
	assert.NoError(t, err)
	assert.Len(t, out.Sessions, 2)

	// Decision 10's normalization, at its smallest: two sessions of one person, so the array
	// they resolve against holds one record and both rows are keys into it.
	require.Len(t, out.Users, 1)
	assert.Equal(t, testUser.Id, out.Users[0].Id)
	assert.Equal(t, testUser.Email, out.Users[0].Email)
	assert.Equal(t, "Test", out.Users[0].GivenName)
	assert.Equal(t, "User", out.Users[0].FamilyName)

	for _, s := range out.Sessions {
		assert.Greater(t, s.Id, int64(0))
		assert.NotEmpty(t, s.SessionIdentifier)
		require.NotNil(t, s.Started)
		require.NotNil(t, s.LastAccessed)
		assert.Equal(t, "192.168.1.100", s.IpAddress)
		assert.Equal(t, "Test Device", s.DeviceName)
		assert.Equal(t, "computer", s.DeviceType)
		assert.Equal(t, "linux", s.DeviceOS)
		assert.Equal(t, testSessionUserAgent, s.UserAgent)
		assert.Equal(t, testUser.Id, s.UserId)
		assert.Contains(t, s.ClientIdentifiers, testClient.ClientIdentifier)
	}
}

func TestAPIClientSessionsGet_EmptySessions(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Create a client without linked sessions
	testClient := &models.Client{
		ClientIdentifier:         "test-client-empty-" + fake.UUID()[:8],
		ClientSecretEncrypted:    []byte("encrypted-secret"),
		Description:              "Empty Client",
		Enabled:                  true,
		ConsentRequired:          false,
		IsPublic:                 false,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: false,
	}
	err := database.CreateClient(nil, testClient)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(nil, testClient.Id) }()

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(testClient.Id, 10) + "/sessions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Read the bytes, not the struct. Both fields are required arrays that the spec does not
	// mark nullable, and a nil slice reaches the wire as null: a decode into
	// GetClientSessionsResponse gives a zero-length slice either way, so it is blind to exactly
	// the defect this asserts against. Empty is the shape a client with no live sessions hits,
	// which is every client until somebody signs in through it (#373).
	body := readBody(t, resp)
	assert.Contains(t, body, `"sessions":[]`)
	assert.Contains(t, body, `"users":[]`)

	var out api.GetClientSessionsResponse
	err = json.Unmarshal([]byte(body), &out)
	assert.NoError(t, err)
	assert.Len(t, out.Sessions, 0)
	assert.Len(t, out.Users, 0)
}

func TestAPIClientSessionsGet_ClientNotFound(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/999999/sessions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	var errResp api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Equal(t, "Client not found", errResp.ErrorDescription)
}

func TestAPIClientSessionsGet_InvalidId(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	cases := []struct {
		name     string
		clientId string
		expected int
	}{
		{"non-numeric", "abc", http.StatusBadRequest},
		{"negative", "-1", http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + tc.clientId + "/sessions"
			resp := makeAPIRequest(t, "GET", url, accessToken, nil)
			defer func() { _ = resp.Body.Close() }()
			assert.Equal(t, tc.expected, resp.StatusCode)
			var errResp api.ErrorResponse
			_ = json.NewDecoder(resp.Body).Decode(&errResp)
			if tc.clientId == "abc" {
				assert.Equal(t, "Invalid client ID format", errResp.ErrorDescription)
			}
			if tc.clientId == "-1" {
				assert.Equal(t, "Client not found", errResp.ErrorDescription)
			}
		})
	}
}

func TestAPIClientSessionsGet_Unauthorized(t *testing.T) {
	// Create a client
	testClient := &models.Client{
		ClientIdentifier:         "test-client-unauth-" + fake.UUID()[:8],
		ClientSecretEncrypted:    []byte("encrypted-secret"),
		Description:              "Client",
		Enabled:                  true,
		ConsentRequired:          false,
		IsPublic:                 false,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: false,
	}
	err := database.CreateClient(nil, testClient)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(nil, testClient.Id) }()

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(testClient.Id, 10) + "/sessions"
	req, err := http.NewRequest("GET", url, nil)
	assert.NoError(t, err)
	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAPIClientSessionsGet_OnlyValidSessions(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Client
	testClient := &models.Client{
		ClientIdentifier:         "test-client-valid-" + fake.UUID()[:8],
		ClientSecretEncrypted:    []byte("encrypted-secret"),
		Description:              "Client",
		Enabled:                  true,
		ConsentRequired:          false,
		IsPublic:                 false,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: false,
	}
	err := database.CreateClient(nil, testClient)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(nil, testClient.Id) }()

	// User
	testUser := &models.User{
		Subject:       fake.UUID(),
		Enabled:       true,
		Email:         uniqueEmail("testuser@client-valid-sessions.test"),
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err = database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteUser(nil, testUser.Id) }()

	// Valid session
	valid := &models.UserSession{
		SessionIdentifier: fake.UUID(),
		Started:           time.Now().UTC().Add(-30 * time.Minute),
		LastAccessed:      time.Now().UTC().Add(-5 * time.Minute),
		AuthMethods:       "pwd",
		AcrLevel:          "urn:goiabada:pwd",
		AuthTime:          time.Now().UTC().Add(-30 * time.Minute),
		IpAddress:         "192.168.1.100",
		DeviceName:        "Valid Session Device",
		DeviceType:        "computer",
		DeviceOS:          "linux",
		UserId:            testUser.Id,
	}
	err = database.CreateUserSession(nil, valid)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteUserSession(nil, valid.Id) }()

	// Expired session
	expired := &models.UserSession{
		SessionIdentifier: fake.UUID(),
		Started:           time.Now().UTC().Add(-25 * time.Hour),
		LastAccessed:      time.Now().UTC().Add(-24 * time.Hour),
		AuthMethods:       "pwd",
		AcrLevel:          "urn:goiabada:pwd",
		AuthTime:          time.Now().UTC().Add(-25 * time.Hour),
		IpAddress:         "192.168.1.100",
		DeviceName:        "Expired Session Device",
		DeviceType:        "computer",
		DeviceOS:          "linux",
		UserId:            testUser.Id,
	}
	err = database.CreateUserSession(nil, expired)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteUserSession(nil, expired.Id) }()

	// Link both to client
	now := time.Now().UTC()
	err = database.CreateUserSessionClient(nil, &models.UserSessionClient{UserSessionId: valid.Id, ClientId: testClient.Id, Started: now.Add(-time.Hour), LastAccessed: now.Add(-5 * time.Minute)})
	assert.NoError(t, err)
	err = database.CreateUserSessionClient(nil, &models.UserSessionClient{UserSessionId: expired.Id, ClientId: testClient.Id, Started: now.Add(-26 * time.Hour), LastAccessed: now.Add(-25 * time.Hour)})
	assert.NoError(t, err)

	// Call endpoint
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(testClient.Id, 10) + "/sessions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var out api.GetClientSessionsResponse
	err = json.NewDecoder(resp.Body).Decode(&out)
	assert.NoError(t, err)
	assert.Len(t, out.Sessions, 1)
	assert.Equal(t, valid.SessionIdentifier, out.Sessions[0].SessionIdentifier)
	assert.Equal(t, "Valid Session Device", out.Sessions[0].DeviceName)
}

// Test default pagination (size=50) and size cap (max 100)
func TestAPIClientSessionsGet_PaginationDefaultAndCap(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Client
	testClient := &models.Client{
		ClientIdentifier:         "test-client-page-" + fake.UUID()[:8],
		ClientSecretEncrypted:    []byte("encrypted-secret"),
		Description:              "Client",
		Enabled:                  true,
		ConsentRequired:          false,
		IsPublic:                 false,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: false,
	}
	err := database.CreateClient(nil, testClient)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(nil, testClient.Id) }()

	// User
	testUser := &models.User{
		Subject:       fake.UUID(),
		Enabled:       true,
		Email:         uniqueEmail("testuser@client-page.test"),
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err = database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteUser(nil, testUser.Id) }()

	// Create many valid sessions (e.g., 120)
	total := 120
	sessions := make([]*models.UserSession, 0, total)
	now := time.Now().UTC()
	for i := 0; i < total; i++ {
		s := &models.UserSession{
			SessionIdentifier: fake.UUID(),
			Started:           now.Add(-time.Hour),
			LastAccessed:      now.Add(-time.Minute * 5),
			AuthMethods:       "pwd",
			AcrLevel:          "urn:goiabada:pwd",
			AuthTime:          now.Add(-time.Hour),
			IpAddress:         "192.168.1.100",
			DeviceName:        "Test Device",
			DeviceType:        "computer",
			DeviceOS:          "linux",
			UserId:            testUser.Id,
		}
		err := database.CreateUserSession(nil, s)
		assert.NoError(t, err)
		sessions = append(sessions, s)
		// Link to client
		usc := &models.UserSessionClient{UserSessionId: s.Id, ClientId: testClient.Id, Started: now.Add(-time.Hour), LastAccessed: now.Add(-time.Minute * 5)}
		err = database.CreateUserSessionClient(nil, usc)
		assert.NoError(t, err)
	}
	defer func() {
		for _, s := range sessions {
			_ = database.DeleteUserSession(nil, s.Id)
		}
	}()

	// Default pagination (no page/size): expect 50 items returned
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(testClient.Id, 10) + "/sessions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var out api.GetClientSessionsResponse
	err = json.NewDecoder(resp.Body).Decode(&out)
	assert.NoError(t, err)
	assert.Len(t, out.Sessions, 50)

	// Request size over cap (e.g., 200) should cap at 100
	url2 := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(testClient.Id, 10) + "/sessions?size=200"
	resp2 := makeAPIRequest(t, "GET", url2, accessToken, nil)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)
	var out2 api.GetClientSessionsResponse
	err = json.NewDecoder(resp2.Body).Decode(&out2)
	assert.NoError(t, err)
	assert.Len(t, out2.Sessions, 100)
}

// Decision 10, at the endpoint: the users array is normalized, so a person holding several
// sessions on a client appears in it once, and every listed session's userId is a key into it.
// A producer mapping one record per session would pass the success case above, which has a
// single owner, and double a name here.
//
// Decision 12 rides on the same request, on the raw bytes: this route is reached with the
// clients scopes alone -- admin-read, manage-clients or manage -- while every users route needs
// the users scopes, so what a clients-only caller learns about a person is the five fields a
// session page shows. The profile fields asserted absent are the ones an api.UserResponse would
// have put here, and a decode into SessionOwnerResponse cannot see them arrive (#373).
func TestAPIClientSessionsGet_UsersAreNormalizedAndCarryOnlyTheOwnerFields(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	testClient := &models.Client{
		ClientIdentifier:         "test-client-owners-" + fake.UUID()[:8],
		ClientSecretEncrypted:    []byte("encrypted-secret"),
		Description:              "Client",
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
	}
	err := database.CreateClient(nil, testClient)
	require.NoError(t, err)
	defer func() { _ = database.DeleteClient(nil, testClient.Id) }()

	// Two sessions for the first person, one for the second.
	first := &models.User{
		Subject:       fake.UUID(),
		Enabled:       true,
		Email:         uniqueEmail("first@client-owners.test"),
		GivenName:     "Jane",
		MiddleName:    "Q",
		FamilyName:    "Doe",
		PhoneNumber:   "555-0100",
		AddressLine1:  "1 Somewhere Street",
		Nickname:      "jd",
		EmailVerified: true,
	}
	err = database.CreateUser(nil, first)
	require.NoError(t, err)
	defer func() { _ = database.DeleteUser(nil, first.Id) }()

	second := &models.User{
		Subject:       fake.UUID(),
		Enabled:       true,
		Email:         uniqueEmail("second@client-owners.test"),
		GivenName:     "Sam",
		FamilyName:    "Reed",
		EmailVerified: true,
	}
	err = database.CreateUser(nil, second)
	require.NoError(t, err)
	defer func() { _ = database.DeleteUser(nil, second.Id) }()

	now := time.Now().UTC()
	for _, userId := range []int64{first.Id, first.Id, second.Id} {
		session := createTestUserSession(t, userId, fake.UUID())
		defer func(id int64) { _ = database.DeleteUserSession(nil, id) }(session.Id)

		err = database.CreateUserSessionClient(nil, &models.UserSessionClient{
			UserSessionId: session.Id, ClientId: testClient.Id,
			Started: now.Add(-time.Hour), LastAccessed: now.Add(-5 * time.Minute),
		})
		require.NoError(t, err)
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(testClient.Id, 10) + "/sessions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body := readBody(t, resp)
	var out api.GetClientSessionsResponse
	require.NoError(t, json.Unmarshal([]byte(body), &out))

	require.Len(t, out.Sessions, 3)
	require.Len(t, out.Users, 2, "the person with two sessions must appear once")

	owners := make(map[int64]api.SessionOwnerResponse, len(out.Users))
	for _, owner := range out.Users {
		_, duplicate := owners[owner.Id]
		assert.False(t, duplicate, "user %d appears twice in the users array", owner.Id)
		owners[owner.Id] = owner
	}
	for _, session := range out.Sessions {
		_, resolved := owners[session.UserId]
		assert.True(t, resolved, "session %d names user %d, which the users array does not carry",
			session.Id, session.UserId)
	}

	assert.Equal(t, "Jane", owners[first.Id].GivenName)
	assert.Equal(t, "Q", owners[first.Id].MiddleName)
	assert.Equal(t, "Doe", owners[first.Id].FamilyName)
	assert.Equal(t, first.Email, owners[first.Id].Email)
	assert.Equal(t, "Sam Reed", owners[second.Id].GivenName+" "+owners[second.Id].FamilyName)

	// The profile a clients-only caller is not entitled to. Each of these is a key an
	// api.UserResponse would have carried into the same array.
	for _, key := range []string{`"subject"`, `"nickname"`, `"phoneNumber"`, `"addressLine1"`,
		`"birthDate"`, `"otpEnabled"`, `"username"`, `"locale"`} {
		assert.NotContains(t, body, key,
			"the client sessions response carries %s, which is reachable with manage-clients "+
				"alone and belongs to the users scopes (#373 decision 12)", key)
	}
}
