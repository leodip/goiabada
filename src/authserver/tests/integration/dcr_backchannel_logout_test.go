package integration

// A registration's backchannel_logout_uri and backchannel_logout_session_required, through
// POST /connect/register (#784 decision 10): stored on the new client, echoed in the answer, and
// read back through the admin API, which is where an administrator sees them. A URI a
// self-registered client cannot use is refused with invalid_client_metadata and creates nothing.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// postDCRBody posts a raw registration body, so the answer can be read member by member.
func postDCRBody(t *testing.T, body string) (int, map[string]json.RawMessage) {
	t.Helper()
	req, err := http.NewRequest("POST", appConfig.AuthServer.BaseURL+"/connect/register", bytes.NewReader([]byte(body)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := createHttpClient(t).Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	var members map[string]json.RawMessage
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&members))
	return resp.StatusCode, members
}

// registeredClientThroughTheAdminAPI reads a self-registered client through the admin API by its
// identifier from the answer, and deletes it when the test ends.
func registeredClientThroughTheAdminAPI(t *testing.T, adminToken string, members map[string]json.RawMessage) api.ClientResponse {
	t.Helper()
	var identifier string
	require.NoError(t, json.Unmarshal(members["client_id"], &identifier))
	client, err := database.GetClientByClientIdentifier(context.Background(), nil, identifier)
	require.NoError(t, err)
	require.NotNil(t, client)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })

	detail := makeAPIRequest(t, "GET", appConfig.AuthServer.BaseURL+"/api/v1/admin/clients/"+
		strconv.FormatInt(client.Id, 10), adminToken, nil)
	defer func() { _ = detail.Body.Close() }()
	require.Equal(t, http.StatusOK, detail.StatusCode)

	var body api.GetClientResponse
	require.NoError(t, json.NewDecoder(detail.Body).Decode(&body))
	return body.Client
}

func TestDCR_ABackchannelLogoutURIIsStoredAndEchoedWithItsFlag(t *testing.T) {
	enableDCR(t)
	adminToken, _ := createAdminClientWithToken(t)

	status, members := postDCRBody(t, `{"client_name":"Back-channel Registration",`+
		`"redirect_uris":["https://dcr-backchannel.example.com/callback"],`+
		`"backchannel_logout_uri":"https://dcr-backchannel.example.com/backchannel-logout?tenant=a",`+
		`"backchannel_logout_session_required":true}`)
	require.Equal(t, http.StatusCreated, status, "%v", members)

	assert.JSONEq(t, `"https://dcr-backchannel.example.com/backchannel-logout?tenant=a"`, string(members["backchannel_logout_uri"]))
	assert.JSONEq(t, `true`, string(members["backchannel_logout_session_required"]))

	client := registeredClientThroughTheAdminAPI(t, adminToken, members)
	assert.Equal(t, "https://dcr-backchannel.example.com/backchannel-logout?tenant=a", client.BackchannelLogoutURI)
	assert.True(t, client.BackchannelLogoutSessionRequired)
}

// A public client may register an https URI too, and its flag left out is stored and echoed false.
func TestDCR_APublicClientsBackchannelLogoutURIEchoesItsFlagFalse(t *testing.T) {
	enableDCR(t)
	adminToken, _ := createAdminClientWithToken(t)

	status, members := postDCRBody(t, `{"redirect_uris":["http://127.0.0.1:8765/callback"],`+
		`"token_endpoint_auth_method":"none",`+
		`"backchannel_logout_uri":"https://dcr-backchannel.example.com/backchannel-logout"}`)
	require.Equal(t, http.StatusCreated, status, "%v", members)

	assert.JSONEq(t, `false`, string(members["backchannel_logout_session_required"]))

	client := registeredClientThroughTheAdminAPI(t, adminToken, members)
	assert.Equal(t, "https://dcr-backchannel.example.com/backchannel-logout", client.BackchannelLogoutURI)
	assert.False(t, client.BackchannelLogoutSessionRequired)
}

// The flag sent without a URI is stored false, and the answer carries neither field.
func TestDCR_TheSessionRequiredFlagWithoutAURIIsStoredFalse(t *testing.T) {
	enableDCR(t)
	adminToken, _ := createAdminClientWithToken(t)

	status, members := postDCRBody(t, `{"redirect_uris":["https://dcr-backchannel.example.com/callback"],`+
		`"backchannel_logout_session_required":true}`)
	require.Equal(t, http.StatusCreated, status, "%v", members)

	assert.NotContains(t, members, "backchannel_logout_uri")
	assert.NotContains(t, members, "backchannel_logout_session_required")

	client := registeredClientThroughTheAdminAPI(t, adminToken, members)
	assert.Empty(t, client.BackchannelLogoutURI)
	assert.False(t, client.BackchannelLogoutSessionRequired)
}

// An http URI, which an administrator may set on a confidential client, is refused at
// registration whatever the client type; so are a URI with no flow that signs users in and a flag
// that is not a boolean. Each names its field and creates nothing.
func TestDCR_ARefusedBackchannelLogoutSettingCreatesNothing(t *testing.T) {
	enableDCR(t)
	adminToken, _ := createAdminClientWithToken(t)
	before := countClientsThroughTheAdminAPI(t, adminToken)

	tests := []struct {
		name  string
		body  string
		field string
	}{
		{name: "confidential, http",
			body:  `{"redirect_uris":["https://dcr-backchannel.example.com/callback"],"backchannel_logout_uri":"http://dcr-backchannel.example.com/backchannel-logout"}`,
			field: "backchannel_logout_uri"},
		{name: "no flow that signs users in",
			body:  `{"grant_types":["client_credentials"],"backchannel_logout_uri":"https://dcr-backchannel.example.com/backchannel-logout"}`,
			field: "backchannel_logout_uri"},
		{name: "a flag that is not a boolean",
			body:  `{"redirect_uris":["https://dcr-backchannel.example.com/callback"],"backchannel_logout_uri":"https://dcr-backchannel.example.com/backchannel-logout","backchannel_logout_session_required":"yes"}`,
			field: "backchannel_logout_session_required"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status, members := postDCRBody(t, tc.body)
			require.Equal(t, http.StatusBadRequest, status, "%v", members)
			assert.JSONEq(t, `"invalid_client_metadata"`, string(members["error"]))
			assert.Contains(t, string(members["error_description"]), tc.field)
			assert.NotContains(t, members, "client_id")
		})
	}

	assert.Equal(t, before, countClientsThroughTheAdminAPI(t, adminToken), "a refused registration creates no client")
}
