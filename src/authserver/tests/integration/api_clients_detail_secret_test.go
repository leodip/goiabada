package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A client's secret is read from GET /api/v1/admin/clients/{id}/secret alone, which admits
// manage-clients or manage, and every read of one leaves a viewed_client_secret row. Neither the
// client detail nor the list carries it, so admin-read, called read-only, receives no credential
// (#402 decision 8, #403).
//
// The cache assertions are here rather than in cache_directives_test.go because this is the test
// that establishes which response carries the secret. GET /clients/{id}/secret is one of the two
// API responses that carry a credential outright (#247), with the TOTP enrolment seed, so RFC 6749
// section 5.1's MUST reaches it.
//
// It cannot be inherited from the route sweep in internal/server/routes_no_store_test.go. That
// sweep calls every registered route WITHOUT credentials, so it never reaches a handler at all: a
// handler that set its own Cache-Control would win, because Header().Set replaces, and the sweep
// would stay green. An authenticated success response is the only seam that can observe it, which
// is why the two credential-bearing ones each carry the assertion themselves.

// confidentialClient stores a confidential client under a fresh secret and returns both.
func confidentialClient(t *testing.T) (*record.Client, string) {
	t.Helper()
	clientSecret := fake.Password(32)
	enc, err := dataCipher.Encrypt(clientSecret)
	require.NoError(t, err)

	client := &record.Client{
		ClientIdentifier:         "secret-client-" + strings.ToLower(fake.LetterN(8)),
		Enabled:                  true,
		ClientCredentialsEnabled: true,
		IsPublic:                 false,
		ClientSecretEncrypted:    enc,
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, client))
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })
	return client, clientSecret
}

func clientSecretPath(clientId int64) string {
	return "/api/v1/admin/clients/" + strconv.FormatInt(clientId, 10) + "/secret"
}

// readClientSecret calls the secret route and decodes its answer when it is a 200.
func readClientSecret(t *testing.T, accessToken string, clientId int64) (*http.Response, map[string]any, string) {
	t.Helper()
	resp, requestId := sendAdmin(t, accessToken, http.MethodGet, clientSecretPath(clientId), nil)
	var body map[string]any
	if resp.StatusCode == http.StatusOK {
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	}
	return resp, body, requestId
}

// The detail and the list carry no clientSecret key at all, not merely an empty one.
func TestAPIClientGet_NeitherTheDetailNorTheListCarriesTheSecret(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	client, clientSecret := confidentialClient(t)

	detailURL := appConfig.AuthServer.BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10)
	resp := makeAPIRequest(t, "GET", detailURL, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var detail struct {
		Client map[string]any `json:"client"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&detail))
	assert.InDelta(t, float64(client.Id), detail.Client["id"], 0, "the detail is this client's")
	assert.NotContains(t, detail.Client, "clientSecret")
	encoded, err := json.Marshal(detail)
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), clientSecret)

	listURL := appConfig.AuthServer.BaseURL + "/api/v1/admin/clients"
	resp2 := makeAPIRequest(t, "GET", listURL, accessToken, nil)
	defer func() { _ = resp2.Body.Close() }()
	require.Equal(t, http.StatusOK, resp2.StatusCode)
	var list struct {
		Clients []map[string]any `json:"clients"`
	}
	require.NoError(t, json.NewDecoder(resp2.Body).Decode(&list))
	found := false
	for _, c := range list.Clients {
		if c["id"] == float64(client.Id) {
			found = true
			assert.NotContains(t, c, "clientSecret")
		}
	}
	assert.True(t, found, "newly created client should be in list")

	// The list carries no credential, and it is asserted anyway: it is an authenticated SUCCESS
	// response, which is the half of the API surface the unauthenticated route sweep structurally
	// cannot reach. One line here covers a non-credential success alongside the two credential
	// ones, so "every route the router registers" is observed on both sides of the guards.
	assertNotStorable(t, resp2, "the admin client list")
}

// manage reads the decrypted secret, the answer may not be stored, and the read is recorded.
func TestAPIClientSecretGet_ReturnsTheDecryptedSecretAndRecordsTheRead(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, manageClient := createAdminClientWithToken(t)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, manageClient.Id) })
	client, clientSecret := confidentialClient(t)

	resp, body, requestId := readClientSecret(t, manageToken, client.Id)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, map[string]any{"clientSecret": clientSecret}, body)

	// The body really did carry the decrypted secret, asserted immediately above, so this is the
	// credential-bearing response rather than an error body that happens to be uncacheable.
	assertNotStorable(t, resp, "the client secret")

	rows := auditRows(t, manageToken, "viewed_client_secret", requestId)
	require.Len(t, rows, 1, "one viewed_client_secret row for the read")
	assert.Equal(t, map[string]any{
		"client_id":         float64(client.Id),
		"client_identifier": client.ClientIdentifier,
		"logged_in_user":    manageClient.ClientIdentifier,
	}, rows[0])
}

// One case per scope: manage-clients and manage read the secret, and every other scope, admin-read
// included, is refused at the route.
func TestAPIClientSecretGet_AdmitsManageClientsAndManageOnly(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)
	client, clientSecret := confidentialClient(t)

	testCases := []struct {
		permission string
		admitted   bool
	}{
		{builtin.ManagePermissionIdentifier, true},
		{builtin.ManageClientsPermissionIdentifier, true},
		{builtin.AdminReadPermissionIdentifier, false},
		{builtin.ManageUsersPermissionIdentifier, false},
		{builtin.ManageSettingsPermissionIdentifier, false},
	}
	for _, tc := range testCases {
		t.Run(tc.permission, func(t *testing.T) {
			token, caller := createClientWithGranularScope(t, tc.permission)
			t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, caller.Id) })

			resp, body, requestId := readClientSecret(t, token, client.Id)
			defer func() { _ = resp.Body.Close() }()

			viewed := auditRows(t, manageToken, "viewed_client_secret", requestId)
			if tc.admitted {
				require.Equal(t, http.StatusOK, resp.StatusCode)
				assert.Equal(t, clientSecret, body["clientSecret"])
				require.Len(t, viewed, 1)
				assert.Equal(t, caller.ClientIdentifier, viewed[0]["logged_in_user"])
				return
			}
			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
			var envelope struct {
				ErrorCode string `json:"error_code"`
			}
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&envelope))
			assert.Equal(t, "INSUFFICIENT_SCOPE", envelope.ErrorCode)
			assert.Empty(t, viewed, "a refused read records no view")
		})
	}
}

// A public client holds no secret: an empty one is answered, and nothing was disclosed to record.
func TestAPIClientSecretGet_APublicClientAnswersAnEmptySecret(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)
	client := createPublicClient(t)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })

	resp, body, requestId := readClientSecret(t, manageToken, client.Id)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, map[string]any{"clientSecret": ""}, body)
	assert.Empty(t, auditRows(t, manageToken, "viewed_client_secret", requestId))
}

func TestAPIClientSecretGet_AnUnknownOrMalformedIdIsRefused(t *testing.T) {
	manageToken, _ := createAdminClientWithToken(t)

	resp, _, _ := readClientSecret(t, manageToken, 999999999)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)

	resp, _ = sendAdmin(t, manageToken, http.MethodGet, "/api/v1/admin/clients/abc/secret", nil)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}
