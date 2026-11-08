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
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// PUT /api/v1/admin/clients/{id}/dpop sets a client's "Require DPoP for token requests" (#42
// decision 12, RFC 9449 section 5.2) from a required dpopBoundAccessTokens boolean, takes the scopes
// of the client's other settings, is never switched on for the admin console's own client, and is
// audited as updated_client_dpop. Every client the admin API answers carries the field.

// clientDPoPPath is the save's path for a client.
func clientDPoPPath(clientId int64) string {
	return "/api/v1/admin/clients/" + strconv.FormatInt(clientId, 10) + "/dpop"
}

// saveClientDPoP sends one save and decodes the answer as a JSON object.
func saveClientDPoP(t *testing.T, accessToken string, clientId int64, body any) (int, map[string]any, string) {
	t.Helper()
	resp, requestId := sendAdmin(t, accessToken, http.MethodPut, clientDPoPPath(clientId), body)
	defer func() { _ = resp.Body.Close() }()
	var decoded map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&decoded))
	return resp.StatusCode, decoded, requestId
}

// newClientRequiringDPoP creates a confidential client with the authorization code flow on, which
// requires DPoP as given, and deletes it when the test ends.
func newClientRequiringDPoP(t *testing.T, prefix string, requires bool) *record.Client {
	t.Helper()
	secret, err := dataCipher.Encrypt(fake.Password(60))
	require.NoError(t, err)
	client := &record.Client{
		ClientIdentifier:         prefix + strings.ToLower(fake.LetterN(8)),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		DefaultAcrLevel:          record.AcrLevel2Optional,
		ClientSecretEncrypted:    secret,
		DPoPBoundAccessTokens:    requires,
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, client))
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })
	return client
}

// readClientDPoP is the setting as GET /clients/{id} answers it.
func readClientDPoP(t *testing.T, accessToken string, clientId int64) bool {
	t.Helper()
	resp := makeAPIRequest(t, http.MethodGet, appConfig.AuthServer.BaseURL+"/api/v1/admin/clients/"+strconv.FormatInt(clientId, 10), accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var got api.GetClientResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	return got.Client.DPoPBoundAccessTokens
}

// The save switches the setting both ways; the answer, the detail, the listing and the row all
// carry it; and each committed save leaves one updated_client_dpop row naming the client, the value
// and the caller.
func TestAPIClientDPoPPut_SavesAndAnswersTheSetting(t *testing.T) {
	requireDatabaseAuditLogs(t)
	accessToken, caller := createAdminClientWithToken(t)
	client := newClientRequiringDPoP(t, "dpop-save-", false)
	assert.False(t, readClientDPoP(t, accessToken, client.Id), "a client created without it does not require DPoP")

	for _, on := range []bool{true, false} {
		status, body, requestId := saveClientDPoP(t, accessToken, client.Id, map[string]any{"dpopBoundAccessTokens": on})
		require.Equal(t, http.StatusOK, status, body)
		answered := body["client"].(map[string]any)
		assert.InDelta(t, float64(client.Id), answered["id"], 0)
		assert.Equal(t, on, answered["dpopBoundAccessTokens"])
		assert.Equal(t, on, storedClient(t, client.Id).DPoPBoundAccessTokens)
		assert.Equal(t, on, readClientDPoP(t, accessToken, client.Id))
		assert.Equal(t, []map[string]any{{
			"client_id":                float64(client.Id),
			"client_identifier":        client.ClientIdentifier,
			"dpop_bound_access_tokens": on,
			"logged_in_user":           caller.ClientIdentifier,
		}}, auditRows(t, accessToken, "updated_client_dpop", requestId))
	}

	required := newClientRequiringDPoP(t, "dpop-listed-", true)
	listing := makeAPIRequest(t, http.MethodGet, appConfig.AuthServer.BaseURL+"/api/v1/admin/clients", accessToken, nil)
	defer func() { _ = listing.Body.Close() }()
	require.Equal(t, http.StatusOK, listing.StatusCode)
	var clients api.GetClientsResponse
	require.NoError(t, json.NewDecoder(listing.Body).Decode(&clients))
	found := 0
	for _, listed := range clients.Clients {
		switch listed.Id {
		case required.Id:
			found++
			assert.True(t, listed.DPoPBoundAccessTokens)
		case client.Id:
			found++
			assert.False(t, listed.DPoPBoundAccessTokens)
		}
	}
	assert.Equal(t, 2, found, "both clients are in the listing")
}

// A body without the boolean, or with null, is refused rather than read as false, and changes
// nothing.
func TestAPIClientDPoPPut_TheBooleanIsRequired(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	client := newClientRequiringDPoP(t, "dpop-required-", true)

	for _, body := range []map[string]any{{}, {"dpopBoundAccessTokens": nil}} {
		status, answer, _ := saveClientDPoP(t, accessToken, client.Id, body)
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, "handler.client_dpop.dpop_bound_access_tokens_required", answer["error_code"])
		assert.Equal(t, "dpopBoundAccessTokens is required: send true or false.", answer["error_description"])
		assert.True(t, storedClient(t, client.Id).DPoPBoundAccessTokens, "nothing changed")
	}
}

// The admin console calls the auth server with Bearer tokens, so its own client is never switched
// on, even by authserver:manage: a localized validation error, nothing stored, nothing audited.
func TestAPIClientDPoPPut_TheAdminConsolesClientIsNeverSwitchedOn(t *testing.T) {
	requireDatabaseAuditLogs(t)
	accessToken, _ := createAdminClientWithToken(t)
	console, err := database.GetClientByClientIdentifier(context.Background(), nil, builtin.AdminConsoleClientIdentifier)
	require.NoError(t, err)
	require.NotNil(t, console)

	status, body, requestId := saveClientDPoP(t, accessToken, console.Id, map[string]any{"dpopBoundAccessTokens": true})
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "handler.client_dpop.admin_console_not_allowed", body["error_code"])
	assert.Equal(t, "The admin console's client can't require DPoP for token requests.", body["error_description"])
	assert.False(t, storedClient(t, console.Id).DPoPBoundAccessTokens)
	assert.Empty(t, auditRows(t, accessToken, "updated_client_dpop", requestId))
}

// The route takes the scopes of the client's other settings: manage-clients saves an ordinary
// client, and admin-read reads the field and cannot save. The request's own refusals answer as on
// the other client routes.
func TestAPIClientDPoPPut_ScopesAndTheRequestsOwnRefusals(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	client := newClientRequiringDPoP(t, "dpop-scopes-", false)

	granularToken, granular := createClientWithGranularScope(t, builtin.ManageClientsPermissionIdentifier)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, granular.Id) })
	status, body, _ := saveClientDPoP(t, granularToken, client.Id, map[string]any{"dpopBoundAccessTokens": true})
	require.Equal(t, http.StatusOK, status, body)
	assert.True(t, storedClient(t, client.Id).DPoPBoundAccessTokens)

	readToken, reader := createClientWithGranularScope(t, builtin.AdminReadPermissionIdentifier)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, reader.Id) })
	assert.True(t, readClientDPoP(t, readToken, client.Id), "admin-read reads the setting")
	status, body, _ = saveClientDPoP(t, readToken, client.Id, map[string]any{"dpopBoundAccessTokens": false})
	assert.Equal(t, http.StatusForbidden, status)
	assert.Equal(t, "INSUFFICIENT_SCOPE", body["error_code"])
	assert.True(t, storedClient(t, client.Id).DPoPBoundAccessTokens, "nothing changed")

	status, body, _ = saveClientDPoP(t, accessToken, 999999, map[string]any{"dpopBoundAccessTokens": true})
	assert.Equal(t, http.StatusNotFound, status)
	assert.Equal(t, "Client not found", body["error_description"])

	resp, _ := sendAdmin(t, accessToken, http.MethodPut, "/api/v1/admin/clients/abc/dpop", map[string]any{"dpopBoundAccessTokens": true})
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	unauthenticated, err := http.NewRequest(http.MethodPut, appConfig.AuthServer.BaseURL+clientDPoPPath(client.Id), nil)
	require.NoError(t, err)
	noToken, err := createHttpClient(t).Do(unauthenticated)
	require.NoError(t, err)
	defer func() { _ = noToken.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, noToken.StatusCode)
}
