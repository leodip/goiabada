package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAPIClientDelete_Success verifies successful deletion of a non-system client
func TestAPIClientDelete_Success(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Create a client directly in DB to delete
	client := &record.Client{
		ClientIdentifier: "del-client-" + fake.LetterN(8),
		Description:      "to delete",
		Enabled:          true,
		IsPublic:         true,
	}
	err := database.CreateClient(context.Background(), nil, client)
	require.NoError(t, err)

	// Delete via API
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.ID, 10)
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var success api.SuccessResponse
	err = json.NewDecoder(resp.Body).Decode(&success)
	require.NoError(t, err)
	assert.True(t, success.Success)

	// Further GET should return 404
	resp2 := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, resp2.StatusCode)
}

// TestAPIClientDelete_SystemLevelRejected ensures system-level client cannot be deleted
func TestAPIClientDelete_SystemLevelRejected(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Find admin-console-client id via list
	listURL := appConfig.AuthServer.BaseURL + "/api/v1/admin/clients"
	resp := makeAPIRequest(t, "GET", listURL, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var listResp api.GetClientsResponse
	err := json.NewDecoder(resp.Body).Decode(&listResp)
	require.NoError(t, err)

	var sysID int64
	for _, c := range listResp.Clients {
		if c.ClientIdentifier == "admin-console-client" {
			sysID = c.ID
			break
		}
	}
	if sysID == 0 {
		t.Skip("system-level client not found")
	}

	delURL := appConfig.AuthServer.BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(sysID, 10)
	resp2 := makeAPIRequest(t, "DELETE", delURL, accessToken, nil)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
	var body map[string]interface{}
	_ = json.NewDecoder(resp2.Body).Decode(&body)
	if body["error_description"] != nil {
		msg := body["error_description"].(string)
		assert.Contains(t, msg, "system level client")
	}
}

// TestAPIClientDelete_NotFoundAndInvalidID covers 404 and 400 branches
func TestAPIClientDelete_NotFoundAndInvalidID(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Not found
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/clients/9999999"
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)

	// Invalid id format
	url = appConfig.AuthServer.BaseURL + "/api/v1/admin/clients/abc"
	resp = makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Unauthorized
	httpClient := createHTTPClient(t)
	req, err := http.NewRequest("DELETE", appConfig.AuthServer.BaseURL+"/api/v1/admin/clients/1", nil)
	require.NoError(t, err)
	resp2, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)
}

// TestAPIClientGetPermissions_IncludesPermissions ensures client-permissions endpoint returns assigned permissions
func TestAPIClientGetPermissions_IncludesPermissions(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Create a client and assign a permission
	client := &record.Client{
		ClientIdentifier: "perm-client-" + fake.LetterN(8),
		Enabled:          true,
		IsPublic:         true,
	}
	err := database.CreateClient(context.Background(), nil, client)
	require.NoError(t, err)
	defer func() { _ = database.DeleteClient(context.Background(), nil, client.ID) }()

	resource := createResource(t)
	perm := createPermission(t, resource.ID)
	err = database.CreateClientPermission(context.Background(), nil, &record.ClientPermission{ClientID: client.ID, PermissionID: perm.ID})
	require.NoError(t, err)

	// Call GET client permissions by id
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.ID, 10) + "/permissions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var getResp api.GetClientPermissionsResponse
	err = json.NewDecoder(resp.Body).Decode(&getResp)
	require.NoError(t, err)

	// Expect at least one permission present
	assert.GreaterOrEqual(t, len(getResp.Permissions), 1)
	// Verify identifiers present
	found := false
	for _, p := range getResp.Permissions {
		if p.ID == perm.ID {
			found = true
			break
		}
	}
	assert.True(t, found, "expected assigned permission in client response")
}

// TestAPIClientDelete_InsufficientScope ensures 403 when token lacks admin scope
func TestAPIClientDelete_InsufficientScope(t *testing.T) {
	// A valid token whose only scope is one no route grants, so the route answers 403
	accessToken := createClientCredentialsTokenWithoutRouteScope(t)

	// Create a target client to attempt deleting
	target := &record.Client{
		ClientIdentifier: "target-del-" + fake.LetterN(6),
		Enabled:          true,
		IsPublic:         true,
	}
	err := database.CreateClient(context.Background(), nil, target)
	require.NoError(t, err)
	defer func() { _ = database.DeleteClient(context.Background(), nil, target.ID) }()

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(target.ID, 10)
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// TestAPIClientDelete_CascadesLinkedData ensures related data is removed when a client is deleted
func TestAPIClientDelete_CascadesLinkedData(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Create client
	client := &record.Client{
		ClientIdentifier: "cascade-client-" + fake.LetterN(6),
		Enabled:          true,
		IsPublic:         true,
	}
	err := database.CreateClient(context.Background(), nil, client)
	require.NoError(t, err)

	// Create permission and assign to client
	resource := createResource(t)
	perm := createPermission(t, resource.ID)
	err = database.CreateClientPermission(context.Background(), nil, &record.ClientPermission{ClientID: client.ID, PermissionID: perm.ID})
	require.NoError(t, err)

	// Create user and consent to the client
	user := &record.User{Subject: fake.UUID(), Enabled: true, Email: fake.Email()}
	err = database.CreateUser(context.Background(), nil, user)
	require.NoError(t, err)
	consent := &record.UserConsent{ClientID: client.ID, UserID: user.ID, Scope: "openid"}
	err = database.CreateUserConsent(context.Background(), nil, consent)
	require.NoError(t, err)

	// Delete client via API
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.ID, 10)
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Assert client permissions removed
	cps, err := database.GetClientPermissionsByClientID(context.Background(), nil, client.ID)
	require.NoError(t, err)
	assert.Empty(t, cps)

	// Assert user consent removed
	uc, err := database.GetConsentByUserIDAndClientID(context.Background(), nil, user.ID, client.ID)
	require.NoError(t, err)
	assert.Nil(t, uc)
}
