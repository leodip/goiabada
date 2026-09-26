package integrationtests

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test GET /api/v1/admin/clients/{id}/permissions success
func TestAPIClientPermissions_Get_Success(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Create client
	client := &models.Client{ClientIdentifier: "api-perm-get-" + fake.LetterN(6), Enabled: true, IsPublic: true}
	err := database.CreateClient(context.Background(), nil, client)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(context.Background(), nil, client.Id) }()

	// Create resource + permission and assign to client
	resource := createResource(t)
	perm := createPermission(t, resource.Id)
	err = database.CreateClientPermission(context.Background(), nil, &models.ClientPermission{ClientId: client.Id, PermissionId: perm.Id})
	assert.NoError(t, err)

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/permissions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var apiResp api.GetClientPermissionsResponse
	err = json.NewDecoder(resp.Body).Decode(&apiResp)
	assert.NoError(t, err)
	assert.Equal(t, client.Id, apiResp.Client.Id)
	assert.GreaterOrEqual(t, len(apiResp.Permissions), 1)

	// Ensure the expected permission is present
	found := false
	for _, p := range apiResp.Permissions {
		if p.Id == perm.Id && p.Resource.Id == resource.Id {
			found = true
			break
		}
	}
	assert.True(t, found, "expected assigned permission in response")
}

// Test GET error cases: invalid id and not found
func TestAPIClientPermissions_Get_Errors(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Invalid format id
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/abc/permissions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var errResp api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Equal(t, "Invalid client ID format", errResp.ErrorDescription)

	// Not found
	url = config.GetAuthServer().BaseURL + "/api/v1/admin/clients/9999999/permissions"
	resp = makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	errResp = api.ErrorResponse{}
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Equal(t, "Client not found", errResp.ErrorDescription)
}

// Test PUT /api/v1/admin/clients/{id}/permissions add and remove
func TestAPIClientPermissions_Put_AddRemove(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Create confidential client with client-credentials enabled
	secret := fake.Password(32)
	enc, err := encryption.EncryptData(secret)
	assert.NoError(t, err)

	client := &models.Client{
		ClientIdentifier:         "api-perm-put-" + strings.ToLower(fake.LetterN(6)),
		Enabled:                  true,
		ClientCredentialsEnabled: true,
		IsPublic:                 false,
		ClientSecretEncrypted:    enc,
	}
	err = database.CreateClient(context.Background(), nil, client)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(context.Background(), nil, client.Id) }()

	// Create two permissions
	res := createResource(t)
	p1 := createPermission(t, res.Id)
	p2 := createPermission(t, res.Id)

	// First assign p1 (with a duplicate in request to test de-dup)
	putURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/permissions"
	reqBody := api.UpdateClientPermissionsRequest{PermissionIds: []int64{p1.Id, p1.Id}, ExpectedPermissionIds: getClientPermissionIds(t, accessToken, client.Id)}
	resp := makeAPIRequest(t, "PUT", putURL, accessToken, &reqBody)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var success api.SuccessResponse
	err = json.NewDecoder(resp.Body).Decode(&success)
	assert.NoError(t, err)
	assert.True(t, success.Success)

	// Verify only p1 is assigned
	cps, err := database.GetClientPermissionsByClientId(context.Background(), nil, client.Id)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(cps))
	assert.Equal(t, p1.Id, cps[0].PermissionId)

	// Now replace with p2 (should remove p1 and add p2)
	reqBody = api.UpdateClientPermissionsRequest{PermissionIds: []int64{p2.Id}, ExpectedPermissionIds: getClientPermissionIds(t, accessToken, client.Id)}
	resp2 := makeAPIRequest(t, "PUT", putURL, accessToken, &reqBody)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)

	cps, err = database.GetClientPermissionsByClientId(context.Background(), nil, client.Id)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(cps))
	assert.Equal(t, p2.Id, cps[0].PermissionId)
}

// Test PUT idempotence when sending the same set of permissions
func TestAPIClientPermissions_Put_Idempotent(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Create confidential client with client-credentials enabled
	secret := fake.Password(32)
	enc, err := encryption.EncryptData(secret)
	assert.NoError(t, err)

	client := &models.Client{ClientIdentifier: "api-perm-put-same-" + strings.ToLower(fake.LetterN(6)), Enabled: true, ClientCredentialsEnabled: true, IsPublic: false, ClientSecretEncrypted: enc}
	err = database.CreateClient(context.Background(), nil, client)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(context.Background(), nil, client.Id) }()

	// Create one permission and assign via PUT
	res := createResource(t)
	p := createPermission(t, res.Id)

	putURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/permissions"
	reqBody := api.UpdateClientPermissionsRequest{PermissionIds: []int64{p.Id}, ExpectedPermissionIds: getClientPermissionIds(t, accessToken, client.Id)}
	resp := makeAPIRequest(t, "PUT", putURL, accessToken, &reqBody)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify assignment
	cps, err := database.GetClientPermissionsByClientId(context.Background(), nil, client.Id)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(cps))
	assert.Equal(t, p.Id, cps[0].PermissionId)

	// Call PUT again with the same set (no changes expected), carrying the set as read again
	reqBody.ExpectedPermissionIds = getClientPermissionIds(t, accessToken, client.Id)
	resp2 := makeAPIRequest(t, "PUT", putURL, accessToken, &reqBody)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)

	// Verify still exactly one assignment, unchanged
	cps, err = database.GetClientPermissionsByClientId(context.Background(), nil, client.Id)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(cps))
	assert.Equal(t, p.Id, cps[0].PermissionId)
}

// Test GET and PUT unauthorized (no access token)
func TestAPIClientPermissions_Unauthorized(t *testing.T) {
	// Create a target client
	client := &models.Client{ClientIdentifier: "api-perm-unauth-" + fake.LetterN(6), Enabled: true, ClientCredentialsEnabled: true, IsPublic: true}
	err := database.CreateClient(context.Background(), nil, client)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(context.Background(), nil, client.Id) }()

	// GET without token
	getURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/permissions"
	httpClient := createHttpClient(t)
	req, _ := http.NewRequest("GET", getURL, nil)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	assert.Contains(t, buf.String(), "Access token required.")

	// PUT without token
	putURL := getURL
	reqBody := api.UpdateClientPermissionsRequest{PermissionIds: []int64{}, ExpectedPermissionIds: []int64{}}
	bodyBytes, _ := json.Marshal(&reqBody)
	req, _ = http.NewRequest("PUT", putURL, bytes.NewBuffer(bodyBytes))
	resp2, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)
	buf2 := new(bytes.Buffer)
	_, _ = buf2.ReadFrom(resp2.Body)
	assert.Contains(t, buf2.String(), "Access token required.")
}

// Test PUT validation: client-credentials disabled
func TestAPIClientPermissions_Put_ClientCredentialsDisabled(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	client := &models.Client{
		ClientIdentifier:         "api-perm-put-nocc-" + fake.LetterN(6),
		Enabled:                  true,
		ClientCredentialsEnabled: false,
		IsPublic:                 true,
	}
	err := database.CreateClient(context.Background(), nil, client)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(context.Background(), nil, client.Id) }()

	res := createResource(t)
	p := createPermission(t, res.Id)

	putURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/permissions"
	reqBody := api.UpdateClientPermissionsRequest{PermissionIds: []int64{p.Id}, ExpectedPermissionIds: getClientPermissionIds(t, accessToken, client.Id)}
	resp := makeAPIRequest(t, "PUT", putURL, accessToken, &reqBody)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var errResp api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Equal(t, "Client permissions can only be configured when client credentials flow is enabled", errResp.ErrorDescription)
}

// Test PUT on system-level client: verifies that the handler allows modifying
// permissions on a system-level client (no system-level blocking).
// The test temporarily enables ClientCredentialsEnabled on the system-level client,
// saves original permissions, adds a test one, asserts 200, then restores everything.
func TestAPIClientPermissions_Put_SystemLevelAllowed(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Find the system-level admin-console-client via DB
	sysClient, err := database.GetClientByClientIdentifier(context.Background(), nil, constants.AdminConsoleClientIdentifier)
	assert.NoError(t, err)
	if sysClient == nil {
		t.Skip("system-level client not found")
	}

	// Save original ClientCredentialsEnabled value and ensure it's enabled for the test
	origCCEnabled := sysClient.ClientCredentialsEnabled
	if !origCCEnabled {
		sysClient.ClientCredentialsEnabled = true
		err = database.UpdateClient(context.Background(), nil, sysClient)
		assert.NoError(t, err)
	}
	defer func() {
		// Restore original ClientCredentialsEnabled value
		if !origCCEnabled {
			sysClient.ClientCredentialsEnabled = origCCEnabled
			_ = database.UpdateClient(context.Background(), nil, sysClient)
		}
	}()

	// GET current permissions to save for restore
	getURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(sysClient.Id, 10) + "/permissions"
	respGet := makeAPIRequest(t, "GET", getURL, accessToken, nil)
	defer func() { _ = respGet.Body.Close() }()
	assert.Equal(t, http.StatusOK, respGet.StatusCode)

	var permsResp api.GetClientPermissionsResponse
	err = json.NewDecoder(respGet.Body).Decode(&permsResp)
	assert.NoError(t, err)

	// Collect original permission IDs for restore; never nil, since the loaded list is sent as it
	// was read and [] is a real value there
	originalPermIds := []int64{}
	for _, p := range permsResp.Permissions {
		originalPermIds = append(originalPermIds, p.Id)
	}

	// Create a new test resource + permission to add
	testResource := createResource(t)
	testPerm := createPermission(t, testResource.Id)

	// PUT: original permissions plus the new test permission
	modifiedPermIds := append([]int64{}, originalPermIds...)
	modifiedPermIds = append(modifiedPermIds, testPerm.Id)

	putURL := getURL
	reqBody := api.UpdateClientPermissionsRequest{PermissionIds: modifiedPermIds, ExpectedPermissionIds: originalPermIds}
	respPut := makeAPIRequest(t, "PUT", putURL, accessToken, &reqBody)
	defer func() { _ = respPut.Body.Close() }()

	// System-level client should NOT be blocked — expect 200
	assert.Equal(t, http.StatusOK, respPut.StatusCode)

	var putSuccess api.SuccessResponse
	_ = json.NewDecoder(respPut.Body).Decode(&putSuccess)
	assert.True(t, putSuccess.Success)

	// Verify the test permission was added
	cps, err := database.GetClientPermissionsByClientId(context.Background(), nil, sysClient.Id)
	assert.NoError(t, err)
	foundTest := false
	for _, cp := range cps {
		if cp.PermissionId == testPerm.Id {
			foundTest = true
			break
		}
	}
	assert.True(t, foundTest, "test permission should be assigned to system-level client")

	// Restore original permissions
	restoreBody := api.UpdateClientPermissionsRequest{PermissionIds: originalPermIds, ExpectedPermissionIds: getClientPermissionIds(t, accessToken, sysClient.Id)}
	respRestore := makeAPIRequest(t, "PUT", putURL, accessToken, &restoreBody)
	defer func() { _ = respRestore.Body.Close() }()
	assert.Equal(t, http.StatusOK, respRestore.StatusCode)
}

// Test PUT validation: permission id not found
func TestAPIClientPermissions_Put_PermissionNotFound(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Create client with client-credentials enabled
	client := &models.Client{ClientIdentifier: "api-perm-put-noperm-" + fake.LetterN(6), Enabled: true, ClientCredentialsEnabled: true, IsPublic: true}
	err := database.CreateClient(context.Background(), nil, client)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(context.Background(), nil, client.Id) }()

	putURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/permissions"
	reqBody := api.UpdateClientPermissionsRequest{PermissionIds: []int64{99999999}, ExpectedPermissionIds: getClientPermissionIds(t, accessToken, client.Id)}
	resp := makeAPIRequest(t, "PUT", putURL, accessToken, &reqBody)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)

	var errResp api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Contains(t, strings.ToLower(errResp.ErrorDescription), "permission not found")
}

// Test PUT insufficient scope (expect 403)
func TestAPIClientPermissions_Put_InsufficientScope(t *testing.T) {
	// A valid token whose only scope is one no route grants, so the route answers 403
	tok := createClientCredentialsTokenWithoutRouteScope(t)

	// Create target client to update
	target := &models.Client{ClientIdentifier: "api-perm-put-target-" + fake.LetterN(6), Enabled: true, ClientCredentialsEnabled: true, IsPublic: true}
	err := database.CreateClient(context.Background(), nil, target)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(context.Background(), nil, target.Id) }()

	putURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(target.Id, 10) + "/permissions"
	reqBody := api.UpdateClientPermissionsRequest{PermissionIds: []int64{}, ExpectedPermissionIds: []int64{}}
	// Intentionally use insufficient scope token
	resp := makeAPIRequest(t, "PUT", putURL, tok, &reqBody)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	// Plain text error from middleware
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	assert.Contains(t, buf.String(), "Insufficient scope.")
}

// getClientPermissionIds reads the client's grants through the API, as a caller does before a
// save, and returns their ids: the loaded set a save carries (#428).
func getClientPermissionIds(t *testing.T, accessToken string, clientId int64) []int64 {
	t.Helper()
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(clientId, 10) + "/permissions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body api.GetClientPermissionsResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	ids := []int64{}
	for _, p := range body.Permissions {
		ids = append(ids, p.Id)
	}
	return ids
}

// createClientForPermissionsSave creates a confidential client with the client credentials flow
// enabled, which is what its permissions are configurable for, and removes it afterwards.
func createClientForPermissionsSave(t *testing.T) *models.Client {
	t.Helper()
	enc, err := encryption.EncryptData(fake.Password(32))
	require.NoError(t, err)
	client := &models.Client{
		ClientIdentifier:         "api-perm-expected-" + strings.ToLower(fake.LetterN(6)),
		Enabled:                  true,
		ClientCredentialsEnabled: true,
		ClientSecretEncrypted:    enc,
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, client))
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })
	return client
}

// The loaded set is required: absent or null answers 400 naming the field, and nothing is granted
// (#428).
func TestAPIClientPermissions_Put_TheLoadedListIsRequired(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	client := createClientForPermissionsSave(t)
	perm := createPermission(t, createResource(t).Id)
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/permissions"

	bodies := map[string]interface{}{
		"absent": map[string]interface{}{"permissionIds": []int64{perm.Id}},
		"null":   map[string]interface{}{"permissionIds": []int64{perm.Id}, "expectedPermissionIds": nil},
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			resp := makeAPIRequest(t, "PUT", url, accessToken, body)
			defer func() { _ = resp.Body.Close() }()
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			var got map[string]interface{}
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
			assert.Equal(t, "VALIDATION_ERROR", got["error_code"])
			assert.Contains(t, got["error_description"], "expectedPermissionIds is required")
			assert.Empty(t, getClientPermissionIds(t, accessToken, client.Id))
		})
	}
}

// Two administrators load the same grants; the first revokes one, and the second, still holding
// the set as it was, saves. The second is refused 409 CONCURRENT_UPDATE and writes nothing, rather
// than re-granting what the first had just revoked (#428).
func TestAPIClientPermissions_Put_AnOutdatedLoadedListIsRefused(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	client := createClientForPermissionsSave(t)
	res := createResource(t)
	permA := createPermission(t, res.Id)
	permB := createPermission(t, res.Id)
	permC := createPermission(t, res.Id)
	for _, p := range []*models.Permission{permA, permB} {
		require.NoError(t, database.CreateClientPermission(context.Background(), nil, &models.ClientPermission{ClientId: client.Id, PermissionId: p.Id}))
	}
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/permissions"

	loadedByBoth := getClientPermissionIds(t, accessToken, client.Id)

	first := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateClientPermissionsRequest{
		PermissionIds: []int64{permB.Id}, ExpectedPermissionIds: loadedByBoth})
	defer func() { _ = first.Body.Close() }()
	require.Equal(t, http.StatusOK, first.StatusCode)

	second := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateClientPermissionsRequest{
		PermissionIds: []int64{permA.Id, permB.Id, permC.Id}, ExpectedPermissionIds: loadedByBoth})
	defer func() { _ = second.Body.Close() }()
	assert.Equal(t, http.StatusConflict, second.StatusCode)
	var body map[string]interface{}
	require.NoError(t, json.NewDecoder(second.Body).Decode(&body))
	assert.Equal(t, "CONCURRENT_UPDATE", body["error_code"])

	assert.Equal(t, []int64{permB.Id}, getClientPermissionIds(t, accessToken, client.Id), "the first save's result stands")
}
