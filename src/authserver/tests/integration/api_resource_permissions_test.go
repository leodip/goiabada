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
	"github.com/leodip/goiabada/core/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAPIResourcePermissionsGet tests the GET /api/v1/admin/resources/{resourceId}/permissions endpoint
func TestAPIResourcePermissionsGet_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test resource
	resource := createTestResource(t, "test-resource-perms-"+fake.UUID()[:8], "Test Resource for Permissions")
	defer func() {
		_ = database.DeleteResource(context.Background(), nil, resource.Id)
	}()

	// Setup: Create test permissions
	perm1 := createTestPermission(t, resource.Id, "read", "Read permission")
	perm2 := createTestPermission(t, resource.Id, "write", "Write permission")
	perm3 := createTestPermission(t, resource.Id, "admin", "Admin permission")
	defer func() {
		_ = database.DeletePermission(context.Background(), nil, perm1.Id)
		_ = database.DeletePermission(context.Background(), nil, perm2.Id)
		_ = database.DeletePermission(context.Background(), nil, perm3.Id)
	}()

	// Test: Get permissions for resource
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(resource.Id, 10) + "/permissions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var getResponse api.GetPermissionsByResourceResponse
	err := json.NewDecoder(resp.Body).Decode(&getResponse)
	assert.NoError(t, err)

	// Assert: Should return all 3 permissions with embedded resource info
	assert.Len(t, getResponse.Permissions, 3)

	// Create map for easier verification
	permissionMap := make(map[string]api.PermissionResponse)
	for _, perm := range getResponse.Permissions {
		permissionMap[perm.PermissionIdentifier] = perm

		// Verify each permission has embedded resource info
		assert.Equal(t, resource.Id, perm.ResourceId)
		assert.Equal(t, resource.ResourceIdentifier, perm.Resource.ResourceIdentifier)
		assert.Equal(t, resource.Description, perm.Resource.Description)
	}

	// Verify specific permissions
	readPerm, foundRead := permissionMap["read"]
	assert.True(t, foundRead, "Read permission should be present")
	assert.Equal(t, perm1.Id, readPerm.Id)
	assert.Equal(t, "Read permission", readPerm.Description)

	writePerm, foundWrite := permissionMap["write"]
	assert.True(t, foundWrite, "Write permission should be present")
	assert.Equal(t, perm2.Id, writePerm.Id)
	assert.Equal(t, "Write permission", writePerm.Description)

	adminPerm, foundAdmin := permissionMap["admin"]
	assert.True(t, foundAdmin, "Admin permission should be present")
	assert.Equal(t, perm3.Id, adminPerm.Id)
	assert.Equal(t, "Admin permission", adminPerm.Description)
}

func TestAPIResourcePermissionsGet_NoPermissions(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test resource without permissions
	resource := createTestResource(t, "test-resource-no-perms-"+fake.UUID()[:8], "Test Resource without Permissions")
	defer func() {
		_ = database.DeleteResource(context.Background(), nil, resource.Id)
	}()

	// Test: Get permissions for resource with no permissions
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(resource.Id, 10) + "/permissions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var getResponse api.GetPermissionsByResourceResponse
	err := json.NewDecoder(resp.Body).Decode(&getResponse)
	assert.NoError(t, err)

	// Assert: Should return empty permissions array (not nil)
	assert.Len(t, getResponse.Permissions, 0)
	assert.NotNil(t, getResponse.Permissions, "Permissions should be empty array, not nil")
}

func TestAPIResourcePermissionsGet_NonExistentResource(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Get permissions for non-existent resource
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/resources/99999/permissions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return OK with empty permissions (current implementation doesn't validate resource existence)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var getResponse api.GetPermissionsByResourceResponse
	err := json.NewDecoder(resp.Body).Decode(&getResponse)
	assert.NoError(t, err)

	// Assert: Should return empty permissions array
	assert.Len(t, getResponse.Permissions, 0)
}

func TestAPIResourcePermissionsGet_InvalidResourceId(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	testCases := []struct {
		name           string
		resourceId     string
		expectedStatus int
	}{
		{"non-numeric ID", "abc", http.StatusBadRequest},
		{"empty ID", "", http.StatusBadRequest},
		{"negative ID", "-1", http.StatusOK}, // Negative IDs are parsed but return empty results
		{"zero ID", "0", http.StatusOK},      // Zero ID returns empty results
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := appConfig.AuthServer.BaseURL + "/api/v1/admin/resources/" + tc.resourceId + "/permissions"
			resp := makeAPIRequest(t, "GET", url, accessToken, nil)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)

			if tc.expectedStatus == http.StatusOK {
				// For successful responses, verify empty permissions
				var getResponse api.GetPermissionsByResourceResponse
				err := json.NewDecoder(resp.Body).Decode(&getResponse)
				assert.NoError(t, err)
				assert.Len(t, getResponse.Permissions, 0)
			}
		})
	}
}

// The authserver resource's GET answers every permission stored on it: the seven built-ins, and any
// other, a permission identified userinfo included. It used to leave userinfo out, and the save
// demanded it as a built-in, so a save built from what the GET answered was refused (#449).
func TestAPIResourcePermissionsGet_TheAuthServerResourceAnswersEveryStoredPermission(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	authServerResource, err := database.GetResourceByResourceIdentifier(context.Background(), nil, builtin.AuthServerResourceIdentifier)
	require.NoError(t, err)
	require.NotNil(t, authServerResource, "the seed creates the authserver resource")

	userinfoNamed := createTestPermission(t, authServerResource.Id, "userinfo", "Created by an administrator")
	t.Cleanup(func() { _ = database.DeletePermission(context.Background(), nil, userinfoNamed.Id) })

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(authServerResource.Id, 10) + "/permissions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var getResponse api.GetPermissionsByResourceResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&getResponse))

	stored, err := database.GetPermissionsByResourceId(context.Background(), nil, authServerResource.Id)
	require.NoError(t, err)
	storedIds := make(map[int64]string, len(stored))
	for _, p := range stored {
		storedIds[p.Id] = p.PermissionIdentifier
	}
	answeredIds := make(map[int64]string, len(getResponse.Permissions))
	for _, p := range getResponse.Permissions {
		answeredIds[p.Id] = p.PermissionIdentifier
	}
	assert.Equal(t, storedIds, answeredIds, "the GET answers exactly the stored permissions")

	answered := make([]string, 0, len(getResponse.Permissions))
	for _, p := range getResponse.Permissions {
		answered = append(answered, p.PermissionIdentifier)
	}
	assert.Subset(t, answered, builtin.AuthServerPermissionIdentifiers(), "every built-in is answered")
	assert.Contains(t, answered, "userinfo", "a permission identified userinfo is answered as any other")
}

func TestAPIResourcePermissionsGet_AuthServerResourceIncludesOtherPermissions(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Get the AuthServer resource
	authServerResource, err := database.GetResourceByResourceIdentifier(context.Background(), nil, builtin.AuthServerResourceIdentifier)
	assert.NoError(t, err)
	if authServerResource == nil {
		t.Skip("AuthServer resource not found in database - skipping permission inclusion test")
	}

	// Setup: Create a test permission for AuthServer resource (non-userinfo)
	testPerm := createTestPermission(t, authServerResource.Id, "test-auth-perm", "Test Auth Permission")
	defer func() {
		_ = database.DeletePermission(context.Background(), nil, testPerm.Id)
	}()

	// Test: Get permissions for AuthServer resource
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(authServerResource.Id, 10) + "/permissions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var getResponse api.GetPermissionsByResourceResponse
	err = json.NewDecoder(resp.Body).Decode(&getResponse)
	assert.NoError(t, err)

	// Assert: Should include our test permission
	found := false
	for _, perm := range getResponse.Permissions {
		if perm.Id == testPerm.Id {
			found = true
			assert.Equal(t, "test-auth-perm", perm.PermissionIdentifier)
			assert.Equal(t, "Test Auth Permission", perm.Description)
			break
		}
	}
	assert.True(t, found, "Test permission should be included for AuthServer resource")
}

func TestAPIResourcePermissionsGet_NonAuthServerResourceIncludesAllPermissions(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test resource (non-AuthServer)
	resource := createTestResource(t, "test-non-authserver-"+fake.UUID()[:8], "Test Non-AuthServer Resource")
	defer func() {
		_ = database.DeleteResource(context.Background(), nil, resource.Id)
	}()

	// Setup: a permission identified userinfo, which the authserver resource's GET used to leave out
	userinfoLikePerm := createTestPermission(t, resource.Id, "userinfo", "Userinfo-like permission")
	regularPerm := createTestPermission(t, resource.Id, "regular-perm", "Regular permission")
	defer func() {
		_ = database.DeletePermission(context.Background(), nil, userinfoLikePerm.Id)
		_ = database.DeletePermission(context.Background(), nil, regularPerm.Id)
	}()

	// Test: Get permissions for non-AuthServer resource
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(resource.Id, 10) + "/permissions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var getResponse api.GetPermissionsByResourceResponse
	err := json.NewDecoder(resp.Body).Decode(&getResponse)
	assert.NoError(t, err)

	// Assert: Should include both permissions (no filtering for non-AuthServer resources)
	assert.Len(t, getResponse.Permissions, 2)

	permMap := make(map[string]api.PermissionResponse)
	for _, perm := range getResponse.Permissions {
		permMap[perm.PermissionIdentifier] = perm
	}

	// Both permissions should be present
	userinfoResp, foundUserinfo := permMap["userinfo"]
	assert.True(t, foundUserinfo, "Userinfo permission should be present")
	assert.Equal(t, userinfoLikePerm.Id, userinfoResp.Id)

	regularResp, foundRegular := permMap["regular-perm"]
	assert.True(t, foundRegular, "Regular permission should be present")
	assert.Equal(t, regularPerm.Id, regularResp.Id)
}

func TestAPIResourcePermissionsGet_Unauthorized(t *testing.T) {
	// Setup: Create test resource
	resource := createTestResource(t, "test-resource-unauth-"+fake.UUID()[:8], "Test Resource for Unauthorized Test")
	defer func() {
		_ = database.DeleteResource(context.Background(), nil, resource.Id)
	}()

	// Test: Request without access token
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(resource.Id, 10) + "/permissions"
	req, err := http.NewRequest("GET", url, nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAPIResourcePermissionsGet_InvalidAccessToken(t *testing.T) {
	// Setup: Create test resource
	resource := createTestResource(t, "test-resource-invalid-token-"+fake.UUID()[:8], "Test Resource for Invalid Token Test")
	defer func() {
		_ = database.DeleteResource(context.Background(), nil, resource.Id)
	}()

	// Test: Request with invalid access token
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(resource.Id, 10) + "/permissions"
	resp := makeAPIRequest(t, "GET", url, "invalid-token-here", nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAPIResourcePermissionsGet_LargeNumberOfPermissions(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test resource
	resource := createTestResource(t, "test-resource-many-perms-"+fake.UUID()[:8], "Test Resource with Many Permissions")
	defer func() {
		_ = database.DeleteResource(context.Background(), nil, resource.Id)
	}()

	// Setup: Create many permissions
	const numPermissions = 10
	var permissions []*record.Permission
	for i := 0; i < numPermissions; i++ {
		perm := createTestPermission(t, resource.Id,
			"permission-"+strconv.Itoa(i),
			"Permission number "+strconv.Itoa(i))
		permissions = append(permissions, perm)
	}

	defer func() {
		for _, perm := range permissions {
			_ = database.DeletePermission(context.Background(), nil, perm.Id)
		}
	}()

	// Test: Get permissions for resource with many permissions
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(resource.Id, 10) + "/permissions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var getResponse api.GetPermissionsByResourceResponse
	err := json.NewDecoder(resp.Body).Decode(&getResponse)
	assert.NoError(t, err)

	// Assert: Should return all permissions
	assert.Len(t, getResponse.Permissions, numPermissions)

	// Verify all permissions have proper resource info embedded
	for _, perm := range getResponse.Permissions {
		assert.Equal(t, resource.Id, perm.ResourceId)
		assert.Equal(t, resource.ResourceIdentifier, perm.Resource.ResourceIdentifier)
		assert.Equal(t, resource.Description, perm.Resource.Description)
		assert.NotEmpty(t, perm.PermissionIdentifier)
		assert.NotEmpty(t, perm.Description)
	}

	// Verify we can find all our created permissions
	responsePermIds := make(map[int64]bool)
	for _, perm := range getResponse.Permissions {
		responsePermIds[perm.Id] = true
	}

	for _, createdPerm := range permissions {
		assert.True(t, responsePermIds[createdPerm.Id],
			"Permission %d should be in response", createdPerm.Id)
	}
}
