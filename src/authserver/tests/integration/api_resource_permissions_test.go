package integrationtests

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

// TestAPIResourcePermissionsGet tests the GET /api/v1/admin/resources/{resourceId}/permissions endpoint
func TestAPIResourcePermissionsGet_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test resource
	resource := createTestResource(t, "test-resource-perms-"+uuid.New().String()[:8], "Test Resource for Permissions")
	defer func() {
		_ = database.DeleteResource(nil, resource.Id)
	}()

	// Setup: Create test permissions
	perm1 := createTestPermission(t, resource.Id, "read", "Read permission")
	perm2 := createTestPermission(t, resource.Id, "write", "Write permission")
	perm3 := createTestPermission(t, resource.Id, "admin", "Admin permission")
	defer func() {
		_ = database.DeletePermission(nil, perm1.Id)
		_ = database.DeletePermission(nil, perm2.Id)
		_ = database.DeletePermission(nil, perm3.Id)
	}()

	// Test: Get permissions for resource
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(resource.Id, 10) + "/permissions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

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
	resource := createTestResource(t, "test-resource-no-perms-"+uuid.New().String()[:8], "Test Resource without Permissions")
	defer func() {
		_ = database.DeleteResource(nil, resource.Id)
	}()

	// Test: Get permissions for resource with no permissions
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(resource.Id, 10) + "/permissions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

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
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/99999/permissions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

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
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/" + tc.resourceId + "/permissions"
			resp := makeAPIRequest(t, "GET", url, accessToken, nil)
			defer resp.Body.Close()

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

func TestAPIResourcePermissionsGet_AuthServerResourceFiltersUserinfo(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Get the AuthServer resource (should exist as a default system resource)
	authServerResource, err := database.GetResourceByResourceIdentifier(nil, constants.AuthServerResourceIdentifier)
	assert.NoError(t, err)
	if authServerResource == nil {
		t.Skip("AuthServer resource not found in database - skipping userinfo filter test")
	}

	// Test: Get permissions for AuthServer resource
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(authServerResource.Id, 10) + "/permissions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var getResponse api.GetPermissionsByResourceResponse
	err = json.NewDecoder(resp.Body).Decode(&getResponse)
	assert.NoError(t, err)

	// Assert: Should not contain userinfo permission (it should be filtered out)
	for _, perm := range getResponse.Permissions {
		assert.NotEqual(t, constants.UserinfoPermissionIdentifier, perm.PermissionIdentifier,
			"Userinfo permission should be filtered out for AuthServer resource")
	}
}

func TestAPIResourcePermissionsGet_AuthServerResourceIncludesOtherPermissions(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Get the AuthServer resource
	authServerResource, err := database.GetResourceByResourceIdentifier(nil, constants.AuthServerResourceIdentifier)
	assert.NoError(t, err)
	if authServerResource == nil {
		t.Skip("AuthServer resource not found in database - skipping permission inclusion test")
	}

	// Setup: Create a test permission for AuthServer resource (non-userinfo)
	testPerm := createTestPermission(t, authServerResource.Id, "test-auth-perm", "Test Auth Permission")
	defer func() {
		_ = database.DeletePermission(nil, testPerm.Id)
	}()

	// Test: Get permissions for AuthServer resource
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(authServerResource.Id, 10) + "/permissions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

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
	resource := createTestResource(t, "test-non-authserver-"+uuid.New().String()[:8], "Test Non-AuthServer Resource")
	defer func() {
		_ = database.DeleteResource(nil, resource.Id)
	}()

	// Setup: Create permission with userinfo identifier (should NOT be filtered for non-AuthServer resources)
	userinfoLikePerm := createTestPermission(t, resource.Id, constants.UserinfoPermissionIdentifier, "Userinfo-like permission")
	regularPerm := createTestPermission(t, resource.Id, "regular-perm", "Regular permission")
	defer func() {
		_ = database.DeletePermission(nil, userinfoLikePerm.Id)
		_ = database.DeletePermission(nil, regularPerm.Id)
	}()

	// Test: Get permissions for non-AuthServer resource
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(resource.Id, 10) + "/permissions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

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
	userinfoResp, foundUserinfo := permMap[constants.UserinfoPermissionIdentifier]
	assert.True(t, foundUserinfo, "Userinfo permission should NOT be filtered for non-AuthServer resource")
	assert.Equal(t, userinfoLikePerm.Id, userinfoResp.Id)

	regularResp, foundRegular := permMap["regular-perm"]
	assert.True(t, foundRegular, "Regular permission should be present")
	assert.Equal(t, regularPerm.Id, regularResp.Id)
}

func TestAPIResourcePermissionsGet_Unauthorized(t *testing.T) {
	// Setup: Create test resource
	resource := createTestResource(t, "test-resource-unauth-"+uuid.New().String()[:8], "Test Resource for Unauthorized Test")
	defer func() {
		_ = database.DeleteResource(nil, resource.Id)
	}()

	// Test: Request without access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(resource.Id, 10) + "/permissions"
	req, err := http.NewRequest("GET", url, nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAPIResourcePermissionsGet_InvalidAccessToken(t *testing.T) {
	// Setup: Create test resource
	resource := createTestResource(t, "test-resource-invalid-token-"+uuid.New().String()[:8], "Test Resource for Invalid Token Test")
	defer func() {
		_ = database.DeleteResource(nil, resource.Id)
	}()

	// Test: Request with invalid access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(resource.Id, 10) + "/permissions"
	resp := makeAPIRequest(t, "GET", url, "invalid-token-here", nil)
	defer resp.Body.Close()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAPIResourcePermissionsGet_LargeNumberOfPermissions(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test resource
	resource := createTestResource(t, "test-resource-many-perms-"+uuid.New().String()[:8], "Test Resource with Many Permissions")
	defer func() {
		_ = database.DeleteResource(nil, resource.Id)
	}()

	// Setup: Create many permissions
	const numPermissions = 10
	var permissions []*models.Permission
	for i := 0; i < numPermissions; i++ {
		perm := createTestPermission(t, resource.Id, 
			"permission-"+strconv.Itoa(i), 
			"Permission number "+strconv.Itoa(i))
		permissions = append(permissions, perm)
	}
	
	defer func() {
		for _, perm := range permissions {
			_ = database.DeletePermission(nil, perm.Id)
		}
	}()

	// Test: Get permissions for resource with many permissions
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(resource.Id, 10) + "/permissions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

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