package integrationtests

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
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

// TestAPIResourcesGet tests the GET /api/v1/admin/resources endpoint
func TestAPIResourcesGet_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test resources
	resource1 := createTestResource(t, "api-test-resource-1", "API Test Resource 1")
	resource2 := createTestResource(t, "api-test-resource-2", "API Test Resource 2")
	defer func() {
		_ = database.DeleteResource(context.Background(), nil, resource1.Id)
		_ = database.DeleteResource(context.Background(), nil, resource2.Id)
	}()

	// Test: Get all resources
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var getResponse api.GetResourcesResponse
	err := json.NewDecoder(resp.Body).Decode(&getResponse)
	assert.NoError(t, err)

	// Assert: Should include our test resources (plus any existing ones)
	assert.GreaterOrEqual(t, len(getResponse.Resources), 2)

	// Create map for easier assertion
	resourceMap := make(map[string]api.ResourceResponse)
	for _, resource := range getResponse.Resources {
		resourceMap[resource.ResourceIdentifier] = resource
	}

	// Verify our test resources are present
	res1, exists := resourceMap["api-test-resource-1"]
	assert.True(t, exists)
	assert.Equal(t, "API Test Resource 1", res1.Description)
	assert.Equal(t, resource1.Id, res1.Id)

	res2, exists := resourceMap["api-test-resource-2"]
	assert.True(t, exists)
	assert.Equal(t, "API Test Resource 2", res2.Description)
	assert.Equal(t, resource2.Id, res2.Id)

	// Verify resources are sorted by identifier (should come before existing resources like "goiabada-authserver")
	if len(getResponse.Resources) >= 2 {
		for i := 0; i < len(getResponse.Resources)-1; i++ {
			assert.True(t, getResponse.Resources[i].ResourceIdentifier <= getResponse.Resources[i+1].ResourceIdentifier,
				"Resources should be sorted by identifier")
		}
	}
}

func TestAPIResourcesGet_EmptyDatabase(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Note: We can't truly test empty database since the system creates default resources
	// But we can still test the endpoint structure

	// Test: Get resources
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var getResponse api.GetResourcesResponse
	err := json.NewDecoder(resp.Body).Decode(&getResponse)
	assert.NoError(t, err)

	// Assert: Should have proper structure (system resources exist)
	assert.NotNil(t, getResponse.Resources)
	// System should have at least the default authserver and adminconsole resources
	assert.GreaterOrEqual(t, len(getResponse.Resources), 0)
}

func TestAPIResourcesGet_Unauthorized(t *testing.T) {
	// Test: Request without access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources"
	req, err := http.NewRequest("GET", url, nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Assert error body
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	assert.Contains(t, string(body), "Access token required.")
}

func TestAPIResourcesGet_InvalidToken(t *testing.T) {
	// Test: Request with invalid access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources"
	resp := makeAPIRequest(t, "GET", url, "invalid-token", nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Assert error body matches middleware message
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	assert.Contains(t, string(body), "Access token required.")
}

// Test insufficient scope returns 403 with proper error text
func TestAPIResourcesGet_InsufficientScope(t *testing.T) {
	// A non-admin client whose only scope is one no route grants
	token := createClientCredentialsTokenWithoutRouteScope(t)

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources"
	resp := makeAPIRequest(t, "GET", url, token, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	// Assert error body and content type from middleware
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	assert.Contains(t, string(body), "Insufficient scope.")
}

// Helper to create a client-credentials access token with a specific scope
func createClientCredentialsTokenWithScope(t *testing.T, resourceIdentifier, permissionIdentifier string) string {
	// Create a confidential client eligible for client_credentials
	clientSecret := "test-secret-non-admin-1234567890"

	encSecret, err := encryption.EncryptData(clientSecret)
	assert.NoError(t, err)

	client := &models.Client{
		ClientIdentifier:         "nonadmin-test-client-" + fake.UUID()[:8],
		Enabled:                  true,
		ClientCredentialsEnabled: true,
		IsPublic:                 false,
		ClientSecretEncrypted:    encSecret,
	}
	err = database.CreateClient(context.Background(), nil, client)
	assert.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, database.DeleteClient(context.Background(), nil, client.Id))
	})

	// Find the requested permission
	resource, err := database.GetResourceByResourceIdentifier(context.Background(), nil, resourceIdentifier)
	assert.NoError(t, err)
	assert.NotNil(t, resource)

	perms, err := database.GetPermissionsByResourceId(context.Background(), nil, resource.Id)
	assert.NoError(t, err)

	var selected *models.Permission
	for i := range perms {
		if perms[i].PermissionIdentifier == permissionIdentifier {
			selected = &perms[i]
			break
		}
	}
	assert.NotNil(t, selected, "permission should exist")

	// Assign permission to client
	err = database.CreateClientPermission(context.Background(), nil, &models.ClientPermission{ClientId: client.Id, PermissionId: selected.Id})
	assert.NoError(t, err)

	// Request an access token with that scope
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"scope":         {resourceIdentifier + ":" + permissionIdentifier},
	}
	tokenEndpoint := config.GetAuthServer().BaseURL + "/auth/token/"
	httpClient := createHttpClient(t)
	data := postToTokenEndpoint(t, httpClient, tokenEndpoint, form)
	accessToken, ok := data["access_token"].(string)
	assert.True(t, ok)
	assert.NotEmpty(t, accessToken)
	assert.Equal(t, resourceIdentifier+":"+permissionIdentifier, data["scope"], "the reported scope is the grant")
	return accessToken
}

// createClientCredentialsTokenWithoutRouteScope returns a valid client-credentials token whose only
// scope is a throwaway permission no route requires, for the tests showing a route answers 403 to a
// token lacking its scope. The permission sits on the authserver resource so the token's aud names
// authserver, as does every token those routes serve (#401); and it is deleted when the test
// ends, because later tests read, count and save the authserver resource's permission list (#449).
func createClientCredentialsTokenWithoutRouteScope(t *testing.T) string {
	t.Helper()
	resource, err := database.GetResourceByResourceIdentifier(context.Background(), nil, constants.AuthServerResourceIdentifier)
	require.NoError(t, err)
	require.NotNil(t, resource)

	permission := createTestPermission(t, resource.Id, "no-route-scope-"+strings.ToLower(fake.LetterN(8)), "Grants no route")
	require.NotZero(t, permission.Id)
	t.Cleanup(func() {
		assert.NoError(t, database.DeletePermission(context.Background(), nil, permission.Id))
	})

	return createClientCredentialsTokenWithScope(t, constants.AuthServerResourceIdentifier, permission.PermissionIdentifier)
}

// Helper function to create multiple test resources for more comprehensive testing
func TestAPIResourcesGet_ManyResources(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create multiple test resources with different identifiers for sorting test
	var testResources []*models.Resource
	resourceNames := []string{"zebra-resource", "alpha-resource", "beta-resource"}

	for _, name := range resourceNames {
		resource := createTestResource(t, name, "Description for "+name)
		testResources = append(testResources, resource)
	}

	defer func() {
		// Cleanup test resources
		for _, resource := range testResources {
			_ = database.DeleteResource(context.Background(), nil, resource.Id)
		}
	}()

	// Test: Get all resources
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var getResponse api.GetResourcesResponse
	err := json.NewDecoder(resp.Body).Decode(&getResponse)
	assert.NoError(t, err)

	// Assert: All test resources should be present
	assert.GreaterOrEqual(t, len(getResponse.Resources), 3)

	// Verify alphabetical sorting - alpha should come before beta, beta before zebra
	resourceIdentifiers := make([]string, len(getResponse.Resources))
	for i, resource := range getResponse.Resources {
		resourceIdentifiers[i] = resource.ResourceIdentifier
	}

	// Find positions of our test resources
	alphaPos, betaPos, zebraPos := -1, -1, -1
	for i, identifier := range resourceIdentifiers {
		switch identifier {
		case "alpha-resource":
			alphaPos = i
		case "beta-resource":
			betaPos = i
		case "zebra-resource":
			zebraPos = i
		}
	}

	// All should be found
	assert.NotEqual(t, -1, alphaPos, "alpha-resource should be found")
	assert.NotEqual(t, -1, betaPos, "beta-resource should be found")
	assert.NotEqual(t, -1, zebraPos, "zebra-resource should be found")

	// Should be in alphabetical order
	assert.True(t, alphaPos < betaPos, "alpha should come before beta")
	assert.True(t, betaPos < zebraPos, "beta should come before zebra")
}
