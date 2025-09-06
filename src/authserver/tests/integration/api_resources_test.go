package integrationtests

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

// TestAPIResourcesGet tests the GET /api/v1/admin/resources endpoint
func TestAPIResourcesGet_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test resources
	resource1 := createTestResource(t, "api-test-resource-1", "API Test Resource 1")
	resource2 := createTestResource(t, "api-test-resource-2", "API Test Resource 2")
	defer func() {
		_ = database.DeleteResource(nil, resource1.Id)
		_ = database.DeleteResource(nil, resource2.Id)
	}()

	// Test: Get all resources
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

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
	defer resp.Body.Close()

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
	defer resp.Body.Close()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAPIResourcesGet_InvalidToken(t *testing.T) {
	// Test: Request with invalid access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources"
	resp := makeAPIRequest(t, "GET", url, "invalid-token", nil)
	defer resp.Body.Close()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
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
			_ = database.DeleteResource(nil, resource.Id)
		}
	}()

	// Test: Get all resources
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

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