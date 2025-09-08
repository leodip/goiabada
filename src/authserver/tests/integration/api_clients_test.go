package integrationtests

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/stretchr/testify/assert"
)

// TestAPIClientsGet tests the GET /api/v1/admin/clients endpoint
func TestAPIClientsGet_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Get all clients
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var getResponse api.GetClientsResponse
	err := json.NewDecoder(resp.Body).Decode(&getResponse)
	assert.NoError(t, err)

	// Assert: Should return at least the admin console client (system client)
	assert.GreaterOrEqual(t, len(getResponse.Clients), 1, "Should have at least the admin console client")

	// Find admin console client
	var adminConsoleClient *api.ClientResponse
	for _, client := range getResponse.Clients {
		if client.ClientIdentifier == "admin-console-client" {
			adminConsoleClient = &client
			break
		}
	}

	assert.NotNil(t, adminConsoleClient, "Should find admin console client")
	if adminConsoleClient != nil {
		assert.True(t, adminConsoleClient.Enabled, "Admin console client should be enabled")
		assert.True(t, adminConsoleClient.IsSystemLevelClient, "Admin console should be system level")
		assert.Empty(t, adminConsoleClient.ClientSecret, "Client secret should not be included in list API")
	}
}

func TestAPIClientsGet_Unauthorized(t *testing.T) {
	// Test: Request without access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients"
	req, err := http.NewRequest("GET", url, nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestAPIClientGet tests the GET /api/v1/admin/clients/{id} endpoint
func TestAPIClientGet_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// First get all clients to find one to test with
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	var getResponse api.GetClientsResponse
	err := json.NewDecoder(resp.Body).Decode(&getResponse)
	assert.NoError(t, err)
	assert.Greater(t, len(getResponse.Clients), 0, "Should have at least one client")

	clientId := getResponse.Clients[0].Id

	// Test: Get specific client
	url = config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(clientId, 10)
	resp = makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var getClientResponse api.GetClientResponse
	err = json.NewDecoder(resp.Body).Decode(&getClientResponse)
	assert.NoError(t, err)

	// Assert: Should return the correct client
	assert.Equal(t, clientId, getClientResponse.Client.Id)
	assert.NotEmpty(t, getClientResponse.Client.ClientIdentifier)

	// Note: Client secret will be included in detail API for confidential clients
	// but will be empty for public clients
}

func TestAPIClientGet_NotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Get non-existent client
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/99999"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIClientGet_InvalidId(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	testCases := []struct {
		name           string
		clientId       string
		expectedStatus int
	}{
		{"non-numeric ID", "abc", http.StatusBadRequest},
		{"negative ID", "-1", http.StatusNotFound},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + tc.clientId
			resp := makeAPIRequest(t, "GET", url, accessToken, nil)
			defer resp.Body.Close()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIClientGet_EmptyId(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Request with empty ID (this will actually hit the listing endpoint due to router behavior)
	// The URL "/api/v1/admin/clients/" matches the listing route, not the detail route
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Due to chi router behavior, this hits the listing endpoint and returns 200
	// This is actually correct behavior - empty ID paths should go to the listing
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestAPIClientGet_Unauthorized(t *testing.T) {
	// Test: Request without access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/1"
	req, err := http.NewRequest("GET", url, nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}
