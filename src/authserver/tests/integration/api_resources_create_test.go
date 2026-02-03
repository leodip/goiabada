package integrationtests

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/stretchr/testify/assert"
)

// TestAPIResourcesCreate_Success tests POST /api/v1/admin/resources success flow
func TestAPIResourcesCreate_Success(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	identifier := "api-test-create-resource-" + gofakeit.LetterN(8)
	reqBody := api.CreateResourceRequest{
		ResourceIdentifier: identifier,
		Description:        "  Created via API  ",
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources"
	resp := makeAPIRequest(t, "POST", url, accessToken, reqBody)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var createResp api.CreateResourceResponse
	err := json.NewDecoder(resp.Body).Decode(&createResp)
	assert.NoError(t, err)

	// Assert returned resource
	assert.Equal(t, identifier, createResp.Resource.ResourceIdentifier)
	assert.Equal(t, "Created via API", createResp.Resource.Description, "Description should be trimmed/sanitized")

	// Verify persistence
	stored, err := database.GetResourceByResourceIdentifier(nil, identifier)
	assert.NoError(t, err)
	assert.NotNil(t, stored)
	assert.Equal(t, identifier, stored.ResourceIdentifier)
	assert.Equal(t, "Created via API", stored.Description)

	// Cleanup
	_ = database.DeleteResource(nil, stored.Id)
}

func TestAPIResourcesCreate_ValidationErrors(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	testCases := []struct {
		name           string
		body           api.CreateResourceRequest
		expectedStatus int
		expectedMsg    string
	}{
		{
			name:           "missing identifier",
			body:           api.CreateResourceRequest{ResourceIdentifier: "", Description: "desc"},
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "Resource identifier is required",
		},
		{
			name:           "too long description",
			body:           api.CreateResourceRequest{ResourceIdentifier: "valid-identifier", Description: strings.Repeat("a", 101)},
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "The description cannot exceed a maximum length of 100 characters",
		},
		{
			name:           "invalid identifier format",
			body:           api.CreateResourceRequest{ResourceIdentifier: "invalid identifier with spaces", Description: "desc"},
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "", // message comes from validator; we'll just check status if empty here
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources"
			resp := makeAPIRequest(t, "POST", url, accessToken, tc.body)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)

			// If we set an expected message, assert it
			if tc.expectedMsg != "" {
				var errResp api.ErrorResponse
				_ = json.NewDecoder(resp.Body).Decode(&errResp)
				assert.Equal(t, tc.expectedMsg, errResp.Error.Message)
			}
		})
	}
}

func TestAPIResourcesCreate_DuplicateIdentifier(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Pre-create a resource
	identifier := "api-test-dup-resource-" + gofakeit.LetterN(8)
	existing := createTestResource(t, identifier, "Existing")
	defer func() { _ = database.DeleteResource(nil, existing.Id) }()

	// Attempt to create with the same identifier
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources"
	resp := makeAPIRequest(t, "POST", url, accessToken, api.CreateResourceRequest{
		ResourceIdentifier: identifier,
		Description:        "New",
	})
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var errResp api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Equal(t, "The resource identifier is already in use", errResp.Error.Message)
}

func TestAPIResourcesCreate_InvalidRequestBody(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources"
	// makeAPIRequest with nil body sends empty body, leading to 400 from handler
	resp := makeAPIRequest(t, "POST", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAPIResourcesCreate_UnauthorizedAndScope(t *testing.T) {
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources"

	// No token
	req, err := http.NewRequest("POST", url, nil)
	assert.NoError(t, err)
	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "text/plain; charset=utf-8", resp.Header.Get("Content-Type"))
	assert.Equal(t, "Access token required", strings.TrimSpace(string(body)))

	// Invalid token
	resp2 := makeAPIRequest(t, "POST", url, "invalid-token", api.CreateResourceRequest{ResourceIdentifier: "x", Description: ""})
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)
	body2, _ := io.ReadAll(resp2.Body)
	assert.Equal(t, "text/plain; charset=utf-8", resp2.Header.Get("Content-Type"))
	assert.Equal(t, "Access token required", strings.TrimSpace(string(body2)))

	// Insufficient scope (e.g., userinfo only)
	token := createClientCredentialsTokenWithScope(t, constants.AuthServerResourceIdentifier, constants.UserinfoPermissionIdentifier)
	resp3 := makeAPIRequest(t, "POST", url, token, api.CreateResourceRequest{ResourceIdentifier: "valid-" + gofakeit.LetterN(6), Description: "x"})
	defer func() { _ = resp3.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, resp3.StatusCode)
	body3, _ := io.ReadAll(resp3.Body)
	assert.Equal(t, "text/plain; charset=utf-8", resp3.Header.Get("Content-Type"))
	assert.Equal(t, "Insufficient scope", strings.TrimSpace(string(body3)))
}
