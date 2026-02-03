package integrationtests

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	neturl "net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

// Test GET /api/v1/admin/groups/search annotated with permission (success path)
func TestAPIGroupsSearch_Annotated_Success(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Create a resource and a permission to annotate by
	resource := createResource(t)
	perm := createPermission(t, resource.Id)

	// Create three groups; grant the permission to two of them
	g1 := createTestGroup(t)
	defer func() { _ = database.DeleteGroup(nil, g1.Id) }()
	g2 := createTestGroup(t)
	defer func() { _ = database.DeleteGroup(nil, g2.Id) }()
	g3 := createTestGroup(t)
	defer func() { _ = database.DeleteGroup(nil, g3.Id) }()

	// Assign permission to g1 and g3
	err := database.CreateGroupPermission(nil, &models.GroupPermission{GroupId: g1.Id, PermissionId: perm.Id})
	assert.NoError(t, err)
	err = database.CreateGroupPermission(nil, &models.GroupPermission{GroupId: g3.Id, PermissionId: perm.Id})
	assert.NoError(t, err)

	// Query page 1 with a large size to increase chance our groups are returned
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/search?annotatePermissionId=" + strconv.FormatInt(perm.Id, 10) + "&page=1&size=200"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var apiResp api.SearchGroupsWithPermissionAnnotationResponse
	err = json.NewDecoder(resp.Body).Decode(&apiResp)
	assert.NoError(t, err)

	// Total should be at least the number of groups we created
	assert.GreaterOrEqual(t, apiResp.Total, 3)

	// Find our three groups by identifier and assert annotation
	var seenG1, seenG2, seenG3 bool
	for _, gr := range apiResp.Groups {
		switch gr.GroupIdentifier {
		case g1.GroupIdentifier:
			seenG1 = true
			assert.True(t, gr.HasPermission, "g1 should be annotated with HasPermission=true")
		case g2.GroupIdentifier:
			seenG2 = true
			assert.False(t, gr.HasPermission, "g2 should be annotated with HasPermission=false")
		case g3.GroupIdentifier:
			seenG3 = true
			assert.True(t, gr.HasPermission, "g3 should be annotated with HasPermission=true")
		}
	}
	// At least one of our groups should appear in the first page
	assert.True(t, seenG1 || seenG2 || seenG3, "Expected to see at least one created group in the page")
}

// Test missing annotatePermissionId parameter
func TestAPIGroupsSearch_MissingAnnotateParam(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/search?page=1&size=10" // missing annotatePermissionId
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var errResp api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Equal(t, "annotatePermissionId is required", errResp.Error.Message)
}

// Test invalid annotatePermissionId format
func TestAPIGroupsSearch_InvalidAnnotateParam(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/search?annotatePermissionId=abc&page=1&size=10"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var errResp api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Equal(t, "Invalid annotatePermissionId", errResp.Error.Message)
}

// Test permission not found
func TestAPIGroupsSearch_PermissionNotFound(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Use a random large ID that should not exist
	missingId := int64(gofakeit.Number(9_000_000, 9_999_999))
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/search?annotatePermissionId=" + strconv.FormatInt(missingId, 10)
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	var errResp api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Equal(t, "Permission not found", errResp.Error.Message)
}

// Test unauthorized access (no token)
func TestAPIGroupsSearch_Unauthorized(t *testing.T) {
	// Create a permission to reference
	resource := createResource(t)
	perm := createPermission(t, resource.Id)
	u := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/search?annotatePermissionId=" + neturl.QueryEscape(strconv.FormatInt(perm.Id, 10))

	httpClient := createHttpClient(t)
	req, _ := http.NewRequest("GET", u, nil)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	buf := new(bytes.Buffer)
	_, _ = io.Copy(buf, resp.Body)
	assert.Equal(t, "Access token required", strings.TrimSpace(buf.String()))
}
