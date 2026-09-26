package integrationtests

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test successful create/update/delete of resource permissions via PUT
func TestAPIResourcePermissionsPut_Success_CreateUpdateDelete(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Create resource
	resource := createTestResource(t, "perm-put-res-"+fake.LetterN(6), "Perms Test")
	defer func() { _ = database.DeleteResource(context.Background(), nil, resource.Id) }()

	// Seed existing permissions
	p1 := createTestPermission(t, resource.Id, "read", "Read")
	p2 := createTestPermission(t, resource.Id, "write", "Write")
	defer func() {
		_ = database.DeletePermission(context.Background(), nil, p1.Id)
		_ = database.DeletePermission(context.Background(), nil, p2.Id)
	}()

	// Build request: update p1 description, remove p2 (not included), add new p3
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(resource.Id, 10) + "/permissions"
	req := api.UpdateResourcePermissionsRequest{
		Permissions: []api.ResourcePermissionUpsert{
			{Id: p1.Id, PermissionIdentifier: "read", Description: "Read updated"},
			{Id: 0, PermissionIdentifier: "admin", Description: "Admin"},
			{Id: 0, PermissionIdentifier: "read-extra", Description: "Extra"},
		},
		ExpectedPermissions: storedPermissionEntries(t, resource.Id),
	}

	resp := makeAPIRequest(t, "PUT", url, accessToken, req)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var success api.SuccessResponse
	err := json.NewDecoder(resp.Body).Decode(&success)
	assert.NoError(t, err)
	assert.True(t, success.Success)

	// Verify via GET that we have read (updated), admin, read-extra and not write
	getResp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = getResp.Body.Close() }()
	assert.Equal(t, http.StatusOK, getResp.StatusCode)
	var list api.GetPermissionsByResourceResponse
	err = json.NewDecoder(getResp.Body).Decode(&list)
	assert.NoError(t, err)

	idents := map[string]bool{}
	descByIdent := map[string]string{}
	for _, pr := range list.Permissions {
		idents[pr.PermissionIdentifier] = true
		descByIdent[pr.PermissionIdentifier] = pr.Description
	}
	assert.True(t, idents["read"], "read should remain")
	assert.True(t, idents["admin"], "admin should be created")
	assert.True(t, idents["read-extra"], "read-extra should be created")
	assert.False(t, idents["write"], "write should be deleted")
	assert.Equal(t, "Read updated", descByIdent["read"])
}

// Test validations: empty identifier, invalid format, html in description, too long, duplicate
func TestAPIResourcePermissionsPut_ValidationErrors(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	resource := createTestResource(t, "perm-put-val-"+fake.LetterN(6), "Val Test")
	defer func() { _ = database.DeleteResource(context.Background(), nil, resource.Id) }()

	baseURL := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(resource.Id, 10) + "/permissions"

	cases := []struct {
		name       string
		req        api.UpdateResourcePermissionsRequest
		wantStatus int
		wantMsg    string
		// wantCode is asserted only when set: most of these refusals are literal strings under
		// the generic VALIDATION_ERROR code, and only the ones going through a localized
		// validator carry a catalog key.
		wantCode string
	}{
		{"empty identifier", api.UpdateResourcePermissionsRequest{Permissions: []api.ResourcePermissionUpsert{{PermissionIdentifier: "", Description: "x"}}}, http.StatusBadRequest, "Permission identifier is required", ""},
		{"invalid format", api.UpdateResourcePermissionsRequest{Permissions: []api.ResourcePermissionUpsert{{PermissionIdentifier: "__bad", Description: "x"}}}, http.StatusBadRequest, "Invalid identifier format", ""},
		// The identifier reaches ValidateIdentifier as it was sent. It used to be run through the
		// HTML sanitizer first, which turned "valid<b" into "valid" and created a permission under
		// a name the caller never asked for (#275).
		{"html in identifier", api.UpdateResourcePermissionsRequest{Permissions: []api.ResourcePermissionUpsert{{PermissionIdentifier: "valid<b", Description: "x"}}}, http.StatusBadRequest, "Invalid identifier format", ""},
		{"html in description", api.UpdateResourcePermissionsRequest{Permissions: []api.ResourcePermissionUpsert{{PermissionIdentifier: "good", Description: "<b>x</b>"}}}, http.StatusBadRequest, "The description contains invalid characters, as we do not permit the use of HTML in the description.", "handler.admin_resource_permissions.description_html_not_allowed"},
		{"too long description", api.UpdateResourcePermissionsRequest{Permissions: []api.ResourcePermissionUpsert{{PermissionIdentifier: "good", Description: strings.Repeat("a", 101)}}}, http.StatusBadRequest, "The description cannot exceed a maximum length of 100 characters.", ""},
		{"duplicate identifiers", api.UpdateResourcePermissionsRequest{Permissions: []api.ResourcePermissionUpsert{{PermissionIdentifier: "dup", Description: "x"}, {PermissionIdentifier: "dup", Description: "y"}}}, http.StatusBadRequest, "Permission dup is duplicated.", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The resource has no permissions, which is the list every row loaded (#428).
			tc.req.ExpectedPermissions = []api.ResourcePermissionUpsert{}
			resp := makeAPIRequest(t, "PUT", baseURL, accessToken, tc.req)
			defer func() { _ = resp.Body.Close() }()
			assert.Equal(t, tc.wantStatus, resp.StatusCode)
			var errResp api.ErrorResponse
			_ = json.NewDecoder(resp.Body).Decode(&errResp)
			assert.Contains(t, errResp.ErrorDescription, tc.wantMsg)
			if tc.wantCode != "" {
				assert.Equal(t, tc.wantCode, errResp.ErrorCode)
			}
		})
	}

	// Nothing in the table above was created, "valid<b" included.
	perms, err := database.GetPermissionsByResourceId(context.Background(), nil, resource.Id)
	assert.NoError(t, err)
	assert.Empty(t, perms)
}

// Test conflict when updating to an existing identifier
func TestAPIResourcePermissionsPut_UpdateConflict(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	resource := createTestResource(t, "perm-put-conf-"+fake.LetterN(6), "Conf Test")
	defer func() { _ = database.DeleteResource(context.Background(), nil, resource.Id) }()

	p1 := createTestPermission(t, resource.Id, "aaa", "A")
	p2 := createTestPermission(t, resource.Id, "bbb", "B")
	defer func() {
		_ = database.DeletePermission(context.Background(), nil, p1.Id)
		_ = database.DeletePermission(context.Background(), nil, p2.Id)
	}()

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(resource.Id, 10) + "/permissions"
	// Try to change p1 identifier to "bbb" which already exists in DB (do not include p2 in request)
	// This should fail before deletion phase due to identifier conflict with existing permission p2
	req := api.UpdateResourcePermissionsRequest{
		Permissions:         []api.ResourcePermissionUpsert{{Id: p1.Id, PermissionIdentifier: "bbb", Description: "A"}},
		ExpectedPermissions: storedPermissionEntries(t, resource.Id),
	}
	resp := makeAPIRequest(t, "PUT", url, accessToken, req)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var errResp api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Contains(t, errResp.ErrorDescription, "already in use")
}

// Test system-level resource cannot be modified

// Test that adding new permissions to system resource is allowed
func TestAPIResourcePermissionsPut_SystemResourceAddPermissionAllowed(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	sysRes, err := database.GetResourceByResourceIdentifier(context.Background(), nil, constants.AuthServerResourceIdentifier)
	assert.NoError(t, err)
	if sysRes == nil {
		t.Skip("system authserver resource not found")
	}

	existingPerms, err := database.GetPermissionsByResourceId(context.Background(), nil, sysRes.Id)
	assert.NoError(t, err)

	// Build request with all existing built-in permissions PLUS a new one
	var permUpserts []api.ResourcePermissionUpsert
	for _, p := range existingPerms {
		permUpserts = append(permUpserts, api.ResourcePermissionUpsert{
			Id:                   p.Id,
			PermissionIdentifier: p.PermissionIdentifier,
			Description:          p.Description,
		})
	}
	// Add a new permission
	newPermIdentifier := "test-new-perm-" + fake.LetterN(6)
	permUpserts = append(permUpserts, api.ResourcePermissionUpsert{
		Id:                   0, // New permission
		PermissionIdentifier: newPermIdentifier,
		Description:          "Test new permission",
	})

	// Cleanup: delete only the specific permission created by this test
	defer func() {
		afterPerms, _ := database.GetPermissionsByResourceId(context.Background(), nil, sysRes.Id)
		for _, p := range afterPerms {
			if p.PermissionIdentifier == newPermIdentifier {
				_ = database.DeletePermission(context.Background(), nil, p.Id)
				break
			}
		}
	}()

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(sysRes.Id, 10) + "/permissions"
	req := api.UpdateResourcePermissionsRequest{Permissions: permUpserts, ExpectedPermissions: storedPermissionEntries(t, sysRes.Id)}
	resp := makeAPIRequest(t, "PUT", url, accessToken, req)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// Test that renaming a built-in permission is blocked
func TestAPIResourcePermissionsPut_SystemResourceRenameBuiltInBlocked(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	sysRes, err := database.GetResourceByResourceIdentifier(context.Background(), nil, constants.AuthServerResourceIdentifier)
	assert.NoError(t, err)
	if sysRes == nil {
		t.Skip("system authserver resource not found")
	}

	// Get existing permissions
	existingPerms, err := database.GetPermissionsByResourceId(context.Background(), nil, sysRes.Id)
	assert.NoError(t, err)

	// Find the "manage" built-in permission
	var managePermId int64
	for _, p := range existingPerms {
		if p.PermissionIdentifier == constants.ManagePermissionIdentifier {
			managePermId = p.Id
			break
		}
	}
	if managePermId == 0 {
		t.Skip("manage permission not found")
	}

	// Build request that attempts to rename "manage" to "manage-renamed"
	var permUpserts []api.ResourcePermissionUpsert
	for _, p := range existingPerms {
		identifier := p.PermissionIdentifier
		if p.Id == managePermId {
			identifier = "manage-renamed" // Attempt to rename
		}
		permUpserts = append(permUpserts, api.ResourcePermissionUpsert{
			Id:                   p.Id,
			PermissionIdentifier: identifier,
			Description:          p.Description,
		})
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(sysRes.Id, 10) + "/permissions"
	req := api.UpdateResourcePermissionsRequest{Permissions: permUpserts, ExpectedPermissions: storedPermissionEntries(t, sysRes.Id)}
	resp := makeAPIRequest(t, "PUT", url, accessToken, req)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var errResp api.ErrorResponse
	err = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.NoError(t, err)
	assert.Contains(t, errResp.ErrorDescription, "Built-in permission")
	assert.Contains(t, errResp.ErrorDescription, "cannot be renamed")
}

// Test that deleting a built-in permission is blocked
func TestAPIResourcePermissionsPut_SystemResourceDeleteBuiltInBlocked(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	sysRes, err := database.GetResourceByResourceIdentifier(context.Background(), nil, constants.AuthServerResourceIdentifier)
	assert.NoError(t, err)
	if sysRes == nil {
		t.Skip("system authserver resource not found")
	}

	// Get existing permissions
	existingPerms, err := database.GetPermissionsByResourceId(context.Background(), nil, sysRes.Id)
	assert.NoError(t, err)

	// Build request that omits the "manage-account" built-in permission (attempt to delete)
	var permUpserts []api.ResourcePermissionUpsert
	for _, p := range existingPerms {
		if p.PermissionIdentifier != constants.ManageAccountPermissionIdentifier {
			permUpserts = append(permUpserts, api.ResourcePermissionUpsert{
				Id:                   p.Id,
				PermissionIdentifier: p.PermissionIdentifier,
				Description:          p.Description,
			})
		}
		// Omit manage-account permission
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(sysRes.Id, 10) + "/permissions"
	req := api.UpdateResourcePermissionsRequest{Permissions: permUpserts, ExpectedPermissions: storedPermissionEntries(t, sysRes.Id)}
	resp := makeAPIRequest(t, "PUT", url, accessToken, req)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var errResp api.ErrorResponse
	err = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.NoError(t, err)
	assert.Contains(t, errResp.ErrorDescription, "Built-in permission")
	assert.Contains(t, errResp.ErrorDescription, "cannot be deleted")
}

// Test that delete+recreate of a built-in permission is blocked (prevents FK orphaning)
func TestAPIResourcePermissionsPut_SystemResourceDeleteRecreateBuiltInBlocked(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	sysRes, err := database.GetResourceByResourceIdentifier(context.Background(), nil, constants.AuthServerResourceIdentifier)
	assert.NoError(t, err)
	if sysRes == nil {
		t.Skip("system authserver resource not found")
	}

	existingPerms, err := database.GetPermissionsByResourceId(context.Background(), nil, sysRes.Id)
	assert.NoError(t, err)

	// Find the "manage" built-in permission
	var managePermId int64
	for _, p := range existingPerms {
		if p.PermissionIdentifier == constants.ManagePermissionIdentifier {
			managePermId = p.Id
			break
		}
	}
	if managePermId == 0 {
		t.Skip("manage permission not found")
	}

	// Build request that omits the original "manage" row and adds a new one with Id=0
	// This attempts to delete the original and recreate with a new DB ID, orphaning FK references
	var permUpserts []api.ResourcePermissionUpsert
	for _, p := range existingPerms {
		if p.Id == managePermId {
			continue // Omit original manage row
		}
		permUpserts = append(permUpserts, api.ResourcePermissionUpsert{
			Id:                   p.Id,
			PermissionIdentifier: p.PermissionIdentifier,
			Description:          p.Description,
		})
	}
	// Add new row with same identifier but Id=0 (new)
	permUpserts = append(permUpserts, api.ResourcePermissionUpsert{
		Id:                   0,
		PermissionIdentifier: constants.ManagePermissionIdentifier,
		Description:          "Recreated manage",
	})

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(sysRes.Id, 10) + "/permissions"
	req := api.UpdateResourcePermissionsRequest{Permissions: permUpserts, ExpectedPermissions: storedPermissionEntries(t, sysRes.Id)}
	resp := makeAPIRequest(t, "PUT", url, accessToken, req)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var errResp api.ErrorResponse
	err = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.NoError(t, err)
	assert.Contains(t, errResp.ErrorDescription, "Built-in permission")
	assert.Contains(t, errResp.ErrorDescription, "cannot be deleted")
}

// Test that changing built-in permission description is allowed
func TestAPIResourcePermissionsPut_SystemResourceChangeDescriptionAllowed(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	sysRes, err := database.GetResourceByResourceIdentifier(context.Background(), nil, constants.AuthServerResourceIdentifier)
	assert.NoError(t, err)
	if sysRes == nil {
		t.Skip("system authserver resource not found")
	}

	// Get existing permissions
	existingPerms, err := database.GetPermissionsByResourceId(context.Background(), nil, sysRes.Id)
	assert.NoError(t, err)

	// Find the "manage" built-in permission and save original description
	var managePermId int64
	var origDescription string
	for _, p := range existingPerms {
		if p.PermissionIdentifier == constants.ManagePermissionIdentifier {
			managePermId = p.Id
			origDescription = p.Description
			break
		}
	}
	if managePermId == 0 {
		t.Skip("manage permission not found")
	}

	// Restore original description after test
	defer func() {
		perm, _ := database.GetPermissionById(context.Background(), nil, managePermId)
		if perm != nil {
			perm.Description = origDescription
			_ = database.UpdatePermission(context.Background(), nil, perm)
		}
	}()

	// Build request that changes the description of "manage" but keeps ID and identifier
	var permUpserts []api.ResourcePermissionUpsert
	for _, p := range existingPerms {
		desc := p.Description
		if p.Id == managePermId {
			desc = "Updated description for manage permission"
		}
		permUpserts = append(permUpserts, api.ResourcePermissionUpsert{
			Id:                   p.Id,
			PermissionIdentifier: p.PermissionIdentifier,
			Description:          desc,
		})
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(sysRes.Id, 10) + "/permissions"
	req := api.UpdateResourcePermissionsRequest{Permissions: permUpserts, ExpectedPermissions: storedPermissionEntries(t, sysRes.Id)}
	resp := makeAPIRequest(t, "PUT", url, accessToken, req)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify description was updated
	updatedPerms, err := database.GetPermissionsByResourceId(context.Background(), nil, sysRes.Id)
	assert.NoError(t, err)
	for _, p := range updatedPerms {
		if p.Id == managePermId {
			assert.Equal(t, "Updated description for manage permission", p.Description)
		}
	}
}

// Test that duplicate IDs in request are rejected (prevents built-in permission rename bypass)
// Attack vector: send two entries with the same built-in permission ID — first with correct
// identifier (passes validation), second with a renamed identifier (would be applied).
func TestAPIResourcePermissionsPut_DuplicateIdRejected(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	sysRes, err := database.GetResourceByResourceIdentifier(context.Background(), nil, constants.AuthServerResourceIdentifier)
	assert.NoError(t, err)
	if sysRes == nil {
		t.Skip("system authserver resource not found")
	}

	existingPerms, err := database.GetPermissionsByResourceId(context.Background(), nil, sysRes.Id)
	assert.NoError(t, err)

	// Find the "manage" built-in permission
	var managePermId int64
	for _, p := range existingPerms {
		if p.PermissionIdentifier == constants.ManagePermissionIdentifier {
			managePermId = p.Id
			break
		}
	}
	if managePermId == 0 {
		t.Skip("manage permission not found")
	}

	// Build request: include all existing permissions normally, then add a second
	// entry for the manage permission ID with a renamed identifier
	var permUpserts []api.ResourcePermissionUpsert
	for _, p := range existingPerms {
		permUpserts = append(permUpserts, api.ResourcePermissionUpsert{
			Id:                   p.Id,
			PermissionIdentifier: p.PermissionIdentifier,
			Description:          p.Description,
		})
	}
	// Duplicate entry for manage ID with a different identifier
	permUpserts = append(permUpserts, api.ResourcePermissionUpsert{
		Id:                   managePermId,
		PermissionIdentifier: "manage-renamed",
		Description:          "Bypass attempt",
	})

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(sysRes.Id, 10) + "/permissions"
	req := api.UpdateResourcePermissionsRequest{Permissions: permUpserts, ExpectedPermissions: storedPermissionEntries(t, sysRes.Id)}
	resp := makeAPIRequest(t, "PUT", url, accessToken, req)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var errResp api.ErrorResponse
	err = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.NoError(t, err)
	assert.Contains(t, errResp.ErrorDescription, "Duplicate permission IDs")
}

// Test that duplicate IDs are also rejected on non-system resources
func TestAPIResourcePermissionsPut_DuplicateIdNonSystemRejected(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	resource := createTestResource(t, "perm-put-dupid-"+fake.LetterN(6), "DupId Test")
	defer func() { _ = database.DeleteResource(context.Background(), nil, resource.Id) }()

	p1 := createTestPermission(t, resource.Id, "read", "Read")
	defer func() { _ = database.DeletePermission(context.Background(), nil, p1.Id) }()

	// Two entries with the same existing ID
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(resource.Id, 10) + "/permissions"
	req := api.UpdateResourcePermissionsRequest{Permissions: []api.ResourcePermissionUpsert{
		{Id: p1.Id, PermissionIdentifier: "read", Description: "Read"},
		{Id: p1.Id, PermissionIdentifier: "read-changed", Description: "Changed"},
	}, ExpectedPermissions: storedPermissionEntries(t, resource.Id)}
	resp := makeAPIRequest(t, "PUT", url, accessToken, req)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var errResp api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Contains(t, errResp.ErrorDescription, "Duplicate permission IDs")
}

// Test unauthorized and invalid token
func TestAPIResourcePermissionsPut_Unauthorized(t *testing.T) {
	// Create a resource
	res := createTestResource(t, "perm-put-unauth-"+fake.LetterN(6), "Unauth Test")
	defer func() { _ = database.DeleteResource(context.Background(), nil, res.Id) }()

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(res.Id, 10) + "/permissions"

	// No token
	req, _ := http.NewRequest("PUT", url, strings.NewReader(`{"permissions":[]}`))
	req.Header.Set("Content-Type", "application/json")
	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Invalid token
	resp2 := makeAPIRequest(t, "PUT", url, "invalid-token", api.UpdateResourcePermissionsRequest{Permissions: []api.ResourcePermissionUpsert{}})
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)
}

// storedPermissionEntries is the resource's stored permissions as the loaded list a caller that
// read them sends back: every entry's id, identifier and description (#428).
func storedPermissionEntries(t *testing.T, resourceId int64) []api.ResourcePermissionUpsert {
	t.Helper()
	stored, err := database.GetPermissionsByResourceId(context.Background(), nil, resourceId)
	require.NoError(t, err)
	entries := make([]api.ResourcePermissionUpsert, 0, len(stored))
	for _, p := range stored {
		entries = append(entries, api.ResourcePermissionUpsert{Id: p.Id, PermissionIdentifier: p.PermissionIdentifier, Description: p.Description})
	}
	return entries
}

// readResourcePermissions is the resource's permissions as the API's own GET answers them.
func readResourcePermissions(t *testing.T, url, accessToken string) []api.PermissionResponse {
	t.Helper()
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var list api.GetPermissionsByResourceResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&list))
	return list.Permissions
}

// The save requires the list as its caller loaded it: a body without expectedPermissions, or with
// it null, is refused 400 naming the field, and nothing is written (#428).
func TestAPIResourcePermissionsPut_TheLoadedListIsRequired(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	resource := createTestResource(t, "perm-put-req-"+fake.LetterN(6), "Required Test")
	defer func() { _ = database.DeleteResource(context.Background(), nil, resource.Id) }()
	p1 := createTestPermission(t, resource.Id, "read", "Read")
	defer func() { _ = database.DeletePermission(context.Background(), nil, p1.Id) }()

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(resource.Id, 10) + "/permissions"
	for name, body := range map[string]string{
		"absent": `{"permissions":[]}`,
		"null":   `{"permissions":[],"expectedPermissions":null}`,
	} {
		t.Run(name, func(t *testing.T) {
			resp := makeAPIRequest(t, "PUT", url, accessToken, json.RawMessage(body))
			defer func() { _ = resp.Body.Close() }()
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			var errResp api.ErrorResponse
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&errResp))
			assert.Equal(t, "VALIDATION_ERROR", errResp.ErrorCode)
			assert.Contains(t, errResp.ErrorDescription, "expectedPermissions is required")

			assert.Equal(t, []api.ResourcePermissionUpsert{{Id: p1.Id, PermissionIdentifier: "read", Description: "Read"}},
				storedPermissionEntries(t, resource.Id), "the save that would have dropped read wrote nothing")
		})
	}
}

// Two administrators load the same list. The first re-describes a permission and saves; the
// second, still holding the list as it was, drops that permission and saves. The second save is
// refused 409 CONCURRENT_UPDATE and the list reads back as the first save left it, where applying
// the second's whole list would silently have undone the first's change (#428).
func TestAPIResourcePermissionsPut_AnOutdatedLoadedListIsRefused(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	resource := createTestResource(t, "perm-put-old-"+fake.LetterN(6), "Outdated Test")
	defer func() { _ = database.DeleteResource(context.Background(), nil, resource.Id) }()
	p1 := createTestPermission(t, resource.Id, "read", "Read")
	p2 := createTestPermission(t, resource.Id, "write", "Write")
	defer func() {
		_ = database.DeletePermission(context.Background(), nil, p1.Id)
		_ = database.DeletePermission(context.Background(), nil, p2.Id)
	}()

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(resource.Id, 10) + "/permissions"
	loaded := storedPermissionEntries(t, resource.Id)

	first := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateResourcePermissionsRequest{
		Permissions: []api.ResourcePermissionUpsert{
			{Id: p1.Id, PermissionIdentifier: "read", Description: "Read"},
			{Id: p2.Id, PermissionIdentifier: "write", Description: "Write anything"},
		},
		ExpectedPermissions: loaded,
	})
	defer func() { _ = first.Body.Close() }()
	require.Equal(t, http.StatusOK, first.StatusCode)
	afterFirst := storedPermissionEntries(t, resource.Id)

	second := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateResourcePermissionsRequest{
		Permissions:         []api.ResourcePermissionUpsert{{Id: p1.Id, PermissionIdentifier: "read", Description: "Read"}},
		ExpectedPermissions: loaded,
	})
	defer func() { _ = second.Body.Close() }()
	assert.Equal(t, http.StatusConflict, second.StatusCode)
	var errResp api.ErrorResponse
	require.NoError(t, json.NewDecoder(second.Body).Decode(&errResp))
	assert.Equal(t, "CONCURRENT_UPDATE", errResp.ErrorCode)

	assert.ElementsMatch(t, afterFirst, storedPermissionEntries(t, resource.Id), "the outdated save wrote nothing")
	assert.ElementsMatch(t, []api.ResourcePermissionUpsert{
		{Id: p1.Id, PermissionIdentifier: "read", Description: "Read"},
		{Id: p2.Id, PermissionIdentifier: "write", Description: "Write anything"},
	}, afterFirst)
}

// What the console does: read the resource's permissions through the API's GET, edit them, and
// send the entries as the GET answered them as the loaded list. That GET is the only list a caller
// has, so its entries have to compare equal to the stored ones, id, identifier and description, or
// every save from the page would be refused as outdated. A non-system resource: the system one's
// GET leaves out userinfo, which its save requires, and that page's defect is a follow-up of #428.
func TestAPIResourcePermissionsPut_SavedWithTheListTheAPIRead(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	resource := createTestResource(t, "perm-put-read-"+fake.LetterN(6), "Read Test")
	defer func() { _ = database.DeleteResource(context.Background(), nil, resource.Id) }()
	p1 := createTestPermission(t, resource.Id, "read", "Reads the invoices")
	p2 := createTestPermission(t, resource.Id, "write", "Writes the invoices")
	defer func() {
		_ = database.DeletePermission(context.Background(), nil, p1.Id)
		_ = database.DeletePermission(context.Background(), nil, p2.Id)
	}()

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(resource.Id, 10) + "/permissions"
	read := readResourcePermissions(t, url, accessToken)
	require.Len(t, read, 2)
	loaded := make([]api.ResourcePermissionUpsert, 0, len(read))
	for _, p := range read {
		loaded = append(loaded, api.ResourcePermissionUpsert{Id: p.Id, PermissionIdentifier: p.PermissionIdentifier, Description: p.Description})
	}

	resp := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateResourcePermissionsRequest{
		Permissions: []api.ResourcePermissionUpsert{
			{Id: p1.Id, PermissionIdentifier: "read", Description: "Reads every invoice"},
			{PermissionIdentifier: "export", Description: "Exports the invoices"},
		},
		ExpectedPermissions: loaded,
	})
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	descByIdent := map[string]string{}
	for _, p := range readResourcePermissions(t, url, accessToken) {
		descByIdent[p.PermissionIdentifier] = p.Description
	}
	assert.Equal(t, map[string]string{"read": "Reads every invoice", "export": "Exports the invoices"}, descByIdent)
}
