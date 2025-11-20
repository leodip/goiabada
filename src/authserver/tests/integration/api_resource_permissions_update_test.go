package integrationtests

import (
    "encoding/json"
    "net/http"
    "strconv"
    "strings"
    "testing"

    "github.com/brianvoe/gofakeit/v6"
    "github.com/leodip/goiabada/core/api"
    "github.com/leodip/goiabada/core/config"
    "github.com/leodip/goiabada/core/constants"
    "github.com/stretchr/testify/assert"
)

// Test successful create/update/delete of resource permissions via PUT
func TestAPIResourcePermissionsPut_Success_CreateUpdateDelete(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    // Create resource
    resource := createTestResource(t, "perm-put-res-"+gofakeit.LetterN(6), "Perms Test")
    defer func() { _ = database.DeleteResource(nil, resource.Id) }()

    // Seed existing permissions
    p1 := createTestPermission(t, resource.Id, "read", "Read")
    p2 := createTestPermission(t, resource.Id, "write", "Write")
    defer func() {
        _ = database.DeletePermission(nil, p1.Id)
        _ = database.DeletePermission(nil, p2.Id)
    }()

    // Build request: update p1 description, remove p2 (not included), add new p3
    url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(resource.Id, 10) + "/permissions"
    req := api.UpdateResourcePermissionsRequest{
        Permissions: []api.ResourcePermissionUpsert{
            {Id: p1.Id, PermissionIdentifier: "read", Description: "Read updated"},
            {Id: 0, PermissionIdentifier: "admin", Description: "Admin"},
            {Id: 0, PermissionIdentifier: "read-extra", Description: "Extra"},
        },
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

    resource := createTestResource(t, "perm-put-val-"+gofakeit.LetterN(6), "Val Test")
    defer func() { _ = database.DeleteResource(nil, resource.Id) }()

    baseURL := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(resource.Id, 10) + "/permissions"

    cases := []struct{
        name string
        req  api.UpdateResourcePermissionsRequest
        wantStatus int
        wantMsg string
    }{
        {"empty identifier", api.UpdateResourcePermissionsRequest{Permissions: []api.ResourcePermissionUpsert{{PermissionIdentifier: "", Description: "x"}}}, http.StatusBadRequest, "Permission identifier is required"},
        {"invalid format", api.UpdateResourcePermissionsRequest{Permissions: []api.ResourcePermissionUpsert{{PermissionIdentifier: "__bad", Description: "x"}}}, http.StatusBadRequest, "Invalid identifier format"},
        {"html in description", api.UpdateResourcePermissionsRequest{Permissions: []api.ResourcePermissionUpsert{{PermissionIdentifier: "good", Description: "<b>x</b>"}}}, http.StatusBadRequest, "The description contains invalid characters, as we do not permit the use of HTML in the description."},
        {"too long description", api.UpdateResourcePermissionsRequest{Permissions: []api.ResourcePermissionUpsert{{PermissionIdentifier: "good", Description: strings.Repeat("a", 101)}}}, http.StatusBadRequest, "The description cannot exceed a maximum length of 100 characters."},
        {"duplicate identifiers", api.UpdateResourcePermissionsRequest{Permissions: []api.ResourcePermissionUpsert{{PermissionIdentifier: "dup", Description: "x"},{PermissionIdentifier: "dup", Description: "y"}}}, http.StatusBadRequest, "Permission dup is duplicated."},
    }

    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            resp := makeAPIRequest(t, "PUT", baseURL, accessToken, tc.req)
            defer func() { _ = resp.Body.Close() }()
            assert.Equal(t, tc.wantStatus, resp.StatusCode)
            var errResp api.ErrorResponse
            _ = json.NewDecoder(resp.Body).Decode(&errResp)
            assert.Contains(t, errResp.Error.Message, tc.wantMsg)
        })
    }
}

// Test conflict when updating to an existing identifier
func TestAPIResourcePermissionsPut_UpdateConflict(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    resource := createTestResource(t, "perm-put-conf-"+gofakeit.LetterN(6), "Conf Test")
    defer func() { _ = database.DeleteResource(nil, resource.Id) }()

    p1 := createTestPermission(t, resource.Id, "aaa", "A")
    p2 := createTestPermission(t, resource.Id, "bbb", "B")
    defer func() {
        _ = database.DeletePermission(nil, p1.Id)
        _ = database.DeletePermission(nil, p2.Id)
    }()

    url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(resource.Id, 10) + "/permissions"
    // Try to change p1 identifier to "bbb" which already exists in DB (do not include p2 in request)
    // This should fail before deletion phase due to identifier conflict with existing permission p2
    req := api.UpdateResourcePermissionsRequest{Permissions: []api.ResourcePermissionUpsert{{Id: p1.Id, PermissionIdentifier: "bbb", Description: "A"}}}
    resp := makeAPIRequest(t, "PUT", url, accessToken, req)
    defer func() { _ = resp.Body.Close() }()
    assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
    var errResp api.ErrorResponse
    _ = json.NewDecoder(resp.Body).Decode(&errResp)
    assert.Contains(t, errResp.Error.Message, "already in use")
}

// Test system-level resource cannot be modified
func TestAPIResourcePermissionsPut_SystemResourceDenied(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    sysRes, err := database.GetResourceByResourceIdentifier(nil, constants.AuthServerResourceIdentifier)
    assert.NoError(t, err)
    if sysRes == nil { t.Skip("system authserver resource not found") }

    url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(sysRes.Id, 10) + "/permissions"
    req := api.UpdateResourcePermissionsRequest{Permissions: []api.ResourcePermissionUpsert{{PermissionIdentifier: "x", Description: "x"}}}
    resp := makeAPIRequest(t, "PUT", url, accessToken, req)
    defer func() { _ = resp.Body.Close() }()
    assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
    var errResp api.ErrorResponse
    _ = json.NewDecoder(resp.Body).Decode(&errResp)
    assert.Equal(t, "System level resources cannot be modified", errResp.Error.Message)
}

// Test unauthorized and invalid token
func TestAPIResourcePermissionsPut_Unauthorized(t *testing.T) {
    // Create a resource
    res := createTestResource(t, "perm-put-unauth-"+gofakeit.LetterN(6), "Unauth Test")
    defer func() { _ = database.DeleteResource(nil, res.Id) }()

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
