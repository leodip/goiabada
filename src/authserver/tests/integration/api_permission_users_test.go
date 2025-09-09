package integrationtests

import (
    "encoding/json"
    "net/http"
    "strconv"
    "testing"

    "github.com/brianvoe/gofakeit/v6"
    "github.com/google/uuid"
    "github.com/leodip/goiabada/core/api"
    "github.com/leodip/goiabada/core/config"
    "github.com/leodip/goiabada/core/constants"
    "github.com/leodip/goiabada/core/models"
    "github.com/stretchr/testify/assert"
)

// Test GET /api/v1/admin/permissions/{permissionId}/users success path
func TestAPIPermissionUsersGet_Success(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    res := createResource(t)
    perm := createPermission(t, res.Id)

    // Create three users; assign permission to two
    u1 := &models.User{Subject: uuid.New(), Enabled: true, Email: "permuser1-" + gofakeit.LetterN(6) + "@test.com", GivenName: "U1", FamilyName: "T"}
    u2 := &models.User{Subject: uuid.New(), Enabled: true, Email: "permuser2-" + gofakeit.LetterN(6) + "@test.com", GivenName: "U2", FamilyName: "T"}
    u3 := &models.User{Subject: uuid.New(), Enabled: true, Email: "permuser3-" + gofakeit.LetterN(6) + "@test.com", GivenName: "U3", FamilyName: "T"}
    assert.NoError(t, database.CreateUser(nil, u1))
    assert.NoError(t, database.CreateUser(nil, u2))
    assert.NoError(t, database.CreateUser(nil, u3))
    defer func() {
        _ = database.DeleteUser(nil, u1.Id)
        _ = database.DeleteUser(nil, u2.Id)
        _ = database.DeleteUser(nil, u3.Id)
    }()

    assignPermissionToUser(t, u1.Id, perm.Id)
    assignPermissionToUser(t, u3.Id, perm.Id)

    url := config.GetAuthServer().BaseURL + "/api/v1/admin/permissions/" + strconv.FormatInt(perm.Id, 10) + "/users?page=1&size=200"
    resp := makeAPIRequest(t, "GET", url, accessToken, nil)
    defer resp.Body.Close()

    assert.Equal(t, http.StatusOK, resp.StatusCode)
    assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

    var apiResp api.GetUsersByPermissionResponse
    err := json.NewDecoder(resp.Body).Decode(&apiResp)
    assert.NoError(t, err)

    // Total should be at least 2; ensure u1 and u3 appear; u2 does not
    assert.GreaterOrEqual(t, apiResp.Total, 2)
    var seen1, seen3, seen2 bool
    for _, u := range apiResp.Users {
        if u.Email == u1.Email { seen1 = true }
        if u.Email == u3.Email { seen3 = true }
        if u.Email == u2.Email { seen2 = true }
    }
    assert.True(t, seen1, "u1 should be included")
    assert.True(t, seen3, "u3 should be included")
    assert.False(t, seen2, "u2 should not be included")
}

func TestAPIPermissionUsersGet_InvalidPermissionId(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)
    url := config.GetAuthServer().BaseURL + "/api/v1/admin/permissions/invalid/users"
    resp := makeAPIRequest(t, "GET", url, accessToken, nil)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
    var errResp api.ErrorResponse
    _ = json.NewDecoder(resp.Body).Decode(&errResp)
    assert.Equal(t, "Invalid permission ID format", errResp.Error.Message)
}

func TestAPIPermissionUsersGet_PermissionNotFound(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)
    missingId := int64(gofakeit.Number(7_000_000, 7_999_999))
    url := config.GetAuthServer().BaseURL + "/api/v1/admin/permissions/" + strconv.FormatInt(missingId, 10) + "/users"
    resp := makeAPIRequest(t, "GET", url, accessToken, nil)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusNotFound, resp.StatusCode)
    var errResp api.ErrorResponse
    _ = json.NewDecoder(resp.Body).Decode(&errResp)
    assert.Equal(t, "Permission not found", errResp.Error.Message)
}

func TestAPIPermissionUsersGet_UserinfoForbidden(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    // Get existing AuthServer resource
    authRes, err := database.GetResourceByResourceIdentifier(nil, constants.AuthServerResourceIdentifier)
    assert.NoError(t, err)
    if authRes == nil {
        t.Skip("AuthServer resource not found in database - skipping userinfo test")
    }
    // Find builtin userinfo permission
    perms, err := database.GetPermissionsByResourceId(nil, authRes.Id)
    assert.NoError(t, err)
    err = database.PermissionsLoadResources(nil, perms)
    assert.NoError(t, err)
    var userinfoPermId int64
    for i := range perms {
        if perms[i].PermissionIdentifier == constants.UserinfoPermissionIdentifier {
            userinfoPermId = perms[i].Id
            break
        }
    }
    if userinfoPermId == 0 {
        t.Skip("userinfo permission not found for authserver resource - skipping")
    }

    url := config.GetAuthServer().BaseURL + "/api/v1/admin/permissions/" + strconv.FormatInt(userinfoPermId, 10) + "/users"
    resp := makeAPIRequest(t, "GET", url, accessToken, nil)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
    var errResp api.ErrorResponse
    _ = json.NewDecoder(resp.Body).Decode(&errResp)
    assert.Equal(t, "Operation not allowed for userinfo permission", errResp.Error.Message)
}

func TestAPIPermissionUsersGet_Unauthorized(t *testing.T) {
    res := createResource(t)
    perm := createPermission(t, res.Id)
    url := config.GetAuthServer().BaseURL + "/api/v1/admin/permissions/" + strconv.FormatInt(perm.Id, 10) + "/users"
    req, _ := http.NewRequest("GET", url, nil)
    httpClient := createHttpClient(t)
    resp, err := httpClient.Do(req)
    assert.NoError(t, err)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}
