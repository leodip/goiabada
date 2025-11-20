package integrationtests

import (
    "encoding/json"
    "net/http"
    neturl "net/url"
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

func TestAPIUsersSearch_AnnotatePermission_Success(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    res := createResource(t)
    perm := createPermission(t, res.Id)

    // Create three users; grant permission to two
    randSuffix := gofakeit.LetterN(6)
    u1 := &models.User{Subject: uuid.New(), Enabled: true, Username: "annperm1-" + randSuffix, Email: "annperm1-" + randSuffix + "@test.com", GivenName: "A1", FamilyName: "T"}
    u2 := &models.User{Subject: uuid.New(), Enabled: true, Username: "annperm2-" + randSuffix, Email: "annperm2-" + randSuffix + "@test.com", GivenName: "A2", FamilyName: "T"}
    u3 := &models.User{Subject: uuid.New(), Enabled: true, Username: "annperm3-" + randSuffix, Email: "annperm3-" + randSuffix + "@test.com", GivenName: "A3", FamilyName: "T"}
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

    // Use query parameter to filter to our test users (search matches on email, username, given_name, etc.)
    url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/search?query=annperm&annotatePermissionId=" + strconv.FormatInt(perm.Id, 10) + "&page=1&size=200"
    resp := makeAPIRequest(t, "GET", url, accessToken, nil)
    defer func() { _ = resp.Body.Close() }()

    assert.Equal(t, http.StatusOK, resp.StatusCode)
    assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

    var apiResp api.SearchUsersWithPermissionAnnotationResponse
    err := json.NewDecoder(resp.Body).Decode(&apiResp)
    assert.NoError(t, err)

    // Find our users and verify HasPermission
    var seen1, seen2, seen3 bool
    for _, u := range apiResp.Users {
        switch u.Email {
        case u1.Email:
            seen1 = true
            assert.True(t, u.HasPermission)
        case u2.Email:
            seen2 = true
            assert.False(t, u.HasPermission)
        case u3.Email:
            seen3 = true
            assert.True(t, u.HasPermission)
        }
    }
    assert.True(t, seen1 || seen2 || seen3, "Expected to see at least one created user in the page")
}

func TestAPIUsersSearch_AnnotatePermission_InvalidParam(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/search?annotatePermissionId=abc"
    resp := makeAPIRequest(t, "GET", url, accessToken, nil)
    defer func() { _ = resp.Body.Close() }()

    assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
    var errResp api.ErrorResponse
    _ = json.NewDecoder(resp.Body).Decode(&errResp)
    assert.Equal(t, "Invalid annotatePermissionId value", errResp.Error.Message)
}

func TestAPIUsersSearch_AnnotatePermission_PermissionNotFound(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)
    missingId := int64(gofakeit.Number(8_000_000, 8_999_999))
    url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/search?annotatePermissionId=" + strconv.FormatInt(missingId, 10)
    resp := makeAPIRequest(t, "GET", url, accessToken, nil)
    defer func() { _ = resp.Body.Close() }()
    assert.Equal(t, http.StatusNotFound, resp.StatusCode)
    var errResp api.ErrorResponse
    _ = json.NewDecoder(resp.Body).Decode(&errResp)
    assert.Equal(t, "Permission not found", errResp.Error.Message)
}

func TestAPIUsersSearch_AnnotatePermission_Unauthorized(t *testing.T) {
    res := createResource(t)
    perm := createPermission(t, res.Id)
    u := config.GetAuthServer().BaseURL + "/api/v1/admin/users/search?annotatePermissionId=" + neturl.QueryEscape(strconv.FormatInt(perm.Id, 10))
    httpClient := createHttpClient(t)
    req, _ := http.NewRequest("GET", u, nil)
    resp, err := httpClient.Do(req)
    assert.NoError(t, err)
    defer func() { _ = resp.Body.Close() }()
    assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAPIUsersSearch_AnnotatePermission_ConflictWithGroupAnnotation(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    res := createResource(t)
    perm := createPermission(t, res.Id)

    // Create a group to reference
    grp := createTestGroup(t)
    defer func() { _ = database.DeleteGroup(nil, grp.Id) }()

    url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/search?annotatePermissionId=" + strconv.FormatInt(perm.Id, 10) + "&annotateGroupMembership=" + strconv.FormatInt(grp.Id, 10)
    resp := makeAPIRequest(t, "GET", url, accessToken, nil)
    defer func() { _ = resp.Body.Close() }()

    assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
    var errResp api.ErrorResponse
    _ = json.NewDecoder(resp.Body).Decode(&errResp)
    assert.Equal(t, "annotateGroupMembership and annotatePermissionId cannot be used together", errResp.Error.Message)
}

func TestAPIUsersSearch_AnnotatePermission_UserinfoForbidden(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    // Get existing AuthServer resource
    authRes, err := database.GetResourceByResourceIdentifier(nil, constants.AuthServerResourceIdentifier)
    assert.NoError(t, err)
    if authRes == nil {
        t.Skip("AuthServer resource not found in database - skipping userinfo annotation test")
    }
    // Locate userinfo permission
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

    url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/search?annotatePermissionId=" + strconv.FormatInt(userinfoPermId, 10)
    resp := makeAPIRequest(t, "GET", url, accessToken, nil)
    defer func() { _ = resp.Body.Close() }()
    assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
    var errResp api.ErrorResponse
    _ = json.NewDecoder(resp.Body).Decode(&errResp)
    assert.Equal(t, "Operation not allowed for userinfo permission", errResp.Error.Message)
}
