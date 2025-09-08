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

// GET /api/v1/admin/resources/{id}
func TestAPIResourceGet_Success(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    res := createTestResource(t, "api-test-get-resource-"+gofakeit.LetterN(6), "Get Resource")
    defer func() { _ = database.DeleteResource(nil, res.Id) }()

    url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(res.Id, 10)
    resp := makeAPIRequest(t, "GET", url, accessToken, nil)
    defer resp.Body.Close()

    assert.Equal(t, http.StatusOK, resp.StatusCode)
    assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

    var getResp api.GetResourceResponse
    err := json.NewDecoder(resp.Body).Decode(&getResp)
    assert.NoError(t, err)

    assert.Equal(t, res.Id, getResp.Resource.Id)
    assert.Equal(t, res.ResourceIdentifier, getResp.Resource.ResourceIdentifier)
    assert.Equal(t, res.Description, getResp.Resource.Description)
}

func TestAPIResourceGet_NotFoundAndInvalidId(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    // Not found
    urlNF := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/9999999"
    respNF := makeAPIRequest(t, "GET", urlNF, accessToken, nil)
    defer respNF.Body.Close()
    assert.Equal(t, http.StatusNotFound, respNF.StatusCode)
    var errRespNF api.ErrorResponse
    _ = json.NewDecoder(respNF.Body).Decode(&errRespNF)
    assert.Equal(t, "Resource not found", errRespNF.Error.Message)

    // Invalid id (non-numeric)
    urlBad := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/abc"
    respBad := makeAPIRequest(t, "GET", urlBad, accessToken, nil)
    defer respBad.Body.Close()
    assert.Equal(t, http.StatusBadRequest, respBad.StatusCode)
    var errRespBad api.ErrorResponse
    _ = json.NewDecoder(respBad.Body).Decode(&errRespBad)
    assert.Equal(t, "Invalid resource ID", errRespBad.Error.Message)

    // Negative id -> not found
    urlNeg := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/-1"
    respNeg := makeAPIRequest(t, "GET", urlNeg, accessToken, nil)
    defer respNeg.Body.Close()
    assert.Equal(t, http.StatusNotFound, respNeg.StatusCode)
}

func TestAPIResourceGet_UnauthorizedAndScope(t *testing.T) {
    // No token
    url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/1"
    req, err := http.NewRequest("GET", url, nil)
    assert.NoError(t, err)
    httpClient := createHttpClient(t)
    resp, err := httpClient.Do(req)
    assert.NoError(t, err)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

    // Invalid token
    resp2 := makeAPIRequest(t, "GET", url, "invalid-token", nil)
    defer resp2.Body.Close()
    assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)

    // Insufficient scope (userinfo)
    token := createClientCredentialsTokenWithScope(t, constants.AuthServerResourceIdentifier, constants.UserinfoPermissionIdentifier)
    resp3 := makeAPIRequest(t, "GET", url, token, nil)
    defer resp3.Body.Close()
    assert.Equal(t, http.StatusForbidden, resp3.StatusCode)
}

// PUT /api/v1/admin/resources/{id}
func TestAPIResourceUpdatePut_Success(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    res := createTestResource(t, "api-test-update-resource-"+gofakeit.LetterN(6), "Original")
    defer func() { _ = database.DeleteResource(nil, res.Id) }()

    updateReq := api.UpdateResourceRequest{
        ResourceIdentifier: "updated-resource-" + gofakeit.LetterN(6),
        Description:        "  Updated desc  ",
    }
    url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(res.Id, 10)
    resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
    defer resp.Body.Close()

    assert.Equal(t, http.StatusOK, resp.StatusCode)
    assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

    var updResp api.UpdateResourceResponse
    err := json.NewDecoder(resp.Body).Decode(&updResp)
    assert.NoError(t, err)

    assert.Equal(t, res.Id, updResp.Resource.Id)
    assert.Equal(t, updateReq.ResourceIdentifier, updResp.Resource.ResourceIdentifier)
    assert.Equal(t, "Updated desc", updResp.Resource.Description)

    // Verify DB persisted
    stored, err := database.GetResourceById(nil, res.Id)
    assert.NoError(t, err)
    assert.NotNil(t, stored)
    assert.Equal(t, updateReq.ResourceIdentifier, stored.ResourceIdentifier)
    assert.Equal(t, "Updated desc", stored.Description)
}

func TestAPIResourceUpdatePut_ValidationErrors(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)
    res := createTestResource(t, "api-test-update-val-"+gofakeit.LetterN(6), "desc")
    defer func() { _ = database.DeleteResource(nil, res.Id) }()

    // Empty identifier
    url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(res.Id, 10)
    resp := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateResourceRequest{ResourceIdentifier: "", Description: "x"})
    defer resp.Body.Close()
    assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
    var errResp api.ErrorResponse
    _ = json.NewDecoder(resp.Body).Decode(&errResp)
    assert.Equal(t, "Resource identifier is required", errResp.Error.Message)

    // Too long description
    longDesc := strings.Repeat("a", 101)
    resp2 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateResourceRequest{ResourceIdentifier: "valid-identifier", Description: longDesc})
    defer resp2.Body.Close()
    assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
    var errResp2 api.ErrorResponse
    _ = json.NewDecoder(resp2.Body).Decode(&errResp2)
    assert.Equal(t, "The description cannot exceed a maximum length of 100 characters", errResp2.Error.Message)

    // Invalid identifier format
    resp3 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateResourceRequest{ResourceIdentifier: "invalid identifier", Description: "x"})
    defer resp3.Body.Close()
    assert.Equal(t, http.StatusBadRequest, resp3.StatusCode)
    var errResp3 api.ErrorResponse
    _ = json.NewDecoder(resp3.Body).Decode(&errResp3)
    assert.Equal(t, "Invalid identifier format. It must start with a letter, can include letters, numbers, dashes, and underscores, but cannot end with a dash or underscore, or have two consecutive dashes or underscores.", errResp3.Error.Message)
}

func TestAPIResourceUpdatePut_DuplicateIdentifier(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)
    res1 := createTestResource(t, "api-test-dup1-"+gofakeit.LetterN(6), "desc")
    res2 := createTestResource(t, "api-test-dup2-"+gofakeit.LetterN(6), "desc")
    defer func() { _ = database.DeleteResource(nil, res1.Id); _ = database.DeleteResource(nil, res2.Id) }()

    url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(res2.Id, 10)
    resp := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateResourceRequest{ResourceIdentifier: res1.ResourceIdentifier, Description: "x"})
    defer resp.Body.Close()
    assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
    var errResp api.ErrorResponse
    _ = json.NewDecoder(resp.Body).Decode(&errResp)
    assert.Equal(t, "The resource identifier is already in use", errResp.Error.Message)
}

func TestAPIResourceUpdatePut_SystemLevelResource(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    // Find system-level resource (authserver)
    sysRes, err := database.GetResourceByResourceIdentifier(nil, constants.AuthServerResourceIdentifier)
    assert.NoError(t, err)
    assert.NotNil(t, sysRes)

    url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(sysRes.Id, 10)
    resp := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateResourceRequest{ResourceIdentifier: sysRes.ResourceIdentifier, Description: sysRes.Description})
    defer resp.Body.Close()
    assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
    var errResp api.ErrorResponse
    _ = json.NewDecoder(resp.Body).Decode(&errResp)
    assert.Equal(t, "cannot update settings for a system level resource", errResp.Error.Message)
}

func TestAPIResourceUpdatePut_InvalidIdAndBody(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    // Invalid ID
    urlBad := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/abc"
    respBad := makeAPIRequest(t, "PUT", urlBad, accessToken, api.UpdateResourceRequest{ResourceIdentifier: "x", Description: "y"})
    defer respBad.Body.Close()
    assert.Equal(t, http.StatusBadRequest, respBad.StatusCode)
    var errRespBad api.ErrorResponse
    _ = json.NewDecoder(respBad.Body).Decode(&errRespBad)
    assert.Equal(t, "Invalid resource ID", errRespBad.Error.Message)

    // Not found
    urlNF := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/9999999"
    respNF := makeAPIRequest(t, "PUT", urlNF, accessToken, api.UpdateResourceRequest{ResourceIdentifier: "valid-" + gofakeit.LetterN(6), Description: "y"})
    defer respNF.Body.Close()
    assert.Equal(t, http.StatusNotFound, respNF.StatusCode)

    // Empty body -> invalid request body
    // Build request manually with empty body
    url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/1"
    req, err := http.NewRequest("PUT", url, nil)
    assert.NoError(t, err)
    req.Header.Set("Authorization", "Bearer "+accessToken)
    req.Header.Set("Content-Type", "application/json")
    httpClient := createHttpClient(t)
    resp, err := httpClient.Do(req)
    assert.NoError(t, err)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAPIResourceUpdatePut_UnauthorizedAndScope(t *testing.T) {
    // Prepare a test resource to reference
    res := createTestResource(t, "api-test-update-unauth-"+gofakeit.LetterN(6), "desc")
    defer func() { _ = database.DeleteResource(nil, res.Id) }()

    url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(res.Id, 10)

    // No token
    req, err := http.NewRequest("PUT", url, nil)
    assert.NoError(t, err)
    httpClient := createHttpClient(t)
    resp, err := httpClient.Do(req)
    assert.NoError(t, err)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

    // Invalid token
    resp2 := makeAPIRequest(t, "PUT", url, "invalid-token", api.UpdateResourceRequest{ResourceIdentifier: res.ResourceIdentifier, Description: res.Description})
    defer resp2.Body.Close()
    assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)

    // Insufficient scope
    token := createClientCredentialsTokenWithScope(t, constants.AuthServerResourceIdentifier, constants.UserinfoPermissionIdentifier)
    resp3 := makeAPIRequest(t, "PUT", url, token, api.UpdateResourceRequest{ResourceIdentifier: res.ResourceIdentifier, Description: res.Description})
    defer resp3.Body.Close()
    assert.Equal(t, http.StatusForbidden, resp3.StatusCode)
}
