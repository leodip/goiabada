package integrationtests

import (
    "encoding/json"
    "net/http"
    "strconv"
    "testing"

    "github.com/brianvoe/gofakeit/v6"
    "github.com/leodip/goiabada/core/api"
    "github.com/leodip/goiabada/core/config"
    "github.com/leodip/goiabada/core/constants"
    "github.com/stretchr/testify/assert"
)

// DELETE /api/v1/admin/resources/{id}
func TestAPIResourceDelete_Success(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    // Create a test resource to delete
    res := createTestResource(t, "api-test-del-resource-"+gofakeit.LetterN(6), "To be deleted")

    // Delete the resource via API
    url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(res.Id, 10)
    resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
    defer resp.Body.Close()

    assert.Equal(t, http.StatusOK, resp.StatusCode)
    assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

    var success api.SuccessResponse
    err := json.NewDecoder(resp.Body).Decode(&success)
    assert.NoError(t, err)
    assert.True(t, success.Success)

    // Verify resource is gone
    getResp := makeAPIRequest(t, "GET", url, accessToken, nil)
    defer getResp.Body.Close()
    assert.Equal(t, http.StatusNotFound, getResp.StatusCode)
}

func TestAPIResourceDelete_NotFoundAndInvalidId(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    // Not found
    urlNF := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/9999999"
    respNF := makeAPIRequest(t, "DELETE", urlNF, accessToken, nil)
    defer respNF.Body.Close()
    assert.Equal(t, http.StatusNotFound, respNF.StatusCode)
    var errRespNF api.ErrorResponse
    _ = json.NewDecoder(respNF.Body).Decode(&errRespNF)
    assert.Equal(t, "Resource not found", errRespNF.Error.Message)

    // Invalid id (non-numeric)
    urlBad := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/abc"
    respBad := makeAPIRequest(t, "DELETE", urlBad, accessToken, nil)
    defer respBad.Body.Close()
    assert.Equal(t, http.StatusBadRequest, respBad.StatusCode)
    var errRespBad api.ErrorResponse
    _ = json.NewDecoder(respBad.Body).Decode(&errRespBad)
    assert.Equal(t, "Invalid resource ID", errRespBad.Error.Message)

    // Negative id -> not found
    urlNeg := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/-1"
    respNeg := makeAPIRequest(t, "DELETE", urlNeg, accessToken, nil)
    defer respNeg.Body.Close()
    assert.Equal(t, http.StatusNotFound, respNeg.StatusCode)
}

func TestAPIResourceDelete_SystemLevelResource(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    // Find system-level resource (authserver)
    sysRes, err := database.GetResourceByResourceIdentifier(nil, constants.AuthServerResourceIdentifier)
    assert.NoError(t, err)
    assert.NotNil(t, sysRes)

    url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(sysRes.Id, 10)
    resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
    defer resp.Body.Close()

    assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
    var errResp api.ErrorResponse
    _ = json.NewDecoder(resp.Body).Decode(&errResp)
    assert.Equal(t, "Trying to delete a system level resource", errResp.Error.Message)
}

func TestAPIResourceDelete_UnauthorizedAndScope(t *testing.T) {
    // Prepare a test resource to reference
    res := createTestResource(t, "api-test-del-unauth-"+gofakeit.LetterN(6), "desc")
    defer func() { _ = database.DeleteResource(nil, res.Id) }()

    url := config.GetAuthServer().BaseURL + "/api/v1/admin/resources/" + strconv.FormatInt(res.Id, 10)

    // No token
    req, err := http.NewRequest("DELETE", url, nil)
    assert.NoError(t, err)
    httpClient := createHttpClient(t)
    resp, err := httpClient.Do(req)
    assert.NoError(t, err)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

    // Invalid token
    resp2 := makeAPIRequest(t, "DELETE", url, "invalid-token", nil)
    defer resp2.Body.Close()
    assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)

    // Insufficient scope (userinfo)
    token := createClientCredentialsTokenWithScope(t, constants.AuthServerResourceIdentifier, constants.UserinfoPermissionIdentifier)
    resp3 := makeAPIRequest(t, "DELETE", url, token, nil)
    defer resp3.Body.Close()
    assert.Equal(t, http.StatusForbidden, resp3.StatusCode)
}

