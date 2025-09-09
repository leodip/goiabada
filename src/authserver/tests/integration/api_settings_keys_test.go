package integrationtests

import (
    "encoding/json"
    "io"
    "net/http"
    "strconv"
    "strings"
    "testing"

    "github.com/leodip/goiabada/core/api"
    "github.com/leodip/goiabada/core/config"
    "github.com/stretchr/testify/assert"
)

// Helper to GET keys
func getKeys(t *testing.T, accessToken string) []api.SettingsSigningKeyResponse {
    url := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/keys"
    resp := makeAPIRequest(t, "GET", url, accessToken, nil)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusOK, resp.StatusCode)
    var out api.GetSettingsKeysResponse
    err := json.NewDecoder(resp.Body).Decode(&out)
    assert.NoError(t, err)
    return out.Keys
}

// GET /api/v1/admin/settings/keys
func TestAPISettingsKeysGet_Success(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    keys := getKeys(t, accessToken)
    // From seeder: there should be at least next and current
    assert.GreaterOrEqual(t, len(keys), 2)
    // Ordered: next, current, previous...
    assert.Equal(t, "next", keys[0].State)
    assert.Equal(t, "current", keys[1].State)
    // CreatedAt present
    assert.NotNil(t, keys[0].CreatedAt)
    assert.NotNil(t, keys[1].CreatedAt)
    // Public encodings present; no private key exposed
    assert.True(t, strings.HasPrefix(keys[0].PublicKeyPEM, "-----BEGIN RSA PUBLIC KEY-----"))
    assert.NotEmpty(t, keys[0].PublicKeyASN1DER)
    assert.Contains(t, keys[0].PublicKeyJWK, "\"kty\":")
}

// POST /api/v1/admin/settings/keys/rotate - success and ordering
func TestAPISettingsKeysRotatePost_Success(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    // Capture initial ids
    before := getKeys(t, accessToken)
    assert.Equal(t, "next", before[0].State)
    assert.Equal(t, "current", before[1].State)
    initialCurrentId := before[1].Id
    initialNextKid := before[0].KeyIdentifier

    // Rotate
    url := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/keys/rotate"
    resp := makeAPIRequest(t, "POST", url, accessToken, map[string]any{})
    defer resp.Body.Close()
    assert.Equal(t, http.StatusOK, resp.StatusCode)
    var ok api.SuccessResponse
    err := json.NewDecoder(resp.Body).Decode(&ok)
    assert.NoError(t, err)
    assert.True(t, ok.Success)

    // After rotate: expect 3 keys: next, current, previous
    after := getKeys(t, accessToken)
    assert.Equal(t, 3, len(after))
    assert.Equal(t, "next", after[0].State)
    assert.Equal(t, "current", after[1].State)
    assert.Equal(t, "previous", after[2].State)
    // Previous key should be the former current
    assert.Equal(t, initialCurrentId, after[2].Id)
    // New next should have a different kid
    assert.NotEqual(t, initialNextKid, after[0].KeyIdentifier)
}

// POST /api/v1/admin/settings/keys/rotate deletes existing previous
func TestAPISettingsKeysRotatePost_DeletesPrevious(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    // First rotate to create a previous
    url := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/keys/rotate"
    _ = makeAPIRequest(t, "POST", url, accessToken, map[string]any{})
    first := getKeys(t, accessToken)
    assert.Equal(t, 3, len(first))
    prevId := first[2].Id
    currId := first[1].Id

    // Rotate again: should delete previous at start
    resp := makeAPIRequest(t, "POST", url, accessToken, map[string]any{})
    defer resp.Body.Close()
    assert.Equal(t, http.StatusOK, resp.StatusCode)

    // The previous key that signed our original token may have been deleted now.
    // Get a fresh admin token to continue requests.
    accessToken, _ = createAdminClientWithToken(t)
    second := getKeys(t, accessToken)
    assert.Equal(t, 3, len(second))
    // The old previous must be gone
    for _, k := range second {
        assert.NotEqual(t, prevId, k.Id)
    }
    // New previous should be the old current
    assert.Equal(t, currId, second[2].Id)
}

// DELETE /api/v1/admin/settings/keys/{id} - success
func TestAPISettingsKeyDelete_Success(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)
    // Ensure we have a previous key
    urlRotate := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/keys/rotate"
    _ = makeAPIRequest(t, "POST", urlRotate, accessToken, map[string]any{})
    keys := getKeys(t, accessToken)
    assert.Equal(t, 3, len(keys))
    prevId := keys[2].Id

    // Delete previous
    url := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/keys/" + itoa(prevId)
    resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusOK, resp.StatusCode)

    // Our token was signed with the deleted previous key; fetch a new token.
    accessToken, _ = createAdminClientWithToken(t)
    // Now only next and current remain
    keys2 := getKeys(t, accessToken)
    assert.Equal(t, 2, len(keys2))
    for _, k := range keys2 {
        assert.NotEqual(t, prevId, k.Id)
    }
}

// DELETE validation and unauthorized
func TestAPISettingsKeyDelete_ValidationAndUnauthorized(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)
    // Ensure state has at least current/next
    keys := getKeys(t, accessToken)
    currId := keys[1].Id // current

    // Attempt to delete current -> validation error
    url := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/keys/" + itoa(currId)
    resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
    var errBody api.ErrorResponse
    _ = json.NewDecoder(resp.Body).Decode(&errBody)
    assert.Equal(t, "Only a previous key can be revoked", errBody.Error.Message)

    // Non-existent id
    url2 := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/keys/99999999"
    resp2 := makeAPIRequest(t, "DELETE", url2, accessToken, nil)
    defer resp2.Body.Close()
    assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
    var errBody2 api.ErrorResponse
    _ = json.NewDecoder(resp2.Body).Decode(&errBody2)
    assert.Equal(t, "Key not found", errBody2.Error.Message)

    // Unauthorized - GET
    listURL := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/keys"
    req, err := http.NewRequest("GET", listURL, nil)
    assert.NoError(t, err)
    httpClient := createHttpClient(t)
    resp3, err := httpClient.Do(req)
    assert.NoError(t, err)
    defer resp3.Body.Close()
    assert.Equal(t, http.StatusUnauthorized, resp3.StatusCode)
    body3, _ := io.ReadAll(resp3.Body)
    assert.Equal(t, "text/plain; charset=utf-8", resp3.Header.Get("Content-Type"))
    assert.Equal(t, "Access token required", strings.TrimSpace(string(body3)))

    // Unauthorized - POST rotate
    rotateURL := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/keys/rotate"
    req4, _ := http.NewRequest("POST", rotateURL, strings.NewReader("{}"))
    resp4, err := httpClient.Do(req4)
    assert.NoError(t, err)
    defer resp4.Body.Close()
    assert.Equal(t, http.StatusUnauthorized, resp4.StatusCode)

    // Unauthorized - DELETE
    delURL := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/keys/1"
    req5, _ := http.NewRequest("DELETE", delURL, nil)
    resp5, err := httpClient.Do(req5)
    assert.NoError(t, err)
    defer resp5.Body.Close()
    assert.Equal(t, http.StatusUnauthorized, resp5.StatusCode)
}

// itoa for int64
func itoa(v int64) string { return strconv.FormatInt(v, 10) }
