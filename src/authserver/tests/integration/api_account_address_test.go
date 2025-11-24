package integrationtests

import (
    "encoding/json"
    "io"
    "net/http"
    "strings"
    "testing"

    "github.com/leodip/goiabada/core/api"
    "github.com/leodip/goiabada/core/config"
    "github.com/leodip/goiabada/core/constants"
    "github.com/leodip/goiabada/core/models"
    "github.com/stretchr/testify/assert"
)

func getUserAccessTokenWithAccountScope_Address(t *testing.T) (string, *models.User) {
    scope := "openid profile email " + constants.AuthServerResourceIdentifier + ":" + constants.ManageAccountPermissionIdentifier
    return createUserAccessTokenWithScope(t, scope)
}

func TestAPIAccountAddressPut_Success(t *testing.T) {
    accessToken, u := getUserAccessTokenWithAccountScope_Address(t)

    url := config.GetAuthServer().BaseURL + "/api/v1/account/address"
    reqBody := api.UpdateUserAddressRequest{
        AddressLine1:      "123 Main Street",
        AddressLine2:      "Apt 4B",
        AddressLocality:   "New York",
        AddressRegion:     "NY",
        AddressPostalCode: "10001",
        AddressCountry:    "US",
    }
    resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
    defer func() { _ = resp.Body.Close() }()

    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        t.Fatalf("expected 200, got %d. body: %s", resp.StatusCode, string(body))
    }
    assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

    var updateResp api.UpdateUserResponse
    err := json.NewDecoder(resp.Body).Decode(&updateResp)
    assert.NoError(t, err)
    assert.Equal(t, u.Id, updateResp.User.Id)
    assert.Equal(t, reqBody.AddressLine1, updateResp.User.AddressLine1)
    assert.Equal(t, reqBody.AddressLine2, updateResp.User.AddressLine2)
    assert.Equal(t, reqBody.AddressLocality, updateResp.User.AddressLocality)
    assert.Equal(t, reqBody.AddressRegion, updateResp.User.AddressRegion)
    assert.Equal(t, reqBody.AddressPostalCode, updateResp.User.AddressPostalCode)
    assert.Equal(t, reqBody.AddressCountry, updateResp.User.AddressCountry)

    // Verify persisted changes
    updatedUser, err := database.GetUserById(nil, u.Id)
    assert.NoError(t, err)
    assert.NotNil(t, updatedUser)
    assert.Equal(t, reqBody.AddressLine1, updatedUser.AddressLine1)
    assert.Equal(t, reqBody.AddressLine2, updatedUser.AddressLine2)
    assert.Equal(t, reqBody.AddressLocality, updatedUser.AddressLocality)
    assert.Equal(t, reqBody.AddressRegion, updatedUser.AddressRegion)
    assert.Equal(t, reqBody.AddressPostalCode, updatedUser.AddressPostalCode)
    assert.Equal(t, reqBody.AddressCountry, updatedUser.AddressCountry)
}

func TestAPIAccountAddressPut_PartialAddress(t *testing.T) {
    accessToken, _ := getUserAccessTokenWithAccountScope_Address(t)

    // Update only some fields; unspecified fields should be cleared to empty
    url := config.GetAuthServer().BaseURL + "/api/v1/account/address"
    reqBody := api.UpdateUserAddressRequest{
        AddressLine1:    "New Address",
        AddressLocality: "New City",
        // others omitted -> empty strings
    }
    resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
    defer func() { _ = resp.Body.Close() }()

    assert.Equal(t, http.StatusOK, resp.StatusCode)
    var updateResp api.UpdateUserResponse
    err := json.NewDecoder(resp.Body).Decode(&updateResp)
    assert.NoError(t, err)
    assert.Equal(t, reqBody.AddressLine1, updateResp.User.AddressLine1)
    assert.Equal(t, "", updateResp.User.AddressLine2)
    assert.Equal(t, reqBody.AddressLocality, updateResp.User.AddressLocality)
    assert.Equal(t, "", updateResp.User.AddressRegion)
    assert.Equal(t, "", updateResp.User.AddressPostalCode)
    assert.Equal(t, "", updateResp.User.AddressCountry)
}

func TestAPIAccountAddressPut_ClearAllFields(t *testing.T) {
    accessToken, _ := getUserAccessTokenWithAccountScope_Address(t)

    // Clear all address fields by sending empty values
    url := config.GetAuthServer().BaseURL + "/api/v1/account/address"
    reqBody := api.UpdateUserAddressRequest{}
    resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
    defer func() { _ = resp.Body.Close() }()

    assert.Equal(t, http.StatusOK, resp.StatusCode)
    var updateResp api.UpdateUserResponse
    err := json.NewDecoder(resp.Body).Decode(&updateResp)
    assert.NoError(t, err)
    assert.Equal(t, "", updateResp.User.AddressLine1)
    assert.Equal(t, "", updateResp.User.AddressLine2)
    assert.Equal(t, "", updateResp.User.AddressLocality)
    assert.Equal(t, "", updateResp.User.AddressRegion)
    assert.Equal(t, "", updateResp.User.AddressPostalCode)
    assert.Equal(t, "", updateResp.User.AddressCountry)
}

func TestAPIAccountAddressPut_ValidationErrors(t *testing.T) {
    accessToken, _ := getUserAccessTokenWithAccountScope_Address(t)
    url := config.GetAuthServer().BaseURL + "/api/v1/account/address"

    // AddressLine1 too long (>60)
    long60 := strings.Repeat("a", 61)
    resp1 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateUserAddressRequest{AddressLine1: long60})
    defer func() { _ = resp1.Body.Close() }()
    assert.Equal(t, http.StatusBadRequest, resp1.StatusCode)
    var err1 api.ErrorResponse
    _ = json.NewDecoder(resp1.Body).Decode(&err1)
    assert.Equal(t, "Please ensure the address line 1 is no longer than 60 characters.", err1.Error.Message)

    // AddressLine2 too long (>60)
    resp2 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateUserAddressRequest{AddressLine2: long60})
    defer func() { _ = resp2.Body.Close() }()
    assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
    var err2 api.ErrorResponse
    _ = json.NewDecoder(resp2.Body).Decode(&err2)
    assert.Equal(t, "Please ensure the address line 2 is no longer than 60 characters.", err2.Error.Message)

    // Locality too long (>60)
    resp3 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateUserAddressRequest{AddressLocality: long60})
    defer func() { _ = resp3.Body.Close() }()
    assert.Equal(t, http.StatusBadRequest, resp3.StatusCode)
    var err3 api.ErrorResponse
    _ = json.NewDecoder(resp3.Body).Decode(&err3)
    assert.Equal(t, "Please ensure the locality is no longer than 60 characters.", err3.Error.Message)

    // Region too long (>60)
    resp4 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateUserAddressRequest{AddressRegion: long60})
    defer func() { _ = resp4.Body.Close() }()
    assert.Equal(t, http.StatusBadRequest, resp4.StatusCode)
    var err4 api.ErrorResponse
    _ = json.NewDecoder(resp4.Body).Decode(&err4)
    assert.Equal(t, "Please ensure the region is no longer than 60 characters.", err4.Error.Message)

    // Postal code too long (>30)
    long31 := strings.Repeat("1", 31)
    resp5 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateUserAddressRequest{AddressPostalCode: long31})
    defer func() { _ = resp5.Body.Close() }()
    assert.Equal(t, http.StatusBadRequest, resp5.StatusCode)
    var err5 api.ErrorResponse
    _ = json.NewDecoder(resp5.Body).Decode(&err5)
    assert.Equal(t, "Please ensure the postal code is no longer than 30 characters.", err5.Error.Message)

    // Invalid country
    resp6 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateUserAddressRequest{AddressCountry: "INVALID_COUNTRY"})
    defer func() { _ = resp6.Body.Close() }()
    assert.Equal(t, http.StatusBadRequest, resp6.StatusCode)
    var err6 api.ErrorResponse
    _ = json.NewDecoder(resp6.Body).Decode(&err6)
    assert.Equal(t, "Invalid country.", err6.Error.Message)
}

func TestAPIAccountAddressPut_UnauthorizedAndScope(t *testing.T) {
    url := config.GetAuthServer().BaseURL + "/api/v1/account/address"

    // No token
    req, err := http.NewRequest("PUT", url, nil)
    assert.NoError(t, err)
    httpClient := createHttpClient(t)
    resp, err := httpClient.Do(req)
    assert.NoError(t, err)
    defer func() { _ = resp.Body.Close() }()
    assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
    body1, _ := io.ReadAll(resp.Body)
    assert.Equal(t, "text/plain; charset=utf-8", resp.Header.Get("Content-Type"))
    assert.Equal(t, "Access token required", strings.TrimSpace(string(body1)))

    // Invalid token
    respInvalid := makeAPIRequest(t, "PUT", url, "invalid-token", api.UpdateUserAddressRequest{AddressLine1: "X"})
    defer func() { _ = respInvalid.Body.Close() }()
    assert.Equal(t, http.StatusUnauthorized, respInvalid.StatusCode)
    bodyInvalid, _ := io.ReadAll(respInvalid.Body)
    assert.Equal(t, "Access token required", strings.TrimSpace(string(bodyInvalid)))

    // Insufficient scope
    tok := createClientCredentialsTokenWithScope(t, constants.AuthServerResourceIdentifier, constants.UserinfoPermissionIdentifier)
    resp2 := makeAPIRequest(t, "PUT", url, tok, api.UpdateUserAddressRequest{AddressLine1: "X"})
    defer func() { _ = resp2.Body.Close() }()
    assert.Equal(t, http.StatusForbidden, resp2.StatusCode)
    body2, _ := io.ReadAll(resp2.Body)
    assert.Equal(t, "Insufficient scope", strings.TrimSpace(string(body2)))
}

func TestAPIAccountAddressPut_InvalidRequestBody(t *testing.T) {
    accessToken, _ := getUserAccessTokenWithAccountScope_Address(t)
    url := config.GetAuthServer().BaseURL + "/api/v1/account/address"

    // Invalid JSON (no body)
    req, err := http.NewRequest("PUT", url, nil)
    assert.NoError(t, err)
    req.Header.Set("Authorization", "Bearer "+accessToken)
    req.Header.Set("Content-Type", "application/json")
    httpClient := createHttpClient(t)
    resp, err := httpClient.Do(req)
    assert.NoError(t, err)
    defer func() { _ = resp.Body.Close() }()
    assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
    var errResp api.ErrorResponse
    _ = json.NewDecoder(resp.Body).Decode(&errResp)
    assert.Equal(t, "Invalid request body", errResp.Error.Message)
}

