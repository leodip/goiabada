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

func getUserAccessTokenWithAccountScope_Phone(t *testing.T) (string, *models.User) {
    scope := "openid profile email " + constants.AdminConsoleResourceIdentifier + ":" + constants.ManageAccountPermissionIdentifier
    return createUserAccessTokenWithScope(t, scope)
}

func TestAPIAccountPhonePut_Success(t *testing.T) {
    accessToken, u := getUserAccessTokenWithAccountScope_Phone(t)

    url := config.GetAuthServer().BaseURL + "/api/v1/account/phone"
    reqBody := api.UpdateAccountPhoneRequest{
        PhoneCountryUniqueId: "USA_0",
        PhoneNumber:          "555-123-4567",
    }
    resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        t.Fatalf("expected 200, got %d. body: %s", resp.StatusCode, string(body))
    }
    assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

    var updateResp api.UpdateUserResponse
    err := json.NewDecoder(resp.Body).Decode(&updateResp)
    assert.NoError(t, err)
    assert.Equal(t, u.Id, updateResp.User.Id)
    assert.Equal(t, reqBody.PhoneCountryUniqueId, updateResp.User.PhoneNumberCountryUniqueId)
    assert.Equal(t, reqBody.PhoneNumber, updateResp.User.PhoneNumber)
    assert.False(t, updateResp.User.PhoneNumberVerified)
    assert.NotEmpty(t, updateResp.User.PhoneNumberCountryCallingCode)

    // Verify persisted changes
    updatedUser, err := database.GetUserById(nil, u.Id)
    assert.NoError(t, err)
    assert.NotNil(t, updatedUser)
    assert.Equal(t, reqBody.PhoneCountryUniqueId, updatedUser.PhoneNumberCountryUniqueId)
    assert.Equal(t, reqBody.PhoneNumber, updatedUser.PhoneNumber)
    assert.False(t, updatedUser.PhoneNumberVerified)
}

func TestAPIAccountPhonePut_ClearPhone(t *testing.T) {
    accessToken, u := getUserAccessTokenWithAccountScope_Phone(t)

    // First set a phone
    setURL := config.GetAuthServer().BaseURL + "/api/v1/account/phone"
    _ = makeAPIRequest(t, "PUT", setURL, accessToken, api.UpdateAccountPhoneRequest{
        PhoneCountryUniqueId: "USA_0",
        PhoneNumber:          "555-000-1111",
    })

    // Now clear it
    url := config.GetAuthServer().BaseURL + "/api/v1/account/phone"
    reqBody := api.UpdateAccountPhoneRequest{PhoneCountryUniqueId: "", PhoneNumber: ""}
    resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
    defer resp.Body.Close()

    assert.Equal(t, http.StatusOK, resp.StatusCode)
    var updateResp api.UpdateUserResponse
    err := json.NewDecoder(resp.Body).Decode(&updateResp)
    assert.NoError(t, err)
    assert.Equal(t, u.Id, updateResp.User.Id)
    assert.Equal(t, "", updateResp.User.PhoneNumberCountryUniqueId)
    assert.Equal(t, "", updateResp.User.PhoneNumberCountryCallingCode)
    assert.Equal(t, "", updateResp.User.PhoneNumber)
    assert.False(t, updateResp.User.PhoneNumberVerified)
}

func TestAPIAccountPhonePut_ValidationErrors(t *testing.T) {
    accessToken, _ := getUserAccessTokenWithAccountScope_Phone(t)
    url := config.GetAuthServer().BaseURL + "/api/v1/account/phone"

    // Phone number without country
    resp1 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateAccountPhoneRequest{PhoneCountryUniqueId: "", PhoneNumber: "555-123-4567"})
    defer resp1.Body.Close()
    assert.Equal(t, http.StatusBadRequest, resp1.StatusCode)
    var err1 api.ErrorResponse
    _ = json.NewDecoder(resp1.Body).Decode(&err1)
    assert.Equal(t, "You must select a country for your phone number.", err1.Error.Message)

    // Country without phone number
    resp2 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateAccountPhoneRequest{PhoneCountryUniqueId: "USA_0", PhoneNumber: ""})
    defer resp2.Body.Close()
    assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
    var err2 api.ErrorResponse
    _ = json.NewDecoder(resp2.Body).Decode(&err2)
    assert.Equal(t, "The phone number field must contain a valid phone number. To remove the phone number information, please select the (blank) option from the dropdown menu for the phone country and leave the phone number field empty.", err2.Error.Message)

    // Too short
    resp3 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateAccountPhoneRequest{PhoneCountryUniqueId: "USA_0", PhoneNumber: "123"})
    defer resp3.Body.Close()
    assert.Equal(t, http.StatusBadRequest, resp3.StatusCode)
    var err3 api.ErrorResponse
    _ = json.NewDecoder(resp3.Body).Decode(&err3)
    assert.Equal(t, "The phone number must be at least 6 digits long.", err3.Error.Message)

    // Too long (>30) with non-simple pattern
    resp4 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateAccountPhoneRequest{PhoneCountryUniqueId: "USA_0", PhoneNumber: "1234567890123456789012345678901"})
    defer resp4.Body.Close()
    assert.Equal(t, http.StatusBadRequest, resp4.StatusCode)
    var err4 api.ErrorResponse
    _ = json.NewDecoder(resp4.Body).Decode(&err4)
    assert.Equal(t, "The maximum allowed length for a phone number is 30 characters.", err4.Error.Message)

    // Invalid characters
    resp5 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateAccountPhoneRequest{PhoneCountryUniqueId: "USA_0", PhoneNumber: "555-ABC-DEFG"})
    defer resp5.Body.Close()
    assert.Equal(t, http.StatusBadRequest, resp5.StatusCode)
    var err5 api.ErrorResponse
    _ = json.NewDecoder(resp5.Body).Decode(&err5)
    assert.Equal(t, "Please enter a valid number. Phone numbers can contain only digits, and may include single spaces or hyphens as separators.", err5.Error.Message)

    // Invalid country id
    resp6 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateAccountPhoneRequest{PhoneCountryUniqueId: "INVALID_COUNTRY", PhoneNumber: "555-123-4567"})
    defer resp6.Body.Close()
    assert.Equal(t, http.StatusBadRequest, resp6.StatusCode)
    var err6 api.ErrorResponse
    _ = json.NewDecoder(resp6.Body).Decode(&err6)
    assert.Equal(t, "Phone country is invalid.", err6.Error.Message)
}

func TestAPIAccountPhonePut_UnauthorizedAndScope(t *testing.T) {
    url := config.GetAuthServer().BaseURL + "/api/v1/account/phone"

    // No token
    req, err := http.NewRequest("PUT", url, nil)
    assert.NoError(t, err)
    httpClient := createHttpClient(t)
    resp, err := httpClient.Do(req)
    assert.NoError(t, err)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
    body1, _ := io.ReadAll(resp.Body)
    assert.Equal(t, "text/plain; charset=utf-8", resp.Header.Get("Content-Type"))
    assert.Equal(t, "Access token required", strings.TrimSpace(string(body1)))

    // Invalid token
    respInvalid := makeAPIRequest(t, "PUT", url, "invalid-token", api.UpdateAccountPhoneRequest{PhoneCountryUniqueId: "USA_0", PhoneNumber: "555-123-4567"})
    defer respInvalid.Body.Close()
    assert.Equal(t, http.StatusUnauthorized, respInvalid.StatusCode)
    bodyInvalid, _ := io.ReadAll(respInvalid.Body)
    assert.Equal(t, "Access token required", strings.TrimSpace(string(bodyInvalid)))

    // Insufficient scope
    tok := createClientCredentialsTokenWithScope(t, constants.AuthServerResourceIdentifier, constants.UserinfoPermissionIdentifier)
    resp2 := makeAPIRequest(t, "PUT", url, tok, api.UpdateAccountPhoneRequest{PhoneCountryUniqueId: "USA_0", PhoneNumber: "555-123-4567"})
    defer resp2.Body.Close()
    assert.Equal(t, http.StatusForbidden, resp2.StatusCode)
    body2, _ := io.ReadAll(resp2.Body)
    assert.Equal(t, "Insufficient scope", strings.TrimSpace(string(body2)))
}

func TestAPIAccountPhonePut_InvalidRequestBody(t *testing.T) {
    accessToken, _ := getUserAccessTokenWithAccountScope_Phone(t)
    url := config.GetAuthServer().BaseURL + "/api/v1/account/phone"

    // Invalid JSON (no body)
    req, err := http.NewRequest("PUT", url, nil)
    assert.NoError(t, err)
    req.Header.Set("Authorization", "Bearer "+accessToken)
    req.Header.Set("Content-Type", "application/json")
    httpClient := createHttpClient(t)
    resp, err := httpClient.Do(req)
    assert.NoError(t, err)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
    var errResp api.ErrorResponse
    _ = json.NewDecoder(resp.Body).Decode(&errResp)
    assert.Equal(t, "Invalid request body", errResp.Error.Message)
}
