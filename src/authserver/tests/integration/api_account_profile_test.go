package integrationtests

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

func getUserAccessTokenWithAccountScope(t *testing.T) (string, *models.User) {
	scope := "openid profile email " + constants.AdminConsoleResourceIdentifier + ":" + constants.ManageAccountPermissionIdentifier
	return createUserAccessTokenWithScope(t, scope)
}

func TestAPIAccountProfileGet_Success(t *testing.T) {
	accessToken, u := getUserAccessTokenWithAccountScope(t)

	url := config.GetAuthServer().BaseURL + "/api/v1/account/profile"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var getResp api.GetUserResponse
	err := json.NewDecoder(resp.Body).Decode(&getResp)
	assert.NoError(t, err)
	assert.Equal(t, u.Id, getResp.User.Id)
	assert.Equal(t, u.Email, getResp.User.Email)
}

func TestAPIAccountProfileGet_UnauthorizedAndScope(t *testing.T) {
	url := config.GetAuthServer().BaseURL + "/api/v1/account/profile"

	// No token
	req, err := http.NewRequest("GET", url, nil)
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
	resp2 := makeAPIRequest(t, "GET", url, "invalid-token", nil)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)
	body2, _ := io.ReadAll(resp2.Body)
	assert.Equal(t, "Access token required", strings.TrimSpace(string(body2)))

	// Insufficient scope (use userinfo scope via client-credentials)
	tok := createClientCredentialsTokenWithScope(t, constants.AuthServerResourceIdentifier, constants.UserinfoPermissionIdentifier)
	resp3 := makeAPIRequest(t, "GET", url, tok, nil)
	defer func() { _ = resp3.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, resp3.StatusCode)
	body3, _ := io.ReadAll(resp3.Body)
	assert.Equal(t, "Insufficient scope", strings.TrimSpace(string(body3)))
}

func TestAPIAccountProfilePut_Success(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)

	// Use a random username to avoid uniqueness collisions across runs
	randUsername := "u" + strings.ToLower(gofakeit.LetterN(7))
	reqBody := api.UpdateUserProfileRequest{
		Username:            randUsername,
		GivenName:           "First",
		MiddleName:          "Middle",
		FamilyName:          "Last",
		Nickname:            "Nick",
		Website:             "https://example.com",
		Gender:              "1",
		DateOfBirth:         "1990-01-01",
		ZoneInfoCountryName: "United States",
		ZoneInfo:            "America/New_York",
		Locale:              "en-US",
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/account/profile"
	resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Dump error body for debugging
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d. body: %s", resp.StatusCode, string(body))
	}
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var updateResp api.UpdateUserResponse
	err := json.NewDecoder(resp.Body).Decode(&updateResp)
	assert.NoError(t, err)
	assert.Equal(t, reqBody.Username, updateResp.User.Username)
	assert.Equal(t, reqBody.GivenName, updateResp.User.GivenName)
	assert.Equal(t, reqBody.FamilyName, updateResp.User.FamilyName)
	assert.Equal(t, "male", updateResp.User.Gender)
	assert.Equal(t, reqBody.ZoneInfo, updateResp.User.ZoneInfo)
	assert.Equal(t, reqBody.Locale, updateResp.User.Locale)
}

func TestAPIAccountProfilePut_ValidationErrors(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)
	url := config.GetAuthServer().BaseURL + "/api/v1/account/profile"

	// Invalid gender
	resp1 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateUserProfileRequest{GivenName: "Aaa", FamilyName: "Bbb", Gender: "invalid"})
	defer func() { _ = resp1.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp1.StatusCode)
	var err1 api.ErrorResponse
	_ = json.NewDecoder(resp1.Body).Decode(&err1)
	assert.Equal(t, "Gender is invalid.", err1.Error.Message)

	// Invalid date format
	resp2 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateUserProfileRequest{GivenName: "Aaa", FamilyName: "Bbb", DateOfBirth: "20-01-1990"})
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
	var err2 api.ErrorResponse
	_ = json.NewDecoder(resp2.Body).Decode(&err2)
	assert.Equal(t, "The date of birth is invalid. Please use the format YYYY-MM-DD.", err2.Error.Message)

	// Invalid zone info
	resp3 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateUserProfileRequest{GivenName: "Aaa", FamilyName: "Bbb", ZoneInfo: "Invalid/Zone"})
	defer func() { _ = resp3.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp3.StatusCode)
	var err3 api.ErrorResponse
	_ = json.NewDecoder(resp3.Body).Decode(&err3)
	assert.Equal(t, "The zone info is invalid.", err3.Error.Message)

	// Invalid locale
	resp4 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateUserProfileRequest{GivenName: "Aaa", FamilyName: "Bbb", Locale: "xx-INVALID"})
	defer func() { _ = resp4.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp4.StatusCode)
	var err4 api.ErrorResponse
	_ = json.NewDecoder(resp4.Body).Decode(&err4)
	assert.Equal(t, "The locale is invalid.", err4.Error.Message)
}

func TestAPIAccountProfilePut_UnauthorizedAndScope(t *testing.T) {
	url := config.GetAuthServer().BaseURL + "/api/v1/account/profile"

	// No token
	req, err := http.NewRequest("PUT", url, nil)
	assert.NoError(t, err)
	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Insufficient scope (authserver:userinfo)
	tok := createClientCredentialsTokenWithScope(t, constants.AuthServerResourceIdentifier, constants.UserinfoPermissionIdentifier)
	resp2 := makeAPIRequest(t, "PUT", url, tok, api.UpdateUserProfileRequest{GivenName: "A", FamilyName: "B"})
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, resp2.StatusCode)
	body2, _ := io.ReadAll(resp2.Body)
	assert.Equal(t, "Insufficient scope", strings.TrimSpace(string(body2)))
}
