package integrationtests

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

// TestAPIUserProfilePut tests the PUT /api/v1/admin/users/{id}/profile endpoint
func TestAPIUserProfilePut_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "testuser@profile.test",
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Update user profile
	updateReq := api.UpdateUserProfileRequest{
		Username:            "testusername",
		GivenName:           "UpdatedFirst",
		MiddleName:          "UpdatedMiddle",
		FamilyName:          "UpdatedLast",
		Nickname:            "TestNick",
		Website:             "https://example.com",
		Gender:              "1", // Male
		DateOfBirth:         "1990-01-01",
		ZoneInfoCountryName: "United States",
		ZoneInfo:            "America/New_York",
		Locale:              "en-US",
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/profile"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var updateResponse api.UpdateUserResponse
	err = json.NewDecoder(resp.Body).Decode(&updateResponse)
	assert.NoError(t, err)

	// Assert: Profile data should be updated
	assert.Equal(t, updateReq.Username, updateResponse.User.Username)
	assert.Equal(t, updateReq.GivenName, updateResponse.User.GivenName)
	assert.Equal(t, updateReq.MiddleName, updateResponse.User.MiddleName)
	assert.Equal(t, updateReq.FamilyName, updateResponse.User.FamilyName)
	assert.Equal(t, updateReq.Nickname, updateResponse.User.Nickname)
	assert.Equal(t, updateReq.Website, updateResponse.User.Website)
	assert.Equal(t, "male", updateResponse.User.Gender) // Should be converted to string
	assert.Equal(t, updateReq.ZoneInfoCountryName, updateResponse.User.ZoneInfoCountryName)
	assert.Equal(t, updateReq.ZoneInfo, updateResponse.User.ZoneInfo)
	assert.Equal(t, updateReq.Locale, updateResponse.User.Locale)

	// Verify changes were persisted to database
	updatedUser, err := database.GetUserById(nil, testUser.Id)
	assert.NoError(t, err)
	assert.NotNil(t, updatedUser)
	assert.Equal(t, updateReq.Username, updatedUser.Username)
	assert.Equal(t, updateReq.GivenName, updatedUser.GivenName)
	assert.Equal(t, updateReq.MiddleName, updatedUser.MiddleName)
	assert.Equal(t, updateReq.FamilyName, updatedUser.FamilyName)
}

func TestAPIUserProfilePut_PartialUpdate(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user with existing data
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@partial.test",
		GivenName:  "Original",
		FamilyName: "User",
		Username:   "originaluser",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Update only some fields
	updateReq := api.UpdateUserProfileRequest{
		Username:   "", // Empty should clear the field
		GivenName:  "NewFirst",
		FamilyName: "NewLast",
		// Other fields left empty/default
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/profile"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var updateResponse api.UpdateUserResponse
	err = json.NewDecoder(resp.Body).Decode(&updateResponse)
	assert.NoError(t, err)

	// Assert: Updated fields should change, others should be cleared/empty
	assert.Equal(t, "", updateResponse.User.Username) // Should be empty
	assert.Equal(t, updateReq.GivenName, updateResponse.User.GivenName)
	assert.Equal(t, updateReq.FamilyName, updateResponse.User.FamilyName)
	assert.Equal(t, "", updateResponse.User.MiddleName)
	assert.Equal(t, "", updateResponse.User.Nickname)
}

func TestAPIUserProfilePut_InvalidGender(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@gender.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Update with invalid gender value
	updateReq := api.UpdateUserProfileRequest{
		GivenName:  "Test",
		FamilyName: "User",
		Gender:     "invalid_gender", // Invalid gender value
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/profile"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer resp.Body.Close()

	// Assert: Should return 400 due to validation error
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAPIUserProfilePut_ValidGender(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@valid-gender.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	testCases := []struct {
		name           string
		genderValue    string
		expectedGender string
	}{
		{"female", "0", "female"},
		{"male", "1", "male"},
		{"other", "2", "other"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test: Update with valid gender value
			updateReq := api.UpdateUserProfileRequest{
				GivenName:  "Test",
				FamilyName: "User",
				Gender:     tc.genderValue,
			}

			url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/profile"
			resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
			defer resp.Body.Close()

			// Assert: Should succeed
			assert.Equal(t, http.StatusOK, resp.StatusCode)

			var updateResponse api.UpdateUserResponse
			err = json.NewDecoder(resp.Body).Decode(&updateResponse)
			assert.NoError(t, err)

			// Gender should be converted to string representation
			assert.Equal(t, tc.expectedGender, updateResponse.User.Gender)
		})
	}
}

func TestAPIUserProfilePut_InvalidDateOfBirth(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@dob.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Update with invalid date of birth format
	updateReq := api.UpdateUserProfileRequest{
		GivenName:   "Test",
		FamilyName:  "User",
		DateOfBirth: "invalid-date", // Invalid date format
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/profile"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer resp.Body.Close()

	// Assert: Should return 400 due to validation error
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAPIUserProfilePut_UserNotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Update non-existent user
	updateReq := api.UpdateUserProfileRequest{
		GivenName:  "Test",
		FamilyName: "User",
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/99999/profile"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer resp.Body.Close()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIUserProfilePut_InvalidId(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	testCases := []struct {
		name           string
		userId         string
		expectedStatus int
	}{
		{"non-numeric ID", "abc", http.StatusBadRequest},
		{"empty ID", "", http.StatusBadRequest}, // Empty ID results in bad request
		{"negative ID", "-1", http.StatusNotFound},
	}

	updateReq := api.UpdateUserProfileRequest{
		GivenName:  "Test",
		FamilyName: "User",
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + tc.userId + "/profile"
			resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
			defer resp.Body.Close()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIUserProfilePut_InvalidRequestBody(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@invalid.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Invalid JSON
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/profile"
	req, err := http.NewRequest("PUT", url, nil) // No body
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	// Assert: Should return 400 Bad Request
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAPIUserProfilePut_Unauthorized(t *testing.T) {
	// Setup: Create test user
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@unauth.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Request without access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/profile"
	req, err := http.NewRequest("PUT", url, nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestAPIUserAddressPut tests the PUT /api/v1/admin/users/{id}/address endpoint
func TestAPIUserAddressPut_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "testuser@address.test",
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Update user address
	updateReq := api.UpdateUserAddressRequest{
		AddressLine1:      "123 Main Street",
		AddressLine2:      "Apt 4B",
		AddressLocality:   "New York",
		AddressRegion:     "NY",
		AddressPostalCode: "10001",
		AddressCountry:    "US",
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/address"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var updateResponse api.UpdateUserResponse
	err = json.NewDecoder(resp.Body).Decode(&updateResponse)
	assert.NoError(t, err)

	// Assert: Address data should be updated
	assert.Equal(t, updateReq.AddressLine1, updateResponse.User.AddressLine1)
	assert.Equal(t, updateReq.AddressLine2, updateResponse.User.AddressLine2)
	assert.Equal(t, updateReq.AddressLocality, updateResponse.User.AddressLocality)
	assert.Equal(t, updateReq.AddressRegion, updateResponse.User.AddressRegion)
	assert.Equal(t, updateReq.AddressPostalCode, updateResponse.User.AddressPostalCode)
	assert.Equal(t, updateReq.AddressCountry, updateResponse.User.AddressCountry)

	// Verify changes were persisted to database
	updatedUser, err := database.GetUserById(nil, testUser.Id)
	assert.NoError(t, err)
	assert.NotNil(t, updatedUser)
	assert.Equal(t, updateReq.AddressLine1, updatedUser.AddressLine1)
	assert.Equal(t, updateReq.AddressLine2, updatedUser.AddressLine2)
	assert.Equal(t, updateReq.AddressLocality, updatedUser.AddressLocality)
	assert.Equal(t, updateReq.AddressRegion, updatedUser.AddressRegion)
	assert.Equal(t, updateReq.AddressPostalCode, updatedUser.AddressPostalCode)
	assert.Equal(t, updateReq.AddressCountry, updatedUser.AddressCountry)
}

func TestAPIUserAddressPut_PartialAddress(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user with existing address
	testUser := &models.User{
		Subject:           uuid.New(),
		Enabled:           true,
		Email:             "testuser@partial-addr.test",
		GivenName:         "Test",
		FamilyName:        "User",
		AddressLine1:      "Old Address",
		AddressLocality:   "Old City",
		AddressPostalCode: "00000",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Update only some address fields
	updateReq := api.UpdateUserAddressRequest{
		AddressLine1:    "New Address",
		AddressLine2:    "", // Empty should clear
		AddressLocality: "New City",
		// Other fields left empty
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/address"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var updateResponse api.UpdateUserResponse
	err = json.NewDecoder(resp.Body).Decode(&updateResponse)
	assert.NoError(t, err)

	// Assert: Updated fields should change, others should be cleared
	assert.Equal(t, updateReq.AddressLine1, updateResponse.User.AddressLine1)
	assert.Equal(t, "", updateResponse.User.AddressLine2)
	assert.Equal(t, updateReq.AddressLocality, updateResponse.User.AddressLocality)
	assert.Equal(t, "", updateResponse.User.AddressRegion)
	assert.Equal(t, "", updateResponse.User.AddressPostalCode)
	assert.Equal(t, "", updateResponse.User.AddressCountry)
}

func TestAPIUserAddressPut_ClearAllFields(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user with existing address data
	testUser := &models.User{
		Subject:           uuid.New(),
		Enabled:           true,
		Email:             "testuser@clear-addr.test",
		GivenName:         "Test",
		FamilyName:        "User",
		AddressLine1:      "123 Test St",
		AddressLocality:   "Test City",
		AddressPostalCode: "12345",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Clear all address fields
	updateReq := api.UpdateUserAddressRequest{
		// All fields empty
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/address"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var updateResponse api.UpdateUserResponse
	err = json.NewDecoder(resp.Body).Decode(&updateResponse)
	assert.NoError(t, err)

	// Assert: All address fields should be empty
	assert.Equal(t, "", updateResponse.User.AddressLine1)
	assert.Equal(t, "", updateResponse.User.AddressLine2)
	assert.Equal(t, "", updateResponse.User.AddressLocality)
	assert.Equal(t, "", updateResponse.User.AddressRegion)
	assert.Equal(t, "", updateResponse.User.AddressPostalCode)
	assert.Equal(t, "", updateResponse.User.AddressCountry)
}

func TestAPIUserAddressPut_UserNotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Update address for non-existent user
	updateReq := api.UpdateUserAddressRequest{
		AddressLine1: "123 Test St",
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/99999/address"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer resp.Body.Close()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIUserAddressPut_InvalidId(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	testCases := []struct {
		name           string
		userId         string
		expectedStatus int
	}{
		{"non-numeric ID", "abc", http.StatusBadRequest},
		{"empty ID", "", http.StatusBadRequest},
		{"negative ID", "-1", http.StatusNotFound},
	}

	updateReq := api.UpdateUserAddressRequest{
		AddressLine1: "123 Test St",
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + tc.userId + "/address"
			resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
			defer resp.Body.Close()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIUserAddressPut_InvalidRequestBody(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@invalid-addr.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Invalid JSON
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/address"
	req, err := http.NewRequest("PUT", url, nil) // No body
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	// Assert: Should return 400 Bad Request
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAPIUserAddressPut_Unauthorized(t *testing.T) {
	// Setup: Create test user
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@unauth-addr.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Request without access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/address"
	req, err := http.NewRequest("PUT", url, nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}