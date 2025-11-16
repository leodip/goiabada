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

// TestAPIPhoneCountriesGet tests the GET /api/v1/admin/phone-countries endpoint
func TestAPIPhoneCountriesGet_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Get phone countries
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/phone-countries"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var response api.GetPhoneCountriesResponse
	err := json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)

	// Assert: Should return phone countries data
	assert.NotEmpty(t, response.PhoneCountries)

	// Verify structure of first phone country
	firstCountry := response.PhoneCountries[0]
	assert.NotEmpty(t, firstCountry.UniqueId)
	assert.NotEmpty(t, firstCountry.CallingCode)
	assert.NotEmpty(t, firstCountry.Name)

	// Assert: Should contain some expected countries (verify a few common ones)
	countryMap := make(map[string]api.PhoneCountryResponse)
	for _, country := range response.PhoneCountries {
		countryMap[country.UniqueId] = country
	}

	// We expect at least some basic countries to be present
	// Note: The actual UniqueIds depend on the phonecountries.Get() implementation
	assert.True(t, len(countryMap) > 100, "Should have many countries available")
}

func TestAPIPhoneCountriesGet_Unauthorized(t *testing.T) {
	// Test: Request without access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/phone-countries"
	req, err := http.NewRequest("GET", url, nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAPIPhoneCountriesGet_InvalidToken(t *testing.T) {
	// Test: Request with invalid access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/phone-countries"
	resp := makeAPIRequest(t, "GET", url, "invalid-token", nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestAPIUserPhonePut tests the PUT /api/v1/admin/users/{id}/phone endpoint
func TestAPIUserPhonePut_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "testuser@phone.test",
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Update user phone
	updateReq := api.UpdateUserPhoneRequest{
		PhoneCountryUniqueId: "USA_0", // Assuming this is a valid country ID
		PhoneNumber:          "555-123-4567",
		PhoneNumberVerified:  true,
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/phone"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var updateResponse api.UpdateUserResponse
	err = json.NewDecoder(resp.Body).Decode(&updateResponse)
	assert.NoError(t, err)

	// Assert: Phone data should be updated
	assert.Equal(t, updateReq.PhoneCountryUniqueId, updateResponse.User.PhoneNumberCountryUniqueId)
	assert.Equal(t, updateReq.PhoneNumber, updateResponse.User.PhoneNumber)
	assert.Equal(t, updateReq.PhoneNumberVerified, updateResponse.User.PhoneNumberVerified)
	assert.NotEmpty(t, updateResponse.User.PhoneNumberCountryCallingCode) // Should be set based on country

	// Verify changes were persisted to database
	updatedUser, err := database.GetUserById(nil, testUser.Id)
	assert.NoError(t, err)
	assert.NotNil(t, updatedUser)
	assert.Equal(t, updateReq.PhoneCountryUniqueId, updatedUser.PhoneNumberCountryUniqueId)
	assert.Equal(t, updateReq.PhoneNumber, updatedUser.PhoneNumber)
	assert.Equal(t, updateReq.PhoneNumberVerified, updatedUser.PhoneNumberVerified)
}

func TestAPIUserPhonePut_ClearPhoneNumber(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user with existing phone number
	testUser := &models.User{
		Subject:                       uuid.New(),
		Enabled:                       true,
		Email:                         "testuser@phone-clear.test",
		GivenName:                     "Test",
		FamilyName:                    "User",
		EmailVerified:                 true,
		PhoneNumberCountryUniqueId:    "USA_0",
		PhoneNumberCountryCallingCode: "+1",
		PhoneNumber:                   "555-999-8888",
		PhoneNumberVerified:           true,
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Clear phone number by setting empty values
	updateReq := api.UpdateUserPhoneRequest{
		PhoneCountryUniqueId: "",
		PhoneNumber:          "",
		PhoneNumberVerified:  false,
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/phone"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var updateResponse api.UpdateUserResponse
	err = json.NewDecoder(resp.Body).Decode(&updateResponse)
	assert.NoError(t, err)

	// Assert: Phone fields should be cleared
	assert.Empty(t, updateResponse.User.PhoneNumberCountryUniqueId)
	assert.Empty(t, updateResponse.User.PhoneNumberCountryCallingCode)
	assert.Empty(t, updateResponse.User.PhoneNumber)
	assert.False(t, updateResponse.User.PhoneNumberVerified)

	// Verify changes were persisted to database
	updatedUser, err := database.GetUserById(nil, testUser.Id)
	assert.NoError(t, err)
	assert.Empty(t, updatedUser.PhoneNumberCountryUniqueId)
	assert.Empty(t, updatedUser.PhoneNumberCountryCallingCode)
	assert.Empty(t, updatedUser.PhoneNumber)
	assert.False(t, updatedUser.PhoneNumberVerified)
}

func TestAPIUserPhonePut_ValidationErrors(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "testuser@phone-validation.test",
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	testCases := []struct {
		name           string
		request        api.UpdateUserPhoneRequest
		expectedStatus int
	}{
		{
			"phone number without country",
			api.UpdateUserPhoneRequest{
				PhoneCountryUniqueId: "",
				PhoneNumber:          "555-123-4567",
				PhoneNumberVerified:  false,
			},
			http.StatusBadRequest,
		},
		{
			"country without phone number",
			api.UpdateUserPhoneRequest{
				PhoneCountryUniqueId: "USA_0",
				PhoneNumber:          "",
				PhoneNumberVerified:  false,
			},
			http.StatusBadRequest,
		},
		{
			"phone number too short",
			api.UpdateUserPhoneRequest{
				PhoneCountryUniqueId: "USA_0",
				PhoneNumber:          "123",
				PhoneNumberVerified:  false,
			},
			http.StatusBadRequest,
		},
		{
			"phone number too long",
			api.UpdateUserPhoneRequest{
				PhoneCountryUniqueId: "USA_0",
				PhoneNumber:          "1234567890123456789012345678901", // 31 chars
				PhoneNumberVerified:  false,
			},
			http.StatusBadRequest,
		},
		{
			"invalid phone number characters",
			api.UpdateUserPhoneRequest{
				PhoneCountryUniqueId: "USA_0",
				PhoneNumber:          "555-ABC-DEFG",
				PhoneNumberVerified:  false,
			},
			http.StatusBadRequest,
		},
		{
			"invalid country id",
			api.UpdateUserPhoneRequest{
				PhoneCountryUniqueId: "INVALID_COUNTRY",
				PhoneNumber:          "555-123-4567",
				PhoneNumberVerified:  false,
			},
			http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/phone"
			resp := makeAPIRequest(t, "PUT", url, accessToken, tc.request)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIUserPhonePut_UserNotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Update phone for non-existent user
	updateReq := api.UpdateUserPhoneRequest{
		PhoneCountryUniqueId: "USA_0",
		PhoneNumber:          "555-123-4567",
		PhoneNumberVerified:  false,
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/99999/phone"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIUserPhonePut_InvalidUserId(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	updateReq := api.UpdateUserPhoneRequest{
		PhoneCountryUniqueId: "USA_0",
		PhoneNumber:          "555-123-4567",
		PhoneNumberVerified:  false,
	}

	testCases := []struct {
		name           string
		userId         string
		expectedStatus int
	}{
		{"non-numeric ID", "abc", http.StatusBadRequest},
		{"empty ID", "", http.StatusBadRequest},
		{"negative ID", "-1", http.StatusNotFound},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + tc.userId + "/phone"
			resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIUserPhonePut_InvalidRequestBody(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "testuser@phone-invalid-body.test",
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Invalid JSON
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/phone"
	req, err := http.NewRequest("PUT", url, nil)
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 400 Bad Request
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAPIUserPhonePut_Unauthorized(t *testing.T) {
	// Setup: Create test user
	testUser := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "testuser@phone-unauth.test",
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Request without access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/phone"
	req, err := http.NewRequest("PUT", url, nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAPIUserPhonePut_PhoneNumberVerifiedAutoCleared(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "testuser@phone-verified.test",
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Set phone number verified to true but clear the phone number
	// The verified flag should be automatically set to false when phone is cleared
	updateReq := api.UpdateUserPhoneRequest{
		PhoneCountryUniqueId: "",
		PhoneNumber:          "",
		PhoneNumberVerified:  true, // This should be ignored/overridden
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/phone"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var updateResponse api.UpdateUserResponse
	err = json.NewDecoder(resp.Body).Decode(&updateResponse)
	assert.NoError(t, err)

	// Assert: Phone verified should be false when phone is empty, regardless of request
	assert.False(t, updateResponse.User.PhoneNumberVerified)

	// Verify in database
	updatedUser, err := database.GetUserById(nil, testUser.Id)
	assert.NoError(t, err)
	assert.False(t, updatedUser.PhoneNumberVerified)
}
