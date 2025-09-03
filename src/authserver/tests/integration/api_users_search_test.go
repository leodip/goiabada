package integrationtests

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)


// createTestUsers creates test users in the database for search testing
func createTestUsers(t *testing.T) []*models.User {
	users := make([]*models.User, 0)

	// Create user 1
	user1 := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "john.doe@test.com",
		GivenName:     "John",
		FamilyName:    "Doe",
		EmailVerified: true,
	}
	err := database.CreateUser(nil, user1)
	assert.NoError(t, err)
	users = append(users, user1)

	// Create user 2
	user2 := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "jane.smith@test.com",
		GivenName:     "Jane",
		FamilyName:    "Smith",
		EmailVerified: true,
	}
	err = database.CreateUser(nil, user2)
	assert.NoError(t, err)
	users = append(users, user2)

	// Create user 3
	user3 := &models.User{
		Subject:       uuid.New(),
		Enabled:       false, // Disabled user
		Email:         "disabled@test.com",
		GivenName:     "Disabled",
		FamilyName:    "User",
		EmailVerified: false,
	}
	err = database.CreateUser(nil, user3)
	assert.NoError(t, err)
	users = append(users, user3)

	return users
}


func TestAPIUsersSearch_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test users
	testUsers := createTestUsers(t)
	defer func() {
		// Cleanup: Delete test users
		for _, user := range testUsers {
			_ = database.DeleteUser(nil, user.Id)
		}
	}()

	// Test: Basic search without query
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/search"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var searchResponse api.SearchUsersResponse
	err := json.NewDecoder(resp.Body).Decode(&searchResponse)
	assert.NoError(t, err)

	// Assert: Response structure
	assert.GreaterOrEqual(t, searchResponse.Total, 3, "Should have at least our 3 test users")
	assert.Equal(t, 1, searchResponse.Page)
	assert.Equal(t, 10, searchResponse.Size) // Default size
	assert.Equal(t, "", searchResponse.Query)
	assert.GreaterOrEqual(t, len(searchResponse.Users), 3, "Should return at least our test users")

	// Verify that our test users are in the results
	userEmails := make(map[string]bool)
	for _, user := range searchResponse.Users {
		userEmails[user.Email] = true
	}

	assert.True(t, userEmails["john.doe@test.com"], "Should find john.doe@test.com")
	assert.True(t, userEmails["jane.smith@test.com"], "Should find jane.smith@test.com")
	assert.True(t, userEmails["disabled@test.com"], "Should find disabled@test.com")
}

func TestAPIUsersSearch_WithQuery(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test users
	testUsers := createTestUsers(t)
	defer func() {
		// Cleanup: Delete test users
		for _, user := range testUsers {
			_ = database.DeleteUser(nil, user.Id)
		}
	}()

	// Test: Search with query parameter
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/search?query=john"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var searchResponse api.SearchUsersResponse
	err := json.NewDecoder(resp.Body).Decode(&searchResponse)
	assert.NoError(t, err)

	// Assert: Should find John Doe
	assert.Equal(t, "john", searchResponse.Query)
	assert.GreaterOrEqual(t, searchResponse.Total, 1, "Should find at least John")

	// Check if john.doe@test.com is in results
	foundJohn := false
	for _, user := range searchResponse.Users {
		if user.Email == "john.doe@test.com" {
			foundJohn = true
			assert.Equal(t, "John", user.GivenName)
			assert.Equal(t, "Doe", user.FamilyName)
			break
		}
	}
	assert.True(t, foundJohn, "Should find John Doe in search results")
}

func TestAPIUsersSearch_WithPagination(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test users
	testUsers := createTestUsers(t)
	defer func() {
		// Cleanup: Delete test users
		for _, user := range testUsers {
			_ = database.DeleteUser(nil, user.Id)
		}
	}()

	// Test: Search with pagination
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/search?page=1&size=2"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var searchResponse api.SearchUsersResponse
	err := json.NewDecoder(resp.Body).Decode(&searchResponse)
	assert.NoError(t, err)

	// Assert: Pagination parameters
	assert.Equal(t, 1, searchResponse.Page)
	assert.Equal(t, 2, searchResponse.Size)
	assert.LessOrEqual(t, len(searchResponse.Users), 2, "Should return at most 2 users per page")
	assert.GreaterOrEqual(t, searchResponse.Total, 3, "Total should be at least 3")
}

func TestAPIUsersSearch_Unauthorized(t *testing.T) {
	// Test: Request without access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/search"
	req, err := http.NewRequest("GET", url, nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAPIUsersSearch_InvalidToken(t *testing.T) {
	// Test: Request with invalid access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/search"
	resp := makeAPIRequest(t, "GET", url, "invalid-token", nil)
	defer resp.Body.Close()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAPIUsersSearch_InvalidParameters(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test users
	testUsers := createTestUsers(t)
	defer func() {
		// Cleanup: Delete test users
		for _, user := range testUsers {
			_ = database.DeleteUser(nil, user.Id)
		}
	}()

	testCases := []struct {
		name     string
		url      string
		expPage  int
		expSize  int
	}{
		{"negative page", "/api/v1/admin/users/search?page=-1", 1, 10},
		{"zero page", "/api/v1/admin/users/search?page=0", 1, 10},
		{"non-numeric page", "/api/v1/admin/users/search?page=abc", 1, 10},
		{"negative size", "/api/v1/admin/users/search?size=-1", 1, 10},
		{"zero size", "/api/v1/admin/users/search?size=0", 1, 10},
		{"over-limit size", "/api/v1/admin/users/search?size=300", 1, 10},
		{"non-numeric size", "/api/v1/admin/users/search?size=xyz", 1, 10},
		{"both invalid", "/api/v1/admin/users/search?page=abc&size=xyz", 1, 10},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := config.GetAuthServer().BaseURL + tc.url
			resp := makeAPIRequest(t, "GET", url, accessToken, nil)
			defer resp.Body.Close()

			// Assert: Response should be successful
			assert.Equal(t, http.StatusOK, resp.StatusCode)

			// Parse response
			var searchResponse api.SearchUsersResponse
			err := json.NewDecoder(resp.Body).Decode(&searchResponse)
			assert.NoError(t, err)

			// Assert: Should fallback to default values
			assert.Equal(t, tc.expPage, searchResponse.Page, "Page should fallback to default")
			assert.Equal(t, tc.expSize, searchResponse.Size, "Size should fallback to default")
		})
	}
}

func TestAPIUsersSearch_SizeLimit(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test users
	testUsers := createTestUsers(t)
	defer func() {
		// Cleanup: Delete test users
		for _, user := range testUsers {
			_ = database.DeleteUser(nil, user.Id)
		}
	}()

	// Test: Maximum allowed size (200)
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/search?size=200"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var searchResponse api.SearchUsersResponse
	err := json.NewDecoder(resp.Body).Decode(&searchResponse)
	assert.NoError(t, err)

	// Assert: Should accept maximum size
	assert.Equal(t, 200, searchResponse.Size, "Should accept size=200")

	// Test: Over maximum size (201) should fallback to default
	url = config.GetAuthServer().BaseURL + "/api/v1/admin/users/search?size=201"
	resp = makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	err = json.NewDecoder(resp.Body).Decode(&searchResponse)
	assert.NoError(t, err)

	// Assert: Should fallback to default size
	assert.Equal(t, 10, searchResponse.Size, "Size over 200 should fallback to default")
}

func TestAPIUsersSearch_NoResults(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test users
	testUsers := createTestUsers(t)
	defer func() {
		// Cleanup: Delete test users
		for _, user := range testUsers {
			_ = database.DeleteUser(nil, user.Id)
		}
	}()

	// Test: Query that returns no users
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/search?query=nonexistent-user-12345"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Should still return 200 even with no results
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var searchResponse api.SearchUsersResponse
	err := json.NewDecoder(resp.Body).Decode(&searchResponse)
	assert.NoError(t, err)

	// Assert: Should return empty results but valid structure
	assert.Equal(t, 0, searchResponse.Total, "Total should be 0 for no results")
	assert.Equal(t, 0, len(searchResponse.Users), "Users array should be empty")
	assert.Equal(t, 1, searchResponse.Page, "Page should be 1")
	assert.Equal(t, 10, searchResponse.Size, "Size should be default 10")
	assert.Equal(t, "nonexistent-user-12345", searchResponse.Query, "Query should be preserved")
}

func TestAPIUsersSearch_SpecialCharacters(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test users
	testUsers := createTestUsers(t)
	defer func() {
		// Cleanup: Delete test users
		for _, user := range testUsers {
			_ = database.DeleteUser(nil, user.Id)
		}
	}()

	testCases := []struct {
		name        string
		queryParam  string
		expectedQuery string
	}{
		{"empty query", "query=", ""},
		{"space query", "query=%20", " "},
		{"at symbol", "query=john%40doe", "john@doe"},
		{"plus symbol", "query=john%2Bdoe", "john+doe"},
		{"special chars", "query=%21%40%23%24", "!@#$"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/search?" + tc.queryParam
			resp := makeAPIRequest(t, "GET", url, accessToken, nil)
			defer resp.Body.Close()

			// Assert: Should handle special characters gracefully
			assert.Equal(t, http.StatusOK, resp.StatusCode)

			// Parse response
			var searchResponse api.SearchUsersResponse
			err := json.NewDecoder(resp.Body).Decode(&searchResponse)
			assert.NoError(t, err)

			// Assert: Query should be preserved correctly
			assert.Equal(t, tc.expectedQuery, searchResponse.Query, "Query should be URL decoded correctly")
		})
	}
}

func TestAPIUsersSearch_MultiplePages(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create multiple users for pagination testing
	var testUsers []*models.User
	for i := 1; i <= 8; i++ {
		user := &models.User{
			Subject:       uuid.New(),
			Enabled:       true,
			Email:         "testuser" + string(rune('0'+i)) + "@pagination.test",
			GivenName:     "Test",
			FamilyName:    "User" + string(rune('0'+i)),
			EmailVerified: true,
		}
		err := database.CreateUser(nil, user)
		assert.NoError(t, err)
		testUsers = append(testUsers, user)
	}

	defer func() {
		// Cleanup: Delete test users
		for _, user := range testUsers {
			_ = database.DeleteUser(nil, user.Id)
		}
	}()

	// Test: First page
	url1 := config.GetAuthServer().BaseURL + "/api/v1/admin/users/search?size=5&page=1"
	resp1 := makeAPIRequest(t, "GET", url1, accessToken, nil)
	defer resp1.Body.Close()

	assert.Equal(t, http.StatusOK, resp1.StatusCode)

	var searchResponse1 api.SearchUsersResponse
	err := json.NewDecoder(resp1.Body).Decode(&searchResponse1)
	assert.NoError(t, err)

	// Test: Second page
	url2 := config.GetAuthServer().BaseURL + "/api/v1/admin/users/search?size=5&page=2"
	resp2 := makeAPIRequest(t, "GET", url2, accessToken, nil)
	defer resp2.Body.Close()

	assert.Equal(t, http.StatusOK, resp2.StatusCode)

	var searchResponse2 api.SearchUsersResponse
	err = json.NewDecoder(resp2.Body).Decode(&searchResponse2)
	assert.NoError(t, err)

	// Assert: Pagination parameters
	assert.Equal(t, 1, searchResponse1.Page, "First page should be 1")
	assert.Equal(t, 2, searchResponse2.Page, "Second page should be 2")
	assert.Equal(t, 5, searchResponse1.Size, "Size should be 5")
	assert.Equal(t, 5, searchResponse2.Size, "Size should be 5")

	// Assert: Both pages should have total count (including existing users from database)
	assert.Equal(t, searchResponse1.Total, searchResponse2.Total, "Total count should be same across pages")
	assert.GreaterOrEqual(t, searchResponse1.Total, 8, "Should find at least our 8 test users")

	// Assert: No duplicate users between pages
	page1Emails := make(map[string]bool)
	for _, user := range searchResponse1.Users {
		page1Emails[user.Email] = true
	}

	for _, user := range searchResponse2.Users {
		assert.False(t, page1Emails[user.Email], "User %s should not appear in both pages", user.Email)
	}

	// Assert: Each page should return appropriate number of users (up to size limit)
	assert.LessOrEqual(t, len(searchResponse1.Users), 5, "Page 1 should have at most 5 users")
	assert.LessOrEqual(t, len(searchResponse2.Users), 5, "Page 2 should have at most 5 users")
}
