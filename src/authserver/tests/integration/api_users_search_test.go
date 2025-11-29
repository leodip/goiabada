package integrationtests

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

func TestAPIUsersSearch_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test users with unique identifiers to avoid conflicts
	// and allow searching by query instead of paginating through all users
	uniqueSuffix := gofakeit.LetterN(10)
	testUsers := createTestUsersWithSuffix(t, uniqueSuffix)
	defer func() {
		// Cleanup: Delete test users
		for _, user := range testUsers {
			_ = database.DeleteUser(nil, user.Id)
		}
	}()

	// Debug: Verify test users were created
	t.Logf("Created %d test users with suffix '%s':", len(testUsers), uniqueSuffix)
	for _, user := range testUsers {
		t.Logf("  - %s '%s' (ID: %d, Enabled: %t)", user.Email, user.GivenName, user.Id, user.Enabled)
	}

	// Test: Search using query parameter to find our specific test users
	// This is more reliable than paginating through all users
	url := fmt.Sprintf("%s/api/v1/admin/users/search?query=%s&size=50",
		config.GetAuthServer().BaseURL, uniqueSuffix)
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var searchResponse api.SearchUsersResponse
	err := json.NewDecoder(resp.Body).Decode(&searchResponse)
	_ = resp.Body.Close()
	assert.NoError(t, err)

	t.Logf("Search returned %d users matching suffix '%s'", searchResponse.Total, uniqueSuffix)

	// Build map of expected emails
	expectedEmails := make(map[string]bool)
	for _, user := range testUsers {
		expectedEmails[user.Email] = false
	}

	// Check search results for our test users
	for _, user := range searchResponse.Users {
		if _, exists := expectedEmails[user.Email]; exists {
			expectedEmails[user.Email] = true
			t.Logf("Found test user: %s '%s' (ID: %d, Enabled: %t)",
				user.Email, user.GivenName, user.Id, user.Enabled)
		}
	}

	// Assert: All test users should be found
	for email, found := range expectedEmails {
		assert.True(t, found, "Should find test user: %s", email)
	}

	// Assert: We should have found exactly our 3 test users
	assert.GreaterOrEqual(t, searchResponse.Total, 3, "Should find at least our 3 test users")
}

func TestAPIUsersSearch_WithQuery(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test users with more unique identifiers to avoid conflicts
	uniqueSuffix := gofakeit.LetterN(8)
	user1 := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "uniquejohn" + uniqueSuffix + "@searchtest.com",
		GivenName:     "UniqueJohn",
		FamilyName:    "TestUser",
		EmailVerified: true,
	}
	err := database.CreateUser(nil, user1)
	assert.NoError(t, err)

	defer func() {
		_ = database.DeleteUser(nil, user1.Id)
	}()

	// Debug: Verify test user was created
	t.Logf("Created test user: %s '%s %s' (ID: %d, Enabled: %t)",
		user1.Email, user1.GivenName, user1.FamilyName, user1.Id, user1.Enabled)

	// Test: Search with specific query that should match our user
	searchQuery := "uniquejohn" + uniqueSuffix
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/search?query=" + searchQuery
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var searchResponse api.SearchUsersResponse
	err = json.NewDecoder(resp.Body).Decode(&searchResponse)
	assert.NoError(t, err)

	// Assert: Should find our test user
	assert.Equal(t, searchQuery, searchResponse.Query)
	assert.GreaterOrEqual(t, searchResponse.Total, 1, "Should find at least our test user")

	// Debug: Log search response details
	t.Logf("Search query: '%s'", searchResponse.Query)
	t.Logf("Total results: %d", searchResponse.Total)
	t.Logf("Number of users returned: %d", len(searchResponse.Users))
	t.Logf("Search results:")
	for i, user := range searchResponse.Users {
		t.Logf("  [%d] ID: %d, Email: %s, GivenName: %s, FamilyName: %s, Enabled: %t",
			i, user.Id, user.Email, user.GivenName, user.FamilyName, user.Enabled)
	}

	// Check if our test user is in results
	foundTestUser := false
	for _, user := range searchResponse.Users {
		if user.Email == user1.Email {
			foundTestUser = true
			assert.Equal(t, "UniqueJohn", user.GivenName)
			assert.Equal(t, "TestUser", user.FamilyName)
			break
		}
	}
	assert.True(t, foundTestUser, "Should find our test user in search results")
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
	defer func() { _ = resp.Body.Close() }()

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
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAPIUsersSearch_InvalidToken(t *testing.T) {
	// Test: Request with invalid access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/search"
	resp := makeAPIRequest(t, "GET", url, "invalid-token", nil)
	defer func() { _ = resp.Body.Close() }()

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
		name    string
		url     string
		expPage int
		expSize int
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
			defer func() { _ = resp.Body.Close() }()

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
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var searchResponse api.SearchUsersResponse
	err := json.NewDecoder(resp.Body).Decode(&searchResponse)
	assert.NoError(t, err)

	// Assert: Should accept maximum size
	assert.Equal(t, 200, searchResponse.Size, "Should accept size=200")

	// Test: Over maximum size (201) should fallback to default
	url = config.GetAuthServer().BaseURL + "/api/v1/admin/users/search?size=201"
	resp = makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

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
	defer func() { _ = resp.Body.Close() }()

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
		name          string
		queryParam    string
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
			defer func() { _ = resp.Body.Close() }()

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
	defer func() { _ = resp1.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp1.StatusCode)

	var searchResponse1 api.SearchUsersResponse
	err := json.NewDecoder(resp1.Body).Decode(&searchResponse1)
	assert.NoError(t, err)

	// Test: Second page
	url2 := config.GetAuthServer().BaseURL + "/api/v1/admin/users/search?size=5&page=2"
	resp2 := makeAPIRequest(t, "GET", url2, accessToken, nil)
	defer func() { _ = resp2.Body.Close() }()

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

// createTestUsers creates test users in the database for search testing
// Note: Uses fixed email addresses - prefer createTestUsersWithSuffix for tests
// that need to search for specific users in a database with many existing users
func createTestUsers(t *testing.T) []*models.User {
	users := make([]*models.User, 0)

	// Create user 1
	user1 := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "john.doe@test.com",
		GivenName:     "AAA John",
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
		GivenName:     "AAA Jane",
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
		GivenName:     "AAA Disabled",
		FamilyName:    "User",
		EmailVerified: false,
	}
	err = database.CreateUser(nil, user3)
	assert.NoError(t, err)
	users = append(users, user3)

	return users
}

// createTestUsersWithSuffix creates test users with unique email addresses
// using the provided suffix. This allows tests to search for specific users
// using a query parameter, making tests reliable regardless of existing data.
func createTestUsersWithSuffix(t *testing.T, suffix string) []*models.User {
	users := make([]*models.User, 0)

	// Create user 1 - enabled user
	user1 := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "john.doe." + suffix + "@test.com",
		GivenName:     "John" + suffix,
		FamilyName:    "Doe",
		EmailVerified: true,
	}
	err := database.CreateUser(nil, user1)
	assert.NoError(t, err)
	users = append(users, user1)

	// Create user 2 - enabled user
	user2 := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "jane.smith." + suffix + "@test.com",
		GivenName:     "Jane" + suffix,
		FamilyName:    "Smith",
		EmailVerified: true,
	}
	err = database.CreateUser(nil, user2)
	assert.NoError(t, err)
	users = append(users, user2)

	// Create user 3 - disabled user
	user3 := &models.User{
		Subject:       uuid.New(),
		Enabled:       false,
		Email:         "disabled." + suffix + "@test.com",
		GivenName:     "Disabled" + suffix,
		FamilyName:    "User",
		EmailVerified: false,
	}
	err = database.CreateUser(nil, user3)
	assert.NoError(t, err)
	users = append(users, user3)

	return users
}
