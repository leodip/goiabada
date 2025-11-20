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

// TestAPIGroupMembersGet tests the GET /api/v1/admin/groups/{id}/members endpoint
func TestAPIGroupMembersGet_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := &models.Group{
		GroupIdentifier:      "test-group-members",
		Description:          "Test Group for Members",
		IncludeInIdToken:     true,
		IncludeInAccessToken: false,
	}
	err := database.CreateGroup(nil, testGroup)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	// Setup: Create test users and add to group
	testUser1 := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "member1@group.test",
		GivenName:     "Member",
		FamilyName:    "One",
		EmailVerified: true,
	}
	err = database.CreateUser(nil, testUser1)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser1.Id)
	}()

	testUser2 := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "member2@group.test",
		GivenName:     "Member",
		FamilyName:    "Two",
		EmailVerified: true,
	}
	err = database.CreateUser(nil, testUser2)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser2.Id)
	}()

	// Add users to group
	userGroup1 := &models.UserGroup{UserId: testUser1.Id, GroupId: testGroup.Id}
	err = database.CreateUserGroup(nil, userGroup1)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUserGroup(nil, userGroup1.Id)
	}()

	userGroup2 := &models.UserGroup{UserId: testUser2.Id, GroupId: testGroup.Id}
	err = database.CreateUserGroup(nil, userGroup2)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUserGroup(nil, userGroup2.Id)
	}()

	// Test: Get group members
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10) + "/members"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var membersResponse api.GetGroupMembersResponse
	err = json.NewDecoder(resp.Body).Decode(&membersResponse)
	assert.NoError(t, err)

	// Assert: Should return both members
	assert.Equal(t, 2, membersResponse.Total)
	assert.Len(t, membersResponse.Members, 2)
	assert.Equal(t, 1, membersResponse.Page)
	assert.Equal(t, 10, membersResponse.Size)

	// Verify member details
	memberEmails := make(map[string]bool)
	for _, member := range membersResponse.Members {
		memberEmails[member.Email] = true
	}
	assert.True(t, memberEmails["member1@group.test"])
	assert.True(t, memberEmails["member2@group.test"])
}

func TestAPIGroupMembersGet_EmptyGroup(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group with no members
	testGroup := &models.Group{
		GroupIdentifier:      "empty-group",
		Description:          "Empty Test Group",
		IncludeInIdToken:     true,
		IncludeInAccessToken: false,
	}
	err := database.CreateGroup(nil, testGroup)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	// Test: Get group members
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10) + "/members"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var membersResponse api.GetGroupMembersResponse
	err = json.NewDecoder(resp.Body).Decode(&membersResponse)
	assert.NoError(t, err)

	// Assert: Should return empty members
	assert.Equal(t, 0, membersResponse.Total)
	assert.Len(t, membersResponse.Members, 0)
}

func TestAPIGroupMembersGet_Pagination(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := &models.Group{
		GroupIdentifier: "pagination-group",
		Description:     "Pagination Test Group",
	}
	err := database.CreateGroup(nil, testGroup)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	// Setup: Create multiple users and add to group
	var testUsers []*models.User
	var userGroups []*models.UserGroup

	for i := 1; i <= 3; i++ {
		user := &models.User{
			Subject:    uuid.New(),
			Enabled:    true,
			Email:      "paguser" + strconv.Itoa(i) + "@group.test",
			GivenName:  "Page",
			FamilyName: "User" + strconv.Itoa(i),
		}
		err = database.CreateUser(nil, user)
		assert.NoError(t, err)
		testUsers = append(testUsers, user)

		userGroup := &models.UserGroup{UserId: user.Id, GroupId: testGroup.Id}
		err = database.CreateUserGroup(nil, userGroup)
		assert.NoError(t, err)
		userGroups = append(userGroups, userGroup)
	}

	defer func() {
		for _, userGroup := range userGroups {
			_ = database.DeleteUserGroup(nil, userGroup.Id)
		}
		for _, user := range testUsers {
			_ = database.DeleteUser(nil, user.Id)
		}
	}()

	// Test: Get first page with size=2
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10) + "/members?page=1&size=2"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var membersResponse api.GetGroupMembersResponse
	err = json.NewDecoder(resp.Body).Decode(&membersResponse)
	assert.NoError(t, err)

	// Assert: Should return pagination info
	assert.Equal(t, 3, membersResponse.Total)
	assert.LessOrEqual(t, len(membersResponse.Members), 2)
	assert.Equal(t, 1, membersResponse.Page)
	assert.Equal(t, 2, membersResponse.Size)
}

func TestAPIGroupMembersGet_GroupNotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Get members for non-existent group
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/99999/members"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIGroupMembersGet_InvalidGroupId(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	testCases := []struct {
		name           string
		groupId        string
		expectedStatus int
	}{
		{"non-numeric ID", "abc", http.StatusBadRequest},
		{"empty ID", "", http.StatusBadRequest},
		{"negative ID", "-1", http.StatusNotFound},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + tc.groupId + "/members"
			resp := makeAPIRequest(t, "GET", url, accessToken, nil)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

// TestAPIGroupMemberAdd tests the POST /api/v1/admin/groups/{id}/members endpoint
func TestAPIGroupMemberAdd_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := &models.Group{
		GroupIdentifier: "test-add-member",
		Description:     "Test Group for Adding Member",
	}
	err := database.CreateGroup(nil, testGroup)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	// Setup: Create test user
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "newmember@group.test",
		GivenName:  "New",
		FamilyName: "Member",
	}
	err = database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Add user to group
	addRequest := api.AddGroupMemberRequest{
		UserId: testUser.Id,
	}
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10) + "/members"
	resp := makeAPIRequest(t, "POST", url, accessToken, addRequest)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var successResponse api.SuccessResponse
	err = json.NewDecoder(resp.Body).Decode(&successResponse)
	assert.NoError(t, err)
	assert.True(t, successResponse.Success)

	// Verify user was added to group in database
	userGroup, err := database.GetUserGroupByUserIdAndGroupId(nil, testUser.Id, testGroup.Id)
	assert.NoError(t, err)
	assert.NotNil(t, userGroup)
	assert.Equal(t, testUser.Id, userGroup.UserId)
	assert.Equal(t, testGroup.Id, userGroup.GroupId)

	// Cleanup
	_ = database.DeleteUserGroup(nil, userGroup.Id)
}

func TestAPIGroupMemberAdd_UserAlreadyInGroup(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := &models.Group{
		GroupIdentifier: "duplicate-member-group",
		Description:     "Test Group for Duplicate Member",
	}
	err := database.CreateGroup(nil, testGroup)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	// Setup: Create test user and add to group
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "duplicate@group.test",
		GivenName:  "Duplicate",
		FamilyName: "User",
	}
	err = database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	userGroup := &models.UserGroup{UserId: testUser.Id, GroupId: testGroup.Id}
	err = database.CreateUserGroup(nil, userGroup)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUserGroup(nil, userGroup.Id)
	}()

	// Test: Try to add user to group again
	addRequest := api.AddGroupMemberRequest{
		UserId: testUser.Id,
	}
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10) + "/members"
	resp := makeAPIRequest(t, "POST", url, accessToken, addRequest)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return validation error
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAPIGroupMemberAdd_UserNotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := &models.Group{
		GroupIdentifier: "test-user-not-found",
		Description:     "Test Group for User Not Found",
	}
	err := database.CreateGroup(nil, testGroup)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	// Test: Try to add non-existent user to group
	addRequest := api.AddGroupMemberRequest{
		UserId: 99999,
	}
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10) + "/members"
	resp := makeAPIRequest(t, "POST", url, accessToken, addRequest)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return not found
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIGroupMemberAdd_GroupNotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Try to add user to non-existent group
	addRequest := api.AddGroupMemberRequest{
		UserId: 1,
	}
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/99999/members"
	resp := makeAPIRequest(t, "POST", url, accessToken, addRequest)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return not found
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIGroupMemberAdd_InvalidRequestBody(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := &models.Group{
		GroupIdentifier: "invalid-request-group",
		Description:     "Test Group for Invalid Request",
	}
	err := database.CreateGroup(nil, testGroup)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	// Test: Send request with no body
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10) + "/members"
	req, err := http.NewRequest("POST", url, nil)
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return bad request
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestAPIGroupMemberRemove tests the DELETE /api/v1/admin/groups/{id}/members/{userId} endpoint
func TestAPIGroupMemberRemove_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := &models.Group{
		GroupIdentifier: "test-remove-member",
		Description:     "Test Group for Removing Member",
	}
	err := database.CreateGroup(nil, testGroup)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	// Setup: Create test user and add to group
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "removeme@group.test",
		GivenName:  "Remove",
		FamilyName: "Me",
	}
	err = database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	userGroup := &models.UserGroup{UserId: testUser.Id, GroupId: testGroup.Id}
	err = database.CreateUserGroup(nil, userGroup)
	assert.NoError(t, err)

	// Test: Remove user from group
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10) + "/members/" + strconv.FormatInt(testUser.Id, 10)
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var successResponse api.SuccessResponse
	err = json.NewDecoder(resp.Body).Decode(&successResponse)
	assert.NoError(t, err)
	assert.True(t, successResponse.Success)

	// Verify user was removed from group in database
	removedUserGroup, err := database.GetUserGroupByUserIdAndGroupId(nil, testUser.Id, testGroup.Id)
	assert.NoError(t, err)
	assert.Nil(t, removedUserGroup)
}

func TestAPIGroupMemberRemove_UserNotInGroup(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := &models.Group{
		GroupIdentifier: "test-not-in-group",
		Description:     "Test Group for User Not In Group",
	}
	err := database.CreateGroup(nil, testGroup)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	// Setup: Create test user (not in group)
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "notingroup@group.test",
		GivenName:  "Not",
		FamilyName: "InGroup",
	}
	err = database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Try to remove user from group they're not in
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10) + "/members/" + strconv.FormatInt(testUser.Id, 10)
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return validation error
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAPIGroupMemberRemove_UserNotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := &models.Group{
		GroupIdentifier: "test-remove-user-not-found",
		Description:     "Test Group for Remove User Not Found",
	}
	err := database.CreateGroup(nil, testGroup)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	// Test: Try to remove non-existent user from group
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10) + "/members/99999"
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return not found
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIGroupMemberRemove_GroupNotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Try to remove user from non-existent group
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/99999/members/1"
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return not found
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIGroupMemberRemove_InvalidIds(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	testCases := []struct {
		name           string
		groupId        string
		userId         string
		expectedStatus int
	}{
		{"non-numeric group ID", "abc", "1", http.StatusBadRequest},
		{"non-numeric user ID", "1", "abc", http.StatusBadRequest},
		{"negative group ID", "-1", "1", http.StatusNotFound},
		{"negative user ID", "1", "-1", http.StatusNotFound},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + tc.groupId + "/members/" + tc.userId
			resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

// Test authorization for all endpoints
func TestAPIGroupMembers_Unauthorized(t *testing.T) {
	// Setup: Create test group
	testGroup := &models.Group{
		GroupIdentifier: "unauthorized-test",
		Description:     "Test Group for Unauthorized",
	}
	err := database.CreateGroup(nil, testGroup)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	testCases := []struct {
		name   string
		method string
		url    string
	}{
		{"GET members", "GET", "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10) + "/members"},
		{"POST add member", "POST", "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10) + "/members"},
		{"DELETE remove member", "DELETE", "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10) + "/members/1"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := config.GetAuthServer().BaseURL + tc.url
			req, err := http.NewRequest(tc.method, url, nil)
			assert.NoError(t, err)

			httpClient := createHttpClient(t)
			resp, err := httpClient.Do(req)
			assert.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			// Assert: Should be unauthorized
			assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		})
	}
}