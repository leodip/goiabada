package integrationtests

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAPIUserGroupsPut tests the PUT /api/v1/admin/users/{id}/groups endpoint
func TestAPIUserGroupsPut_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:       fake.UUID(),
		Enabled:       true,
		Email:         uniqueEmail("testuser@groups-update.test"),
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.Id)
	}()

	// Setup: Create test groups
	groups := make([]*models.Group, 3)
	for i := 0; i < 3; i++ {
		groups[i] = &models.Group{
			GroupIdentifier:  "update-group-" + strconv.Itoa(i+1),
			Description:      "Update Group " + strconv.Itoa(i+1),
			IncludeInIdToken: i%2 == 0, // alternate true/false
		}
		err = database.CreateGroup(context.Background(), nil, groups[i])
		assert.NoError(t, err)
		defer func(group *models.Group) {
			_ = database.DeleteGroup(context.Background(), nil, group.Id)
		}(groups[i])
	}

	// Setup: Initially assign user to group 0 and group 1
	for i := 0; i < 2; i++ {
		userGroup := &models.UserGroup{
			UserId:  testUser.Id,
			GroupId: groups[i].Id,
		}
		err = database.CreateUserGroup(context.Background(), nil, userGroup)
		assert.NoError(t, err)
		// Don't defer cleanup - the API call will modify these
	}

	// Test: Update user groups - remove group 0, keep group 1, add group 2
	updateReq := api.UpdateUserGroupsRequest{
		GroupIds:         []int64{groups[1].Id, groups[2].Id},
		ExpectedGroupIds: getUserGroupIds(t, accessToken, testUser.Id),
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/groups"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var updateResponse api.GetUserGroupsResponse
	err = json.NewDecoder(resp.Body).Decode(&updateResponse)
	assert.NoError(t, err)

	// Assert: User should be in groups 1 and 2 only
	assert.Equal(t, testUser.Id, updateResponse.User.Id)
	assert.Len(t, updateResponse.Groups, 2)

	// Create map for easier verification
	responseGroupIds := make(map[int64]bool)
	for _, group := range updateResponse.Groups {
		responseGroupIds[group.Id] = true
	}

	assert.True(t, responseGroupIds[groups[1].Id], "Should include group 1")
	assert.True(t, responseGroupIds[groups[2].Id], "Should include group 2")
	assert.False(t, responseGroupIds[groups[0].Id], "Should not include group 0")

	// Verify changes were persisted to database
	updatedUser, err := database.GetUserById(context.Background(), nil, testUser.Id)
	assert.NoError(t, err)
	err = database.UserLoadGroups(context.Background(), nil, updatedUser)
	assert.NoError(t, err)

	assert.Len(t, updatedUser.Groups, 2)
	dbGroupIds := make(map[int64]bool)
	for _, group := range updatedUser.Groups {
		dbGroupIds[group.Id] = true
	}

	assert.True(t, dbGroupIds[groups[1].Id], "Database should include group 1")
	assert.True(t, dbGroupIds[groups[2].Id], "Database should include group 2")
	assert.False(t, dbGroupIds[groups[0].Id], "Database should not include group 0")
}

func TestAPIUserGroupsPut_EmptyGroups(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail("testuser@empty-groups.test"),
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.Id)
	}()

	// Setup: Create test group and assign user to it
	testGroup := &models.Group{
		GroupIdentifier: "remove-all-group",
		Description:     "Group to be removed",
	}
	err = database.CreateGroup(context.Background(), nil, testGroup)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup.Id)
	}()

	userGroup := &models.UserGroup{
		UserId:  testUser.Id,
		GroupId: testGroup.Id,
	}
	err = database.CreateUserGroup(context.Background(), nil, userGroup)
	assert.NoError(t, err)

	// Test: Remove all groups (empty array)
	updateReq := api.UpdateUserGroupsRequest{
		GroupIds:         []int64{}, // Empty array
		ExpectedGroupIds: getUserGroupIds(t, accessToken, testUser.Id),
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/groups"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var updateResponse api.GetUserGroupsResponse
	err = json.NewDecoder(resp.Body).Decode(&updateResponse)
	assert.NoError(t, err)

	// Assert: User should have no groups
	assert.Equal(t, testUser.Id, updateResponse.User.Id)
	assert.Len(t, updateResponse.Groups, 0)

	// Verify in database
	updatedUser, err := database.GetUserById(context.Background(), nil, testUser.Id)
	assert.NoError(t, err)
	err = database.UserLoadGroups(context.Background(), nil, updatedUser)
	assert.NoError(t, err)
	assert.Len(t, updatedUser.Groups, 0)
}

func TestAPIUserGroupsPut_NonExistentGroup(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail("testuser@invalid-group.test"),
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.Id)
	}()

	// Test: Try to assign user to non-existent group
	updateReq := api.UpdateUserGroupsRequest{
		GroupIds:         []int64{99999}, // Non-existent group ID
		ExpectedGroupIds: getUserGroupIds(t, accessToken, testUser.Id),
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/groups"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 400 due to validation error
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAPIUserGroupsPut_UserNotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Update groups for non-existent user
	updateReq := api.UpdateUserGroupsRequest{
		GroupIds:         []int64{}, // Empty groups
		ExpectedGroupIds: []int64{},
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/99999/groups"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIUserGroupsPut_InvalidId(t *testing.T) {
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

	updateReq := api.UpdateUserGroupsRequest{
		GroupIds:         []int64{},
		ExpectedGroupIds: []int64{},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + tc.userId + "/groups"
			resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIUserGroupsPut_InvalidRequestBody(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail("testuser@invalid-body.test"),
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.Id)
	}()

	// Test: Invalid JSON
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/groups"
	req, err := http.NewRequest("PUT", url, nil) // No body
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

func TestAPIUserGroupsPut_Unauthorized(t *testing.T) {
	// Setup: Create test user
	testUser := &models.User{
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail("testuser@unauth-update.test"),
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.Id)
	}()

	// Test: Request without access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/groups"
	req, err := http.NewRequest("PUT", url, nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestAPIUserGroupsPut_TheGroupIdArrayIsBounded is the caller-steerable half of #373's id-list
// sweep. Every id this endpoint is given is read back to check the group exists, and every id in
// an IN list is a bound parameter: before the sweep, an array past SQL Server's 2,100 parameter
// ceiling answered HTTP 500 on a deployment running that engine. The lookup reads long lists in
// several statements now, so nothing crashes, but an unbounded array would still buy one statement
// per thousand ids for a set that cannot exist -- a user can hold at most as many groups as the
// deployment has defined.
//
// The pair is the boundary. At the cap the request is not refused for its size: it goes through to
// the existence check and is answered by it, which is the code the second row asserts. One past,
// it never reaches a query at all. Asserting the code rather than the status is what separates
// them, since both are 400.
func TestAPIUserGroupsPut_TheGroupIdArrayIsBounded(t *testing.T) {
	const maxGroupIdsPerRequest = 1000

	accessToken, _ := createAdminClientWithToken(t)

	testCases := []struct {
		name string
		// total is how many ids the array carries. None of them names a real group: the point is
		// which check answers, and both answer before anything is written.
		total int
		// wantCode is the error_code in the envelope, which is what tells the two checks apart.
		wantCode string
	}{
		{
			name:     "one past the cap is refused for its size",
			total:    maxGroupIdsPerRequest + 1,
			wantCode: "VALIDATION_ERROR",
		},
		{
			name:     "the cap itself reaches the existence check",
			total:    maxGroupIdsPerRequest,
			wantCode: "handler.admin_user_groups.not_found",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			testUser := &models.User{
				Subject:    fake.UUID(),
				Enabled:    true,
				Email:      uniqueEmail("testuser@groups-bound.test"),
				GivenName:  "Test",
				FamilyName: "User",
			}
			err := database.CreateUser(context.Background(), nil, testUser)
			assert.NoError(t, err)
			defer func() {
				_ = database.DeleteUser(context.Background(), nil, testUser.Id)
			}()

			groupIds := make([]int64, testCase.total)
			for i := range groupIds {
				groupIds[i] = int64(1_000_000_000 + i)
			}

			url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" +
				strconv.FormatInt(testUser.Id, 10) + "/groups"
			resp := makeAPIRequest(t, "PUT", url, accessToken,
				api.UpdateUserGroupsRequest{GroupIds: groupIds, ExpectedGroupIds: []int64{}})
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

			var errResp api.ErrorResponse
			err = json.NewDecoder(resp.Body).Decode(&errResp)
			assert.NoError(t, err)
			assert.Equal(t, testCase.wantCode, errResp.ErrorCode)

			// Nothing was written either way: the user belongs to no group afterwards.
			err = database.UserLoadGroups(context.Background(), nil, testUser)
			assert.NoError(t, err)
			assert.Empty(t, testUser.Groups)
		})
	}
}

// getUserGroupIds reads the user's groups through the API, as a caller does before a save, and
// returns their ids: the loaded set a save carries (#428).
func getUserGroupIds(t *testing.T, accessToken string, userId int64) []int64 {
	t.Helper()
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(userId, 10) + "/groups"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body api.GetUserGroupsResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	ids := []int64{}
	for _, g := range body.Groups {
		ids = append(ids, g.Id)
	}
	return ids
}

// createUserForGroupsSave creates an enabled user for one save case and removes it afterwards.
func createUserForGroupsSave(t *testing.T) *models.User {
	t.Helper()
	user := &models.User{
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail("testuser@groups-expected.test"),
		GivenName:  "Test",
		FamilyName: "User",
	}
	require.NoError(t, database.CreateUser(context.Background(), nil, user))
	t.Cleanup(func() { _ = database.DeleteUser(context.Background(), nil, user.Id) })
	return user
}

// The loaded set is required: absent or null answers 400 naming the field, and no membership is
// added (#428).
func TestAPIUserGroupsPut_TheLoadedListIsRequired(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	user := createUserForGroupsSave(t)
	group := createTestGroup(t)
	t.Cleanup(func() { _ = database.DeleteGroup(context.Background(), nil, group.Id) })
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(user.Id, 10) + "/groups"

	bodies := map[string]interface{}{
		"absent": map[string]interface{}{"groupIds": []int64{group.Id}},
		"null":   map[string]interface{}{"groupIds": []int64{group.Id}, "expectedGroupIds": nil},
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			resp := makeAPIRequest(t, "PUT", url, accessToken, body)
			defer func() { _ = resp.Body.Close() }()
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			var got map[string]interface{}
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
			assert.Equal(t, "VALIDATION_ERROR", got["error_code"])
			assert.Contains(t, got["error_description"], "expectedGroupIds is required")
			assert.Empty(t, getUserGroupIds(t, accessToken, user.Id))
		})
	}
}

// Two administrators load the same memberships; the first removes the user from one group, and
// the second, still holding the set as it was, saves. The second is refused 409 CONCURRENT_UPDATE
// and writes nothing, rather than putting the user back into the group the first had just removed
// them from (#428).
func TestAPIUserGroupsPut_AnOutdatedLoadedListIsRefused(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	user := createUserForGroupsSave(t)
	groupA := createTestGroup(t)
	t.Cleanup(func() { _ = database.DeleteGroup(context.Background(), nil, groupA.Id) })
	groupB := createTestGroup(t)
	t.Cleanup(func() { _ = database.DeleteGroup(context.Background(), nil, groupB.Id) })
	groupC := createTestGroup(t)
	t.Cleanup(func() { _ = database.DeleteGroup(context.Background(), nil, groupC.Id) })
	for _, g := range []*models.Group{groupA, groupB} {
		require.NoError(t, database.CreateUserGroup(context.Background(), nil, &models.UserGroup{UserId: user.Id, GroupId: g.Id}))
	}
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(user.Id, 10) + "/groups"

	loadedByBoth := getUserGroupIds(t, accessToken, user.Id)

	first := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateUserGroupsRequest{
		GroupIds: []int64{groupB.Id}, ExpectedGroupIds: loadedByBoth})
	defer func() { _ = first.Body.Close() }()
	require.Equal(t, http.StatusOK, first.StatusCode)

	second := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateUserGroupsRequest{
		GroupIds: []int64{groupA.Id, groupB.Id, groupC.Id}, ExpectedGroupIds: loadedByBoth})
	defer func() { _ = second.Body.Close() }()
	assert.Equal(t, http.StatusConflict, second.StatusCode)
	var body map[string]interface{}
	require.NoError(t, json.NewDecoder(second.Body).Decode(&body))
	assert.Equal(t, "CONCURRENT_UPDATE", body["error_code"])

	assert.Equal(t, []int64{groupB.Id}, getUserGroupIds(t, accessToken, user.Id), "the first save's result stands")
}

// A group id named twice is one membership, where it used to be refused as a group that does not
// exist, and a following save without it removes the membership (#428).
func TestAPIUserGroupsPut_ARepeatedGroupIdIsOneMembership(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	user := createUserForGroupsSave(t)
	group := createTestGroup(t)
	t.Cleanup(func() { _ = database.DeleteGroup(context.Background(), nil, group.Id) })
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(user.Id, 10) + "/groups"

	resp := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateUserGroupsRequest{
		GroupIds: []int64{group.Id, group.Id}, ExpectedGroupIds: []int64{}})
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	stored, err := database.GetUserGroupsByUserId(context.Background(), nil, user.Id)
	require.NoError(t, err)
	require.Len(t, stored, 1, "one row for the repeated id")

	again := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateUserGroupsRequest{
		GroupIds: []int64{}, ExpectedGroupIds: getUserGroupIds(t, accessToken, user.Id)})
	defer func() { _ = again.Body.Close() }()
	require.Equal(t, http.StatusOK, again.StatusCode)
	assert.Empty(t, getUserGroupIds(t, accessToken, user.Id))
}
