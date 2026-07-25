package datatests

import (
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/models"
)

// The association loaders in commondb had no direct data-layer tests: they are
// exercised only indirectly, through the auth flows in the integration suite.
// They are the queries behind permission checks (UserHasScopePermission loads a
// user's permissions, groups and the groups' permissions before deciding), so a
// silent regression in one of them is an authorization bug.

// createUserWithGivenName creates an enabled user with a controlled given name,
// which GetGroupMembersPaginated orders by.
func createUserWithGivenName(t *testing.T, givenName string) *models.User {
	t.Helper()
	user := &models.User{
		Enabled:   true,
		Subject:   uuid.New(),
		Username:  "u" + gofakeit.LetterN(12),
		GivenName: givenName,
		Email:     gofakeit.LetterN(12) + "@example.com",
	}
	if err := database.CreateUser(nil, user); err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}
	return user
}

// =============================================================================
// User association loaders
// =============================================================================

func TestUserLoadPermissions(t *testing.T) {
	user := createTestUser(t)
	resource := createTestResource(t)
	permission := createTestPermission(t, resource)
	createTestUserPermissionWithUserAndPermission(t, user.Id, permission.Id)

	if err := database.UserLoadPermissions(nil, user); err != nil {
		t.Fatalf("UserLoadPermissions failed: %v", err)
	}

	if len(user.Permissions) != 1 {
		t.Fatalf("Expected 1 permission, got %d", len(user.Permissions))
	}
	if user.Permissions[0].Id != permission.Id {
		t.Errorf("Expected permission id %d, got %d", permission.Id, user.Permissions[0].Id)
	}
	if user.Permissions[0].PermissionIdentifier != permission.PermissionIdentifier {
		t.Errorf("Expected permission identifier %s, got %s",
			permission.PermissionIdentifier, user.Permissions[0].PermissionIdentifier)
	}
}

func TestUserLoadPermissions_NoPermissions(t *testing.T) {
	user := createTestUser(t)

	if err := database.UserLoadPermissions(nil, user); err != nil {
		t.Fatalf("UserLoadPermissions failed: %v", err)
	}

	if len(user.Permissions) != 0 {
		t.Errorf("Expected no permissions, got %d", len(user.Permissions))
	}
}

// Each user must receive only its own permissions; a mix-up here would grant one
// user another's access.
func TestUsersLoadPermissions(t *testing.T) {
	resource := createTestResource(t)
	permissionA := createTestPermission(t, resource)
	permissionB := createTestPermission(t, resource)

	userA := createTestUser(t)
	userB := createTestUser(t)
	userC := createTestUser(t) // deliberately has none

	createTestUserPermissionWithUserAndPermission(t, userA.Id, permissionA.Id)
	createTestUserPermissionWithUserAndPermission(t, userB.Id, permissionB.Id)

	users := []models.User{*userA, *userB, *userC}

	if err := database.UsersLoadPermissions(nil, users); err != nil {
		t.Fatalf("UsersLoadPermissions failed: %v", err)
	}

	if len(users[0].Permissions) != 1 || users[0].Permissions[0].Id != permissionA.Id {
		t.Errorf("Expected user A to hold only permission %d, got %+v", permissionA.Id, users[0].Permissions)
	}
	if len(users[1].Permissions) != 1 || users[1].Permissions[0].Id != permissionB.Id {
		t.Errorf("Expected user B to hold only permission %d, got %+v", permissionB.Id, users[1].Permissions)
	}
	if len(users[2].Permissions) != 0 {
		t.Errorf("Expected user C to hold no permissions, got %d", len(users[2].Permissions))
	}
}

func TestUsersLoadPermissions_NilAndEmptySlices(t *testing.T) {
	if err := database.UsersLoadPermissions(nil, nil); err != nil {
		t.Errorf("UsersLoadPermissions(nil) should be a no-op, got: %v", err)
	}
	if err := database.UsersLoadPermissions(nil, []models.User{}); err != nil {
		t.Errorf("UsersLoadPermissions(empty) should be a no-op, got: %v", err)
	}
}

func TestUserLoadGroups(t *testing.T) {
	user := createTestUser(t)
	groupA := createTestGroup(t)
	groupB := createTestGroup(t)
	createTestUserGroupWithUserAndGroup(t, user.Id, groupA.Id)
	createTestUserGroupWithUserAndGroup(t, user.Id, groupB.Id)

	if err := database.UserLoadGroups(nil, user); err != nil {
		t.Fatalf("UserLoadGroups failed: %v", err)
	}

	if len(user.Groups) != 2 {
		t.Fatalf("Expected 2 groups, got %d", len(user.Groups))
	}

	found := map[int64]bool{}
	for _, g := range user.Groups {
		found[g.Id] = true
		if g.GroupIdentifier == "" {
			t.Error("Expected the group identifier to be populated, not just the id")
		}
	}
	if !found[groupA.Id] || !found[groupB.Id] {
		t.Errorf("Expected groups %d and %d, got %+v", groupA.Id, groupB.Id, found)
	}
}

func TestUserLoadGroups_NoGroups(t *testing.T) {
	user := createTestUser(t)

	if err := database.UserLoadGroups(nil, user); err != nil {
		t.Fatalf("UserLoadGroups failed: %v", err)
	}

	if len(user.Groups) != 0 {
		t.Errorf("Expected no groups, got %d", len(user.Groups))
	}
}

func TestUsersLoadGroups(t *testing.T) {
	groupA := createTestGroup(t)
	groupB := createTestGroup(t)

	userA := createTestUser(t)
	userB := createTestUser(t)
	createTestUserGroupWithUserAndGroup(t, userA.Id, groupA.Id)
	createTestUserGroupWithUserAndGroup(t, userB.Id, groupB.Id)

	users := []models.User{*userA, *userB}

	if err := database.UsersLoadGroups(nil, users); err != nil {
		t.Fatalf("UsersLoadGroups failed: %v", err)
	}

	if len(users[0].Groups) != 1 || users[0].Groups[0].Id != groupA.Id {
		t.Errorf("Expected user A in group %d, got %+v", groupA.Id, users[0].Groups)
	}
	if len(users[1].Groups) != 1 || users[1].Groups[0].Id != groupB.Id {
		t.Errorf("Expected user B in group %d, got %+v", groupB.Id, users[1].Groups)
	}
}

func TestUsersLoadGroups_NilAndEmptySlices(t *testing.T) {
	if err := database.UsersLoadGroups(nil, nil); err != nil {
		t.Errorf("UsersLoadGroups(nil) should be a no-op, got: %v", err)
	}
	if err := database.UsersLoadGroups(nil, []models.User{}); err != nil {
		t.Errorf("UsersLoadGroups(empty) should be a no-op, got: %v", err)
	}
}

func TestUserLoadAttributes(t *testing.T) {
	user := createTestUser(t)
	attributeA := createTestUserAttribute(t, user.Id)
	attributeB := createTestUserAttribute(t, user.Id)

	if err := database.UserLoadAttributes(nil, user); err != nil {
		t.Fatalf("UserLoadAttributes failed: %v", err)
	}

	if len(user.Attributes) != 2 {
		t.Fatalf("Expected 2 attributes, got %d", len(user.Attributes))
	}

	found := map[int64]bool{}
	for _, a := range user.Attributes {
		found[a.Id] = true
		if a.Key == "" {
			t.Error("Expected the attribute key to be populated")
		}
	}
	if !found[attributeA.Id] || !found[attributeB.Id] {
		t.Errorf("Expected attributes %d and %d, got %+v", attributeA.Id, attributeB.Id, found)
	}
}

func TestUserLoadAttributes_NoAttributes(t *testing.T) {
	user := createTestUser(t)

	if err := database.UserLoadAttributes(nil, user); err != nil {
		t.Fatalf("UserLoadAttributes failed: %v", err)
	}

	if len(user.Attributes) != 0 {
		t.Errorf("Expected no attributes, got %d", len(user.Attributes))
	}
}

// =============================================================================
// GetUsersByIds
//
// The batch read behind UserSessionsLoadUsers: it resolves a whole page of
// sessions to their users in one query. Unlike every other *ByIds reader it
// returns a map keyed by user id rather than a slice, so it silently tolerates
// duplicate input ids and cannot be indexed positionally.
// =============================================================================

func TestGetUsersByIds(t *testing.T) {
	userA := createTestUser(t)
	userB := createTestUser(t)
	userC := createTestUser(t)

	// Deliberately ask for only two of the three.
	users, err := database.GetUsersByIds(nil, []int64{userA.Id, userC.Id})
	if err != nil {
		t.Fatalf("GetUsersByIds failed: %v", err)
	}

	if len(users) != 2 {
		t.Fatalf("Expected 2 users, got %d", len(users))
	}

	// Keyed by user id, and the row is fully scanned (not just the id).
	if users[userA.Id].Subject != userA.Subject {
		t.Errorf("Expected user A subject %s, got %s", userA.Subject, users[userA.Id].Subject)
	}
	if users[userA.Id].Email != userA.Email {
		t.Errorf("Expected user A email %s, got %s", userA.Email, users[userA.Id].Email)
	}
	if users[userC.Id].Subject != userC.Subject {
		t.Errorf("Expected user C subject %s, got %s", userC.Subject, users[userC.Id].Subject)
	}
	if _, present := users[userB.Id]; present {
		t.Error("User B was not requested and must not be returned")
	}
}

func TestGetUsersByIds_UnknownIdIsSkipped(t *testing.T) {
	user := createTestUser(t)

	users, err := database.GetUsersByIds(nil, []int64{user.Id, 999999999})
	if err != nil {
		t.Fatalf("GetUsersByIds failed: %v", err)
	}

	if len(users) != 1 {
		t.Fatalf("Expected only the existing user, got %d entries", len(users))
	}
	if _, present := users[user.Id]; !present {
		t.Errorf("Expected user %d in the result, got %+v", user.Id, users)
	}
}

// A repeated id must not produce a duplicate entry. This holds trivially because
// the result is a map, but UserSessionsLoadUsers feeds it one id per session and
// several sessions of the same user is the normal case, so pin it.
func TestGetUsersByIds_DuplicateIdsCollapse(t *testing.T) {
	user := createTestUser(t)

	users, err := database.GetUsersByIds(nil, []int64{user.Id, user.Id})
	if err != nil {
		t.Fatalf("GetUsersByIds failed: %v", err)
	}

	if len(users) != 1 {
		t.Errorf("Expected a repeated id to yield one entry, got %d", len(users))
	}
	if users[user.Id].Id != user.Id {
		t.Errorf("Expected user %d in the result, got %+v", user.Id, users)
	}
}

// An empty or nil id list must not reach the database. GetUsersByIds returns
// early like every other *ByIds reader (GetGroupsByIds, GetClientsByIds,
// GetPermissionsByIds, GetResourcesByIds, GetUserSessionsClientByIds and
// GetUserSessionClientsByUserSessionIds).
//
// This case is reachable: the load helpers guard userSessions == nil but not
// len(userSessions) == 0, so a caller-built empty page arrives here as an empty
// slice. Before the guard was added it still behaved correctly, because
// go-sqlbuilder's Cond.In emits "0 = 1" rather than an illegal "IN ()" when
// given no values, but it cost a pointless round-trip and depended on that
// upstream detail.
//
// Asserted as len()==0 rather than == nil so the test states the contract
// callers rely on (no users came back) and not the representation.
func TestGetUsersByIds_EmptyInput(t *testing.T) {
	users, err := database.GetUsersByIds(nil, []int64{})
	if err != nil {
		t.Fatalf("GetUsersByIds(empty) failed: %v", err)
	}
	if len(users) != 0 {
		t.Errorf("Expected no users for an empty id list, got %+v", users)
	}

	users, err = database.GetUsersByIds(nil, nil)
	if err != nil {
		t.Fatalf("GetUsersByIds(nil) failed: %v", err)
	}
	if len(users) != 0 {
		t.Errorf("Expected no users for a nil id list, got %+v", users)
	}
}

// =============================================================================
// Group association loaders
// =============================================================================

func TestGroupLoadPermissions(t *testing.T) {
	group := createTestGroup(t)
	resource := createTestResource(t)
	permission := createTestPermission(t, resource)
	createTestGroupPermission(t, group.Id, permission.Id)

	if err := database.GroupLoadPermissions(nil, group); err != nil {
		t.Fatalf("GroupLoadPermissions failed: %v", err)
	}

	if len(group.Permissions) != 1 {
		t.Fatalf("Expected 1 permission, got %d", len(group.Permissions))
	}
	if group.Permissions[0].Id != permission.Id {
		t.Errorf("Expected permission id %d, got %d", permission.Id, group.Permissions[0].Id)
	}
}

func TestGroupLoadPermissions_NoPermissions(t *testing.T) {
	group := createTestGroup(t)

	if err := database.GroupLoadPermissions(nil, group); err != nil {
		t.Fatalf("GroupLoadPermissions failed: %v", err)
	}

	if len(group.Permissions) != 0 {
		t.Errorf("Expected no permissions, got %d", len(group.Permissions))
	}
}

// This is the loader UserHasScopePermission relies on for group-derived
// permissions, so each group must get exactly its own.
func TestGroupsLoadPermissions(t *testing.T) {
	resource := createTestResource(t)
	permissionA := createTestPermission(t, resource)
	permissionB := createTestPermission(t, resource)

	groupA := createTestGroup(t)
	groupB := createTestGroup(t)
	groupC := createTestGroup(t) // deliberately has none

	createTestGroupPermission(t, groupA.Id, permissionA.Id)
	createTestGroupPermission(t, groupB.Id, permissionB.Id)

	groups := []models.Group{*groupA, *groupB, *groupC}

	if err := database.GroupsLoadPermissions(nil, groups); err != nil {
		t.Fatalf("GroupsLoadPermissions failed: %v", err)
	}

	if len(groups[0].Permissions) != 1 || groups[0].Permissions[0].Id != permissionA.Id {
		t.Errorf("Expected group A to hold only permission %d, got %+v", permissionA.Id, groups[0].Permissions)
	}
	if len(groups[1].Permissions) != 1 || groups[1].Permissions[0].Id != permissionB.Id {
		t.Errorf("Expected group B to hold only permission %d, got %+v", permissionB.Id, groups[1].Permissions)
	}
	if len(groups[2].Permissions) != 0 {
		t.Errorf("Expected group C to hold no permissions, got %d", len(groups[2].Permissions))
	}
}

func TestGroupsLoadPermissions_NilAndEmptySlices(t *testing.T) {
	if err := database.GroupsLoadPermissions(nil, nil); err != nil {
		t.Errorf("GroupsLoadPermissions(nil) should be a no-op, got: %v", err)
	}
	if err := database.GroupsLoadPermissions(nil, []models.Group{}); err != nil {
		t.Errorf("GroupsLoadPermissions(empty) should be a no-op, got: %v", err)
	}
}

func TestGroupsLoadAttributes(t *testing.T) {
	groupA := createTestGroup(t)
	groupB := createTestGroup(t)
	attributeA := createTestGroupAttribute(t, groupA.Id)
	attributeB := createTestGroupAttribute(t, groupB.Id)

	groups := []models.Group{*groupA, *groupB}

	if err := database.GroupsLoadAttributes(nil, groups); err != nil {
		t.Fatalf("GroupsLoadAttributes failed: %v", err)
	}

	if len(groups[0].Attributes) != 1 || groups[0].Attributes[0].Id != attributeA.Id {
		t.Errorf("Expected group A attribute %d, got %+v", attributeA.Id, groups[0].Attributes)
	}
	if len(groups[1].Attributes) != 1 || groups[1].Attributes[0].Id != attributeB.Id {
		t.Errorf("Expected group B attribute %d, got %+v", attributeB.Id, groups[1].Attributes)
	}
}

func TestGroupsLoadAttributes_NilAndEmptySlices(t *testing.T) {
	if err := database.GroupsLoadAttributes(nil, nil); err != nil {
		t.Errorf("GroupsLoadAttributes(nil) should be a no-op, got: %v", err)
	}
	if err := database.GroupsLoadAttributes(nil, []models.Group{}); err != nil {
		t.Errorf("GroupsLoadAttributes(empty) should be a no-op, got: %v", err)
	}
}

func TestGetGroupsByIds(t *testing.T) {
	groupA := createTestGroup(t)
	groupB := createTestGroup(t)
	groupC := createTestGroup(t)

	// Deliberately ask for only two of the three.
	groups, err := database.GetGroupsByIds(nil, []int64{groupA.Id, groupC.Id})
	if err != nil {
		t.Fatalf("GetGroupsByIds failed: %v", err)
	}

	if len(groups) != 2 {
		t.Fatalf("Expected 2 groups, got %d", len(groups))
	}

	found := map[int64]string{}
	for _, g := range groups {
		found[g.Id] = g.GroupIdentifier
	}
	if found[groupA.Id] != groupA.GroupIdentifier {
		t.Errorf("Expected group A identifier %s, got %s", groupA.GroupIdentifier, found[groupA.Id])
	}
	if found[groupC.Id] != groupC.GroupIdentifier {
		t.Errorf("Expected group C identifier %s, got %s", groupC.GroupIdentifier, found[groupC.Id])
	}
	if _, present := found[groupB.Id]; present {
		t.Error("Group B was not requested and must not be returned")
	}
}

func TestGetGroupsByIds_EmptyInput(t *testing.T) {
	groups, err := database.GetGroupsByIds(nil, []int64{})
	if err != nil {
		t.Fatalf("GetGroupsByIds(empty) failed: %v", err)
	}
	if groups != nil {
		t.Errorf("Expected nil for an empty id list, got %+v", groups)
	}

	groups, err = database.GetGroupsByIds(nil, nil)
	if err != nil {
		t.Fatalf("GetGroupsByIds(nil) failed: %v", err)
	}
	if groups != nil {
		t.Errorf("Expected nil for a nil id list, got %+v", groups)
	}
}

func TestGetGroupsByIds_UnknownIdIsSkipped(t *testing.T) {
	group := createTestGroup(t)

	groups, err := database.GetGroupsByIds(nil, []int64{group.Id, 999999999})
	if err != nil {
		t.Fatalf("GetGroupsByIds failed: %v", err)
	}

	if len(groups) != 1 || groups[0].Id != group.Id {
		t.Errorf("Expected only the existing group %d, got %+v", group.Id, groups)
	}
}

// =============================================================================
// Group membership
// =============================================================================

func TestCountGroupMembers(t *testing.T) {
	group := createTestGroup(t)

	count, err := database.CountGroupMembers(nil, group.Id)
	if err != nil {
		t.Fatalf("CountGroupMembers failed: %v", err)
	}
	if count != 0 {
		t.Errorf("Expected 0 members in a new group, got %d", count)
	}

	userA := createTestUser(t)
	userB := createTestUser(t)
	createTestUserGroupWithUserAndGroup(t, userA.Id, group.Id)
	createTestUserGroupWithUserAndGroup(t, userB.Id, group.Id)

	count, err = database.CountGroupMembers(nil, group.Id)
	if err != nil {
		t.Fatalf("CountGroupMembers failed: %v", err)
	}
	if count != 2 {
		t.Errorf("Expected 2 members, got %d", count)
	}
}

// Members are ordered by given name, so the page boundaries are deterministic.
func TestGetGroupMembersPaginated(t *testing.T) {
	group := createTestGroup(t)
	suffix := gofakeit.LetterN(6)

	userA := createUserWithGivenName(t, "Aaa"+suffix)
	userB := createUserWithGivenName(t, "Bbb"+suffix)
	userC := createUserWithGivenName(t, "Ccc"+suffix)
	for _, u := range []*models.User{userA, userB, userC} {
		createTestUserGroupWithUserAndGroup(t, u.Id, group.Id)
	}

	t.Run("first page", func(t *testing.T) {
		users, total, err := database.GetGroupMembersPaginated(nil, group.Id, 1, 2)
		if err != nil {
			t.Fatalf("GetGroupMembersPaginated failed: %v", err)
		}
		if total != 3 {
			t.Errorf("Expected total 3, got %d", total)
		}
		if len(users) != 2 {
			t.Fatalf("Expected 2 users on the first page, got %d", len(users))
		}
		if users[0].Id != userA.Id || users[1].Id != userB.Id {
			t.Errorf("Expected users ordered by given name (A, B), got %s, %s",
				users[0].GivenName, users[1].GivenName)
		}
	})

	t.Run("second page", func(t *testing.T) {
		users, total, err := database.GetGroupMembersPaginated(nil, group.Id, 2, 2)
		if err != nil {
			t.Fatalf("GetGroupMembersPaginated failed: %v", err)
		}
		if total != 3 {
			t.Errorf("Expected total 3, got %d", total)
		}
		if len(users) != 1 {
			t.Fatalf("Expected 1 user on the second page, got %d", len(users))
		}
		if users[0].Id != userC.Id {
			t.Errorf("Expected user C, got %s", users[0].GivenName)
		}
	})

	t.Run("page past the end", func(t *testing.T) {
		users, total, err := database.GetGroupMembersPaginated(nil, group.Id, 99, 2)
		if err != nil {
			t.Fatalf("GetGroupMembersPaginated failed: %v", err)
		}
		if total != 3 {
			t.Errorf("Expected total 3, got %d", total)
		}
		if len(users) != 0 {
			t.Errorf("Expected no users past the end, got %d", len(users))
		}
	})

	// page < 1 and pageSize < 1 are clamped to 1 and 10 respectively.
	t.Run("non-positive page and size are clamped", func(t *testing.T) {
		users, total, err := database.GetGroupMembersPaginated(nil, group.Id, 0, 0)
		if err != nil {
			t.Fatalf("GetGroupMembersPaginated failed: %v", err)
		}
		if total != 3 {
			t.Errorf("Expected total 3, got %d", total)
		}
		if len(users) != 3 {
			t.Errorf("Expected all 3 users with the clamped default size, got %d", len(users))
		}
	})
}

func TestGetGroupMembersPaginated_EmptyGroup(t *testing.T) {
	group := createTestGroup(t)

	users, total, err := database.GetGroupMembersPaginated(nil, group.Id, 1, 10)
	if err != nil {
		t.Fatalf("GetGroupMembersPaginated failed: %v", err)
	}
	if total != 0 {
		t.Errorf("Expected total 0, got %d", total)
	}
	if len(users) != 0 {
		t.Errorf("Expected no users, got %d", len(users))
	}
}

func TestGetGroupMembersPaginated_InvalidGroupId(t *testing.T) {
	for _, groupId := range []int64{0, -1} {
		if _, _, err := database.GetGroupMembersPaginated(nil, groupId, 1, 10); err == nil {
			t.Errorf("Expected an error for group id %d", groupId)
		}
	}
}

// =============================================================================
// GetLastUserWithOTPState
//
// Used by the OTP backfill to walk users by OTP state. It returns the
// highest-numbered ENABLED user matching the requested state, so a freshly
// created user is the expected answer.
// =============================================================================

func TestGetLastUserWithOTPState(t *testing.T) {
	t.Run("otp enabled", func(t *testing.T) {
		user := createUserWithGivenName(t, "Otp"+gofakeit.LetterN(6))
		user.OTPEnabled = true
		if err := database.UpdateUser(nil, user); err != nil {
			t.Fatalf("Failed to update user: %v", err)
		}

		found, err := database.GetLastUserWithOTPState(nil, true)
		if err != nil {
			t.Fatalf("GetLastUserWithOTPState failed: %v", err)
		}
		if found == nil {
			t.Fatal("Expected a user, got nil")
		}
		if found.Id != user.Id {
			t.Errorf("Expected the most recently created matching user %d, got %d", user.Id, found.Id)
		}
		if !found.OTPEnabled {
			t.Error("Expected the returned user to have OTP enabled")
		}
	})

	t.Run("otp disabled", func(t *testing.T) {
		user := createUserWithGivenName(t, "NoOtp"+gofakeit.LetterN(6))
		user.OTPEnabled = false
		if err := database.UpdateUser(nil, user); err != nil {
			t.Fatalf("Failed to update user: %v", err)
		}

		found, err := database.GetLastUserWithOTPState(nil, false)
		if err != nil {
			t.Fatalf("GetLastUserWithOTPState failed: %v", err)
		}
		if found == nil {
			t.Fatal("Expected a user, got nil")
		}
		if found.Id != user.Id {
			t.Errorf("Expected the most recently created matching user %d, got %d", user.Id, found.Id)
		}
		if found.OTPEnabled {
			t.Error("Expected the returned user to have OTP disabled")
		}
	})

	// A disabled user is skipped even when its OTP state matches.
	t.Run("disabled users are ignored", func(t *testing.T) {
		enabledUser := createUserWithGivenName(t, "Enabled"+gofakeit.LetterN(6))
		enabledUser.OTPEnabled = true
		if err := database.UpdateUser(nil, enabledUser); err != nil {
			t.Fatalf("Failed to update user: %v", err)
		}

		disabledUser := createUserWithGivenName(t, "Disabled"+gofakeit.LetterN(6))
		disabledUser.OTPEnabled = true
		disabledUser.Enabled = false
		if err := database.UpdateUser(nil, disabledUser); err != nil {
			t.Fatalf("Failed to update user: %v", err)
		}

		found, err := database.GetLastUserWithOTPState(nil, true)
		if err != nil {
			t.Fatalf("GetLastUserWithOTPState failed: %v", err)
		}
		if found == nil {
			t.Fatal("Expected a user, got nil")
		}
		if found.Id == disabledUser.Id {
			t.Error("A disabled user must not be returned")
		}
		if found.Id != enabledUser.Id {
			t.Errorf("Expected the enabled user %d, got %d", enabledUser.Id, found.Id)
		}
	})
}

// =============================================================================
// User session client loaders
// =============================================================================

func TestUserSessionClientsLoadClients(t *testing.T) {
	user := createTestUser(t)
	userSession := createTestUserSession(t, user.Id)
	clientA := createTestClient(t)
	clientB := createTestClient(t)

	sessionClientA := createTestUserSessionClientWithIds(t, userSession.Id, clientA.Id)
	sessionClientB := createTestUserSessionClientWithIds(t, userSession.Id, clientB.Id)

	sessionClients := []models.UserSessionClient{*sessionClientA, *sessionClientB}

	if err := database.UserSessionClientsLoadClients(nil, sessionClients); err != nil {
		t.Fatalf("UserSessionClientsLoadClients failed: %v", err)
	}

	if sessionClients[0].Client.Id != clientA.Id {
		t.Errorf("Expected client %d, got %d", clientA.Id, sessionClients[0].Client.Id)
	}
	if sessionClients[0].Client.ClientIdentifier != clientA.ClientIdentifier {
		t.Errorf("Expected client identifier %s, got %s",
			clientA.ClientIdentifier, sessionClients[0].Client.ClientIdentifier)
	}
	if sessionClients[1].Client.Id != clientB.Id {
		t.Errorf("Expected client %d, got %d", clientB.Id, sessionClients[1].Client.Id)
	}
}

func TestUserSessionClientsLoadClients_NilAndEmptySlices(t *testing.T) {
	if err := database.UserSessionClientsLoadClients(nil, nil); err != nil {
		t.Errorf("UserSessionClientsLoadClients(nil) should be a no-op, got: %v", err)
	}
	if err := database.UserSessionClientsLoadClients(nil, []models.UserSessionClient{}); err != nil {
		t.Errorf("UserSessionClientsLoadClients(empty) should be a no-op, got: %v", err)
	}
}

func TestGetUserSessionsClientByIds(t *testing.T) {
	user := createTestUser(t)
	userSession := createTestUserSession(t, user.Id)
	clientA := createTestClient(t)
	clientB := createTestClient(t)

	sessionClientA := createTestUserSessionClientWithIds(t, userSession.Id, clientA.Id)
	sessionClientB := createTestUserSessionClientWithIds(t, userSession.Id, clientB.Id)

	result, err := database.GetUserSessionsClientByIds(nil, []int64{sessionClientA.Id, sessionClientB.Id})
	if err != nil {
		t.Fatalf("GetUserSessionsClientByIds failed: %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("Expected 2 user session clients, got %d", len(result))
	}

	found := map[int64]int64{}
	for _, sc := range result {
		found[sc.Id] = sc.ClientId
	}
	if found[sessionClientA.Id] != clientA.Id {
		t.Errorf("Expected session client %d to point at client %d", sessionClientA.Id, clientA.Id)
	}
	if found[sessionClientB.Id] != clientB.Id {
		t.Errorf("Expected session client %d to point at client %d", sessionClientB.Id, clientB.Id)
	}
}

func TestGetUserSessionsClientByIds_EmptyInput(t *testing.T) {
	result, err := database.GetUserSessionsClientByIds(nil, []int64{})
	if err != nil {
		t.Fatalf("GetUserSessionsClientByIds(empty) failed: %v", err)
	}
	if result != nil {
		t.Errorf("Expected nil for an empty id list, got %+v", result)
	}

	result, err = database.GetUserSessionsClientByIds(nil, nil)
	if err != nil {
		t.Fatalf("GetUserSessionsClientByIds(nil) failed: %v", err)
	}
	if result != nil {
		t.Errorf("Expected nil for a nil id list, got %+v", result)
	}
}

// GetUserSessionClientsByUserSessionIds is the batch read behind
// UserSessionsLoadClients. Note it selects by user_session_id, not by primary
// key, which is what distinguishes it from GetUserSessionsClientByIds above: it
// returns every client row of every requested session, flattened into one slice
// that the caller re-groups by UserSessionId. So the contract that matters is
// that rows from different sessions are all present and stay attributable.
func TestGetUserSessionClientsByUserSessionIds(t *testing.T) {
	user := createTestUser(t)
	sessionA := createTestUserSession(t, user.Id)
	sessionB := createTestUserSession(t, user.Id)
	sessionC := createTestUserSession(t, user.Id)
	clientA := createTestClient(t)
	clientB := createTestClient(t)

	// Two clients on session A, one on B, and one on the unrequested session C.
	scA1 := createTestUserSessionClientWithIds(t, sessionA.Id, clientA.Id)
	scA2 := createTestUserSessionClientWithIds(t, sessionA.Id, clientB.Id)
	scB1 := createTestUserSessionClientWithIds(t, sessionB.Id, clientA.Id)
	scC1 := createTestUserSessionClientWithIds(t, sessionC.Id, clientA.Id)

	result, err := database.GetUserSessionClientsByUserSessionIds(nil, []int64{sessionA.Id, sessionB.Id})
	if err != nil {
		t.Fatalf("GetUserSessionClientsByUserSessionIds failed: %v", err)
	}

	if len(result) != 3 {
		t.Fatalf("Expected 3 user session clients across the two sessions, got %d", len(result))
	}

	// Re-group exactly as UserSessionsLoadClients does.
	bySession := map[int64][]int64{}
	ids := map[int64]bool{}
	for _, sc := range result {
		bySession[sc.UserSessionId] = append(bySession[sc.UserSessionId], sc.Id)
		ids[sc.Id] = true
	}

	if len(bySession[sessionA.Id]) != 2 {
		t.Errorf("Expected 2 clients on session %d, got %d", sessionA.Id, len(bySession[sessionA.Id]))
	}
	if len(bySession[sessionB.Id]) != 1 {
		t.Errorf("Expected 1 client on session %d, got %d", sessionB.Id, len(bySession[sessionB.Id]))
	}
	for _, want := range []int64{scA1.Id, scA2.Id, scB1.Id} {
		if !ids[want] {
			t.Errorf("Expected user session client %d in the result", want)
		}
	}
	if ids[scC1.Id] {
		t.Errorf("Session %d was not requested; its client %d must not be returned", sessionC.Id, scC1.Id)
	}
	if _, present := bySession[sessionC.Id]; present {
		t.Errorf("Session %d was not requested and must not appear in the result", sessionC.Id)
	}
}

// A session with no clients contributes no rows rather than an error or a
// placeholder, which is what lets UserSessionsLoadClients leave Clients nil.
func TestGetUserSessionClientsByUserSessionIds_SessionWithNoClients(t *testing.T) {
	user := createTestUser(t)
	withClient := createTestUserSession(t, user.Id)
	withoutClient := createTestUserSession(t, user.Id)
	client := createTestClient(t)
	sc := createTestUserSessionClientWithIds(t, withClient.Id, client.Id)

	result, err := database.GetUserSessionClientsByUserSessionIds(nil, []int64{withClient.Id, withoutClient.Id})
	if err != nil {
		t.Fatalf("GetUserSessionClientsByUserSessionIds failed: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("Expected 1 user session client, got %d", len(result))
	}
	if result[0].Id != sc.Id {
		t.Errorf("Expected user session client %d, got %d", sc.Id, result[0].Id)
	}
	if result[0].UserSessionId != withClient.Id {
		t.Errorf("Expected the row to belong to session %d, got %d", withClient.Id, result[0].UserSessionId)
	}
}

func TestGetUserSessionClientsByUserSessionIds_UnknownIdIsSkipped(t *testing.T) {
	user := createTestUser(t)
	userSession := createTestUserSession(t, user.Id)
	client := createTestClient(t)
	sc := createTestUserSessionClientWithIds(t, userSession.Id, client.Id)

	result, err := database.GetUserSessionClientsByUserSessionIds(nil, []int64{userSession.Id, 999999999})
	if err != nil {
		t.Fatalf("GetUserSessionClientsByUserSessionIds failed: %v", err)
	}

	if len(result) != 1 || result[0].Id != sc.Id {
		t.Errorf("Expected only the existing session's client %d, got %+v", sc.Id, result)
	}
}

func TestGetUserSessionClientsByUserSessionIds_EmptyInput(t *testing.T) {
	result, err := database.GetUserSessionClientsByUserSessionIds(nil, []int64{})
	if err != nil {
		t.Fatalf("GetUserSessionClientsByUserSessionIds(empty) failed: %v", err)
	}
	if result != nil {
		t.Errorf("Expected nil for an empty id list, got %+v", result)
	}

	result, err = database.GetUserSessionClientsByUserSessionIds(nil, nil)
	if err != nil {
		t.Fatalf("GetUserSessionClientsByUserSessionIds(nil) failed: %v", err)
	}
	if result != nil {
		t.Errorf("Expected nil for a nil id list, got %+v", result)
	}
}

// =============================================================================
// DeleteAllUserConsent
//
// NOTE: this truncates the whole user_consents table, which is why it is
// asserted here on its own. Every data test builds its own fixtures inside the
// test function, so a global delete between tests is safe.
// =============================================================================

func TestDeleteAllUserConsent(t *testing.T) {
	userA := createTestUser(t)
	userB := createTestUser(t)
	consentA := createTestUserConsentForUser(t, userA.Id)
	consentB := createTestUserConsentForUser(t, userB.Id)

	// Both exist to begin with.
	for _, id := range []int64{consentA.Id, consentB.Id} {
		consent, err := database.GetUserConsentById(nil, id)
		if err != nil {
			t.Fatalf("Failed to read consent %d: %v", id, err)
		}
		if consent == nil {
			t.Fatalf("Expected consent %d to exist before the delete", id)
		}
	}

	if err := database.DeleteAllUserConsent(nil); err != nil {
		t.Fatalf("DeleteAllUserConsent failed: %v", err)
	}

	for _, id := range []int64{consentA.Id, consentB.Id} {
		consent, err := database.GetUserConsentById(nil, id)
		if err != nil {
			t.Fatalf("Failed to read consent %d: %v", id, err)
		}
		if consent != nil {
			t.Errorf("Expected consent %d to be deleted", id)
		}
	}
}

// Deleting from an already empty table must succeed rather than error.
func TestDeleteAllUserConsent_Idempotent(t *testing.T) {
	if err := database.DeleteAllUserConsent(nil); err != nil {
		t.Fatalf("First DeleteAllUserConsent failed: %v", err)
	}
	if err := database.DeleteAllUserConsent(nil); err != nil {
		t.Fatalf("Second DeleteAllUserConsent failed: %v", err)
	}
}

// =============================================================================
// IsEmpty
// =============================================================================

// IsEmpty reports whether the database still needs seeding, which it decides
// purely by the presence of the settings row with id 1. The data-test database is
// migrated but not seeded, and settings_test.go may add rows later in the run, so
// asserting a fixed answer here would be order-dependent. Instead this pins the
// contract: IsEmpty is true exactly when that row is absent.
func TestIsEmpty(t *testing.T) {
	empty, err := database.IsEmpty()
	if err != nil {
		t.Fatalf("IsEmpty failed: %v", err)
	}

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatalf("Failed to read settings: %v", err)
	}

	if empty != (settings == nil) {
		t.Errorf("IsEmpty returned %v but the settings row with id 1 %s",
			empty, map[bool]string{true: "is absent", false: "exists"}[settings == nil])
	}
}
