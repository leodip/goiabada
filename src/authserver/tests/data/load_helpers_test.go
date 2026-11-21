package datatests

import (
	"context"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
)

// The association loaders in commondb had no direct data-layer tests: they are
// exercised only indirectly, through the auth flows in the integration suite.
// They are the queries behind permission checks (UserHasScopePermission loads a
// user's permissions, groups and the groups' permissions before deciding), so a
// silent regression in one of them is an authorization bug.

// createUserWithGivenName creates an enabled user with a controlled given name,
// which GetGroupMembersPaginated orders by.
func createUserWithGivenName(t *testing.T, givenName string) *record.User {
	t.Helper()
	user := &record.User{
		Enabled:   true,
		Subject:   fake.UUID(),
		Username:  "u" + fake.LetterN(12),
		GivenName: givenName,
		Email:     fake.LetterN(12) + "@example.com",
	}
	if err := database.CreateUser(context.Background(), nil, user); err != nil {
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
	createTestUserPermissionWithUserAndPermission(t, user.ID, permission.ID)

	if err := database.UserLoadPermissions(context.Background(), nil, user); err != nil {
		t.Fatalf("UserLoadPermissions failed: %v", err)
	}

	if len(user.Permissions) != 1 {
		t.Fatalf("Expected 1 permission, got %d", len(user.Permissions))
	}
	if user.Permissions[0].ID != permission.ID {
		t.Errorf("Expected permission id %d, got %d", permission.ID, user.Permissions[0].ID)
	}
	if user.Permissions[0].PermissionIdentifier != permission.PermissionIdentifier {
		t.Errorf("Expected permission identifier %s, got %s",
			permission.PermissionIdentifier, user.Permissions[0].PermissionIdentifier)
	}
}

func TestUserLoadPermissions_NoPermissions(t *testing.T) {
	user := createTestUser(t)

	if err := database.UserLoadPermissions(context.Background(), nil, user); err != nil {
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

	createTestUserPermissionWithUserAndPermission(t, userA.ID, permissionA.ID)
	createTestUserPermissionWithUserAndPermission(t, userB.ID, permissionB.ID)

	users := []record.User{*userA, *userB, *userC}

	if err := database.UsersLoadPermissions(context.Background(), nil, users); err != nil {
		t.Fatalf("UsersLoadPermissions failed: %v", err)
	}

	if len(users[0].Permissions) != 1 || users[0].Permissions[0].ID != permissionA.ID {
		t.Errorf("Expected user A to hold only permission %d, got %+v", permissionA.ID, users[0].Permissions)
	}
	if len(users[1].Permissions) != 1 || users[1].Permissions[0].ID != permissionB.ID {
		t.Errorf("Expected user B to hold only permission %d, got %+v", permissionB.ID, users[1].Permissions)
	}
	if len(users[2].Permissions) != 0 {
		t.Errorf("Expected user C to hold no permissions, got %d", len(users[2].Permissions))
	}
}

func TestUsersLoadPermissions_NilAndEmptySlices(t *testing.T) {
	if err := database.UsersLoadPermissions(context.Background(), nil, nil); err != nil {
		t.Errorf("UsersLoadPermissions(nil) should be a no-op, got: %v", err)
	}
	if err := database.UsersLoadPermissions(context.Background(), nil, []record.User{}); err != nil {
		t.Errorf("UsersLoadPermissions(empty) should be a no-op, got: %v", err)
	}
}

func TestUserLoadGroups(t *testing.T) {
	user := createTestUser(t)
	groupA := createTestGroup(t)
	groupB := createTestGroup(t)
	createTestUserGroupWithUserAndGroup(t, user.ID, groupA.ID)
	createTestUserGroupWithUserAndGroup(t, user.ID, groupB.ID)

	if err := database.UserLoadGroups(context.Background(), nil, user); err != nil {
		t.Fatalf("UserLoadGroups failed: %v", err)
	}

	if len(user.Groups) != 2 {
		t.Fatalf("Expected 2 groups, got %d", len(user.Groups))
	}

	found := map[int64]bool{}
	for _, g := range user.Groups {
		found[g.ID] = true
		if g.GroupIdentifier == "" {
			t.Error("Expected the group identifier to be populated, not just the id")
		}
	}
	if !found[groupA.ID] || !found[groupB.ID] {
		t.Errorf("Expected groups %d and %d, got %+v", groupA.ID, groupB.ID, found)
	}
}

func TestUserLoadGroups_NoGroups(t *testing.T) {
	user := createTestUser(t)

	if err := database.UserLoadGroups(context.Background(), nil, user); err != nil {
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
	createTestUserGroupWithUserAndGroup(t, userA.ID, groupA.ID)
	createTestUserGroupWithUserAndGroup(t, userB.ID, groupB.ID)

	users := []record.User{*userA, *userB}

	if err := database.UsersLoadGroups(context.Background(), nil, users); err != nil {
		t.Fatalf("UsersLoadGroups failed: %v", err)
	}

	if len(users[0].Groups) != 1 || users[0].Groups[0].ID != groupA.ID {
		t.Errorf("Expected user A in group %d, got %+v", groupA.ID, users[0].Groups)
	}
	if len(users[1].Groups) != 1 || users[1].Groups[0].ID != groupB.ID {
		t.Errorf("Expected user B in group %d, got %+v", groupB.ID, users[1].Groups)
	}
}

func TestUsersLoadGroups_NilAndEmptySlices(t *testing.T) {
	if err := database.UsersLoadGroups(context.Background(), nil, nil); err != nil {
		t.Errorf("UsersLoadGroups(nil) should be a no-op, got: %v", err)
	}
	if err := database.UsersLoadGroups(context.Background(), nil, []record.User{}); err != nil {
		t.Errorf("UsersLoadGroups(empty) should be a no-op, got: %v", err)
	}
}

func TestUserLoadAttributes(t *testing.T) {
	user := createTestUser(t)
	attributeA := createTestUserAttribute(t, user.ID)
	attributeB := createTestUserAttribute(t, user.ID)

	if err := database.UserLoadAttributes(context.Background(), nil, user); err != nil {
		t.Fatalf("UserLoadAttributes failed: %v", err)
	}

	if len(user.Attributes) != 2 {
		t.Fatalf("Expected 2 attributes, got %d", len(user.Attributes))
	}

	found := map[int64]bool{}
	for _, a := range user.Attributes {
		found[a.ID] = true
		if a.Key == "" {
			t.Error("Expected the attribute key to be populated")
		}
	}
	if !found[attributeA.ID] || !found[attributeB.ID] {
		t.Errorf("Expected attributes %d and %d, got %+v", attributeA.ID, attributeB.ID, found)
	}
}

func TestUserLoadAttributes_NoAttributes(t *testing.T) {
	user := createTestUser(t)

	if err := database.UserLoadAttributes(context.Background(), nil, user); err != nil {
		t.Fatalf("UserLoadAttributes failed: %v", err)
	}

	if len(user.Attributes) != 0 {
		t.Errorf("Expected no attributes, got %d", len(user.Attributes))
	}
}

// =============================================================================
// GetUsersByIDs
//
// The batch read behind UserSessionsLoadUsers: it resolves a whole page of
// sessions to their users in one query. Unlike every other *ByIds reader it
// returns a map keyed by user id rather than a slice, so it silently tolerates
// duplicate input ids and cannot be indexed positionally.
// =============================================================================

func TestGetUsersByIDs(t *testing.T) {
	userA := createTestUser(t)
	userB := createTestUser(t)
	userC := createTestUser(t)

	// Deliberately ask for only two of the three.
	users, err := database.GetUsersByIDs(context.Background(), nil, []int64{userA.ID, userC.ID})
	if err != nil {
		t.Fatalf("GetUsersByIDs failed: %v", err)
	}

	if len(users) != 2 {
		t.Fatalf("Expected 2 users, got %d", len(users))
	}

	// Keyed by user id, and the row is fully scanned (not just the id).
	if users[userA.ID].Subject != userA.Subject {
		t.Errorf("Expected user A subject %s, got %s", userA.Subject, users[userA.ID].Subject)
	}
	if users[userA.ID].Email != userA.Email {
		t.Errorf("Expected user A email %s, got %s", userA.Email, users[userA.ID].Email)
	}
	if users[userC.ID].Subject != userC.Subject {
		t.Errorf("Expected user C subject %s, got %s", userC.Subject, users[userC.ID].Subject)
	}
	if _, present := users[userB.ID]; present {
		t.Error("User B was not requested and must not be returned")
	}
}

func TestGetUsersByIDs_UnknownIDIsSkipped(t *testing.T) {
	user := createTestUser(t)

	users, err := database.GetUsersByIDs(context.Background(), nil, []int64{user.ID, 999999999})
	if err != nil {
		t.Fatalf("GetUsersByIDs failed: %v", err)
	}

	if len(users) != 1 {
		t.Fatalf("Expected only the existing user, got %d entries", len(users))
	}
	if _, present := users[user.ID]; !present {
		t.Errorf("Expected user %d in the result, got %+v", user.ID, users)
	}
}

// A repeated id must not produce a duplicate entry. This holds trivially because
// the result is a map, but UserSessionsLoadUsers feeds it one id per session and
// several sessions of the same user is the normal case, so pin it.
func TestGetUsersByIDs_DuplicateIDsCollapse(t *testing.T) {
	user := createTestUser(t)

	users, err := database.GetUsersByIDs(context.Background(), nil, []int64{user.ID, user.ID})
	if err != nil {
		t.Fatalf("GetUsersByIDs failed: %v", err)
	}

	if len(users) != 1 {
		t.Errorf("Expected a repeated id to yield one entry, got %d", len(users))
	}
	if users[user.ID].ID != user.ID {
		t.Errorf("Expected user %d in the result, got %+v", user.ID, users)
	}
}

// An empty or nil id list must not reach the database. GetUsersByIDs returns
// early like every other *ByIds reader (GetGroupsByIDs, GetClientsByIDs,
// GetPermissionsByIDs, GetResourcesByIDs, GetUserSessionsClientByIDs and
// GetUserSessionClientsByUserSessionIDs).
//
// This case is reachable: the load helpers guard userSessions == nil but not
// len(userSessions) == 0, so a caller-built empty page arrives here as an empty
// slice. Before the guard was added it still behaved correctly, because the
// query builder the data layer used then emitted "0 = 1" rather than an illegal
// "IN ()" when given no values, as commondb's inList does now, but it cost a
// pointless round-trip and depended on that detail.
//
// Asserted as len()==0 rather than == nil so the test states the contract
// callers rely on (no users came back) and not the representation.
func TestGetUsersByIDs_EmptyInput(t *testing.T) {
	users, err := database.GetUsersByIDs(context.Background(), nil, []int64{})
	if err != nil {
		t.Fatalf("GetUsersByIDs(empty) failed: %v", err)
	}
	if len(users) != 0 {
		t.Errorf("Expected no users for an empty id list, got %+v", users)
	}

	users, err = database.GetUsersByIDs(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("GetUsersByIDs(nil) failed: %v", err)
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
	createTestGroupPermission(t, group.ID, permission.ID)

	if err := database.GroupLoadPermissions(context.Background(), nil, group); err != nil {
		t.Fatalf("GroupLoadPermissions failed: %v", err)
	}

	if len(group.Permissions) != 1 {
		t.Fatalf("Expected 1 permission, got %d", len(group.Permissions))
	}
	if group.Permissions[0].ID != permission.ID {
		t.Errorf("Expected permission id %d, got %d", permission.ID, group.Permissions[0].ID)
	}
}

func TestGroupLoadPermissions_NoPermissions(t *testing.T) {
	group := createTestGroup(t)

	if err := database.GroupLoadPermissions(context.Background(), nil, group); err != nil {
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

	createTestGroupPermission(t, groupA.ID, permissionA.ID)
	createTestGroupPermission(t, groupB.ID, permissionB.ID)

	groups := []record.Group{*groupA, *groupB, *groupC}

	if err := database.GroupsLoadPermissions(context.Background(), nil, groups); err != nil {
		t.Fatalf("GroupsLoadPermissions failed: %v", err)
	}

	if len(groups[0].Permissions) != 1 || groups[0].Permissions[0].ID != permissionA.ID {
		t.Errorf("Expected group A to hold only permission %d, got %+v", permissionA.ID, groups[0].Permissions)
	}
	if len(groups[1].Permissions) != 1 || groups[1].Permissions[0].ID != permissionB.ID {
		t.Errorf("Expected group B to hold only permission %d, got %+v", permissionB.ID, groups[1].Permissions)
	}
	if len(groups[2].Permissions) != 0 {
		t.Errorf("Expected group C to hold no permissions, got %d", len(groups[2].Permissions))
	}
}

func TestGroupsLoadPermissions_NilAndEmptySlices(t *testing.T) {
	if err := database.GroupsLoadPermissions(context.Background(), nil, nil); err != nil {
		t.Errorf("GroupsLoadPermissions(nil) should be a no-op, got: %v", err)
	}
	if err := database.GroupsLoadPermissions(context.Background(), nil, []record.Group{}); err != nil {
		t.Errorf("GroupsLoadPermissions(empty) should be a no-op, got: %v", err)
	}
}

func TestGroupsLoadAttributes(t *testing.T) {
	groupA := createTestGroup(t)
	groupB := createTestGroup(t)
	attributeA := createTestGroupAttribute(t, groupA.ID)
	attributeB := createTestGroupAttribute(t, groupB.ID)

	groups := []record.Group{*groupA, *groupB}

	if err := database.GroupsLoadAttributes(context.Background(), nil, groups); err != nil {
		t.Fatalf("GroupsLoadAttributes failed: %v", err)
	}

	if len(groups[0].Attributes) != 1 || groups[0].Attributes[0].ID != attributeA.ID {
		t.Errorf("Expected group A attribute %d, got %+v", attributeA.ID, groups[0].Attributes)
	}
	if len(groups[1].Attributes) != 1 || groups[1].Attributes[0].ID != attributeB.ID {
		t.Errorf("Expected group B attribute %d, got %+v", attributeB.ID, groups[1].Attributes)
	}
}

func TestGroupsLoadAttributes_NilAndEmptySlices(t *testing.T) {
	if err := database.GroupsLoadAttributes(context.Background(), nil, nil); err != nil {
		t.Errorf("GroupsLoadAttributes(nil) should be a no-op, got: %v", err)
	}
	if err := database.GroupsLoadAttributes(context.Background(), nil, []record.Group{}); err != nil {
		t.Errorf("GroupsLoadAttributes(empty) should be a no-op, got: %v", err)
	}
}

func TestGetGroupsByIDs(t *testing.T) {
	groupA := createTestGroup(t)
	groupB := createTestGroup(t)
	groupC := createTestGroup(t)

	// Deliberately ask for only two of the three.
	groups, err := database.GetGroupsByIDs(context.Background(), nil, []int64{groupA.ID, groupC.ID})
	if err != nil {
		t.Fatalf("GetGroupsByIDs failed: %v", err)
	}

	if len(groups) != 2 {
		t.Fatalf("Expected 2 groups, got %d", len(groups))
	}

	found := map[int64]string{}
	for _, g := range groups {
		found[g.ID] = g.GroupIdentifier
	}
	if found[groupA.ID] != groupA.GroupIdentifier {
		t.Errorf("Expected group A identifier %s, got %s", groupA.GroupIdentifier, found[groupA.ID])
	}
	if found[groupC.ID] != groupC.GroupIdentifier {
		t.Errorf("Expected group C identifier %s, got %s", groupC.GroupIdentifier, found[groupC.ID])
	}
	if _, present := found[groupB.ID]; present {
		t.Error("Group B was not requested and must not be returned")
	}
}

func TestGetGroupsByIDs_EmptyInput(t *testing.T) {
	groups, err := database.GetGroupsByIDs(context.Background(), nil, []int64{})
	if err != nil {
		t.Fatalf("GetGroupsByIDs(empty) failed: %v", err)
	}
	if groups != nil {
		t.Errorf("Expected nil for an empty id list, got %+v", groups)
	}

	groups, err = database.GetGroupsByIDs(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("GetGroupsByIDs(nil) failed: %v", err)
	}
	if groups != nil {
		t.Errorf("Expected nil for a nil id list, got %+v", groups)
	}
}

func TestGetGroupsByIDs_UnknownIDIsSkipped(t *testing.T) {
	group := createTestGroup(t)

	groups, err := database.GetGroupsByIDs(context.Background(), nil, []int64{group.ID, 999999999})
	if err != nil {
		t.Fatalf("GetGroupsByIDs failed: %v", err)
	}

	if len(groups) != 1 || groups[0].ID != group.ID {
		t.Errorf("Expected only the existing group %d, got %+v", group.ID, groups)
	}
}

// =============================================================================
// Group membership
// =============================================================================

func TestCountGroupMembers(t *testing.T) {
	group := createTestGroup(t)

	count, err := database.CountGroupMembers(context.Background(), nil, group.ID)
	if err != nil {
		t.Fatalf("CountGroupMembers failed: %v", err)
	}
	if count != 0 {
		t.Errorf("Expected 0 members in a new group, got %d", count)
	}

	userA := createTestUser(t)
	userB := createTestUser(t)
	createTestUserGroupWithUserAndGroup(t, userA.ID, group.ID)
	createTestUserGroupWithUserAndGroup(t, userB.ID, group.ID)

	count, err = database.CountGroupMembers(context.Background(), nil, group.ID)
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
	suffix := fake.LetterN(6)

	userA := createUserWithGivenName(t, "Aaa"+suffix)
	userB := createUserWithGivenName(t, "Bbb"+suffix)
	userC := createUserWithGivenName(t, "Ccc"+suffix)
	for _, u := range []*record.User{userA, userB, userC} {
		createTestUserGroupWithUserAndGroup(t, u.ID, group.ID)
	}

	t.Run("first page", func(t *testing.T) {
		users, total, err := database.GetGroupMembersPaginated(context.Background(), nil, group.ID, 1, 2)
		if err != nil {
			t.Fatalf("GetGroupMembersPaginated failed: %v", err)
		}
		if total != 3 {
			t.Errorf("Expected total 3, got %d", total)
		}
		if len(users) != 2 {
			t.Fatalf("Expected 2 users on the first page, got %d", len(users))
		}
		if users[0].ID != userA.ID || users[1].ID != userB.ID {
			t.Errorf("Expected users ordered by given name (A, B), got %s, %s",
				users[0].GivenName, users[1].GivenName)
		}
	})

	t.Run("second page", func(t *testing.T) {
		users, total, err := database.GetGroupMembersPaginated(context.Background(), nil, group.ID, 2, 2)
		if err != nil {
			t.Fatalf("GetGroupMembersPaginated failed: %v", err)
		}
		if total != 3 {
			t.Errorf("Expected total 3, got %d", total)
		}
		if len(users) != 1 {
			t.Fatalf("Expected 1 user on the second page, got %d", len(users))
		}
		if users[0].ID != userC.ID {
			t.Errorf("Expected user C, got %s", users[0].GivenName)
		}
	})

	t.Run("page past the end", func(t *testing.T) {
		users, total, err := database.GetGroupMembersPaginated(context.Background(), nil, group.ID, 99, 2)
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
		users, total, err := database.GetGroupMembersPaginated(context.Background(), nil, group.ID, 0, 0)
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

	users, total, err := database.GetGroupMembersPaginated(context.Background(), nil, group.ID, 1, 10)
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

func TestGetGroupMembersPaginated_InvalidGroupID(t *testing.T) {
	for _, groupID := range []int64{0, -1} {
		if _, _, err := database.GetGroupMembersPaginated(context.Background(), nil, groupID, 1, 10); err == nil {
			t.Errorf("Expected an error for group id %d", groupID)
		}
	}
}

// =============================================================================
// User session client loaders
// =============================================================================

func TestUserSessionClientsLoadClients(t *testing.T) {
	user := createTestUser(t)
	userSession := createTestUserSession(t, user.ID)
	clientA := createTestClient(t)
	clientB := createTestClient(t)

	sessionClientA := createTestUserSessionClientWithIDs(t, userSession.ID, clientA.ID)
	sessionClientB := createTestUserSessionClientWithIDs(t, userSession.ID, clientB.ID)

	sessionClients := []record.UserSessionClient{*sessionClientA, *sessionClientB}

	if err := database.UserSessionClientsLoadClients(context.Background(), nil, sessionClients); err != nil {
		t.Fatalf("UserSessionClientsLoadClients failed: %v", err)
	}

	if sessionClients[0].Client.ID != clientA.ID {
		t.Errorf("Expected client %d, got %d", clientA.ID, sessionClients[0].Client.ID)
	}
	if sessionClients[0].Client.ClientIdentifier != clientA.ClientIdentifier {
		t.Errorf("Expected client identifier %s, got %s",
			clientA.ClientIdentifier, sessionClients[0].Client.ClientIdentifier)
	}
	if sessionClients[1].Client.ID != clientB.ID {
		t.Errorf("Expected client %d, got %d", clientB.ID, sessionClients[1].Client.ID)
	}
}

func TestUserSessionClientsLoadClients_NilAndEmptySlices(t *testing.T) {
	if err := database.UserSessionClientsLoadClients(context.Background(), nil, nil); err != nil {
		t.Errorf("UserSessionClientsLoadClients(nil) should be a no-op, got: %v", err)
	}
	if err := database.UserSessionClientsLoadClients(context.Background(), nil, []record.UserSessionClient{}); err != nil {
		t.Errorf("UserSessionClientsLoadClients(empty) should be a no-op, got: %v", err)
	}
}

func TestGetUserSessionsClientByIDs(t *testing.T) {
	user := createTestUser(t)
	userSession := createTestUserSession(t, user.ID)
	clientA := createTestClient(t)
	clientB := createTestClient(t)

	sessionClientA := createTestUserSessionClientWithIDs(t, userSession.ID, clientA.ID)
	sessionClientB := createTestUserSessionClientWithIDs(t, userSession.ID, clientB.ID)

	result, err := database.GetUserSessionsClientByIDs(context.Background(), nil, []int64{sessionClientA.ID, sessionClientB.ID})
	if err != nil {
		t.Fatalf("GetUserSessionsClientByIDs failed: %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("Expected 2 user session clients, got %d", len(result))
	}

	found := map[int64]int64{}
	for _, sc := range result {
		found[sc.ID] = sc.ClientID
	}
	if found[sessionClientA.ID] != clientA.ID {
		t.Errorf("Expected session client %d to point at client %d", sessionClientA.ID, clientA.ID)
	}
	if found[sessionClientB.ID] != clientB.ID {
		t.Errorf("Expected session client %d to point at client %d", sessionClientB.ID, clientB.ID)
	}
}

func TestGetUserSessionsClientByIDs_EmptyInput(t *testing.T) {
	result, err := database.GetUserSessionsClientByIDs(context.Background(), nil, []int64{})
	if err != nil {
		t.Fatalf("GetUserSessionsClientByIDs(empty) failed: %v", err)
	}
	if result != nil {
		t.Errorf("Expected nil for an empty id list, got %+v", result)
	}

	result, err = database.GetUserSessionsClientByIDs(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("GetUserSessionsClientByIDs(nil) failed: %v", err)
	}
	if result != nil {
		t.Errorf("Expected nil for a nil id list, got %+v", result)
	}
}

// GetUserSessionClientsByUserSessionIDs is the batch read behind
// UserSessionsLoadClients. Note it selects by user_session_id, not by primary
// key, which is what distinguishes it from GetUserSessionsClientByIDs above: it
// returns every client row of every requested session, flattened into one slice
// that the caller re-groups by UserSessionID. So the contract that matters is
// that rows from different sessions are all present and stay attributable.
func TestGetUserSessionClientsByUserSessionIDs(t *testing.T) {
	user := createTestUser(t)
	sessionA := createTestUserSession(t, user.ID)
	sessionB := createTestUserSession(t, user.ID)
	sessionC := createTestUserSession(t, user.ID)
	clientA := createTestClient(t)
	clientB := createTestClient(t)

	// Two clients on session A, one on B, and one on the unrequested session C.
	scA1 := createTestUserSessionClientWithIDs(t, sessionA.ID, clientA.ID)
	scA2 := createTestUserSessionClientWithIDs(t, sessionA.ID, clientB.ID)
	scB1 := createTestUserSessionClientWithIDs(t, sessionB.ID, clientA.ID)
	scC1 := createTestUserSessionClientWithIDs(t, sessionC.ID, clientA.ID)

	result, err := database.GetUserSessionClientsByUserSessionIDs(context.Background(), nil, []int64{sessionA.ID, sessionB.ID})
	if err != nil {
		t.Fatalf("GetUserSessionClientsByUserSessionIDs failed: %v", err)
	}

	if len(result) != 3 {
		t.Fatalf("Expected 3 user session clients across the two sessions, got %d", len(result))
	}

	// Re-group exactly as UserSessionsLoadClients does.
	bySession := map[int64][]int64{}
	ids := map[int64]bool{}
	for _, sc := range result {
		bySession[sc.UserSessionID] = append(bySession[sc.UserSessionID], sc.ID)
		ids[sc.ID] = true
	}

	if len(bySession[sessionA.ID]) != 2 {
		t.Errorf("Expected 2 clients on session %d, got %d", sessionA.ID, len(bySession[sessionA.ID]))
	}
	if len(bySession[sessionB.ID]) != 1 {
		t.Errorf("Expected 1 client on session %d, got %d", sessionB.ID, len(bySession[sessionB.ID]))
	}
	for _, want := range []int64{scA1.ID, scA2.ID, scB1.ID} {
		if !ids[want] {
			t.Errorf("Expected user session client %d in the result", want)
		}
	}
	if ids[scC1.ID] {
		t.Errorf("Session %d was not requested; its client %d must not be returned", sessionC.ID, scC1.ID)
	}
	if _, present := bySession[sessionC.ID]; present {
		t.Errorf("Session %d was not requested and must not appear in the result", sessionC.ID)
	}
}

// A session with no clients contributes no rows rather than an error or a
// placeholder, which is what lets UserSessionsLoadClients leave Clients nil.
func TestGetUserSessionClientsByUserSessionIDs_SessionWithNoClients(t *testing.T) {
	user := createTestUser(t)
	withClient := createTestUserSession(t, user.ID)
	withoutClient := createTestUserSession(t, user.ID)
	client := createTestClient(t)
	sc := createTestUserSessionClientWithIDs(t, withClient.ID, client.ID)

	result, err := database.GetUserSessionClientsByUserSessionIDs(context.Background(), nil, []int64{withClient.ID, withoutClient.ID})
	if err != nil {
		t.Fatalf("GetUserSessionClientsByUserSessionIDs failed: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("Expected 1 user session client, got %d", len(result))
	}
	if result[0].ID != sc.ID {
		t.Errorf("Expected user session client %d, got %d", sc.ID, result[0].ID)
	}
	if result[0].UserSessionID != withClient.ID {
		t.Errorf("Expected the row to belong to session %d, got %d", withClient.ID, result[0].UserSessionID)
	}
}

func TestGetUserSessionClientsByUserSessionIDs_UnknownIDIsSkipped(t *testing.T) {
	user := createTestUser(t)
	userSession := createTestUserSession(t, user.ID)
	client := createTestClient(t)
	sc := createTestUserSessionClientWithIDs(t, userSession.ID, client.ID)

	result, err := database.GetUserSessionClientsByUserSessionIDs(context.Background(), nil, []int64{userSession.ID, 999999999})
	if err != nil {
		t.Fatalf("GetUserSessionClientsByUserSessionIDs failed: %v", err)
	}

	if len(result) != 1 || result[0].ID != sc.ID {
		t.Errorf("Expected only the existing session's client %d, got %+v", sc.ID, result)
	}
}

func TestGetUserSessionClientsByUserSessionIDs_EmptyInput(t *testing.T) {
	result, err := database.GetUserSessionClientsByUserSessionIDs(context.Background(), nil, []int64{})
	if err != nil {
		t.Fatalf("GetUserSessionClientsByUserSessionIDs(empty) failed: %v", err)
	}
	if result != nil {
		t.Errorf("Expected nil for an empty id list, got %+v", result)
	}

	result, err = database.GetUserSessionClientsByUserSessionIDs(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("GetUserSessionClientsByUserSessionIDs(nil) failed: %v", err)
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
	consentA := createTestUserConsentForUser(t, userA.ID)
	consentB := createTestUserConsentForUser(t, userB.ID)

	// Both exist to begin with.
	for _, id := range []int64{consentA.ID, consentB.ID} {
		consent, err := database.GetUserConsentByID(context.Background(), nil, id)
		if err != nil {
			t.Fatalf("Failed to read consent %d: %v", id, err)
		}
		if consent == nil {
			t.Fatalf("Expected consent %d to exist before the delete", id)
		}
	}

	if err := database.DeleteAllUserConsent(context.Background(), nil); err != nil {
		t.Fatalf("DeleteAllUserConsent failed: %v", err)
	}

	for _, id := range []int64{consentA.ID, consentB.ID} {
		consent, err := database.GetUserConsentByID(context.Background(), nil, id)
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
	if err := database.DeleteAllUserConsent(context.Background(), nil); err != nil {
		t.Fatalf("First DeleteAllUserConsent failed: %v", err)
	}
	if err := database.DeleteAllUserConsent(context.Background(), nil); err != nil {
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
	empty, err := database.IsEmpty(context.Background())
	if err != nil {
		t.Fatalf("IsEmpty failed: %v", err)
	}

	settings, err := database.GetSettingsByID(context.Background(), nil, 1)
	if err != nil {
		t.Fatalf("Failed to read settings: %v", err)
	}

	if empty != (settings == nil) {
		t.Errorf("IsEmpty returned %v but the settings row with id 1 %s",
			empty, map[bool]string{true: "is absent", false: "exists"}[settings == nil])
	}
}
