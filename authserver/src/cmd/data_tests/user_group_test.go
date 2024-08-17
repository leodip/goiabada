package datatests

import (
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/models"
)

func TestCreateUserGroup(t *testing.T) {
	user := createTestUser(t)
	group := createTestGroup(t)

	userGroup := &models.UserGroup{
		UserId:  user.Id,
		GroupId: group.Id,
	}

	err := database.CreateUserGroup(nil, userGroup)
	if err != nil {
		t.Fatalf("Failed to create user group: %v", err)
	}

	if userGroup.Id == 0 {
		t.Error("Expected non-zero ID after creation")
	}
	if !userGroup.CreatedAt.Valid || userGroup.CreatedAt.Time.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
	if !userGroup.UpdatedAt.Valid || userGroup.UpdatedAt.Time.IsZero() {
		t.Error("Expected UpdatedAt to be set")
	}

	retrievedUserGroup, err := database.GetUserGroupById(nil, userGroup.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve created user group: %v", err)
	}

	if retrievedUserGroup.UserId != userGroup.UserId {
		t.Errorf("Expected UserId %d, got %d", userGroup.UserId, retrievedUserGroup.UserId)
	}
	if retrievedUserGroup.GroupId != userGroup.GroupId {
		t.Errorf("Expected GroupId %d, got %d", userGroup.GroupId, retrievedUserGroup.GroupId)
	}

	database.DeleteUserGroup(nil, userGroup.Id)
	database.DeleteUser(nil, user.Id)
	database.DeleteGroup(nil, group.Id)
}

func TestUpdateUserGroup(t *testing.T) {
	userGroup := createTestUserGroup(t)

	newUser := createTestUser(t)
	newGroup := createTestGroup(t)

	userGroup.UserId = newUser.Id
	userGroup.GroupId = newGroup.Id

	time.Sleep(time.Millisecond * 100)

	err := database.UpdateUserGroup(nil, userGroup)
	if err != nil {
		t.Fatalf("Failed to update user group: %v", err)
	}

	updatedUserGroup, err := database.GetUserGroupById(nil, userGroup.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve updated user group: %v", err)
	}

	if updatedUserGroup.UserId != newUser.Id {
		t.Errorf("Expected UserId %d, got %d", newUser.Id, updatedUserGroup.UserId)
	}
	if updatedUserGroup.GroupId != newGroup.Id {
		t.Errorf("Expected GroupId %d, got %d", newGroup.Id, updatedUserGroup.GroupId)
	}
	if !updatedUserGroup.UpdatedAt.Time.After(updatedUserGroup.CreatedAt.Time) {
		t.Error("Expected UpdatedAt to be after CreatedAt")
	}

	database.DeleteUserGroup(nil, userGroup.Id)
	database.DeleteUser(nil, newUser.Id)
	database.DeleteGroup(nil, newGroup.Id)
}

func TestGetUserGroupById(t *testing.T) {
	userGroup := createTestUserGroup(t)

	retrievedUserGroup, err := database.GetUserGroupById(nil, userGroup.Id)
	if err != nil {
		t.Fatalf("Failed to get user group by ID: %v", err)
	}

	if retrievedUserGroup.Id != userGroup.Id {
		t.Errorf("Expected ID %d, got %d", userGroup.Id, retrievedUserGroup.Id)
	}
	if retrievedUserGroup.UserId != userGroup.UserId {
		t.Errorf("Expected UserId %d, got %d", userGroup.UserId, retrievedUserGroup.UserId)
	}
	if retrievedUserGroup.GroupId != userGroup.GroupId {
		t.Errorf("Expected GroupId %d, got %d", userGroup.GroupId, retrievedUserGroup.GroupId)
	}

	nonExistentUserGroup, err := database.GetUserGroupById(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error for non-existent user group, got: %v", err)
	}
	if nonExistentUserGroup != nil {
		t.Errorf("Expected nil for non-existent user group, got a user group with ID: %d", nonExistentUserGroup.Id)
	}

	database.DeleteUserGroup(nil, userGroup.Id)
}

func TestGetUserGroupsByUserIds(t *testing.T) {
	user1 := createTestUser(t)
	user2 := createTestUser(t)
	group1 := createTestGroup(t)
	group2 := createTestGroup(t)

	userGroup1 := createTestUserGroupWithUserAndGroup(t, user1.Id, group1.Id)
	userGroup2 := createTestUserGroupWithUserAndGroup(t, user2.Id, group2.Id)

	userIds := []int64{user1.Id, user2.Id}
	userGroups, err := database.GetUserGroupsByUserIds(nil, userIds)
	if err != nil {
		t.Fatalf("Failed to get user groups by user IDs: %v", err)
	}

	if len(userGroups) != 2 {
		t.Errorf("Expected 2 user groups, got %d", len(userGroups))
	}

	foundUserGroup1 := false
	foundUserGroup2 := false
	for _, ug := range userGroups {
		if ug.Id == userGroup1.Id {
			foundUserGroup1 = true
		}
		if ug.Id == userGroup2.Id {
			foundUserGroup2 = true
		}
	}

	if !foundUserGroup1 || !foundUserGroup2 {
		t.Error("Not all created user groups were found in GetUserGroupsByUserIds result")
	}

	database.DeleteUserGroup(nil, userGroup1.Id)
	database.DeleteUserGroup(nil, userGroup2.Id)
	database.DeleteUser(nil, user1.Id)
	database.DeleteUser(nil, user2.Id)
	database.DeleteGroup(nil, group1.Id)
	database.DeleteGroup(nil, group2.Id)
}

func TestGetUserGroupsByUserId(t *testing.T) {
	user := createTestUser(t)
	group1 := createTestGroup(t)
	group2 := createTestGroup(t)

	userGroup1 := createTestUserGroupWithUserAndGroup(t, user.Id, group1.Id)
	userGroup2 := createTestUserGroupWithUserAndGroup(t, user.Id, group2.Id)

	userGroups, err := database.GetUserGroupsByUserId(nil, user.Id)
	if err != nil {
		t.Fatalf("Failed to get user groups by user ID: %v", err)
	}

	if len(userGroups) != 2 {
		t.Errorf("Expected 2 user groups, got %d", len(userGroups))
	}

	foundUserGroup1 := false
	foundUserGroup2 := false
	for _, ug := range userGroups {
		if ug.Id == userGroup1.Id {
			foundUserGroup1 = true
		}
		if ug.Id == userGroup2.Id {
			foundUserGroup2 = true
		}
	}

	if !foundUserGroup1 || !foundUserGroup2 {
		t.Error("Not all created user groups were found in GetUserGroupsByUserId result")
	}

	database.DeleteUserGroup(nil, userGroup1.Id)
	database.DeleteUserGroup(nil, userGroup2.Id)
	database.DeleteUser(nil, user.Id)
	database.DeleteGroup(nil, group1.Id)
	database.DeleteGroup(nil, group2.Id)
}

func TestGetUserGroupByUserIdAndGroupId(t *testing.T) {
	user := createTestUser(t)
	group := createTestGroup(t)
	userGroup := createTestUserGroupWithUserAndGroup(t, user.Id, group.Id)

	retrievedUserGroup, err := database.GetUserGroupByUserIdAndGroupId(nil, user.Id, group.Id)
	if err != nil {
		t.Fatalf("Failed to get user group by user ID and group ID: %v", err)
	}

	if retrievedUserGroup.Id != userGroup.Id {
		t.Errorf("Expected ID %d, got %d", userGroup.Id, retrievedUserGroup.Id)
	}
	if retrievedUserGroup.UserId != user.Id {
		t.Errorf("Expected UserId %d, got %d", user.Id, retrievedUserGroup.UserId)
	}
	if retrievedUserGroup.GroupId != group.Id {
		t.Errorf("Expected GroupId %d, got %d", group.Id, retrievedUserGroup.GroupId)
	}

	nonExistentUserGroup, err := database.GetUserGroupByUserIdAndGroupId(nil, 99999, 99999)
	if err != nil {
		t.Errorf("Expected no error for non-existent user group, got: %v", err)
	}
	if nonExistentUserGroup != nil {
		t.Errorf("Expected nil for non-existent user group, got a user group with ID: %d", nonExistentUserGroup.Id)
	}

	database.DeleteUserGroup(nil, userGroup.Id)
	database.DeleteUser(nil, user.Id)
	database.DeleteGroup(nil, group.Id)
}

func TestDeleteUserGroup(t *testing.T) {
	userGroup := createTestUserGroup(t)

	err := database.DeleteUserGroup(nil, userGroup.Id)
	if err != nil {
		t.Fatalf("Failed to delete user group: %v", err)
	}

	deletedUserGroup, err := database.GetUserGroupById(nil, userGroup.Id)
	if err != nil {
		t.Fatalf("Error while checking for deleted user group: %v", err)
	}
	if deletedUserGroup != nil {
		t.Errorf("User group still exists after deletion")
	}

	err = database.DeleteUserGroup(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error when deleting non-existent user group, got: %v", err)
	}
}

func createTestUserGroup(t *testing.T) *models.UserGroup {
	user := createTestUser(t)
	group := createTestGroup(t)
	return createTestUserGroupWithUserAndGroup(t, user.Id, group.Id)
}

func createTestUserGroupWithUserAndGroup(t *testing.T, userId, groupId int64) *models.UserGroup {
	userGroup := &models.UserGroup{
		UserId:  userId,
		GroupId: groupId,
	}
	err := database.CreateUserGroup(nil, userGroup)
	if err != nil {
		t.Fatalf("Failed to create test user group: %v", err)
	}
	return userGroup
}
