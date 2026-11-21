package datatests

import (
	"context"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
)

func TestCreateUserGroup(t *testing.T) {
	user := createTestUser(t)
	group := createTestGroup(t)

	userGroup := &record.UserGroup{
		UserID:  user.ID,
		GroupID: group.ID,
	}

	err := database.CreateUserGroup(context.Background(), nil, userGroup)
	if err != nil {
		t.Fatalf("Failed to create user group: %v", err)
	}

	if userGroup.ID == 0 {
		t.Error("Expected non-zero ID after creation")
	}
	if !userGroup.CreatedAt.Valid || userGroup.CreatedAt.Time.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
	if !userGroup.UpdatedAt.Valid || userGroup.UpdatedAt.Time.IsZero() {
		t.Error("Expected UpdatedAt to be set")
	}

	retrievedUserGroup, err := database.GetUserGroupByID(context.Background(), nil, userGroup.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve created user group: %v", err)
	}

	if retrievedUserGroup.UserID != userGroup.UserID {
		t.Errorf("Expected UserID %d, got %d", userGroup.UserID, retrievedUserGroup.UserID)
	}
	if retrievedUserGroup.GroupID != userGroup.GroupID {
		t.Errorf("Expected GroupID %d, got %d", userGroup.GroupID, retrievedUserGroup.GroupID)
	}
}

func TestUpdateUserGroup(t *testing.T) {
	userGroup := createTestUserGroup(t)

	newUser := createTestUser(t)
	newGroup := createTestGroup(t)

	userGroup.UserID = newUser.ID
	userGroup.GroupID = newGroup.ID

	time.Sleep(timestampTick)

	err := database.UpdateUserGroup(context.Background(), nil, userGroup)
	if err != nil {
		t.Fatalf("Failed to update user group: %v", err)
	}

	updatedUserGroup, err := database.GetUserGroupByID(context.Background(), nil, userGroup.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve updated user group: %v", err)
	}

	if updatedUserGroup.UserID != newUser.ID {
		t.Errorf("Expected UserID %d, got %d", newUser.ID, updatedUserGroup.UserID)
	}
	if updatedUserGroup.GroupID != newGroup.ID {
		t.Errorf("Expected GroupID %d, got %d", newGroup.ID, updatedUserGroup.GroupID)
	}
	if !updatedUserGroup.UpdatedAt.Time.After(updatedUserGroup.CreatedAt.Time) {
		t.Error("Expected UpdatedAt to be after CreatedAt")
	}
}

func TestGetUserGroupByID(t *testing.T) {
	userGroup := createTestUserGroup(t)

	retrievedUserGroup, err := database.GetUserGroupByID(context.Background(), nil, userGroup.ID)
	if err != nil {
		t.Fatalf("Failed to get user group by ID: %v", err)
	}

	if retrievedUserGroup.ID != userGroup.ID {
		t.Errorf("Expected ID %d, got %d", userGroup.ID, retrievedUserGroup.ID)
	}
	if retrievedUserGroup.UserID != userGroup.UserID {
		t.Errorf("Expected UserID %d, got %d", userGroup.UserID, retrievedUserGroup.UserID)
	}
	if retrievedUserGroup.GroupID != userGroup.GroupID {
		t.Errorf("Expected GroupID %d, got %d", userGroup.GroupID, retrievedUserGroup.GroupID)
	}

	nonExistentUserGroup, err := database.GetUserGroupByID(context.Background(), nil, 99999)
	if err != nil {
		t.Errorf("Expected no error for non-existent user group, got: %v", err)
	}
	if nonExistentUserGroup != nil {
		t.Errorf("Expected nil for non-existent user group, got a user group with ID: %d", nonExistentUserGroup.ID)
	}
}

func TestGetUserGroupsByUserIDs(t *testing.T) {
	user1 := createTestUser(t)
	user2 := createTestUser(t)
	group1 := createTestGroup(t)
	group2 := createTestGroup(t)

	userGroup1 := createTestUserGroupWithUserAndGroup(t, user1.ID, group1.ID)
	userGroup2 := createTestUserGroupWithUserAndGroup(t, user2.ID, group2.ID)

	userIDs := []int64{user1.ID, user2.ID}
	userGroups, err := database.GetUserGroupsByUserIDs(context.Background(), nil, userIDs)
	if err != nil {
		t.Fatalf("Failed to get user groups by user IDs: %v", err)
	}

	if len(userGroups) != 2 {
		t.Errorf("Expected 2 user groups, got %d", len(userGroups))
	}

	foundUserGroup1 := false
	foundUserGroup2 := false
	for _, ug := range userGroups {
		if ug.ID == userGroup1.ID {
			foundUserGroup1 = true
		}
		if ug.ID == userGroup2.ID {
			foundUserGroup2 = true
		}
	}

	if !foundUserGroup1 || !foundUserGroup2 {
		t.Error("Not all created user groups were found in GetUserGroupsByUserIDs result")
	}
}

func TestGetUserGroupsByUserID(t *testing.T) {
	user := createTestUser(t)
	group1 := createTestGroup(t)
	group2 := createTestGroup(t)

	userGroup1 := createTestUserGroupWithUserAndGroup(t, user.ID, group1.ID)
	userGroup2 := createTestUserGroupWithUserAndGroup(t, user.ID, group2.ID)

	userGroups, err := database.GetUserGroupsByUserID(context.Background(), nil, user.ID)
	if err != nil {
		t.Fatalf("Failed to get user groups by user ID: %v", err)
	}

	if len(userGroups) != 2 {
		t.Errorf("Expected 2 user groups, got %d", len(userGroups))
	}

	foundUserGroup1 := false
	foundUserGroup2 := false
	for _, ug := range userGroups {
		if ug.ID == userGroup1.ID {
			foundUserGroup1 = true
		}
		if ug.ID == userGroup2.ID {
			foundUserGroup2 = true
		}
	}

	if !foundUserGroup1 || !foundUserGroup2 {
		t.Error("Not all created user groups were found in GetUserGroupsByUserID result")
	}
}

func TestGetUserGroupByUserIDAndGroupID(t *testing.T) {
	user := createTestUser(t)
	group := createTestGroup(t)
	userGroup := createTestUserGroupWithUserAndGroup(t, user.ID, group.ID)

	retrievedUserGroup, err := database.GetUserGroupByUserIDAndGroupID(context.Background(), nil, user.ID, group.ID)
	if err != nil {
		t.Fatalf("Failed to get user group by user ID and group ID: %v", err)
	}

	if retrievedUserGroup.ID != userGroup.ID {
		t.Errorf("Expected ID %d, got %d", userGroup.ID, retrievedUserGroup.ID)
	}
	if retrievedUserGroup.UserID != user.ID {
		t.Errorf("Expected UserID %d, got %d", user.ID, retrievedUserGroup.UserID)
	}
	if retrievedUserGroup.GroupID != group.ID {
		t.Errorf("Expected GroupID %d, got %d", group.ID, retrievedUserGroup.GroupID)
	}

	nonExistentUserGroup, err := database.GetUserGroupByUserIDAndGroupID(context.Background(), nil, 99999, 99999)
	if err != nil {
		t.Errorf("Expected no error for non-existent user group, got: %v", err)
	}
	if nonExistentUserGroup != nil {
		t.Errorf("Expected nil for non-existent user group, got a user group with ID: %d", nonExistentUserGroup.ID)
	}
}

func TestDeleteUserGroup(t *testing.T) {
	userGroup := createTestUserGroup(t)

	err := database.DeleteUserGroup(context.Background(), nil, userGroup.ID)
	if err != nil {
		t.Fatalf("Failed to delete user group: %v", err)
	}

	deletedUserGroup, err := database.GetUserGroupByID(context.Background(), nil, userGroup.ID)
	if err != nil {
		t.Fatalf("Error while checking for deleted user group: %v", err)
	}
	if deletedUserGroup != nil {
		t.Errorf("User group still exists after deletion")
	}

	err = database.DeleteUserGroup(context.Background(), nil, 99999)
	if err != nil {
		t.Errorf("Expected no error when deleting non-existent user group, got: %v", err)
	}
}

func createTestUserGroup(t *testing.T) *record.UserGroup {
	user := createTestUser(t)
	group := createTestGroup(t)
	return createTestUserGroupWithUserAndGroup(t, user.ID, group.ID)
}

func createTestUserGroupWithUserAndGroup(t *testing.T, userID, groupID int64) *record.UserGroup {
	userGroup := &record.UserGroup{
		UserID:  userID,
		GroupID: groupID,
	}
	err := database.CreateUserGroup(context.Background(), nil, userGroup)
	if err != nil {
		t.Fatalf("Failed to create test user group: %v", err)
	}
	return userGroup
}
