package datatests

import (
	"context"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
)

func TestCreateGroupPermission(t *testing.T) {
	group := createTestGroup(t)
	resource := createTestResource(t)
	permission := createTestPermission(t, resource)

	groupPermission := &record.GroupPermission{
		GroupID:      group.ID,
		PermissionID: permission.ID,
	}

	err := database.CreateGroupPermission(context.Background(), nil, groupPermission)
	if err != nil {
		t.Fatalf("Failed to create group permission: %v", err)
	}

	if groupPermission.ID == 0 {
		t.Error("Expected non-zero ID after creation")
	}

	// Retrieve the created group permission
	createdGroupPermission, err := database.GetGroupPermissionByID(context.Background(), nil, groupPermission.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve created group permission: %v", err)
	}

	// Verify all properties
	if createdGroupPermission.ID != groupPermission.ID {
		t.Errorf("Expected ID %d, got %d", groupPermission.ID, createdGroupPermission.ID)
	}
	if createdGroupPermission.GroupID != groupPermission.GroupID {
		t.Errorf("Expected GroupID %d, got %d", groupPermission.GroupID, createdGroupPermission.GroupID)
	}
	if createdGroupPermission.PermissionID != groupPermission.PermissionID {
		t.Errorf("Expected PermissionID %d, got %d", groupPermission.PermissionID, createdGroupPermission.PermissionID)
	}
	if !createdGroupPermission.CreatedAt.Valid || createdGroupPermission.CreatedAt.Time.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
	if !createdGroupPermission.UpdatedAt.Valid || createdGroupPermission.UpdatedAt.Time.IsZero() {
		t.Error("Expected UpdatedAt to be set")
	}

	// Test creating with invalid GroupID
	invalidGroupPermission := &record.GroupPermission{
		GroupID:      0,
		PermissionID: permission.ID,
	}
	err = database.CreateGroupPermission(context.Background(), nil, invalidGroupPermission)
	if err == nil {
		t.Error("Expected error when creating group permission with invalid GroupID")
	}

	// Test creating with invalid PermissionID
	invalidGroupPermission = &record.GroupPermission{
		GroupID:      group.ID,
		PermissionID: 0,
	}
	err = database.CreateGroupPermission(context.Background(), nil, invalidGroupPermission)
	if err == nil {
		t.Error("Expected error when creating group permission with invalid PermissionID")
	}
}

func TestUpdateGroupPermission(t *testing.T) {
	// Create initial resources
	group1 := createTestGroup(t)
	resource1 := createTestResource(t)
	permission1 := createTestPermission(t, resource1)
	groupPermission := createTestGroupPermission(t, group1.ID, permission1.ID)

	// Create new resources for update
	group2 := createTestGroup(t)
	resource2 := createTestResource(t)
	permission2 := createTestPermission(t, resource2)

	// Retrieve the original group permission
	originalGroupPermission, err := database.GetGroupPermissionByID(context.Background(), nil, groupPermission.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve original group permission: %v", err)
	}

	// Wait a moment to ensure UpdatedAt will be different
	time.Sleep(timestampTick)

	// Update the group permission
	groupPermission.GroupID = group2.ID
	groupPermission.PermissionID = permission2.ID

	err = database.UpdateGroupPermission(context.Background(), nil, groupPermission)
	if err != nil {
		t.Fatalf("Failed to update group permission: %v", err)
	}

	updatedGroupPermission, err := database.GetGroupPermissionByID(context.Background(), nil, groupPermission.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve updated group permission: %v", err)
	}

	// Verify properties
	if updatedGroupPermission.ID != groupPermission.ID {
		t.Errorf("Expected ID %d, got %d", groupPermission.ID, updatedGroupPermission.ID)
	}
	if updatedGroupPermission.GroupID != group2.ID {
		t.Errorf("Expected GroupID %d, got %d", group2.ID, updatedGroupPermission.GroupID)
	}
	if updatedGroupPermission.PermissionID != permission2.ID {
		t.Errorf("Expected PermissionID %d, got %d", permission2.ID, updatedGroupPermission.PermissionID)
	}
	if !updatedGroupPermission.CreatedAt.Valid || updatedGroupPermission.CreatedAt.Time.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
	if !updatedGroupPermission.UpdatedAt.Valid || updatedGroupPermission.UpdatedAt.Time.IsZero() {
		t.Error("Expected UpdatedAt to be set")
	}
	if !updatedGroupPermission.UpdatedAt.Time.After(originalGroupPermission.UpdatedAt.Time) {
		t.Error("Expected UpdatedAt to be after the original UpdatedAt")
	}

	// Test updating with invalid ID
	invalidGroupPermission := &record.GroupPermission{ID: 0}
	err = database.UpdateGroupPermission(context.Background(), nil, invalidGroupPermission)
	if err == nil {
		t.Error("Expected error when updating group permission with invalid ID")
	}
}

func TestGetGroupPermissionsByGroupID(t *testing.T) {
	group := createTestGroup(t)
	resource1 := createTestResource(t)
	resource2 := createTestResource(t)
	permission1 := createTestPermission(t, resource1)
	permission2 := createTestPermission(t, resource2)
	createTestGroupPermission(t, group.ID, permission1.ID)
	createTestGroupPermission(t, group.ID, permission2.ID)

	groupPermissions, err := database.GetGroupPermissionsByGroupID(context.Background(), nil, group.ID)
	if err != nil {
		t.Fatalf("Failed to get group permissions by group id: %v", err)
	}

	if len(groupPermissions) != 2 {
		t.Errorf("Expected 2 group permissions, got %d", len(groupPermissions))
	}
}

func TestGetGroupPermissionsByGroupIDs(t *testing.T) {
	group1 := createTestGroup(t)
	group2 := createTestGroup(t)
	resource := createTestResource(t)
	permission := createTestPermission(t, resource)
	createTestGroupPermission(t, group1.ID, permission.ID)
	createTestGroupPermission(t, group2.ID, permission.ID)

	groupPermissions, err := database.GetGroupPermissionsByGroupIDs(context.Background(), nil, []int64{group1.ID, group2.ID})
	if err != nil {
		t.Fatalf("Failed to get group permissions by group ids: %v", err)
	}

	if len(groupPermissions) != 2 {
		t.Errorf("Expected 2 group permissions, got %d", len(groupPermissions))
	}

	// Test with empty slice
	emptyPermissions, err := database.GetGroupPermissionsByGroupIDs(context.Background(), nil, []int64{})
	if err != nil {
		t.Fatalf("Failed to get group permissions with empty slice: %v", err)
	}
	if emptyPermissions != nil {
		t.Errorf("Expected nil result for empty slice, got %v", emptyPermissions)
	}
}

func TestGetGroupPermissionByID(t *testing.T) {
	group := createTestGroup(t)
	resource := createTestResource(t)
	permission := createTestPermission(t, resource)
	groupPermission := createTestGroupPermission(t, group.ID, permission.ID)

	retrievedGroupPermission, err := database.GetGroupPermissionByID(context.Background(), nil, groupPermission.ID)
	if err != nil {
		t.Fatalf("Failed to get group permission by id: %v", err)
	}

	if retrievedGroupPermission.ID != groupPermission.ID {
		t.Errorf("Expected ID %d, got %d", groupPermission.ID, retrievedGroupPermission.ID)
	}
	if retrievedGroupPermission.GroupID != groupPermission.GroupID {
		t.Errorf("Expected GroupID %d, got %d", groupPermission.GroupID, retrievedGroupPermission.GroupID)
	}
	if retrievedGroupPermission.PermissionID != groupPermission.PermissionID {
		t.Errorf("Expected PermissionID %d, got %d", groupPermission.PermissionID, retrievedGroupPermission.PermissionID)
	}

	// Test with non-existent id
	nonExistentGroupPermission, err := database.GetGroupPermissionByID(context.Background(), nil, 99999)
	if err != nil {
		t.Fatalf("Unexpected error when getting non-existent group permission: %v", err)
	}
	if nonExistentGroupPermission != nil {
		t.Error("Expected nil result for non-existent group permission")
	}
}

func TestGetGroupPermissionByGroupIDAndPermissionID(t *testing.T) {
	group := createTestGroup(t)
	resource := createTestResource(t)
	permission := createTestPermission(t, resource)
	groupPermission := createTestGroupPermission(t, group.ID, permission.ID)

	retrievedGroupPermission, err := database.GetGroupPermissionByGroupIDAndPermissionID(context.Background(), nil, group.ID, permission.ID)
	if err != nil {
		t.Fatalf("Failed to get group permission by group id and permission id: %v", err)
	}

	if retrievedGroupPermission.ID != groupPermission.ID {
		t.Errorf("Expected ID %d, got %d", groupPermission.ID, retrievedGroupPermission.ID)
	}
	if retrievedGroupPermission.GroupID != groupPermission.GroupID {
		t.Errorf("Expected GroupID %d, got %d", groupPermission.GroupID, retrievedGroupPermission.GroupID)
	}
	if retrievedGroupPermission.PermissionID != groupPermission.PermissionID {
		t.Errorf("Expected PermissionID %d, got %d", groupPermission.PermissionID, retrievedGroupPermission.PermissionID)
	}

	// Test with non-existent group id and permission id
	nonExistentGroupPermission, err := database.GetGroupPermissionByGroupIDAndPermissionID(context.Background(), nil, 99999, 99999)
	if err != nil {
		t.Fatalf("Unexpected error when getting non-existent group permission: %v", err)
	}
	if nonExistentGroupPermission != nil {
		t.Error("Expected nil result for non-existent group permission")
	}
}

func TestDeleteGroupPermission(t *testing.T) {
	group := createTestGroup(t)
	resource := createTestResource(t)
	permission := createTestPermission(t, resource)
	groupPermission := createTestGroupPermission(t, group.ID, permission.ID)

	err := database.DeleteGroupPermission(context.Background(), nil, groupPermission.ID)
	if err != nil {
		t.Fatalf("Failed to delete group permission: %v", err)
	}

	// Verify deletion
	deletedGroupPermission, err := database.GetGroupPermissionByID(context.Background(), nil, groupPermission.ID)
	if err != nil {
		t.Fatalf("Unexpected error when getting deleted group permission: %v", err)
	}
	if deletedGroupPermission != nil {
		t.Error("Expected nil result for deleted group permission")
	}

	// Test deleting non-existent group permission
	err = database.DeleteGroupPermission(context.Background(), nil, 99999)
	if err != nil {
		t.Errorf("Unexpected error when deleting non-existent group permission: %v", err)
	}
}

func createTestGroupPermission(t *testing.T, groupID, permissionID int64) *record.GroupPermission {
	groupPermission := &record.GroupPermission{
		GroupID:      groupID,
		PermissionID: permissionID,
	}
	err := database.CreateGroupPermission(context.Background(), nil, groupPermission)
	if err != nil {
		t.Fatalf("Failed to create test group permission: %v", err)
	}
	return groupPermission
}
