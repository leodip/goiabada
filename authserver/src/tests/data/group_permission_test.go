package datatests

import (
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/models"
)

func TestCreateGroupPermission(t *testing.T) {
	group := createTestGroup(t)
	resource := createTestResource(t)
	permission := createTestPermission(t, resource)

	groupPermission := &models.GroupPermission{
		GroupId:      group.Id,
		PermissionId: permission.Id,
	}

	err := database.CreateGroupPermission(nil, groupPermission)
	if err != nil {
		t.Fatalf("Failed to create group permission: %v", err)
	}

	if groupPermission.Id == 0 {
		t.Error("Expected non-zero ID after creation")
	}

	// Retrieve the created group permission
	createdGroupPermission, err := database.GetGroupPermissionById(nil, groupPermission.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve created group permission: %v", err)
	}

	// Verify all properties
	if createdGroupPermission.Id != groupPermission.Id {
		t.Errorf("Expected Id %d, got %d", groupPermission.Id, createdGroupPermission.Id)
	}
	if createdGroupPermission.GroupId != groupPermission.GroupId {
		t.Errorf("Expected GroupId %d, got %d", groupPermission.GroupId, createdGroupPermission.GroupId)
	}
	if createdGroupPermission.PermissionId != groupPermission.PermissionId {
		t.Errorf("Expected PermissionId %d, got %d", groupPermission.PermissionId, createdGroupPermission.PermissionId)
	}
	if !createdGroupPermission.CreatedAt.Valid || createdGroupPermission.CreatedAt.Time.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
	if !createdGroupPermission.UpdatedAt.Valid || createdGroupPermission.UpdatedAt.Time.IsZero() {
		t.Error("Expected UpdatedAt to be set")
	}

	// Test creating with invalid GroupId
	invalidGroupPermission := &models.GroupPermission{
		GroupId:      0,
		PermissionId: permission.Id,
	}
	err = database.CreateGroupPermission(nil, invalidGroupPermission)
	if err == nil {
		t.Error("Expected error when creating group permission with invalid GroupId")
	}

	// Test creating with invalid PermissionId
	invalidGroupPermission = &models.GroupPermission{
		GroupId:      group.Id,
		PermissionId: 0,
	}
	err = database.CreateGroupPermission(nil, invalidGroupPermission)
	if err == nil {
		t.Error("Expected error when creating group permission with invalid PermissionId")
	}
}

func TestUpdateGroupPermission(t *testing.T) {
	// Create initial resources
	group1 := createTestGroup(t)
	resource1 := createTestResource(t)
	permission1 := createTestPermission(t, resource1)
	groupPermission := createTestGroupPermission(t, group1.Id, permission1.Id)

	// Create new resources for update
	group2 := createTestGroup(t)
	resource2 := createTestResource(t)
	permission2 := createTestPermission(t, resource2)

	// Retrieve the original group permission
	originalGroupPermission, err := database.GetGroupPermissionById(nil, groupPermission.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve original group permission: %v", err)
	}

	// Wait a moment to ensure UpdatedAt will be different
	time.Sleep(time.Millisecond * 100)

	// Update the group permission
	groupPermission.GroupId = group2.Id
	groupPermission.PermissionId = permission2.Id

	err = database.UpdateGroupPermission(nil, groupPermission)
	if err != nil {
		t.Fatalf("Failed to update group permission: %v", err)
	}

	updatedGroupPermission, err := database.GetGroupPermissionById(nil, groupPermission.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve updated group permission: %v", err)
	}

	// Verify properties
	if updatedGroupPermission.Id != groupPermission.Id {
		t.Errorf("Expected Id %d, got %d", groupPermission.Id, updatedGroupPermission.Id)
	}
	if updatedGroupPermission.GroupId != group2.Id {
		t.Errorf("Expected GroupId %d, got %d", group2.Id, updatedGroupPermission.GroupId)
	}
	if updatedGroupPermission.PermissionId != permission2.Id {
		t.Errorf("Expected PermissionId %d, got %d", permission2.Id, updatedGroupPermission.PermissionId)
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

	// Test updating with invalid Id
	invalidGroupPermission := &models.GroupPermission{Id: 0}
	err = database.UpdateGroupPermission(nil, invalidGroupPermission)
	if err == nil {
		t.Error("Expected error when updating group permission with invalid Id")
	}
}

func TestGetGroupPermissionsByGroupId(t *testing.T) {
	group := createTestGroup(t)
	resource1 := createTestResource(t)
	resource2 := createTestResource(t)
	permission1 := createTestPermission(t, resource1)
	permission2 := createTestPermission(t, resource2)
	createTestGroupPermission(t, group.Id, permission1.Id)
	createTestGroupPermission(t, group.Id, permission2.Id)

	groupPermissions, err := database.GetGroupPermissionsByGroupId(nil, group.Id)
	if err != nil {
		t.Fatalf("Failed to get group permissions by group id: %v", err)
	}

	if len(groupPermissions) != 2 {
		t.Errorf("Expected 2 group permissions, got %d", len(groupPermissions))
	}
}

func TestGetGroupPermissionsByGroupIds(t *testing.T) {
	group1 := createTestGroup(t)
	group2 := createTestGroup(t)
	resource := createTestResource(t)
	permission := createTestPermission(t, resource)
	createTestGroupPermission(t, group1.Id, permission.Id)
	createTestGroupPermission(t, group2.Id, permission.Id)

	groupPermissions, err := database.GetGroupPermissionsByGroupIds(nil, []int64{group1.Id, group2.Id})
	if err != nil {
		t.Fatalf("Failed to get group permissions by group ids: %v", err)
	}

	if len(groupPermissions) != 2 {
		t.Errorf("Expected 2 group permissions, got %d", len(groupPermissions))
	}

	// Test with empty slice
	emptyPermissions, err := database.GetGroupPermissionsByGroupIds(nil, []int64{})
	if err != nil {
		t.Fatalf("Failed to get group permissions with empty slice: %v", err)
	}
	if emptyPermissions != nil {
		t.Errorf("Expected nil result for empty slice, got %v", emptyPermissions)
	}
}

func TestGetGroupPermissionById(t *testing.T) {
	group := createTestGroup(t)
	resource := createTestResource(t)
	permission := createTestPermission(t, resource)
	groupPermission := createTestGroupPermission(t, group.Id, permission.Id)

	retrievedGroupPermission, err := database.GetGroupPermissionById(nil, groupPermission.Id)
	if err != nil {
		t.Fatalf("Failed to get group permission by id: %v", err)
	}

	if retrievedGroupPermission.Id != groupPermission.Id {
		t.Errorf("Expected Id %d, got %d", groupPermission.Id, retrievedGroupPermission.Id)
	}
	if retrievedGroupPermission.GroupId != groupPermission.GroupId {
		t.Errorf("Expected GroupId %d, got %d", groupPermission.GroupId, retrievedGroupPermission.GroupId)
	}
	if retrievedGroupPermission.PermissionId != groupPermission.PermissionId {
		t.Errorf("Expected PermissionId %d, got %d", groupPermission.PermissionId, retrievedGroupPermission.PermissionId)
	}

	// Test with non-existent id
	nonExistentGroupPermission, err := database.GetGroupPermissionById(nil, 99999)
	if err != nil {
		t.Fatalf("Unexpected error when getting non-existent group permission: %v", err)
	}
	if nonExistentGroupPermission != nil {
		t.Error("Expected nil result for non-existent group permission")
	}
}

func TestGetGroupPermissionByGroupIdAndPermissionId(t *testing.T) {
	group := createTestGroup(t)
	resource := createTestResource(t)
	permission := createTestPermission(t, resource)
	groupPermission := createTestGroupPermission(t, group.Id, permission.Id)

	retrievedGroupPermission, err := database.GetGroupPermissionByGroupIdAndPermissionId(nil, group.Id, permission.Id)
	if err != nil {
		t.Fatalf("Failed to get group permission by group id and permission id: %v", err)
	}

	if retrievedGroupPermission.Id != groupPermission.Id {
		t.Errorf("Expected Id %d, got %d", groupPermission.Id, retrievedGroupPermission.Id)
	}
	if retrievedGroupPermission.GroupId != groupPermission.GroupId {
		t.Errorf("Expected GroupId %d, got %d", groupPermission.GroupId, retrievedGroupPermission.GroupId)
	}
	if retrievedGroupPermission.PermissionId != groupPermission.PermissionId {
		t.Errorf("Expected PermissionId %d, got %d", groupPermission.PermissionId, retrievedGroupPermission.PermissionId)
	}

	// Test with non-existent group id and permission id
	nonExistentGroupPermission, err := database.GetGroupPermissionByGroupIdAndPermissionId(nil, 99999, 99999)
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
	groupPermission := createTestGroupPermission(t, group.Id, permission.Id)

	err := database.DeleteGroupPermission(nil, groupPermission.Id)
	if err != nil {
		t.Fatalf("Failed to delete group permission: %v", err)
	}

	// Verify deletion
	deletedGroupPermission, err := database.GetGroupPermissionById(nil, groupPermission.Id)
	if err != nil {
		t.Fatalf("Unexpected error when getting deleted group permission: %v", err)
	}
	if deletedGroupPermission != nil {
		t.Error("Expected nil result for deleted group permission")
	}

	// Test deleting non-existent group permission
	err = database.DeleteGroupPermission(nil, 99999)
	if err != nil {
		t.Errorf("Unexpected error when deleting non-existent group permission: %v", err)
	}
}

func createTestGroupPermission(t *testing.T, groupId, permissionId int64) *models.GroupPermission {
	groupPermission := &models.GroupPermission{
		GroupId:      groupId,
		PermissionId: permissionId,
	}
	err := database.CreateGroupPermission(nil, groupPermission)
	if err != nil {
		t.Fatalf("Failed to create test group permission: %v", err)
	}
	return groupPermission
}
