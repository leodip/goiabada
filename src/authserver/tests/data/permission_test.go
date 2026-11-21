package datatests

import (
	"context"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
)

func TestCreatePermission(t *testing.T) {
	resource := createTestResource(t)
	permission := &record.Permission{
		PermissionIdentifier: "test_permission_" + fake.LetterN(6),
		Description:          "Test Permission",
		ResourceID:           resource.ID,
	}

	err := database.CreatePermission(context.Background(), nil, permission)
	if err != nil {
		t.Fatalf("Failed to create permission: %v", err)
	}

	if permission.ID == 0 {
		t.Error("Expected non-zero ID after creation")
	}
	if !permission.CreatedAt.Valid || permission.CreatedAt.Time.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
	if !permission.UpdatedAt.Valid || permission.UpdatedAt.Time.IsZero() {
		t.Error("Expected UpdatedAt to be set")
	}

	retrievedPermission, err := database.GetPermissionByID(context.Background(), nil, permission.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve created permission: %v", err)
	}

	if retrievedPermission.PermissionIdentifier != permission.PermissionIdentifier {
		t.Errorf("Expected PermissionIdentifier %s, got %s", permission.PermissionIdentifier, retrievedPermission.PermissionIdentifier)
	}
	if retrievedPermission.Description != permission.Description {
		t.Errorf("Expected Description %s, got %s", permission.Description, retrievedPermission.Description)
	}
	if retrievedPermission.ResourceID != permission.ResourceID {
		t.Errorf("Expected ResourceID %d, got %d", permission.ResourceID, retrievedPermission.ResourceID)
	}
}

func TestUpdatePermission(t *testing.T) {
	resource1 := createTestResource(t)
	resource2 := createTestResource(t)
	permission := createTestPermission(t, resource1)

	permission.Description = "Updated Description"
	permission.ResourceID = resource2.ID

	time.Sleep(timestampTick)

	err := database.UpdatePermission(context.Background(), nil, permission)
	if err != nil {
		t.Fatalf("Failed to update permission: %v", err)
	}

	updatedPermission, err := database.GetPermissionByID(context.Background(), nil, permission.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve updated permission: %v", err)
	}

	if updatedPermission.Description != permission.Description {
		t.Errorf("Expected Description %s, got %s", permission.Description, updatedPermission.Description)
	}
	if updatedPermission.ResourceID != permission.ResourceID {
		t.Errorf("Expected ResourceID %d, got %d", permission.ResourceID, updatedPermission.ResourceID)
	}
	if !updatedPermission.UpdatedAt.Time.After(updatedPermission.CreatedAt.Time) {
		t.Error("Expected UpdatedAt to be after CreatedAt")
	}
}

func TestGetPermissionByID(t *testing.T) {
	resource := createTestResource(t)
	permission := createTestPermission(t, resource)

	retrievedPermission, err := database.GetPermissionByID(context.Background(), nil, permission.ID)
	if err != nil {
		t.Fatalf("Failed to get permission by ID: %v", err)
	}

	if retrievedPermission.ID != permission.ID {
		t.Errorf("Expected ID %d, got %d", permission.ID, retrievedPermission.ID)
	}
	if retrievedPermission.PermissionIdentifier != permission.PermissionIdentifier {
		t.Errorf("Expected PermissionIdentifier %s, got %s", permission.PermissionIdentifier, retrievedPermission.PermissionIdentifier)
	}

	nonExistentPermission, err := database.GetPermissionByID(context.Background(), nil, 99999)
	if err != nil {
		t.Errorf("Expected no error for non-existent permission, got: %v", err)
	}
	if nonExistentPermission != nil {
		t.Errorf("Expected nil for non-existent permission, got a permission with ID: %d", nonExistentPermission.ID)
	}
}

func TestGetPermissionsByResourceID(t *testing.T) {
	resource := createTestResource(t)
	permission1 := createTestPermission(t, resource)
	permission2 := createTestPermission(t, resource)

	permissions, err := database.GetPermissionsByResourceID(context.Background(), nil, resource.ID)
	if err != nil {
		t.Fatalf("Failed to get permissions by resource ID: %v", err)
	}

	if len(permissions) != 2 {
		t.Errorf("Expected 2 permissions, got %d", len(permissions))
	}

	foundPermission1 := false
	foundPermission2 := false
	for _, p := range permissions {
		if p.ID == permission1.ID {
			foundPermission1 = true
		}
		if p.ID == permission2.ID {
			foundPermission2 = true
		}
	}

	if !foundPermission1 || !foundPermission2 {
		t.Error("Not all created permissions were found in GetPermissionsByResourceID result")
	}
}

func TestPermissionsLoadResources(t *testing.T) {
	resource1 := createTestResource(t)
	resource2 := createTestResource(t)
	permission1 := createTestPermission(t, resource1)
	permission2 := createTestPermission(t, resource2)

	permissions := []record.Permission{*permission1, *permission2}

	err := database.PermissionsLoadResources(context.Background(), nil, permissions)
	if err != nil {
		t.Fatalf("Failed to load resources for permissions: %v", err)
	}

	if permissions[0].Resource.ID != resource1.ID {
		t.Errorf("Expected Resource ID %d for permission 1, got %d", resource1.ID, permissions[0].Resource.ID)
	}
	if permissions[1].Resource.ID != resource2.ID {
		t.Errorf("Expected Resource ID %d for permission 2, got %d", resource2.ID, permissions[1].Resource.ID)
	}
}

func TestGetPermissionsByIDs(t *testing.T) {
	resource := createTestResource(t)
	permission1 := createTestPermission(t, resource)
	permission2 := createTestPermission(t, resource)

	permissionIDs := []int64{permission1.ID, permission2.ID}

	permissions, err := database.GetPermissionsByIDs(context.Background(), nil, permissionIDs)
	if err != nil {
		t.Fatalf("Failed to get permissions by IDs: %v", err)
	}

	if len(permissions) != 2 {
		t.Errorf("Expected 2 permissions, got %d", len(permissions))
	}

	foundPermission1 := false
	foundPermission2 := false
	for _, p := range permissions {
		if p.ID == permission1.ID {
			foundPermission1 = true
		}
		if p.ID == permission2.ID {
			foundPermission2 = true
		}
	}

	if !foundPermission1 || !foundPermission2 {
		t.Error("Not all requested permissions were found in GetPermissionsByIDs result")
	}
}

func TestDeletePermission(t *testing.T) {
	resource := createTestResource(t)
	permission := createTestPermission(t, resource)

	err := database.DeletePermission(context.Background(), nil, permission.ID)
	if err != nil {
		t.Fatalf("Failed to delete permission: %v", err)
	}

	deletedPermission, err := database.GetPermissionByID(context.Background(), nil, permission.ID)
	if err != nil {
		t.Fatalf("Error while checking for deleted permission: %v", err)
	}
	if deletedPermission != nil {
		t.Errorf("Permission still exists after deletion")
	}

	err = database.DeletePermission(context.Background(), nil, 99999)
	if err != nil {
		t.Errorf("Expected no error when deleting non-existent permission, got: %v", err)
	}
}

func createTestPermission(t *testing.T, resource *record.Resource) *record.Permission {
	permission := &record.Permission{
		PermissionIdentifier: "test_permission" + fake.LetterN(6),
		Description:          "Test Permission",
		ResourceID:           resource.ID,
	}
	err := database.CreatePermission(context.Background(), nil, permission)
	if err != nil {
		t.Fatalf("Failed to create test permission: %v", err)
	}
	return permission
}
