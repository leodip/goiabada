package datatests

import (
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/authserver/internal/models"
)

func TestCreatePermission(t *testing.T) {
	resource := createTestResource(t)
	permission := &models.Permission{
		PermissionIdentifier: "test_permission_" + gofakeit.LetterN(6),
		Description:          "Test Permission",
		ResourceId:           resource.Id,
	}

	err := database.CreatePermission(nil, permission)
	if err != nil {
		t.Fatalf("Failed to create permission: %v", err)
	}

	if permission.Id == 0 {
		t.Error("Expected non-zero ID after creation")
	}
	if !permission.CreatedAt.Valid || permission.CreatedAt.Time.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
	if !permission.UpdatedAt.Valid || permission.UpdatedAt.Time.IsZero() {
		t.Error("Expected UpdatedAt to be set")
	}

	retrievedPermission, err := database.GetPermissionById(nil, permission.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve created permission: %v", err)
	}

	if retrievedPermission.PermissionIdentifier != permission.PermissionIdentifier {
		t.Errorf("Expected PermissionIdentifier %s, got %s", permission.PermissionIdentifier, retrievedPermission.PermissionIdentifier)
	}
	if retrievedPermission.Description != permission.Description {
		t.Errorf("Expected Description %s, got %s", permission.Description, retrievedPermission.Description)
	}
	if retrievedPermission.ResourceId != permission.ResourceId {
		t.Errorf("Expected ResourceId %d, got %d", permission.ResourceId, retrievedPermission.ResourceId)
	}
}

func TestUpdatePermission(t *testing.T) {
	resource1 := createTestResource(t)
	resource2 := createTestResource(t)
	permission := createTestPermission(t, resource1)

	permission.Description = "Updated Description"
	permission.ResourceId = resource2.Id

	time.Sleep(time.Millisecond * 100)

	err := database.UpdatePermission(nil, permission)
	if err != nil {
		t.Fatalf("Failed to update permission: %v", err)
	}

	updatedPermission, err := database.GetPermissionById(nil, permission.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve updated permission: %v", err)
	}

	if updatedPermission.Description != permission.Description {
		t.Errorf("Expected Description %s, got %s", permission.Description, updatedPermission.Description)
	}
	if updatedPermission.ResourceId != permission.ResourceId {
		t.Errorf("Expected ResourceId %d, got %d", permission.ResourceId, updatedPermission.ResourceId)
	}
	if !updatedPermission.UpdatedAt.Time.After(updatedPermission.CreatedAt.Time) {
		t.Error("Expected UpdatedAt to be after CreatedAt")
	}
}

func TestGetPermissionById(t *testing.T) {
	resource := createTestResource(t)
	permission := createTestPermission(t, resource)

	retrievedPermission, err := database.GetPermissionById(nil, permission.Id)
	if err != nil {
		t.Fatalf("Failed to get permission by ID: %v", err)
	}

	if retrievedPermission.Id != permission.Id {
		t.Errorf("Expected ID %d, got %d", permission.Id, retrievedPermission.Id)
	}
	if retrievedPermission.PermissionIdentifier != permission.PermissionIdentifier {
		t.Errorf("Expected PermissionIdentifier %s, got %s", permission.PermissionIdentifier, retrievedPermission.PermissionIdentifier)
	}

	nonExistentPermission, err := database.GetPermissionById(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error for non-existent permission, got: %v", err)
	}
	if nonExistentPermission != nil {
		t.Errorf("Expected nil for non-existent permission, got a permission with ID: %d", nonExistentPermission.Id)
	}
}

func TestGetPermissionsByResourceId(t *testing.T) {
	resource := createTestResource(t)
	permission1 := createTestPermission(t, resource)
	permission2 := createTestPermission(t, resource)

	permissions, err := database.GetPermissionsByResourceId(nil, resource.Id)
	if err != nil {
		t.Fatalf("Failed to get permissions by resource ID: %v", err)
	}

	if len(permissions) != 2 {
		t.Errorf("Expected 2 permissions, got %d", len(permissions))
	}

	foundPermission1 := false
	foundPermission2 := false
	for _, p := range permissions {
		if p.Id == permission1.Id {
			foundPermission1 = true
		}
		if p.Id == permission2.Id {
			foundPermission2 = true
		}
	}

	if !foundPermission1 || !foundPermission2 {
		t.Error("Not all created permissions were found in GetPermissionsByResourceId result")
	}
}

func TestPermissionsLoadResources(t *testing.T) {
	resource1 := createTestResource(t)
	resource2 := createTestResource(t)
	permission1 := createTestPermission(t, resource1)
	permission2 := createTestPermission(t, resource2)

	permissions := []models.Permission{*permission1, *permission2}

	err := database.PermissionsLoadResources(nil, permissions)
	if err != nil {
		t.Fatalf("Failed to load resources for permissions: %v", err)
	}

	if permissions[0].Resource.Id != resource1.Id {
		t.Errorf("Expected Resource ID %d for permission 1, got %d", resource1.Id, permissions[0].Resource.Id)
	}
	if permissions[1].Resource.Id != resource2.Id {
		t.Errorf("Expected Resource ID %d for permission 2, got %d", resource2.Id, permissions[1].Resource.Id)
	}
}

func TestGetPermissionsByIds(t *testing.T) {
	resource := createTestResource(t)
	permission1 := createTestPermission(t, resource)
	permission2 := createTestPermission(t, resource)

	permissionIds := []int64{permission1.Id, permission2.Id}

	permissions, err := database.GetPermissionsByIds(nil, permissionIds)
	if err != nil {
		t.Fatalf("Failed to get permissions by IDs: %v", err)
	}

	if len(permissions) != 2 {
		t.Errorf("Expected 2 permissions, got %d", len(permissions))
	}

	foundPermission1 := false
	foundPermission2 := false
	for _, p := range permissions {
		if p.Id == permission1.Id {
			foundPermission1 = true
		}
		if p.Id == permission2.Id {
			foundPermission2 = true
		}
	}

	if !foundPermission1 || !foundPermission2 {
		t.Error("Not all requested permissions were found in GetPermissionsByIds result")
	}
}

func TestDeletePermission(t *testing.T) {
	resource := createTestResource(t)
	permission := createTestPermission(t, resource)

	err := database.DeletePermission(nil, permission.Id)
	if err != nil {
		t.Fatalf("Failed to delete permission: %v", err)
	}

	deletedPermission, err := database.GetPermissionById(nil, permission.Id)
	if err != nil {
		t.Fatalf("Error while checking for deleted permission: %v", err)
	}
	if deletedPermission != nil {
		t.Errorf("Permission still exists after deletion")
	}

	err = database.DeletePermission(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error when deleting non-existent permission, got: %v", err)
	}
}

func createTestPermission(t *testing.T, resource *models.Resource) *models.Permission {
	permission := &models.Permission{
		PermissionIdentifier: "test_permission" + gofakeit.LetterN(6),
		Description:          "Test Permission",
		ResourceId:           resource.Id,
	}
	err := database.CreatePermission(nil, permission)
	if err != nil {
		t.Fatalf("Failed to create test permission: %v", err)
	}
	return permission
}
