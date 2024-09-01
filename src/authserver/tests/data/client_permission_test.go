package datatests

import (
	"strconv"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/models"
)

func TestCreateClientPermission(t *testing.T) {
	client := &models.Client{
		ClientIdentifier: "test_client_" + gofakeit.LetterN(6),
		Description:      "Test Client",
	}
	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatalf("Failed to create test client: %v", err)
	}

	// Create a resource for testing
	resource := &models.Resource{
		ResourceIdentifier: "test_resource_" + gofakeit.LetterN(6),
		Description:        "Test Resource",
	}
	err = database.CreateResource(nil, resource)
	if err != nil {
		t.Fatalf("Failed to create test resource: %v", err)
	}

	// Create a permission for testing
	permission := &models.Permission{
		PermissionIdentifier: "test_permission_" + gofakeit.LetterN(6),
		Description:          "Test Permission",
		ResourceId:           resource.Id,
	}
	err = database.CreatePermission(nil, permission)
	if err != nil {
		t.Fatalf("Failed to create test permission: %v", err)
	}

	// Test case 1: Successfully create a client permission
	clientPermission := &models.ClientPermission{
		ClientId:     client.Id,
		PermissionId: permission.Id,
	}
	err = database.CreateClientPermission(nil, clientPermission)
	if err != nil {
		t.Fatalf("Failed to create client permission: %v", err)
	}
	if clientPermission.Id == 0 {
		t.Error("Expected client permission ID to be set, got 0")
	}
	if !clientPermission.CreatedAt.Valid {
		t.Error("Expected CreatedAt to be set, got zero time")
	}
	if !clientPermission.UpdatedAt.Valid {
		t.Error("Expected UpdatedAt to be set, got zero time")
	}

	// Test case 2: Attempt to create a client permission with invalid client ID
	invalidClientPermission := &models.ClientPermission{
		ClientId:     0,
		PermissionId: permission.Id,
	}
	err = database.CreateClientPermission(nil, invalidClientPermission)
	if err == nil {
		t.Error("Expected an error when creating client permission with invalid client ID, got nil")
	}

	// Test case 3: Attempt to create a client permission with invalid permission ID
	invalidPermissionClientPermission := &models.ClientPermission{
		ClientId:     client.Id,
		PermissionId: 0,
	}
	err = database.CreateClientPermission(nil, invalidPermissionClientPermission)
	if err == nil {
		t.Error("Expected an error when creating client permission with invalid permission ID, got nil")
	}

	// Test case 4: Verify the created client permission
	createdClientPermission, err := database.GetClientPermissionByClientIdAndPermissionId(nil, client.Id, permission.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve created client permission: %v", err)
	}
	if createdClientPermission == nil {
		t.Fatal("Expected to retrieve created client permission, got nil")
	}
	if createdClientPermission.ClientId != client.Id {
		t.Errorf("Expected ClientId %d, got %d", client.Id, createdClientPermission.ClientId)
	}
	if createdClientPermission.PermissionId != permission.Id {
		t.Errorf("Expected PermissionId %d, got %d", permission.Id, createdClientPermission.PermissionId)
	}
}

func TestUpdateClientPermission(t *testing.T) {
	// Create a client for testing
	client := &models.Client{
		ClientIdentifier: "test_client_" + gofakeit.LetterN(6),
		Description:      "Test Client",
	}
	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatalf("Failed to create test client: %v", err)
	}

	// Create another client for updating
	newClient := &models.Client{
		ClientIdentifier: "new_test_client_" + gofakeit.LetterN(6),
		Description:      "New Test Client",
	}
	err = database.CreateClient(nil, newClient)
	if err != nil {
		t.Fatalf("Failed to create new test client: %v", err)
	}

	// Create a resource for testing
	resource := &models.Resource{
		ResourceIdentifier: "test_resource_" + gofakeit.LetterN(6),
		Description:        "Test Resource",
	}
	err = database.CreateResource(nil, resource)
	if err != nil {
		t.Fatalf("Failed to create test resource: %v", err)
	}

	// Create a permission for testing
	permission := &models.Permission{
		PermissionIdentifier: "test_permission_" + gofakeit.LetterN(6),
		Description:          "Test Permission",
		ResourceId:           resource.Id,
	}
	err = database.CreatePermission(nil, permission)
	if err != nil {
		t.Fatalf("Failed to create test permission: %v", err)
	}

	// Create another permission for updating
	newPermission := &models.Permission{
		PermissionIdentifier: "new_test_permission_" + gofakeit.LetterN(6),
		Description:          "New Test Permission",
		ResourceId:           resource.Id,
	}
	err = database.CreatePermission(nil, newPermission)
	if err != nil {
		t.Fatalf("Failed to create new test permission: %v", err)
	}

	// Create a client permission for testing
	clientPermission := &models.ClientPermission{
		ClientId:     client.Id,
		PermissionId: permission.Id,
	}
	err = database.CreateClientPermission(nil, clientPermission)
	if err != nil {
		t.Fatalf("Failed to create client permission: %v", err)
	}

	// Test case 1: Successfully update a client permission
	time.Sleep(time.Millisecond * 100) // Ensure some time passes before update
	clientPermission.ClientId = newClient.Id
	clientPermission.PermissionId = newPermission.Id
	err = database.UpdateClientPermission(nil, clientPermission)
	if err != nil {
		t.Fatalf("Failed to update client permission: %v", err)
	}

	updatedClientPermission, err := database.GetClientPermissionById(nil, clientPermission.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve updated client permission: %v", err)
	}

	if updatedClientPermission.ClientId != newClient.Id {
		t.Errorf("Expected ClientId to be updated to %d, got %d", newClient.Id, updatedClientPermission.ClientId)
	}
	if updatedClientPermission.PermissionId != newPermission.Id {
		t.Errorf("Expected PermissionId to be updated to %d, got %d", newPermission.Id, updatedClientPermission.PermissionId)
	}
	if !updatedClientPermission.UpdatedAt.Time.After(clientPermission.CreatedAt.Time) {
		t.Error("Expected UpdatedAt to be after CreatedAt")
	}

	// Test case 2: Attempt to update a client permission with invalid ID
	invalidClientPermission := &models.ClientPermission{
		Id: 0,
	}
	err = database.UpdateClientPermission(nil, invalidClientPermission)
	if err == nil {
		t.Error("Expected an error when updating client permission with invalid ID, got nil")
	}
}

func TestGetClientPermissionById(t *testing.T) {
	// Create a client for testing
	client := &models.Client{
		ClientIdentifier: "test_client_" + gofakeit.LetterN(6),
		Description:      "Test Client",
	}
	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatalf("Failed to create test client: %v", err)
	}

	// Create a resource for testing
	resource := &models.Resource{
		ResourceIdentifier: "test_resource_" + gofakeit.LetterN(6),
		Description:        "Test Resource",
	}
	err = database.CreateResource(nil, resource)
	if err != nil {
		t.Fatalf("Failed to create test resource: %v", err)
	}

	// Create a permission for testing
	permission := &models.Permission{
		PermissionIdentifier: "test_permission_" + gofakeit.LetterN(6),
		Description:          "Test Permission",
		ResourceId:           resource.Id,
	}
	err = database.CreatePermission(nil, permission)
	if err != nil {
		t.Fatalf("Failed to create test permission: %v", err)
	}

	// Create a client permission for testing
	clientPermission := &models.ClientPermission{
		ClientId:     client.Id,
		PermissionId: permission.Id,
	}
	err = database.CreateClientPermission(nil, clientPermission)
	if err != nil {
		t.Fatalf("Failed to create client permission: %v", err)
	}

	// Test case 1: Successfully retrieve an existing client permission
	retrievedClientPermission, err := database.GetClientPermissionById(nil, clientPermission.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve client permission: %v", err)
	}
	if retrievedClientPermission == nil {
		t.Fatal("Expected to retrieve client permission, got nil")
	}
	if retrievedClientPermission.Id != clientPermission.Id {
		t.Errorf("Expected client permission ID %d, got %d", clientPermission.Id, retrievedClientPermission.Id)
	}
	if retrievedClientPermission.ClientId != client.Id {
		t.Errorf("Expected ClientId %d, got %d", client.Id, retrievedClientPermission.ClientId)
	}
	if retrievedClientPermission.PermissionId != permission.Id {
		t.Errorf("Expected PermissionId %d, got %d", permission.Id, retrievedClientPermission.PermissionId)
	}

	// Test case 2: Attempt to retrieve a non-existent client permission
	nonExistentPermission, err := database.GetClientPermissionById(nil, clientPermission.Id+1000)
	if err != nil {
		t.Fatalf("Unexpected error when retrieving non-existent client permission: %v", err)
	}
	if nonExistentPermission != nil {
		t.Error("Expected nil when retrieving non-existent client permission, got a value")
	}

	// Test case 3: Attempt to retrieve a client permission with an invalid ID (0)
	invalidPermission, err := database.GetClientPermissionById(nil, 0)
	if err != nil {
		t.Fatalf("Unexpected error when retrieving client permission with invalid ID: %v", err)
	}
	if invalidPermission != nil {
		t.Error("Expected nil when retrieving client permission with invalid ID, got a value")
	}
}

func TestGetClientPermissionByClientIdAndPermissionId(t *testing.T) {
	// Create a client for testing
	client := &models.Client{
		ClientIdentifier: "test_client_" + gofakeit.LetterN(6),
		Description:      "Test Client",
	}
	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatalf("Failed to create test client: %v", err)
	}

	// Create a resource for testing
	resource := &models.Resource{
		ResourceIdentifier: "test_resource_" + gofakeit.LetterN(6),
		Description:        "Test Resource",
	}
	err = database.CreateResource(nil, resource)
	if err != nil {
		t.Fatalf("Failed to create test resource: %v", err)
	}

	// Create a permission for testing
	permission := &models.Permission{
		PermissionIdentifier: "test_permission_" + gofakeit.LetterN(6),
		Description:          "Test Permission",
		ResourceId:           resource.Id,
	}
	err = database.CreatePermission(nil, permission)
	if err != nil {
		t.Fatalf("Failed to create test permission: %v", err)
	}

	// Create a client permission for testing
	clientPermission := &models.ClientPermission{
		ClientId:     client.Id,
		PermissionId: permission.Id,
	}
	err = database.CreateClientPermission(nil, clientPermission)
	if err != nil {
		t.Fatalf("Failed to create client permission: %v", err)
	}

	// Test case 1: Successfully retrieve an existing client permission
	retrievedClientPermission, err := database.GetClientPermissionByClientIdAndPermissionId(nil, client.Id, permission.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve client permission: %v", err)
	}
	if retrievedClientPermission == nil {
		t.Fatal("Expected to retrieve client permission, got nil")
	}
	if retrievedClientPermission.Id != clientPermission.Id {
		t.Errorf("Expected client permission ID %d, got %d", clientPermission.Id, retrievedClientPermission.Id)
	}
	if retrievedClientPermission.ClientId != client.Id {
		t.Errorf("Expected ClientId %d, got %d", client.Id, retrievedClientPermission.ClientId)
	}
	if retrievedClientPermission.PermissionId != permission.Id {
		t.Errorf("Expected PermissionId %d, got %d", permission.Id, retrievedClientPermission.PermissionId)
	}

	// Test case 2: Attempt to retrieve a non-existent client permission
	nonExistentPermission, err := database.GetClientPermissionByClientIdAndPermissionId(nil, client.Id+1000, permission.Id+1000)
	if err != nil {
		t.Fatalf("Unexpected error when retrieving non-existent client permission: %v", err)
	}
	if nonExistentPermission != nil {
		t.Error("Expected nil when retrieving non-existent client permission, got a value")
	}
}

func TestGetClientPermissionsByClientId(t *testing.T) {
	// Create a client for testing
	client := &models.Client{
		ClientIdentifier: "test_client_" + gofakeit.LetterN(6),
		Description:      "Test Client",
	}
	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatalf("Failed to create test client: %v", err)
	}

	// Create a resource for testing
	resource := &models.Resource{
		ResourceIdentifier: "test_resource_" + gofakeit.LetterN(6),
		Description:        "Test Resource",
	}
	err = database.CreateResource(nil, resource)
	if err != nil {
		t.Fatalf("Failed to create test resource: %v", err)
	}

	// Create permissions for testing
	permissions := make([]*models.Permission, 3)
	for i := 0; i < 3; i++ {
		permissions[i] = &models.Permission{
			PermissionIdentifier: "test_permission_" + gofakeit.LetterN(6),
			Description:          "Test Permission " + strconv.Itoa(i+1),
			ResourceId:           resource.Id,
		}
		err = database.CreatePermission(nil, permissions[i])
		if err != nil {
			t.Fatalf("Failed to create test permission: %v", err)
		}
	}

	// Create client permissions for testing
	for _, perm := range permissions {
		clientPermission := &models.ClientPermission{
			ClientId:     client.Id,
			PermissionId: perm.Id,
		}
		err = database.CreateClientPermission(nil, clientPermission)
		if err != nil {
			t.Fatalf("Failed to create client permission: %v", err)
		}
	}

	// Test case 1: Successfully retrieve all client permissions for a client
	retrievedClientPermissions, err := database.GetClientPermissionsByClientId(nil, client.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve client permissions: %v", err)
	}
	if len(retrievedClientPermissions) != 3 {
		t.Errorf("Expected to retrieve 3 client permissions, got %d", len(retrievedClientPermissions))
	}
	for _, cp := range retrievedClientPermissions {
		if cp.ClientId != client.Id {
			t.Errorf("Expected ClientId %d, got %d", client.Id, cp.ClientId)
		}
	}

	// Test case 2: Attempt to retrieve client permissions for a non-existent client
	nonExistentClientPermissions, err := database.GetClientPermissionsByClientId(nil, client.Id+1000)
	if err != nil {
		t.Fatalf("Unexpected error when retrieving client permissions for non-existent client: %v", err)
	}
	if len(nonExistentClientPermissions) != 0 {
		t.Errorf("Expected 0 client permissions for non-existent client, got %d", len(nonExistentClientPermissions))
	}
}

func TestDeleteClientPermission(t *testing.T) {
	// Create a client for testing
	client := &models.Client{
		ClientIdentifier: "test_client_" + gofakeit.LetterN(6),
		Description:      "Test Client",
	}
	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatalf("Failed to create test client: %v", err)
	}

	// Create a resource for testing
	resource := &models.Resource{
		ResourceIdentifier: "test_resource_" + gofakeit.LetterN(6),
		Description:        "Test Resource",
	}
	err = database.CreateResource(nil, resource)
	if err != nil {
		t.Fatalf("Failed to create test resource: %v", err)
	}

	// Create a permission for testing
	permission := &models.Permission{
		PermissionIdentifier: "test_permission_" + gofakeit.LetterN(6),
		Description:          "Test Permission",
		ResourceId:           resource.Id,
	}
	err = database.CreatePermission(nil, permission)
	if err != nil {
		t.Fatalf("Failed to create test permission: %v", err)
	}

	// Create a client permission for testing
	clientPermission := &models.ClientPermission{
		ClientId:     client.Id,
		PermissionId: permission.Id,
	}
	err = database.CreateClientPermission(nil, clientPermission)
	if err != nil {
		t.Fatalf("Failed to create client permission: %v", err)
	}

	// Test case 1: Successfully delete an existing client permission
	err = database.DeleteClientPermission(nil, clientPermission.Id)
	if err != nil {
		t.Fatalf("Failed to delete client permission: %v", err)
	}

	// Verify that the client permission has been deleted
	deletedClientPermission, err := database.GetClientPermissionById(nil, clientPermission.Id)
	if err != nil {
		t.Fatalf("Unexpected error when retrieving deleted client permission: %v", err)
	}
	if deletedClientPermission != nil {
		t.Error("Expected nil when retrieving deleted client permission, got a value")
	}

	// Test case 2: Attempt to delete a non-existent client permission
	err = database.DeleteClientPermission(nil, clientPermission.Id+1000)
	if err != nil {
		t.Fatalf("Unexpected error when deleting non-existent client permission: %v", err)
	}
}
