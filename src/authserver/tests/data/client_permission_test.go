package datatests

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
)

func TestCreateClientPermission(t *testing.T) {
	client := &record.Client{
		ClientIdentifier: "test_client_" + fake.LetterN(6),
		Description:      "Test Client",
	}
	err := database.CreateClient(context.Background(), nil, client)
	if err != nil {
		t.Fatalf("Failed to create test client: %v", err)
	}

	// Create a resource for testing
	resource := &record.Resource{
		ResourceIdentifier: "test_resource_" + fake.LetterN(6),
		Description:        "Test Resource",
	}
	err = database.CreateResource(context.Background(), nil, resource)
	if err != nil {
		t.Fatalf("Failed to create test resource: %v", err)
	}

	// Create a permission for testing
	permission := &record.Permission{
		PermissionIdentifier: "test_permission_" + fake.LetterN(6),
		Description:          "Test Permission",
		ResourceID:           resource.ID,
	}
	err = database.CreatePermission(context.Background(), nil, permission)
	if err != nil {
		t.Fatalf("Failed to create test permission: %v", err)
	}

	// Test case 1: Successfully create a client permission
	clientPermission := &record.ClientPermission{
		ClientID:     client.ID,
		PermissionID: permission.ID,
	}
	err = database.CreateClientPermission(context.Background(), nil, clientPermission)
	if err != nil {
		t.Fatalf("Failed to create client permission: %v", err)
	}
	if clientPermission.ID == 0 {
		t.Error("Expected client permission ID to be set, got 0")
	}
	if !clientPermission.CreatedAt.Valid {
		t.Error("Expected CreatedAt to be set, got zero time")
	}
	if !clientPermission.UpdatedAt.Valid {
		t.Error("Expected UpdatedAt to be set, got zero time")
	}

	// Test case 2: Attempt to create a client permission with invalid client ID
	invalidClientPermission := &record.ClientPermission{
		ClientID:     0,
		PermissionID: permission.ID,
	}
	err = database.CreateClientPermission(context.Background(), nil, invalidClientPermission)
	if err == nil {
		t.Error("Expected an error when creating client permission with invalid client ID, got nil")
	}

	// Test case 3: Attempt to create a client permission with invalid permission ID
	invalidPermissionClientPermission := &record.ClientPermission{
		ClientID:     client.ID,
		PermissionID: 0,
	}
	err = database.CreateClientPermission(context.Background(), nil, invalidPermissionClientPermission)
	if err == nil {
		t.Error("Expected an error when creating client permission with invalid permission ID, got nil")
	}

	// Test case 4: Verify the created client permission
	createdClientPermission, err := database.GetClientPermissionByClientIDAndPermissionID(context.Background(), nil, client.ID, permission.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve created client permission: %v", err)
	}
	if createdClientPermission == nil {
		t.Fatal("Expected to retrieve created client permission, got nil")
	}
	if createdClientPermission.ClientID != client.ID {
		t.Errorf("Expected ClientID %d, got %d", client.ID, createdClientPermission.ClientID)
	}
	if createdClientPermission.PermissionID != permission.ID {
		t.Errorf("Expected PermissionID %d, got %d", permission.ID, createdClientPermission.PermissionID)
	}
}

func TestUpdateClientPermission(t *testing.T) {
	// Create a client for testing
	client := &record.Client{
		ClientIdentifier: "test_client_" + fake.LetterN(6),
		Description:      "Test Client",
	}
	err := database.CreateClient(context.Background(), nil, client)
	if err != nil {
		t.Fatalf("Failed to create test client: %v", err)
	}

	// Create another client for updating
	newClient := &record.Client{
		ClientIdentifier: "new_test_client_" + fake.LetterN(6),
		Description:      "New Test Client",
	}
	err = database.CreateClient(context.Background(), nil, newClient)
	if err != nil {
		t.Fatalf("Failed to create new test client: %v", err)
	}

	// Create a resource for testing
	resource := &record.Resource{
		ResourceIdentifier: "test_resource_" + fake.LetterN(6),
		Description:        "Test Resource",
	}
	err = database.CreateResource(context.Background(), nil, resource)
	if err != nil {
		t.Fatalf("Failed to create test resource: %v", err)
	}

	// Create a permission for testing
	permission := &record.Permission{
		PermissionIdentifier: "test_permission_" + fake.LetterN(6),
		Description:          "Test Permission",
		ResourceID:           resource.ID,
	}
	err = database.CreatePermission(context.Background(), nil, permission)
	if err != nil {
		t.Fatalf("Failed to create test permission: %v", err)
	}

	// Create another permission for updating
	newPermission := &record.Permission{
		PermissionIdentifier: "new_test_permission_" + fake.LetterN(6),
		Description:          "New Test Permission",
		ResourceID:           resource.ID,
	}
	err = database.CreatePermission(context.Background(), nil, newPermission)
	if err != nil {
		t.Fatalf("Failed to create new test permission: %v", err)
	}

	// Create a client permission for testing
	clientPermission := &record.ClientPermission{
		ClientID:     client.ID,
		PermissionID: permission.ID,
	}
	err = database.CreateClientPermission(context.Background(), nil, clientPermission)
	if err != nil {
		t.Fatalf("Failed to create client permission: %v", err)
	}

	// Test case 1: Successfully update a client permission
	time.Sleep(timestampTick) // Ensure some time passes before update
	clientPermission.ClientID = newClient.ID
	clientPermission.PermissionID = newPermission.ID
	err = database.UpdateClientPermission(context.Background(), nil, clientPermission)
	if err != nil {
		t.Fatalf("Failed to update client permission: %v", err)
	}

	updatedClientPermission, err := database.GetClientPermissionByID(context.Background(), nil, clientPermission.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve updated client permission: %v", err)
	}

	if updatedClientPermission.ClientID != newClient.ID {
		t.Errorf("Expected ClientID to be updated to %d, got %d", newClient.ID, updatedClientPermission.ClientID)
	}
	if updatedClientPermission.PermissionID != newPermission.ID {
		t.Errorf("Expected PermissionID to be updated to %d, got %d", newPermission.ID, updatedClientPermission.PermissionID)
	}
	if !updatedClientPermission.UpdatedAt.Time.After(clientPermission.CreatedAt.Time) {
		t.Error("Expected UpdatedAt to be after CreatedAt")
	}

	// Test case 2: Attempt to update a client permission with invalid ID
	invalidClientPermission := &record.ClientPermission{
		ID: 0,
	}
	err = database.UpdateClientPermission(context.Background(), nil, invalidClientPermission)
	if err == nil {
		t.Error("Expected an error when updating client permission with invalid ID, got nil")
	}
}

func TestGetClientPermissionByID(t *testing.T) {
	// Create a client for testing
	client := &record.Client{
		ClientIdentifier: "test_client_" + fake.LetterN(6),
		Description:      "Test Client",
	}
	err := database.CreateClient(context.Background(), nil, client)
	if err != nil {
		t.Fatalf("Failed to create test client: %v", err)
	}

	// Create a resource for testing
	resource := &record.Resource{
		ResourceIdentifier: "test_resource_" + fake.LetterN(6),
		Description:        "Test Resource",
	}
	err = database.CreateResource(context.Background(), nil, resource)
	if err != nil {
		t.Fatalf("Failed to create test resource: %v", err)
	}

	// Create a permission for testing
	permission := &record.Permission{
		PermissionIdentifier: "test_permission_" + fake.LetterN(6),
		Description:          "Test Permission",
		ResourceID:           resource.ID,
	}
	err = database.CreatePermission(context.Background(), nil, permission)
	if err != nil {
		t.Fatalf("Failed to create test permission: %v", err)
	}

	// Create a client permission for testing
	clientPermission := &record.ClientPermission{
		ClientID:     client.ID,
		PermissionID: permission.ID,
	}
	err = database.CreateClientPermission(context.Background(), nil, clientPermission)
	if err != nil {
		t.Fatalf("Failed to create client permission: %v", err)
	}

	// Test case 1: Successfully retrieve an existing client permission
	retrievedClientPermission, err := database.GetClientPermissionByID(context.Background(), nil, clientPermission.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve client permission: %v", err)
	}
	if retrievedClientPermission == nil {
		t.Fatal("Expected to retrieve client permission, got nil")
	}
	if retrievedClientPermission.ID != clientPermission.ID {
		t.Errorf("Expected client permission ID %d, got %d", clientPermission.ID, retrievedClientPermission.ID)
	}
	if retrievedClientPermission.ClientID != client.ID {
		t.Errorf("Expected ClientID %d, got %d", client.ID, retrievedClientPermission.ClientID)
	}
	if retrievedClientPermission.PermissionID != permission.ID {
		t.Errorf("Expected PermissionID %d, got %d", permission.ID, retrievedClientPermission.PermissionID)
	}

	// Test case 2: Attempt to retrieve a non-existent client permission
	nonExistentPermission, err := database.GetClientPermissionByID(context.Background(), nil, clientPermission.ID+1000)
	if err != nil {
		t.Fatalf("Unexpected error when retrieving non-existent client permission: %v", err)
	}
	if nonExistentPermission != nil {
		t.Error("Expected nil when retrieving non-existent client permission, got a value")
	}

	// Test case 3: Attempt to retrieve a client permission with an invalid ID (0)
	invalidPermission, err := database.GetClientPermissionByID(context.Background(), nil, 0)
	if err != nil {
		t.Fatalf("Unexpected error when retrieving client permission with invalid ID: %v", err)
	}
	if invalidPermission != nil {
		t.Error("Expected nil when retrieving client permission with invalid ID, got a value")
	}
}

func TestGetClientPermissionByClientIDAndPermissionID(t *testing.T) {
	// Create a client for testing
	client := &record.Client{
		ClientIdentifier: "test_client_" + fake.LetterN(6),
		Description:      "Test Client",
	}
	err := database.CreateClient(context.Background(), nil, client)
	if err != nil {
		t.Fatalf("Failed to create test client: %v", err)
	}

	// Create a resource for testing
	resource := &record.Resource{
		ResourceIdentifier: "test_resource_" + fake.LetterN(6),
		Description:        "Test Resource",
	}
	err = database.CreateResource(context.Background(), nil, resource)
	if err != nil {
		t.Fatalf("Failed to create test resource: %v", err)
	}

	// Create a permission for testing
	permission := &record.Permission{
		PermissionIdentifier: "test_permission_" + fake.LetterN(6),
		Description:          "Test Permission",
		ResourceID:           resource.ID,
	}
	err = database.CreatePermission(context.Background(), nil, permission)
	if err != nil {
		t.Fatalf("Failed to create test permission: %v", err)
	}

	// Create a client permission for testing
	clientPermission := &record.ClientPermission{
		ClientID:     client.ID,
		PermissionID: permission.ID,
	}
	err = database.CreateClientPermission(context.Background(), nil, clientPermission)
	if err != nil {
		t.Fatalf("Failed to create client permission: %v", err)
	}

	// Test case 1: Successfully retrieve an existing client permission
	retrievedClientPermission, err := database.GetClientPermissionByClientIDAndPermissionID(context.Background(), nil, client.ID, permission.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve client permission: %v", err)
	}
	if retrievedClientPermission == nil {
		t.Fatal("Expected to retrieve client permission, got nil")
	}
	if retrievedClientPermission.ID != clientPermission.ID {
		t.Errorf("Expected client permission ID %d, got %d", clientPermission.ID, retrievedClientPermission.ID)
	}
	if retrievedClientPermission.ClientID != client.ID {
		t.Errorf("Expected ClientID %d, got %d", client.ID, retrievedClientPermission.ClientID)
	}
	if retrievedClientPermission.PermissionID != permission.ID {
		t.Errorf("Expected PermissionID %d, got %d", permission.ID, retrievedClientPermission.PermissionID)
	}

	// Test case 2: Attempt to retrieve a non-existent client permission
	nonExistentPermission, err := database.GetClientPermissionByClientIDAndPermissionID(context.Background(), nil, client.ID+1000, permission.ID+1000)
	if err != nil {
		t.Fatalf("Unexpected error when retrieving non-existent client permission: %v", err)
	}
	if nonExistentPermission != nil {
		t.Error("Expected nil when retrieving non-existent client permission, got a value")
	}
}

func TestGetClientPermissionsByClientID(t *testing.T) {
	// Create a client for testing
	client := &record.Client{
		ClientIdentifier: "test_client_" + fake.LetterN(6),
		Description:      "Test Client",
	}
	err := database.CreateClient(context.Background(), nil, client)
	if err != nil {
		t.Fatalf("Failed to create test client: %v", err)
	}

	// Create a resource for testing
	resource := &record.Resource{
		ResourceIdentifier: "test_resource_" + fake.LetterN(6),
		Description:        "Test Resource",
	}
	err = database.CreateResource(context.Background(), nil, resource)
	if err != nil {
		t.Fatalf("Failed to create test resource: %v", err)
	}

	// Create permissions for testing
	permissions := make([]*record.Permission, 3)
	for i := 0; i < 3; i++ {
		permissions[i] = &record.Permission{
			PermissionIdentifier: "test_permission_" + fake.LetterN(6),
			Description:          "Test Permission " + strconv.Itoa(i+1),
			ResourceID:           resource.ID,
		}
		err = database.CreatePermission(context.Background(), nil, permissions[i])
		if err != nil {
			t.Fatalf("Failed to create test permission: %v", err)
		}
	}

	// Create client permissions for testing
	for _, perm := range permissions {
		clientPermission := &record.ClientPermission{
			ClientID:     client.ID,
			PermissionID: perm.ID,
		}
		err = database.CreateClientPermission(context.Background(), nil, clientPermission)
		if err != nil {
			t.Fatalf("Failed to create client permission: %v", err)
		}
	}

	// Test case 1: Successfully retrieve all client permissions for a client
	retrievedClientPermissions, err := database.GetClientPermissionsByClientID(context.Background(), nil, client.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve client permissions: %v", err)
	}
	if len(retrievedClientPermissions) != 3 {
		t.Errorf("Expected to retrieve 3 client permissions, got %d", len(retrievedClientPermissions))
	}
	for _, cp := range retrievedClientPermissions {
		if cp.ClientID != client.ID {
			t.Errorf("Expected ClientID %d, got %d", client.ID, cp.ClientID)
		}
	}

	// Test case 2: Attempt to retrieve client permissions for a non-existent client
	nonExistentClientPermissions, err := database.GetClientPermissionsByClientID(context.Background(), nil, client.ID+1000)
	if err != nil {
		t.Fatalf("Unexpected error when retrieving client permissions for non-existent client: %v", err)
	}
	if len(nonExistentClientPermissions) != 0 {
		t.Errorf("Expected 0 client permissions for non-existent client, got %d", len(nonExistentClientPermissions))
	}
}

func TestDeleteClientPermission(t *testing.T) {
	// Create a client for testing
	client := &record.Client{
		ClientIdentifier: "test_client_" + fake.LetterN(6),
		Description:      "Test Client",
	}
	err := database.CreateClient(context.Background(), nil, client)
	if err != nil {
		t.Fatalf("Failed to create test client: %v", err)
	}

	// Create a resource for testing
	resource := &record.Resource{
		ResourceIdentifier: "test_resource_" + fake.LetterN(6),
		Description:        "Test Resource",
	}
	err = database.CreateResource(context.Background(), nil, resource)
	if err != nil {
		t.Fatalf("Failed to create test resource: %v", err)
	}

	// Create a permission for testing
	permission := &record.Permission{
		PermissionIdentifier: "test_permission_" + fake.LetterN(6),
		Description:          "Test Permission",
		ResourceID:           resource.ID,
	}
	err = database.CreatePermission(context.Background(), nil, permission)
	if err != nil {
		t.Fatalf("Failed to create test permission: %v", err)
	}

	// Create a client permission for testing
	clientPermission := &record.ClientPermission{
		ClientID:     client.ID,
		PermissionID: permission.ID,
	}
	err = database.CreateClientPermission(context.Background(), nil, clientPermission)
	if err != nil {
		t.Fatalf("Failed to create client permission: %v", err)
	}

	// Test case 1: Successfully delete an existing client permission
	err = database.DeleteClientPermission(context.Background(), nil, clientPermission.ID)
	if err != nil {
		t.Fatalf("Failed to delete client permission: %v", err)
	}

	// Verify that the client permission has been deleted
	deletedClientPermission, err := database.GetClientPermissionByID(context.Background(), nil, clientPermission.ID)
	if err != nil {
		t.Fatalf("Unexpected error when retrieving deleted client permission: %v", err)
	}
	if deletedClientPermission != nil {
		t.Error("Expected nil when retrieving deleted client permission, got a value")
	}

	// Test case 2: Attempt to delete a non-existent client permission
	err = database.DeleteClientPermission(context.Background(), nil, clientPermission.ID+1000)
	if err != nil {
		t.Fatalf("Unexpected error when deleting non-existent client permission: %v", err)
	}
}
