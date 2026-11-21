package datatests

import (
	"context"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
)

func TestCreateUserPermission(t *testing.T) {
	user := createTestUser(t)
	resource := createTestResource(t)
	permission := createTestPermission(t, resource)

	userPermission := &record.UserPermission{
		UserID:       user.ID,
		PermissionID: permission.ID,
	}

	err := database.CreateUserPermission(context.Background(), nil, userPermission)
	if err != nil {
		t.Fatalf("Failed to create user permission: %v", err)
	}

	if userPermission.ID == 0 {
		t.Error("Expected non-zero ID after creation")
	}
	if !userPermission.CreatedAt.Valid || userPermission.CreatedAt.Time.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
	if !userPermission.UpdatedAt.Valid || userPermission.UpdatedAt.Time.IsZero() {
		t.Error("Expected UpdatedAt to be set")
	}

	retrievedUserPermission, err := database.GetUserPermissionByID(context.Background(), nil, userPermission.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve created user permission: %v", err)
	}

	if retrievedUserPermission.UserID != userPermission.UserID {
		t.Errorf("Expected UserID %d, got %d", userPermission.UserID, retrievedUserPermission.UserID)
	}
	if retrievedUserPermission.PermissionID != userPermission.PermissionID {
		t.Errorf("Expected PermissionID %d, got %d", userPermission.PermissionID, retrievedUserPermission.PermissionID)
	}
}

func TestUpdateUserPermission(t *testing.T) {
	userPermission := createTestUserPermission(t)

	resource := createTestResource(t)
	permission := createTestPermission(t, resource)

	user := createTestUser(t)

	userPermission.UserID = user.ID
	userPermission.PermissionID = permission.ID

	time.Sleep(timestampTick)

	err := database.UpdateUserPermission(context.Background(), nil, userPermission)
	if err != nil {
		t.Fatalf("Failed to update user permission: %v", err)
	}

	updatedUserPermission, err := database.GetUserPermissionByID(context.Background(), nil, userPermission.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve updated user permission: %v", err)
	}

	if !updatedUserPermission.UpdatedAt.Time.After(updatedUserPermission.CreatedAt.Time) {
		t.Error("Expected UpdatedAt to be after CreatedAt")
	}

	if updatedUserPermission.UserID != user.ID {
		t.Errorf("Expected UserID %d, got %d", user.ID, updatedUserPermission.UserID)
	}

	if updatedUserPermission.PermissionID != permission.ID {
		t.Errorf("Expected PermissionID %d, got %d", permission.ID, updatedUserPermission.PermissionID)
	}
}

func TestGetUserPermissionByID(t *testing.T) {
	userPermission := createTestUserPermission(t)

	retrievedUserPermission, err := database.GetUserPermissionByID(context.Background(), nil, userPermission.ID)
	if err != nil {
		t.Fatalf("Failed to get user permission by ID: %v", err)
	}

	if retrievedUserPermission.ID != userPermission.ID {
		t.Errorf("Expected ID %d, got %d", userPermission.ID, retrievedUserPermission.ID)
	}
	if retrievedUserPermission.UserID != userPermission.UserID {
		t.Errorf("Expected UserID %d, got %d", userPermission.UserID, retrievedUserPermission.UserID)
	}
	if retrievedUserPermission.PermissionID != userPermission.PermissionID {
		t.Errorf("Expected PermissionID %d, got %d", userPermission.PermissionID, retrievedUserPermission.PermissionID)
	}

	nonExistentUserPermission, err := database.GetUserPermissionByID(context.Background(), nil, 99999)
	if err != nil {
		t.Errorf("Expected no error for non-existent user permission, got: %v", err)
	}
	if nonExistentUserPermission != nil {
		t.Errorf("Expected nil for non-existent user permission, got a user permission with ID: %d", nonExistentUserPermission.ID)
	}
}

func TestGetUserPermissionsByUserIDs(t *testing.T) {
	userPermission1 := createTestUserPermission(t)
	userPermission2 := createTestUserPermission(t)

	userIDs := []int64{userPermission1.UserID, userPermission2.UserID}

	userPermissions, err := database.GetUserPermissionsByUserIDs(context.Background(), nil, userIDs)
	if err != nil {
		t.Fatalf("Failed to get user permissions by user IDs: %v", err)
	}

	if len(userPermissions) < 2 {
		t.Errorf("Expected at least 2 user permissions, got %d", len(userPermissions))
	}

	foundUserPermission1 := false
	foundUserPermission2 := false
	for _, up := range userPermissions {
		if up.ID == userPermission1.ID {
			foundUserPermission1 = true
		}
		if up.ID == userPermission2.ID {
			foundUserPermission2 = true
		}
	}

	if !foundUserPermission1 || !foundUserPermission2 {
		t.Error("Not all created user permissions were found in GetUserPermissionsByUserIDs result")
	}
}

func TestGetUserPermissionsByUserID(t *testing.T) {
	user := createTestUser(t)
	resource1 := createTestResource(t)
	resource2 := createTestResource(t)
	permission1 := createTestPermission(t, resource1)
	permission2 := createTestPermission(t, resource2)

	userPermission1 := createTestUserPermissionWithUserAndPermission(t, user.ID, permission1.ID)
	userPermission2 := createTestUserPermissionWithUserAndPermission(t, user.ID, permission2.ID)

	userPermissions, err := database.GetUserPermissionsByUserID(context.Background(), nil, user.ID)
	if err != nil {
		t.Fatalf("Failed to get user permissions by user ID: %v", err)
	}

	if len(userPermissions) != 2 {
		t.Errorf("Expected 2 user permissions, got %d", len(userPermissions))
	}

	foundUserPermission1 := false
	foundUserPermission2 := false
	for _, up := range userPermissions {
		if up.ID == userPermission1.ID {
			foundUserPermission1 = true
		}
		if up.ID == userPermission2.ID {
			foundUserPermission2 = true
		}
	}

	if !foundUserPermission1 || !foundUserPermission2 {
		t.Error("Not all created user permissions were found in GetUserPermissionsByUserID result")
	}
}

func TestGetUserPermissionByUserIDAndPermissionID(t *testing.T) {
	userPermission := createTestUserPermission(t)

	retrievedUserPermission, err := database.GetUserPermissionByUserIDAndPermissionID(context.Background(), nil, userPermission.UserID, userPermission.PermissionID)
	if err != nil {
		t.Fatalf("Failed to get user permission by user ID and permission ID: %v", err)
	}

	if retrievedUserPermission.ID != userPermission.ID {
		t.Errorf("Expected ID %d, got %d", userPermission.ID, retrievedUserPermission.ID)
	}
	if retrievedUserPermission.UserID != userPermission.UserID {
		t.Errorf("Expected UserID %d, got %d", userPermission.UserID, retrievedUserPermission.UserID)
	}
	if retrievedUserPermission.PermissionID != userPermission.PermissionID {
		t.Errorf("Expected PermissionID %d, got %d", userPermission.PermissionID, retrievedUserPermission.PermissionID)
	}

	nonExistentUserPermission, err := database.GetUserPermissionByUserIDAndPermissionID(context.Background(), nil, 99999, 99999)
	if err != nil {
		t.Errorf("Expected no error for non-existent user permission, got: %v", err)
	}
	if nonExistentUserPermission != nil {
		t.Errorf("Expected nil for non-existent user permission, got a user permission with ID: %d", nonExistentUserPermission.ID)
	}
}

func TestGetUsersByPermissionIDPaginated(t *testing.T) {
	resource := createTestResource(t)
	permission := createTestPermission(t, resource)
	numUsers := 25

	createdUserIDs := make([]int64, 0, numUsers)
	for i := 0; i < numUsers; i++ {
		user := createTestUser(t)
		createTestUserPermissionWithUserAndPermission(t, user.ID, permission.ID)
		createdUserIDs = append(createdUserIDs, user.ID)
	}

	// Test first page
	users, total, err := database.GetUsersByPermissionIDPaginated(context.Background(), nil, permission.ID, 1, 10)
	if err != nil {
		t.Fatalf("Failed to get paginated users: %v", err)
	}

	if len(users) != 10 {
		t.Errorf("Expected 10 users on the first page, got %d", len(users))
	}

	if total != numUsers {
		t.Errorf("Expected total to be %d, got %d", numUsers, total)
	}

	// Test second page
	users, total, err = database.GetUsersByPermissionIDPaginated(context.Background(), nil, permission.ID, 2, 10)
	if err != nil {
		t.Fatalf("Failed to get second page of paginated users: %v", err)
	}

	if len(users) != 10 {
		t.Errorf("Expected 10 users on the second page, got %d", len(users))
	}

	if total != numUsers {
		t.Errorf("Expected total to be %d, got %d", numUsers, total)
	}

	// Test last page
	users, total, err = database.GetUsersByPermissionIDPaginated(context.Background(), nil, permission.ID, 3, 10)
	if err != nil {
		t.Fatalf("Failed to get last page of paginated users: %v", err)
	}

	if len(users) != 5 {
		t.Errorf("Expected 5 users on the last page, got %d", len(users))
	}

	if total != numUsers {
		t.Errorf("Expected total to be %d, got %d", numUsers, total)
	}

	// Test page beyond total
	users, total, err = database.GetUsersByPermissionIDPaginated(context.Background(), nil, permission.ID, 4, 10)
	if err != nil {
		t.Fatalf("Failed to get page beyond total: %v", err)
	}

	if len(users) != 0 {
		t.Errorf("Expected 0 users on page beyond total, got %d", len(users))
	}

	if total != numUsers {
		t.Errorf("Expected total to be %d, got %d", numUsers, total)
	}

	// Verify all created users are included in the total
	allUsers, allTotal, err := database.GetUsersByPermissionIDPaginated(context.Background(), nil, permission.ID, 1, numUsers)
	if err != nil {
		t.Fatalf("Failed to get all users: %v", err)
	}

	if allTotal != numUsers {
		t.Errorf("Expected total to be %d, got %d", numUsers, allTotal)
	}

	if len(allUsers) != numUsers {
		t.Errorf("Expected %d users, got %d", numUsers, len(allUsers))
	}

	foundUsers := make(map[int64]bool)
	for _, user := range allUsers {
		foundUsers[user.ID] = true
	}

	for _, userID := range createdUserIDs {
		if !foundUsers[userID] {
			t.Errorf("Created user with ID %d not found in paginated results", userID)
		}
	}
}

func TestDeleteUserPermission(t *testing.T) {
	userPermission := createTestUserPermission(t)

	err := database.DeleteUserPermission(context.Background(), nil, userPermission.ID)
	if err != nil {
		t.Fatalf("Failed to delete user permission: %v", err)
	}

	deletedUserPermission, err := database.GetUserPermissionByID(context.Background(), nil, userPermission.ID)
	if err != nil {
		t.Fatalf("Error while checking for deleted user permission: %v", err)
	}
	if deletedUserPermission != nil {
		t.Errorf("User permission still exists after deletion")
	}

	err = database.DeleteUserPermission(context.Background(), nil, 99999)
	if err != nil {
		t.Errorf("Expected no error when deleting non-existent user permission, got: %v", err)
	}
}

func createTestUserPermission(t *testing.T) *record.UserPermission {
	user := createTestUser(t)
	resource := createTestResource(t)
	permission := createTestPermission(t, resource)
	return createTestUserPermissionWithUserAndPermission(t, user.ID, permission.ID)
}

func createTestUserPermissionWithUserAndPermission(t *testing.T, userID, permissionID int64) *record.UserPermission {
	userPermission := &record.UserPermission{
		UserID:       userID,
		PermissionID: permissionID,
	}
	err := database.CreateUserPermission(context.Background(), nil, userPermission)
	if err != nil {
		t.Fatalf("Failed to create test user permission: %v", err)
	}
	return userPermission
}

// TestGetUsersByPermissionIDPaginated_EnlistsInTheCallersTransaction pins #413's fourth site: the
// count query beside the page passed nil where the page took the caller's transaction, so the two
// halves of one answer were read on two connections.
//
// The rows are created inside the transaction for the reason ClientLoadPermissions' case gives.
func TestGetUsersByPermissionIDPaginated_EnlistsInTheCallersTransaction(t *testing.T) {
	tx := beginTx(t)

	resource := &record.Resource{
		ResourceIdentifier: "tx_resource_" + fake.LetterN(8),
		Description:        "Transaction pass-through resource",
	}
	if err := database.CreateResource(context.Background(), tx, resource); err != nil {
		t.Fatalf("Failed to create resource inside the transaction: %v", err)
	}

	permission := &record.Permission{
		PermissionIdentifier: "tx_permission_" + fake.LetterN(8),
		Description:          "Transaction pass-through permission",
		ResourceID:           resource.ID,
	}
	if err := database.CreatePermission(context.Background(), tx, permission); err != nil {
		t.Fatalf("Failed to create permission inside the transaction: %v", err)
	}

	user := &record.User{
		Enabled:   true,
		Subject:   fake.UUID(),
		Username:  "u" + fake.LetterN(12),
		GivenName: "TxHolder" + fake.LetterN(6),
		Email:     fake.LetterN(12) + "@example.com",
	}
	if err := database.CreateUser(context.Background(), tx, user); err != nil {
		t.Fatalf("Failed to create user inside the transaction: %v", err)
	}

	userPermission := &record.UserPermission{UserID: user.ID, PermissionID: permission.ID}
	if err := database.CreateUserPermission(context.Background(), tx, userPermission); err != nil {
		t.Fatalf("Failed to create users_permissions row inside the transaction: %v", err)
	}

	users, total, err := database.GetUsersByPermissionIDPaginated(context.Background(), tx, permission.ID, 1, 10)
	if err != nil {
		t.Fatalf("GetUsersByPermissionIDPaginated through the transaction: %v", err)
	}

	if len(users) != 1 {
		t.Fatalf("Expected the transaction's own user, got %d", len(users))
	}
	if users[0].ID != user.ID {
		t.Errorf("Expected user %d, got %d", user.ID, users[0].ID)
	}
	if total != 1 {
		t.Errorf("Expected a total of 1 to agree with the one user on the page, got %d: "+
			"the count query ran outside the caller's transaction (#413)", total)
	}

	if err := database.RollbackTransaction(context.Background(), tx); err != nil {
		t.Fatalf("RollbackTransaction: %v", err)
	}
}
