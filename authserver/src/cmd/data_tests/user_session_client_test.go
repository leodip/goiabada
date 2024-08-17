package datatests

import (
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/models"
)

func TestCreateUserSessionClient(t *testing.T) {
	user := createTestUser(t)
	userSession := createTestUserSession(t, user.Id)
	client := createTestClient(t)

	userSessionClient := &models.UserSessionClient{
		UserSessionId: userSession.Id,
		ClientId:      client.Id,
		Started:       time.Now().UTC().Truncate(time.Millisecond),
		LastAccessed:  time.Now().UTC().Truncate(time.Millisecond),
	}

	err := database.CreateUserSessionClient(nil, userSessionClient)
	if err != nil {
		t.Fatalf("Failed to create user session client: %v", err)
	}

	if userSessionClient.Id == 0 {
		t.Error("Expected non-zero ID after creation")
	}
	if !userSessionClient.CreatedAt.Valid || userSessionClient.CreatedAt.Time.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
	if !userSessionClient.UpdatedAt.Valid || userSessionClient.UpdatedAt.Time.IsZero() {
		t.Error("Expected UpdatedAt to be set")
	}

	retrievedUserSessionClient, err := database.GetUserSessionClientById(nil, userSessionClient.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve created user session client: %v", err)
	}

	if retrievedUserSessionClient.UserSessionId != userSessionClient.UserSessionId {
		t.Errorf("Expected UserSessionId %d, got %d", userSessionClient.UserSessionId, retrievedUserSessionClient.UserSessionId)
	}
	if retrievedUserSessionClient.ClientId != userSessionClient.ClientId {
		t.Errorf("Expected ClientId %d, got %d", userSessionClient.ClientId, retrievedUserSessionClient.ClientId)
	}
	if !retrievedUserSessionClient.Started.Equal(userSessionClient.Started) {
		t.Errorf("Expected Started %v, got %v", userSessionClient.Started, retrievedUserSessionClient.Started)
	}
	if !retrievedUserSessionClient.LastAccessed.Equal(userSessionClient.LastAccessed) {
		t.Errorf("Expected LastAccessed %v, got %v", userSessionClient.LastAccessed, retrievedUserSessionClient.LastAccessed)
	}

	database.DeleteUserSessionClient(nil, userSessionClient.Id)
	database.DeleteUserSession(nil, userSession.Id)
	database.DeleteClient(nil, client.Id)
}

func TestUpdateUserSessionClient(t *testing.T) {
	originalUserSessionClient := createTestUserSessionClient(t)
	user := createTestUser(t)
	newUserSession := createTestUserSession(t, user.Id)
	newClient := createTestClient(t)

	// Update all properties
	updatedUserSessionClient := &models.UserSessionClient{
		Id:            originalUserSessionClient.Id,
		UserSessionId: newUserSession.Id,
		ClientId:      newClient.Id,
		Started:       time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Millisecond),
		LastAccessed:  time.Now().UTC().Add(-1 * time.Hour).Truncate(time.Millisecond),
	}

	time.Sleep(time.Millisecond * 100)

	err := database.UpdateUserSessionClient(nil, updatedUserSessionClient)
	if err != nil {
		t.Fatalf("Failed to update user session client: %v", err)
	}

	retrievedUserSessionClient, err := database.GetUserSessionClientById(nil, updatedUserSessionClient.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve updated user session client: %v", err)
	}

	// Verify all updated properties
	if retrievedUserSessionClient.UserSessionId != updatedUserSessionClient.UserSessionId {
		t.Errorf("Expected UserSessionId %d, got %d", updatedUserSessionClient.UserSessionId, retrievedUserSessionClient.UserSessionId)
	}
	if retrievedUserSessionClient.ClientId != updatedUserSessionClient.ClientId {
		t.Errorf("Expected ClientId %d, got %d", updatedUserSessionClient.ClientId, retrievedUserSessionClient.ClientId)
	}
	if !retrievedUserSessionClient.Started.Equal(updatedUserSessionClient.Started) {
		t.Errorf("Expected Started %v, got %v", updatedUserSessionClient.Started, retrievedUserSessionClient.Started)
	}
	if !retrievedUserSessionClient.LastAccessed.Equal(updatedUserSessionClient.LastAccessed) {
		t.Errorf("Expected LastAccessed %v, got %v", updatedUserSessionClient.LastAccessed, retrievedUserSessionClient.LastAccessed)
	}
	if !retrievedUserSessionClient.UpdatedAt.Time.After(retrievedUserSessionClient.CreatedAt.Time) {
		t.Error("Expected UpdatedAt to be after CreatedAt")
	}

	// Clean up
	database.DeleteUserSessionClient(nil, updatedUserSessionClient.Id)
	database.DeleteUserSession(nil, originalUserSessionClient.UserSessionId)
	database.DeleteUserSession(nil, newUserSession.Id)
	database.DeleteClient(nil, originalUserSessionClient.ClientId)
	database.DeleteClient(nil, newClient.Id)
}

func TestGetUserSessionClientById(t *testing.T) {
	userSessionClient := createTestUserSessionClient(t)

	retrievedUserSessionClient, err := database.GetUserSessionClientById(nil, userSessionClient.Id)
	if err != nil {
		t.Fatalf("Failed to get user session client by ID: %v", err)
	}

	if retrievedUserSessionClient.Id != userSessionClient.Id {
		t.Errorf("Expected ID %d, got %d", userSessionClient.Id, retrievedUserSessionClient.Id)
	}
	if retrievedUserSessionClient.UserSessionId != userSessionClient.UserSessionId {
		t.Errorf("Expected UserSessionId %d, got %d", userSessionClient.UserSessionId, retrievedUserSessionClient.UserSessionId)
	}

	nonExistentUserSessionClient, err := database.GetUserSessionClientById(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error for non-existent user session client, got: %v", err)
	}
	if nonExistentUserSessionClient != nil {
		t.Errorf("Expected nil for non-existent user session client, got a user session client with ID: %d", nonExistentUserSessionClient.Id)
	}

	database.DeleteUserSessionClient(nil, userSessionClient.Id)
	database.DeleteUserSession(nil, userSessionClient.UserSessionId)
	database.DeleteClient(nil, userSessionClient.ClientId)
}

func TestGetUserSessionClientsByUserSessionId(t *testing.T) {
	user := createTestUser(t)
	userSession := createTestUserSession(t, user.Id)
	client1 := createTestClient(t)
	client2 := createTestClient(t)

	userSessionClient1 := createTestUserSessionClientWithIds(t, userSession.Id, client1.Id)
	userSessionClient2 := createTestUserSessionClientWithIds(t, userSession.Id, client2.Id)

	userSessionClients, err := database.GetUserSessionClientsByUserSessionId(nil, userSession.Id)
	if err != nil {
		t.Fatalf("Failed to get user session clients by user session ID: %v", err)
	}

	if len(userSessionClients) != 2 {
		t.Errorf("Expected 2 user session clients, got %d", len(userSessionClients))
	}

	foundClient1 := false
	foundClient2 := false
	for _, usc := range userSessionClients {
		if usc.Id == userSessionClient1.Id {
			foundClient1 = true
		}
		if usc.Id == userSessionClient2.Id {
			foundClient2 = true
		}
	}

	if !foundClient1 || !foundClient2 {
		t.Error("Not all created user session clients were found")
	}

	database.DeleteUserSessionClient(nil, userSessionClient1.Id)
	database.DeleteUserSessionClient(nil, userSessionClient2.Id)
	database.DeleteUserSession(nil, userSession.Id)
	database.DeleteClient(nil, client1.Id)
	database.DeleteClient(nil, client2.Id)
}

func TestDeleteUserSessionClient(t *testing.T) {
	userSessionClient := createTestUserSessionClient(t)

	err := database.DeleteUserSessionClient(nil, userSessionClient.Id)
	if err != nil {
		t.Fatalf("Failed to delete user session client: %v", err)
	}

	deletedUserSessionClient, err := database.GetUserSessionClientById(nil, userSessionClient.Id)
	if err != nil {
		t.Fatalf("Error while checking for deleted user session client: %v", err)
	}
	if deletedUserSessionClient != nil {
		t.Errorf("User session client still exists after deletion")
	}

	err = database.DeleteUserSessionClient(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error when deleting non-existent user session client, got: %v", err)
	}

	database.DeleteUserSession(nil, userSessionClient.UserSessionId)
	database.DeleteClient(nil, userSessionClient.ClientId)
}

func createTestUserSessionClient(t *testing.T) *models.UserSessionClient {
	user := createTestUser(t)
	userSession := createTestUserSession(t, user.Id)
	client := createTestClient(t)
	return createTestUserSessionClientWithIds(t, userSession.Id, client.Id)
}

func createTestUserSessionClientWithIds(t *testing.T, userSessionId, clientId int64) *models.UserSessionClient {
	userSessionClient := &models.UserSessionClient{
		UserSessionId: userSessionId,
		ClientId:      clientId,
		Started:       time.Now().UTC(),
		LastAccessed:  time.Now().UTC(),
	}
	err := database.CreateUserSessionClient(nil, userSessionClient)
	if err != nil {
		t.Fatalf("Failed to create test user session client: %v", err)
	}
	return userSessionClient
}
