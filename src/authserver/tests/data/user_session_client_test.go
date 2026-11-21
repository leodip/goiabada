package datatests

import (
	"context"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
)

func TestCreateUserSessionClient(t *testing.T) {
	user := createTestUser(t)
	userSession := createTestUserSession(t, user.ID)
	client := createTestClient(t)

	userSessionClient := &record.UserSessionClient{
		UserSessionID: userSession.ID,
		ClientID:      client.ID,
		Started:       time.Now().UTC().Truncate(time.Millisecond),
		LastAccessed:  time.Now().UTC().Truncate(time.Millisecond),
	}

	err := database.CreateUserSessionClient(context.Background(), nil, userSessionClient)
	if err != nil {
		t.Fatalf("Failed to create user session client: %v", err)
	}

	if userSessionClient.ID == 0 {
		t.Error("Expected non-zero ID after creation")
	}
	if !userSessionClient.CreatedAt.Valid || userSessionClient.CreatedAt.Time.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
	if !userSessionClient.UpdatedAt.Valid || userSessionClient.UpdatedAt.Time.IsZero() {
		t.Error("Expected UpdatedAt to be set")
	}

	retrievedUserSessionClient, err := database.GetUserSessionClientByID(context.Background(), nil, userSessionClient.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve created user session client: %v", err)
	}

	if retrievedUserSessionClient.UserSessionID != userSessionClient.UserSessionID {
		t.Errorf("Expected UserSessionID %d, got %d", userSessionClient.UserSessionID, retrievedUserSessionClient.UserSessionID)
	}
	if retrievedUserSessionClient.ClientID != userSessionClient.ClientID {
		t.Errorf("Expected ClientID %d, got %d", userSessionClient.ClientID, retrievedUserSessionClient.ClientID)
	}
	if !retrievedUserSessionClient.Started.Equal(userSessionClient.Started) {
		t.Errorf("Expected Started %v, got %v", userSessionClient.Started, retrievedUserSessionClient.Started)
	}
	if !retrievedUserSessionClient.LastAccessed.Equal(userSessionClient.LastAccessed) {
		t.Errorf("Expected LastAccessed %v, got %v", userSessionClient.LastAccessed, retrievedUserSessionClient.LastAccessed)
	}
}

func TestUpdateUserSessionClient(t *testing.T) {
	originalUserSessionClient := createTestUserSessionClient(t)
	user := createTestUser(t)
	newUserSession := createTestUserSession(t, user.ID)
	newClient := createTestClient(t)

	// Update all properties
	updatedUserSessionClient := &record.UserSessionClient{
		ID:            originalUserSessionClient.ID,
		UserSessionID: newUserSession.ID,
		ClientID:      newClient.ID,
		Started:       time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Millisecond),
		LastAccessed:  time.Now().UTC().Add(-1 * time.Hour).Truncate(time.Millisecond),
	}

	time.Sleep(timestampTick)

	err := database.UpdateUserSessionClient(context.Background(), nil, updatedUserSessionClient)
	if err != nil {
		t.Fatalf("Failed to update user session client: %v", err)
	}

	retrievedUserSessionClient, err := database.GetUserSessionClientByID(context.Background(), nil, updatedUserSessionClient.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve updated user session client: %v", err)
	}

	// The two keys are NOT among the updated properties: both are dont-update, so this statement
	// leaves the association pointing where it always did. That is
	// TestUpdateUserSessionClient_TheKeysAreNotRewritten's subject, and the reason is a SQL Server
	// foreign key re-check that put a shared clients lock under a session bump (#139). Asserted
	// here too because this test writes them, so it would otherwise pass silently either way.
	if retrievedUserSessionClient.UserSessionID != originalUserSessionClient.UserSessionID {
		t.Errorf("Expected UserSessionID to stay %d, got %d", originalUserSessionClient.UserSessionID, retrievedUserSessionClient.UserSessionID)
	}
	if retrievedUserSessionClient.ClientID != originalUserSessionClient.ClientID {
		t.Errorf("Expected ClientID to stay %d, got %d", originalUserSessionClient.ClientID, retrievedUserSessionClient.ClientID)
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
}

func TestGetUserSessionClientByID(t *testing.T) {
	userSessionClient := createTestUserSessionClient(t)

	retrievedUserSessionClient, err := database.GetUserSessionClientByID(context.Background(), nil, userSessionClient.ID)
	if err != nil {
		t.Fatalf("Failed to get user session client by ID: %v", err)
	}

	if retrievedUserSessionClient.ID != userSessionClient.ID {
		t.Errorf("Expected ID %d, got %d", userSessionClient.ID, retrievedUserSessionClient.ID)
	}
	if retrievedUserSessionClient.UserSessionID != userSessionClient.UserSessionID {
		t.Errorf("Expected UserSessionID %d, got %d", userSessionClient.UserSessionID, retrievedUserSessionClient.UserSessionID)
	}

	nonExistentUserSessionClient, err := database.GetUserSessionClientByID(context.Background(), nil, 99999)
	if err != nil {
		t.Errorf("Expected no error for non-existent user session client, got: %v", err)
	}
	if nonExistentUserSessionClient != nil {
		t.Errorf("Expected nil for non-existent user session client, got a user session client with ID: %d", nonExistentUserSessionClient.ID)
	}
}

func TestGetUserSessionClientsByUserSessionID(t *testing.T) {
	user := createTestUser(t)
	userSession := createTestUserSession(t, user.ID)
	client1 := createTestClient(t)
	client2 := createTestClient(t)

	userSessionClient1 := createTestUserSessionClientWithIDs(t, userSession.ID, client1.ID)
	userSessionClient2 := createTestUserSessionClientWithIDs(t, userSession.ID, client2.ID)

	userSessionClients, err := database.GetUserSessionClientsByUserSessionID(context.Background(), nil, userSession.ID)
	if err != nil {
		t.Fatalf("Failed to get user session clients by user session ID: %v", err)
	}

	if len(userSessionClients) != 2 {
		t.Errorf("Expected 2 user session clients, got %d", len(userSessionClients))
	}

	foundClient1 := false
	foundClient2 := false
	for _, usc := range userSessionClients {
		if usc.ID == userSessionClient1.ID {
			foundClient1 = true
		}
		if usc.ID == userSessionClient2.ID {
			foundClient2 = true
		}
	}

	if !foundClient1 || !foundClient2 {
		t.Error("Not all created user session clients were found")
	}
}

func TestDeleteUserSessionClient(t *testing.T) {
	userSessionClient := createTestUserSessionClient(t)

	err := database.DeleteUserSessionClient(context.Background(), nil, userSessionClient.ID)
	if err != nil {
		t.Fatalf("Failed to delete user session client: %v", err)
	}

	deletedUserSessionClient, err := database.GetUserSessionClientByID(context.Background(), nil, userSessionClient.ID)
	if err != nil {
		t.Fatalf("Error while checking for deleted user session client: %v", err)
	}
	if deletedUserSessionClient != nil {
		t.Errorf("User session client still exists after deletion")
	}

	err = database.DeleteUserSessionClient(context.Background(), nil, 99999)
	if err != nil {
		t.Errorf("Expected no error when deleting non-existent user session client, got: %v", err)
	}
}

func createTestUserSessionClient(t *testing.T) *record.UserSessionClient {
	user := createTestUser(t)
	userSession := createTestUserSession(t, user.ID)
	client := createTestClient(t)
	return createTestUserSessionClientWithIDs(t, userSession.ID, client.ID)
}

func createTestUserSessionClientWithIDs(t *testing.T, userSessionID, clientID int64) *record.UserSessionClient {
	userSessionClient := &record.UserSessionClient{
		UserSessionID: userSessionID,
		ClientID:      clientID,
		Started:       time.Now().UTC(),
		LastAccessed:  time.Now().UTC(),
	}
	err := database.CreateUserSessionClient(context.Background(), nil, userSessionClient)
	if err != nil {
		t.Fatalf("Failed to create test user session client: %v", err)
	}
	return userSessionClient
}
