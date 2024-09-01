package datatests

import (
	"database/sql"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/models"
)

func TestCreateUserConsent(t *testing.T) {
	client := createTestClient(t)
	user := createTestUser(t)

	userConsent := &models.UserConsent{
		UserId:    user.Id,
		ClientId:  client.Id,
		Scope:     "openid profile",
		GrantedAt: sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true},
	}

	err := database.CreateUserConsent(nil, userConsent)
	if err != nil {
		t.Fatalf("Failed to create user consent: %v", err)
	}

	if userConsent.Id == 0 {
		t.Error("Expected non-zero ID after creation")
	}
	if !userConsent.CreatedAt.Valid || userConsent.CreatedAt.Time.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
	if !userConsent.UpdatedAt.Valid || userConsent.UpdatedAt.Time.IsZero() {
		t.Error("Expected UpdatedAt to be set")
	}

	retrievedConsent, err := database.GetUserConsentById(nil, userConsent.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve created user consent: %v", err)
	}

	if retrievedConsent.UserId != userConsent.UserId {
		t.Errorf("Expected UserId %d, got %d", userConsent.UserId, retrievedConsent.UserId)
	}
	if retrievedConsent.ClientId != userConsent.ClientId {
		t.Errorf("Expected ClientId %d, got %d", userConsent.ClientId, retrievedConsent.ClientId)
	}
	if retrievedConsent.Scope != userConsent.Scope {
		t.Errorf("Expected Scope %s, got %s", userConsent.Scope, retrievedConsent.Scope)
	}
	if !retrievedConsent.GrantedAt.Valid || !retrievedConsent.GrantedAt.Time.Equal(userConsent.GrantedAt.Time) {
		t.Errorf("Expected GrantedAt %v, got %v", userConsent.GrantedAt, retrievedConsent.GrantedAt)
	}
}

func TestUpdateUserConsent(t *testing.T) {
	userConsent := createTestUserConsent(t)

	userConsent.Scope = "openid profile email"
	userConsent.GrantedAt = sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true}

	time.Sleep(time.Millisecond * 100)

	err := database.UpdateUserConsent(nil, userConsent)
	if err != nil {
		t.Fatalf("Failed to update user consent: %v", err)
	}

	updatedConsent, err := database.GetUserConsentById(nil, userConsent.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve updated user consent: %v", err)
	}

	if updatedConsent.Scope != userConsent.Scope {
		t.Errorf("Expected Scope %s, got %s", userConsent.Scope, updatedConsent.Scope)
	}
	if !updatedConsent.GrantedAt.Valid || !updatedConsent.GrantedAt.Time.Equal(userConsent.GrantedAt.Time) {
		t.Errorf("Expected GrantedAt %v, got %v", userConsent.GrantedAt, updatedConsent.GrantedAt)
	}
	if !updatedConsent.UpdatedAt.Time.After(updatedConsent.CreatedAt.Time) {
		t.Error("Expected UpdatedAt to be after CreatedAt")
	}
}

func TestGetUserConsentById(t *testing.T) {
	userConsent := createTestUserConsent(t)

	retrievedConsent, err := database.GetUserConsentById(nil, userConsent.Id)
	if err != nil {
		t.Fatalf("Failed to get user consent by ID: %v", err)
	}

	if retrievedConsent.Id != userConsent.Id {
		t.Errorf("Expected ID %d, got %d", userConsent.Id, retrievedConsent.Id)
	}
	if retrievedConsent.UserId != userConsent.UserId {
		t.Errorf("Expected UserId %d, got %d", userConsent.UserId, retrievedConsent.UserId)
	}
	if retrievedConsent.ClientId != userConsent.ClientId {
		t.Errorf("Expected ClientId %d, got %d", userConsent.ClientId, retrievedConsent.ClientId)
	}

	nonExistentConsent, err := database.GetUserConsentById(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error for non-existent user consent, got: %v", err)
	}
	if nonExistentConsent != nil {
		t.Errorf("Expected nil for non-existent user consent, got a consent with ID: %d", nonExistentConsent.Id)
	}
}

func TestGetConsentByUserIdAndClientId(t *testing.T) {
	userConsent := createTestUserConsent(t)

	retrievedConsent, err := database.GetConsentByUserIdAndClientId(nil, userConsent.UserId, userConsent.ClientId)
	if err != nil {
		t.Fatalf("Failed to get consent by user ID and client ID: %v", err)
	}

	if retrievedConsent.Id != userConsent.Id {
		t.Errorf("Expected ID %d, got %d", userConsent.Id, retrievedConsent.Id)
	}
	if retrievedConsent.UserId != userConsent.UserId {
		t.Errorf("Expected UserId %d, got %d", userConsent.UserId, retrievedConsent.UserId)
	}
	if retrievedConsent.ClientId != userConsent.ClientId {
		t.Errorf("Expected ClientId %d, got %d", userConsent.ClientId, retrievedConsent.ClientId)
	}

	nonExistentConsent, err := database.GetConsentByUserIdAndClientId(nil, 99999, 99999)
	if err != nil {
		t.Errorf("Expected no error for non-existent user consent, got: %v", err)
	}
	if nonExistentConsent != nil {
		t.Errorf("Expected nil for non-existent user consent, got a consent with ID: %d", nonExistentConsent.Id)
	}
}

func TestUserConsentsLoadClients(t *testing.T) {
	userConsent1 := createTestUserConsent(t)
	userConsent2 := createTestUserConsent(t)

	userConsents := []models.UserConsent{*userConsent1, *userConsent2}

	err := database.UserConsentsLoadClients(nil, userConsents)
	if err != nil {
		t.Fatalf("Failed to load clients for user consents: %v", err)
	}

	for _, consent := range userConsents {
		if consent.Client.Id != consent.ClientId {
			t.Errorf("Expected Client.Id %d, got %d", consent.ClientId, consent.Client.Id)
		}
	}
}

func TestGetConsentsByUserId(t *testing.T) {
	user := createTestUser(t)
	userConsent1 := createTestUserConsentForUser(t, user.Id)
	userConsent2 := createTestUserConsentForUser(t, user.Id)

	consents, err := database.GetConsentsByUserId(nil, user.Id)
	if err != nil {
		t.Fatalf("Failed to get consents by user ID: %v", err)
	}

	if len(consents) != 2 {
		t.Errorf("Expected 2 consents, got %d", len(consents))
	}

	consentIds := make(map[int64]bool)
	for _, consent := range consents {
		consentIds[consent.Id] = true
		if consent.UserId != user.Id {
			t.Errorf("Expected UserId %d, got %d", user.Id, consent.UserId)
		}
	}

	if !consentIds[userConsent1.Id] || !consentIds[userConsent2.Id] {
		t.Error("Not all created consents were found in GetConsentsByUserId result")
	}
}

func TestDeleteUserConsent(t *testing.T) {
	userConsent := createTestUserConsent(t)

	err := database.DeleteUserConsent(nil, userConsent.Id)
	if err != nil {
		t.Fatalf("Failed to delete user consent: %v", err)
	}

	deletedConsent, err := database.GetUserConsentById(nil, userConsent.Id)
	if err != nil {
		t.Fatalf("Error while checking for deleted user consent: %v", err)
	}
	if deletedConsent != nil {
		t.Errorf("User consent still exists after deletion")
	}

	err = database.DeleteUserConsent(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error when deleting non-existent user consent, got: %v", err)
	}
}

func createTestUserConsent(t *testing.T) *models.UserConsent {
	client := createTestClient(t)
	user := createTestUser(t)

	userConsent := &models.UserConsent{
		UserId:    user.Id,
		ClientId:  client.Id,
		Scope:     "openid profile",
		GrantedAt: sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true},
	}

	err := database.CreateUserConsent(nil, userConsent)
	if err != nil {
		t.Fatalf("Failed to create test user consent: %v", err)
	}

	return userConsent
}

func createTestUserConsentForUser(t *testing.T, userId int64) *models.UserConsent {
	client := createTestClient(t)

	userConsent := &models.UserConsent{
		UserId:   userId,
		ClientId: client.Id,
		Scope:    "openid profile",
	}

	err := database.CreateUserConsent(nil, userConsent)
	if err != nil {
		t.Fatalf("Failed to create test user consent: %v", err)
	}

	return userConsent
}
