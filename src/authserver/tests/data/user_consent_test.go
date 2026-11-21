package datatests

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
)

func TestCreateUserConsent(t *testing.T) {
	client := createTestClient(t)
	user := createTestUser(t)

	userConsent := &record.UserConsent{
		UserID:    user.ID,
		ClientID:  client.ID,
		Scope:     "openid profile",
		GrantedAt: sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true},
	}

	err := database.CreateUserConsent(context.Background(), nil, userConsent)
	if err != nil {
		t.Fatalf("Failed to create user consent: %v", err)
	}

	if userConsent.ID == 0 {
		t.Error("Expected non-zero ID after creation")
	}
	if !userConsent.CreatedAt.Valid || userConsent.CreatedAt.Time.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
	if !userConsent.UpdatedAt.Valid || userConsent.UpdatedAt.Time.IsZero() {
		t.Error("Expected UpdatedAt to be set")
	}

	retrievedConsent, err := database.GetUserConsentByID(context.Background(), nil, userConsent.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve created user consent: %v", err)
	}

	if retrievedConsent.UserID != userConsent.UserID {
		t.Errorf("Expected UserID %d, got %d", userConsent.UserID, retrievedConsent.UserID)
	}
	if retrievedConsent.ClientID != userConsent.ClientID {
		t.Errorf("Expected ClientID %d, got %d", userConsent.ClientID, retrievedConsent.ClientID)
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

	time.Sleep(timestampTick)

	err := database.UpdateUserConsent(context.Background(), nil, userConsent)
	if err != nil {
		t.Fatalf("Failed to update user consent: %v", err)
	}

	updatedConsent, err := database.GetUserConsentByID(context.Background(), nil, userConsent.ID)
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

func TestGetUserConsentByID(t *testing.T) {
	userConsent := createTestUserConsent(t)

	retrievedConsent, err := database.GetUserConsentByID(context.Background(), nil, userConsent.ID)
	if err != nil {
		t.Fatalf("Failed to get user consent by ID: %v", err)
	}

	if retrievedConsent.ID != userConsent.ID {
		t.Errorf("Expected ID %d, got %d", userConsent.ID, retrievedConsent.ID)
	}
	if retrievedConsent.UserID != userConsent.UserID {
		t.Errorf("Expected UserID %d, got %d", userConsent.UserID, retrievedConsent.UserID)
	}
	if retrievedConsent.ClientID != userConsent.ClientID {
		t.Errorf("Expected ClientID %d, got %d", userConsent.ClientID, retrievedConsent.ClientID)
	}

	nonExistentConsent, err := database.GetUserConsentByID(context.Background(), nil, 99999)
	if err != nil {
		t.Errorf("Expected no error for non-existent user consent, got: %v", err)
	}
	if nonExistentConsent != nil {
		t.Errorf("Expected nil for non-existent user consent, got a consent with ID: %d", nonExistentConsent.ID)
	}
}

func TestGetConsentByUserIDAndClientID(t *testing.T) {
	userConsent := createTestUserConsent(t)

	retrievedConsent, err := database.GetConsentByUserIDAndClientID(context.Background(), nil, userConsent.UserID, userConsent.ClientID)
	if err != nil {
		t.Fatalf("Failed to get consent by user ID and client ID: %v", err)
	}

	if retrievedConsent.ID != userConsent.ID {
		t.Errorf("Expected ID %d, got %d", userConsent.ID, retrievedConsent.ID)
	}
	if retrievedConsent.UserID != userConsent.UserID {
		t.Errorf("Expected UserID %d, got %d", userConsent.UserID, retrievedConsent.UserID)
	}
	if retrievedConsent.ClientID != userConsent.ClientID {
		t.Errorf("Expected ClientID %d, got %d", userConsent.ClientID, retrievedConsent.ClientID)
	}

	nonExistentConsent, err := database.GetConsentByUserIDAndClientID(context.Background(), nil, 99999, 99999)
	if err != nil {
		t.Errorf("Expected no error for non-existent user consent, got: %v", err)
	}
	if nonExistentConsent != nil {
		t.Errorf("Expected nil for non-existent user consent, got a consent with ID: %d", nonExistentConsent.ID)
	}
}

func TestUserConsentsLoadClients(t *testing.T) {
	userConsent1 := createTestUserConsent(t)
	userConsent2 := createTestUserConsent(t)

	userConsents := []record.UserConsent{*userConsent1, *userConsent2}

	err := database.UserConsentsLoadClients(context.Background(), nil, userConsents)
	if err != nil {
		t.Fatalf("Failed to load clients for user consents: %v", err)
	}

	for _, consent := range userConsents {
		if consent.Client.ID != consent.ClientID {
			t.Errorf("Expected Client.ID %d, got %d", consent.ClientID, consent.Client.ID)
		}
	}
}

func TestGetConsentsByUserID(t *testing.T) {
	user := createTestUser(t)
	userConsent1 := createTestUserConsentForUser(t, user.ID)
	userConsent2 := createTestUserConsentForUser(t, user.ID)

	consents, err := database.GetConsentsByUserID(context.Background(), nil, user.ID)
	if err != nil {
		t.Fatalf("Failed to get consents by user ID: %v", err)
	}

	if len(consents) != 2 {
		t.Errorf("Expected 2 consents, got %d", len(consents))
	}

	consentIDs := make(map[int64]bool)
	for _, consent := range consents {
		consentIDs[consent.ID] = true
		if consent.UserID != user.ID {
			t.Errorf("Expected UserID %d, got %d", user.ID, consent.UserID)
		}
	}

	if !consentIDs[userConsent1.ID] || !consentIDs[userConsent2.ID] {
		t.Error("Not all created consents were found in GetConsentsByUserID result")
	}
}

func TestDeleteUserConsent(t *testing.T) {
	userConsent := createTestUserConsent(t)

	deleted, err := database.DeleteUserConsent(context.Background(), nil, userConsent.ID)
	if err != nil {
		t.Fatalf("Failed to delete user consent: %v", err)
	}
	if !deleted {
		t.Errorf("Expected the deletion of an existing user consent to report it deleted the row")
	}

	deletedConsent, err := database.GetUserConsentByID(context.Background(), nil, userConsent.ID)
	if err != nil {
		t.Fatalf("Error while checking for deleted user consent: %v", err)
	}
	if deletedConsent != nil {
		t.Errorf("User consent still exists after deletion")
	}

	// The same row again, as a second request withdrawing the same consent would: no error, and
	// the answer says this call deleted nothing (#135 decision 2).
	deleted, err = database.DeleteUserConsent(context.Background(), nil, userConsent.ID)
	if err != nil {
		t.Errorf("Expected no error when deleting an already deleted user consent, got: %v", err)
	}
	if deleted {
		t.Errorf("Expected the deletion of an already deleted user consent to report it deleted nothing")
	}

	deleted, err = database.DeleteUserConsent(context.Background(), nil, 99999)
	if err != nil {
		t.Errorf("Expected no error when deleting non-existent user consent, got: %v", err)
	}
	if deleted {
		t.Errorf("Expected the deletion of a non-existent user consent to report it deleted nothing")
	}
}

// TestGetConsentByUserIDAndClientIDForUpdate reads the consent a disconnect deletes, inside a
// transaction, on every engine's own locking grammar: the user's consent to the client, nil for a
// client the user gave none, and a refusal without a transaction (#135).
func TestGetConsentByUserIDAndClientIDForUpdate(t *testing.T) {
	ctx := context.Background()
	userConsent := createTestUserConsent(t)
	otherClient := createTestClient(t)

	err := database.RunInTransaction(ctx, func(tx *sql.Tx) error {
		got, err := database.GetConsentByUserIDAndClientIDForUpdate(ctx, tx, userConsent.UserID, userConsent.ClientID)
		if err != nil {
			return err
		}
		if got == nil || got.ID != userConsent.ID || got.Scope != "openid profile" {
			t.Errorf("expected consent %d with scope %q, got %+v", userConsent.ID, "openid profile", got)
		}
		none, err := database.GetConsentByUserIDAndClientIDForUpdate(ctx, tx, userConsent.UserID, otherClient.ID)
		if err != nil {
			return err
		}
		if none != nil {
			t.Errorf("expected no consent with a client the user gave none, got %+v", none)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("locking read failed: %v", err)
	}

	if _, err := database.GetConsentByUserIDAndClientIDForUpdate(ctx, nil, userConsent.UserID, userConsent.ClientID); err == nil {
		t.Error("expected a locking read without a transaction to be refused")
	}
}

func createTestUserConsent(t *testing.T) *record.UserConsent {
	client := createTestClient(t)
	user := createTestUser(t)

	userConsent := &record.UserConsent{
		UserID:    user.ID,
		ClientID:  client.ID,
		Scope:     "openid profile",
		GrantedAt: sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true},
	}

	err := database.CreateUserConsent(context.Background(), nil, userConsent)
	if err != nil {
		t.Fatalf("Failed to create test user consent: %v", err)
	}

	return userConsent
}

func createTestUserConsentForUser(t *testing.T, userID int64) *record.UserConsent {
	client := createTestClient(t)

	userConsent := &record.UserConsent{
		UserID:   userID,
		ClientID: client.ID,
		Scope:    "openid profile",
	}

	err := database.CreateUserConsent(context.Background(), nil, userConsent)
	if err != nil {
		t.Fatalf("Failed to create test user consent: %v", err)
	}

	return userConsent
}
