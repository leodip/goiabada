package datatests

import (
	"context"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
)

func TestCreateUserAttribute(t *testing.T) {
	user := createTestUser(t)
	attr := createTestUserAttribute(t, user.ID)

	if attr.ID == 0 {
		t.Error("Expected non-zero ID after creation")
	}
	if !attr.CreatedAt.Valid || attr.CreatedAt.Time.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
	if !attr.UpdatedAt.Valid || attr.UpdatedAt.Time.IsZero() {
		t.Error("Expected UpdatedAt to be set")
	}

	retrievedAttr, err := database.GetUserAttributeByID(context.Background(), nil, attr.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve created user attribute: %v", err)
	}

	if retrievedAttr.Key != attr.Key {
		t.Errorf("Expected Key %s, got %s", attr.Key, retrievedAttr.Key)
	}
	if retrievedAttr.Value != attr.Value {
		t.Errorf("Expected Value %s, got %s", attr.Value, retrievedAttr.Value)
	}
	if retrievedAttr.IncludeInIDToken != attr.IncludeInIDToken {
		t.Errorf("Expected IncludeInIDToken %v, got %v", attr.IncludeInIDToken, retrievedAttr.IncludeInIDToken)
	}
	if retrievedAttr.IncludeInAccessToken != attr.IncludeInAccessToken {
		t.Errorf("Expected IncludeInAccessToken %v, got %v", attr.IncludeInAccessToken, retrievedAttr.IncludeInAccessToken)
	}
	if retrievedAttr.UserID != attr.UserID {
		t.Errorf("Expected UserID %d, got %d", attr.UserID, retrievedAttr.UserID)
	}
}

func TestUpdateUserAttribute(t *testing.T) {
	user := createTestUser(t)
	attr := createTestUserAttribute(t, user.ID)

	attr.Key = "UpdatedKey"
	attr.Value = "UpdatedValue"
	attr.IncludeInIDToken = !attr.IncludeInIDToken
	attr.IncludeInAccessToken = !attr.IncludeInAccessToken

	time.Sleep(timestampTick)

	err := database.UpdateUserAttribute(context.Background(), nil, attr)
	if err != nil {
		t.Fatalf("Failed to update user attribute: %v", err)
	}

	updatedAttr, err := database.GetUserAttributeByID(context.Background(), nil, attr.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve updated user attribute: %v", err)
	}

	if updatedAttr.Key != attr.Key {
		t.Errorf("Expected Key %s, got %s", attr.Key, updatedAttr.Key)
	}
	if updatedAttr.Value != attr.Value {
		t.Errorf("Expected Value %s, got %s", attr.Value, updatedAttr.Value)
	}
	if updatedAttr.IncludeInIDToken != attr.IncludeInIDToken {
		t.Errorf("Expected IncludeInIDToken %v, got %v", attr.IncludeInIDToken, updatedAttr.IncludeInIDToken)
	}
	if updatedAttr.IncludeInAccessToken != attr.IncludeInAccessToken {
		t.Errorf("Expected IncludeInAccessToken %v, got %v", attr.IncludeInAccessToken, updatedAttr.IncludeInAccessToken)
	}
	if !updatedAttr.UpdatedAt.Time.After(updatedAttr.CreatedAt.Time) {
		t.Error("Expected UpdatedAt to be after CreatedAt")
	}
}

func TestGetUserAttributeByID(t *testing.T) {
	user := createTestUser(t)
	attr := createTestUserAttribute(t, user.ID)

	retrievedAttr, err := database.GetUserAttributeByID(context.Background(), nil, attr.ID)
	if err != nil {
		t.Fatalf("Failed to get user attribute by ID: %v", err)
	}

	if retrievedAttr.ID != attr.ID {
		t.Errorf("Expected ID %d, got %d", attr.ID, retrievedAttr.ID)
	}
	if retrievedAttr.Key != attr.Key {
		t.Errorf("Expected Key %s, got %s", attr.Key, retrievedAttr.Key)
	}

	nonExistentAttr, err := database.GetUserAttributeByID(context.Background(), nil, 99999)
	if err != nil {
		t.Errorf("Expected no error for non-existent user attribute, got: %v", err)
	}
	if nonExistentAttr != nil {
		t.Errorf("Expected nil for non-existent user attribute, got an attribute with ID: %d", nonExistentAttr.ID)
	}
}

func TestGetUserAttributesByUserID(t *testing.T) {
	user := createTestUser(t)
	attr1 := createTestUserAttribute(t, user.ID)
	attr2 := createTestUserAttribute(t, user.ID)

	attrs, err := database.GetUserAttributesByUserID(context.Background(), nil, user.ID)
	if err != nil {
		t.Fatalf("Failed to get user attributes by user ID: %v", err)
	}

	if len(attrs) != 2 {
		t.Errorf("Expected 2 attributes, got %d", len(attrs))
	}

	foundAttr1 := false
	foundAttr2 := false
	for _, attr := range attrs {
		if attr.ID == attr1.ID {
			foundAttr1 = true
		}
		if attr.ID == attr2.ID {
			foundAttr2 = true
		}
	}

	if !foundAttr1 || !foundAttr2 {
		t.Error("Not all created attributes were found in GetUserAttributesByUserID result")
	}
}

func TestDeleteUserAttribute(t *testing.T) {
	user := createTestUser(t)
	attr := createTestUserAttribute(t, user.ID)

	err := database.DeleteUserAttribute(context.Background(), nil, attr.ID)
	if err != nil {
		t.Fatalf("Failed to delete user attribute: %v", err)
	}

	deletedAttr, err := database.GetUserAttributeByID(context.Background(), nil, attr.ID)
	if err != nil {
		t.Fatalf("Error while checking for deleted user attribute: %v", err)
	}
	if deletedAttr != nil {
		t.Errorf("User attribute still exists after deletion")
	}

	err = database.DeleteUserAttribute(context.Background(), nil, 99999)
	if err != nil {
		t.Errorf("Expected no error when deleting non-existent user attribute, got: %v", err)
	}
}

func createTestUserAttribute(t *testing.T, userID int64) *record.UserAttribute {
	attr := &record.UserAttribute{
		Key:                  "TestKey_" + fake.LetterN(6),
		Value:                "TestValue_" + fake.LetterN(6),
		IncludeInIDToken:     fake.Bool(),
		IncludeInAccessToken: fake.Bool(),
		UserID:               userID,
	}
	err := database.CreateUserAttribute(context.Background(), nil, attr)
	if err != nil {
		t.Fatalf("Failed to create test user attribute: %v", err)
	}
	return attr
}
