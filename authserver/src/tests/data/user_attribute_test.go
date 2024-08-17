package datatests

import (
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/authserver/internal/models"
)

func TestCreateUserAttribute(t *testing.T) {
	user := createTestUser(t)
	attr := createTestUserAttribute(t, user.Id)

	if attr.Id == 0 {
		t.Error("Expected non-zero ID after creation")
	}
	if !attr.CreatedAt.Valid || attr.CreatedAt.Time.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
	if !attr.UpdatedAt.Valid || attr.UpdatedAt.Time.IsZero() {
		t.Error("Expected UpdatedAt to be set")
	}

	retrievedAttr, err := database.GetUserAttributeById(nil, attr.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve created user attribute: %v", err)
	}

	if retrievedAttr.Key != attr.Key {
		t.Errorf("Expected Key %s, got %s", attr.Key, retrievedAttr.Key)
	}
	if retrievedAttr.Value != attr.Value {
		t.Errorf("Expected Value %s, got %s", attr.Value, retrievedAttr.Value)
	}
	if retrievedAttr.IncludeInIdToken != attr.IncludeInIdToken {
		t.Errorf("Expected IncludeInIdToken %v, got %v", attr.IncludeInIdToken, retrievedAttr.IncludeInIdToken)
	}
	if retrievedAttr.IncludeInAccessToken != attr.IncludeInAccessToken {
		t.Errorf("Expected IncludeInAccessToken %v, got %v", attr.IncludeInAccessToken, retrievedAttr.IncludeInAccessToken)
	}
	if retrievedAttr.UserId != attr.UserId {
		t.Errorf("Expected UserId %d, got %d", attr.UserId, retrievedAttr.UserId)
	}
}

func TestUpdateUserAttribute(t *testing.T) {
	user := createTestUser(t)
	attr := createTestUserAttribute(t, user.Id)

	attr.Key = "UpdatedKey"
	attr.Value = "UpdatedValue"
	attr.IncludeInIdToken = !attr.IncludeInIdToken
	attr.IncludeInAccessToken = !attr.IncludeInAccessToken

	time.Sleep(time.Millisecond * 100)

	err := database.UpdateUserAttribute(nil, attr)
	if err != nil {
		t.Fatalf("Failed to update user attribute: %v", err)
	}

	updatedAttr, err := database.GetUserAttributeById(nil, attr.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve updated user attribute: %v", err)
	}

	if updatedAttr.Key != attr.Key {
		t.Errorf("Expected Key %s, got %s", attr.Key, updatedAttr.Key)
	}
	if updatedAttr.Value != attr.Value {
		t.Errorf("Expected Value %s, got %s", attr.Value, updatedAttr.Value)
	}
	if updatedAttr.IncludeInIdToken != attr.IncludeInIdToken {
		t.Errorf("Expected IncludeInIdToken %v, got %v", attr.IncludeInIdToken, updatedAttr.IncludeInIdToken)
	}
	if updatedAttr.IncludeInAccessToken != attr.IncludeInAccessToken {
		t.Errorf("Expected IncludeInAccessToken %v, got %v", attr.IncludeInAccessToken, updatedAttr.IncludeInAccessToken)
	}
	if !updatedAttr.UpdatedAt.Time.After(updatedAttr.CreatedAt.Time) {
		t.Error("Expected UpdatedAt to be after CreatedAt")
	}
}

func TestGetUserAttributeById(t *testing.T) {
	user := createTestUser(t)
	attr := createTestUserAttribute(t, user.Id)

	retrievedAttr, err := database.GetUserAttributeById(nil, attr.Id)
	if err != nil {
		t.Fatalf("Failed to get user attribute by ID: %v", err)
	}

	if retrievedAttr.Id != attr.Id {
		t.Errorf("Expected ID %d, got %d", attr.Id, retrievedAttr.Id)
	}
	if retrievedAttr.Key != attr.Key {
		t.Errorf("Expected Key %s, got %s", attr.Key, retrievedAttr.Key)
	}

	nonExistentAttr, err := database.GetUserAttributeById(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error for non-existent user attribute, got: %v", err)
	}
	if nonExistentAttr != nil {
		t.Errorf("Expected nil for non-existent user attribute, got an attribute with ID: %d", nonExistentAttr.Id)
	}
}

func TestGetUserAttributesByUserId(t *testing.T) {
	user := createTestUser(t)
	attr1 := createTestUserAttribute(t, user.Id)
	attr2 := createTestUserAttribute(t, user.Id)

	attrs, err := database.GetUserAttributesByUserId(nil, user.Id)
	if err != nil {
		t.Fatalf("Failed to get user attributes by user ID: %v", err)
	}

	if len(attrs) != 2 {
		t.Errorf("Expected 2 attributes, got %d", len(attrs))
	}

	foundAttr1 := false
	foundAttr2 := false
	for _, attr := range attrs {
		if attr.Id == attr1.Id {
			foundAttr1 = true
		}
		if attr.Id == attr2.Id {
			foundAttr2 = true
		}
	}

	if !foundAttr1 || !foundAttr2 {
		t.Error("Not all created attributes were found in GetUserAttributesByUserId result")
	}
}

func TestDeleteUserAttribute(t *testing.T) {
	user := createTestUser(t)
	attr := createTestUserAttribute(t, user.Id)

	err := database.DeleteUserAttribute(nil, attr.Id)
	if err != nil {
		t.Fatalf("Failed to delete user attribute: %v", err)
	}

	deletedAttr, err := database.GetUserAttributeById(nil, attr.Id)
	if err != nil {
		t.Fatalf("Error while checking for deleted user attribute: %v", err)
	}
	if deletedAttr != nil {
		t.Errorf("User attribute still exists after deletion")
	}

	err = database.DeleteUserAttribute(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error when deleting non-existent user attribute, got: %v", err)
	}
}

func createTestUserAttribute(t *testing.T, userId int64) *models.UserAttribute {
	attr := &models.UserAttribute{
		Key:                  "TestKey_" + gofakeit.LetterN(6),
		Value:                "TestValue_" + gofakeit.LetterN(6),
		IncludeInIdToken:     gofakeit.Bool(),
		IncludeInAccessToken: gofakeit.Bool(),
		UserId:               userId,
	}
	err := database.CreateUserAttribute(nil, attr)
	if err != nil {
		t.Fatalf("Failed to create test user attribute: %v", err)
	}
	return attr
}
