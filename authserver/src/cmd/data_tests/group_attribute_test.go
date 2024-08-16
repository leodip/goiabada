package datatests

import (
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/authserver/internal/models"
)

func TestCreateGroupAttribute(t *testing.T) {
	// Create a test group
	group := createTestGroup(t)

	random := gofakeit.LetterN(6)
	groupAttribute := &models.GroupAttribute{
		GroupId:              group.Id,
		Key:                  "testkey_" + random,
		Value:                "testvalue_" + random,
		IncludeInIdToken:     true,
		IncludeInAccessToken: false,
	}

	err := database.CreateGroupAttribute(nil, groupAttribute)
	if err != nil {
		t.Fatalf("Failed to create group attribute: %v", err)
	}

	// Verify the group attribute was created
	createdGroupAttribute, err := database.GetGroupAttributeById(nil, groupAttribute.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve created group attribute: %v", err)
	}

	// Check all properties
	if createdGroupAttribute.GroupId != groupAttribute.GroupId {
		t.Errorf("Expected GroupId %d, got %d", groupAttribute.GroupId, createdGroupAttribute.GroupId)
	}
	if createdGroupAttribute.Key != groupAttribute.Key {
		t.Errorf("Expected Key '%s', got '%s'", groupAttribute.Key, createdGroupAttribute.Key)
	}
	if createdGroupAttribute.Value != groupAttribute.Value {
		t.Errorf("Expected Value '%s', got '%s'", groupAttribute.Value, createdGroupAttribute.Value)
	}
	if createdGroupAttribute.IncludeInIdToken != groupAttribute.IncludeInIdToken {
		t.Errorf("Expected IncludeInIdToken %v, got %v", groupAttribute.IncludeInIdToken, createdGroupAttribute.IncludeInIdToken)
	}
	if createdGroupAttribute.IncludeInAccessToken != groupAttribute.IncludeInAccessToken {
		t.Errorf("Expected IncludeInAccessToken %v, got %v", groupAttribute.IncludeInAccessToken, createdGroupAttribute.IncludeInAccessToken)
	}
	if !createdGroupAttribute.CreatedAt.Valid || createdGroupAttribute.CreatedAt.Time.IsZero() {
		t.Errorf("CreatedAt is not set properly")
	}
	if !createdGroupAttribute.UpdatedAt.Valid || createdGroupAttribute.UpdatedAt.Time.IsZero() {
		t.Errorf("UpdatedAt is not set properly")
	}

	// Test creating a group attribute with invalid group ID
	invalidGroupAttribute := &models.GroupAttribute{
		GroupId: 0,
		Key:     "invalidkey",
		Value:   "invalidvalue",
	}
	err = database.CreateGroupAttribute(nil, invalidGroupAttribute)
	if err == nil {
		t.Errorf("Expected error when creating group attribute with invalid group ID, got nil")
	}

	// Clean up
	database.DeleteGroupAttribute(nil, groupAttribute.Id)
	database.DeleteGroup(nil, group.Id)
}

func TestUpdateGroupAttribute(t *testing.T) {
	// Create a test group and group attribute
	group := createTestGroup(t)
	groupAttribute := createTestGroupAttribute(t, group.Id)

	// Update the group attribute
	groupAttribute.Key = "updated_key"
	groupAttribute.Value = "updated_value"
	groupAttribute.IncludeInIdToken = false
	groupAttribute.IncludeInAccessToken = true

	time.Sleep(time.Millisecond * 100) // Ensure some time passes before update

	err := database.UpdateGroupAttribute(nil, groupAttribute)
	if err != nil {
		t.Fatalf("Failed to update group attribute: %v", err)
	}

	// Fetch the updated group attribute
	updatedGroupAttribute, err := database.GetGroupAttributeById(nil, groupAttribute.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve updated group attribute: %v", err)
	}

	// Check updated properties
	if updatedGroupAttribute.Key != "updated_key" {
		t.Errorf("Expected Key 'updated_key', got '%s'", updatedGroupAttribute.Key)
	}
	if updatedGroupAttribute.Value != "updated_value" {
		t.Errorf("Expected Value 'updated_value', got '%s'", updatedGroupAttribute.Value)
	}
	if updatedGroupAttribute.IncludeInIdToken != false {
		t.Errorf("Expected IncludeInIdToken false, got %v", updatedGroupAttribute.IncludeInIdToken)
	}
	if updatedGroupAttribute.IncludeInAccessToken != true {
		t.Errorf("Expected IncludeInAccessToken true, got %v", updatedGroupAttribute.IncludeInAccessToken)
	}
	if !updatedGroupAttribute.UpdatedAt.Time.After(updatedGroupAttribute.CreatedAt.Time) {
		t.Error("Expected UpdatedAt to be after CreatedAt")
	}

	// Clean up
	database.DeleteGroupAttribute(nil, groupAttribute.Id)
	database.DeleteGroup(nil, group.Id)
}

func TestGetGroupAttributeById(t *testing.T) {
	// Create a test group and group attribute
	group := createTestGroup(t)
	groupAttribute := createTestGroupAttribute(t, group.Id)

	// Retrieve the group attribute
	retrievedGroupAttribute, err := database.GetGroupAttributeById(nil, groupAttribute.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve group attribute by ID: %v", err)
	}

	// Check all properties
	if retrievedGroupAttribute.Id != groupAttribute.Id {
		t.Errorf("Expected Id %d, got %d", groupAttribute.Id, retrievedGroupAttribute.Id)
	}
	if retrievedGroupAttribute.GroupId != groupAttribute.GroupId {
		t.Errorf("Expected GroupId %d, got %d", groupAttribute.GroupId, retrievedGroupAttribute.GroupId)
	}
	if retrievedGroupAttribute.Key != groupAttribute.Key {
		t.Errorf("Expected Key '%s', got '%s'", groupAttribute.Key, retrievedGroupAttribute.Key)
	}
	if retrievedGroupAttribute.Value != groupAttribute.Value {
		t.Errorf("Expected Value '%s', got '%s'", groupAttribute.Value, retrievedGroupAttribute.Value)
	}
	if retrievedGroupAttribute.IncludeInIdToken != groupAttribute.IncludeInIdToken {
		t.Errorf("Expected IncludeInIdToken %v, got %v", groupAttribute.IncludeInIdToken, retrievedGroupAttribute.IncludeInIdToken)
	}
	if retrievedGroupAttribute.IncludeInAccessToken != groupAttribute.IncludeInAccessToken {
		t.Errorf("Expected IncludeInAccessToken %v, got %v", groupAttribute.IncludeInAccessToken, retrievedGroupAttribute.IncludeInAccessToken)
	}
	if !retrievedGroupAttribute.CreatedAt.Valid || retrievedGroupAttribute.CreatedAt.Time.IsZero() {
		t.Errorf("CreatedAt is not set properly")
	}
	if !retrievedGroupAttribute.UpdatedAt.Valid || retrievedGroupAttribute.UpdatedAt.Time.IsZero() {
		t.Errorf("UpdatedAt is not set properly")
	}

	// Test retrieving a non-existent group attribute
	nonExistentGroupAttribute, err := database.GetGroupAttributeById(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error for non-existent group attribute, got: %v", err)
	}
	if nonExistentGroupAttribute != nil {
		t.Errorf("Expected nil for non-existent group attribute, got a group attribute with ID: %d", nonExistentGroupAttribute.Id)
	}

	// Clean up
	database.DeleteGroupAttribute(nil, groupAttribute.Id)
	database.DeleteGroup(nil, group.Id)
}

func TestGetGroupAttributesByGroupIds(t *testing.T) {
	// Create test groups and group attributes
	group1 := createTestGroup(t)
	group2 := createTestGroup(t)
	groupAttribute1 := createTestGroupAttribute(t, group1.Id)
	groupAttribute2 := createTestGroupAttribute(t, group2.Id)

	// Retrieve group attributes by group IDs
	groupAttributes, err := database.GetGroupAttributesByGroupIds(nil, []int64{group1.Id, group2.Id})
	if err != nil {
		t.Fatalf("Failed to retrieve group attributes by group IDs: %v", err)
	}

	if len(groupAttributes) != 2 {
		t.Errorf("Expected 2 group attributes, got %d", len(groupAttributes))
	}

	// Verify the properties of fetched group attributes
	for _, attr := range groupAttributes {
		if attr.GroupId != group1.Id && attr.GroupId != group2.Id {
			t.Errorf("Unexpected GroupId: %d", attr.GroupId)
		}
		if attr.Key == "" {
			t.Errorf("Key is empty")
		}
		if attr.Value == "" {
			t.Errorf("Value is empty")
		}
		if !attr.CreatedAt.Valid || attr.CreatedAt.Time.IsZero() {
			t.Errorf("CreatedAt is not set properly")
		}
		if !attr.UpdatedAt.Valid || attr.UpdatedAt.Time.IsZero() {
			t.Errorf("UpdatedAt is not set properly")
		}
	}

	// Test retrieving group attributes for non-existent group IDs
	nonExistentGroupAttributes, err := database.GetGroupAttributesByGroupIds(nil, []int64{99999})
	if err != nil {
		t.Errorf("Expected no error for non-existent group IDs, got: %v", err)
	}
	if len(nonExistentGroupAttributes) != 0 {
		t.Errorf("Expected 0 group attributes for non-existent group IDs, got %d", len(nonExistentGroupAttributes))
	}

	// Clean up
	database.DeleteGroupAttribute(nil, groupAttribute1.Id)
	database.DeleteGroupAttribute(nil, groupAttribute2.Id)
	database.DeleteGroup(nil, group1.Id)
	database.DeleteGroup(nil, group2.Id)
}

func TestGetGroupAttributesByGroupId(t *testing.T) {
	// Create a test group and multiple group attributes
	group := createTestGroup(t)
	groupAttribute1 := createTestGroupAttribute(t, group.Id)
	groupAttribute2 := createTestGroupAttribute(t, group.Id)

	// Retrieve group attributes by group ID
	groupAttributes, err := database.GetGroupAttributesByGroupId(nil, group.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve group attributes by group ID: %v", err)
	}

	if len(groupAttributes) != 2 {
		t.Errorf("Expected 2 group attributes, got %d", len(groupAttributes))
	}

	// Verify the properties of fetched group attributes
	for _, attr := range groupAttributes {
		if attr.GroupId != group.Id {
			t.Errorf("Expected GroupId %d, got %d", group.Id, attr.GroupId)
		}
		if attr.Key == "" {
			t.Errorf("Key is empty")
		}
		if attr.Value == "" {
			t.Errorf("Value is empty")
		}
		if !attr.CreatedAt.Valid || attr.CreatedAt.Time.IsZero() {
			t.Errorf("CreatedAt is not set properly")
		}
		if !attr.UpdatedAt.Valid || attr.UpdatedAt.Time.IsZero() {
			t.Errorf("UpdatedAt is not set properly")
		}
	}

	// Test retrieving group attributes for a non-existent group ID
	nonExistentGroupAttributes, err := database.GetGroupAttributesByGroupId(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error for non-existent group ID, got: %v", err)
	}
	if len(nonExistentGroupAttributes) != 0 {
		t.Errorf("Expected 0 group attributes for non-existent group ID, got %d", len(nonExistentGroupAttributes))
	}

	// Clean up
	database.DeleteGroupAttribute(nil, groupAttribute1.Id)
	database.DeleteGroupAttribute(nil, groupAttribute2.Id)
	database.DeleteGroup(nil, group.Id)
}

func TestDeleteGroupAttribute(t *testing.T) {
	// Create a test group and group attribute
	group := createTestGroup(t)
	groupAttribute := createTestGroupAttribute(t, group.Id)

	// Delete the group attribute
	err := database.DeleteGroupAttribute(nil, groupAttribute.Id)
	if err != nil {
		t.Fatalf("Failed to delete group attribute: %v", err)
	}

	// Try to retrieve the deleted group attribute
	deletedGroupAttribute, err := database.GetGroupAttributeById(nil, groupAttribute.Id)
	if err != nil {
		t.Fatalf("Error while checking for deleted group attribute: %v", err)
	}
	if deletedGroupAttribute != nil {
		t.Errorf("Group attribute still exists after deletion")
	}

	// Test deleting a non-existent group attribute
	err = database.DeleteGroupAttribute(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error when deleting non-existent group attribute, got: %v", err)
	}

	// Clean up
	database.DeleteGroup(nil, group.Id)
}

// Helper functions

func createTestGroup(t *testing.T) *models.Group {
	random := gofakeit.LetterN(6)
	group := &models.Group{
		GroupIdentifier: "TestGroup_" + random,
		Description:     "Test Group Description",
	}
	err := database.CreateGroup(nil, group)
	if err != nil {
		t.Fatalf("Failed to create test group: %v", err)
	}
	return group
}

func createTestGroupAttribute(t *testing.T, groupId int64) *models.GroupAttribute {
	random := gofakeit.LetterN(6)
	groupAttribute := &models.GroupAttribute{
		GroupId:              groupId,
		Key:                  "TestKey_" + random,
		Value:                "TestValue_" + random,
		IncludeInIdToken:     true,
		IncludeInAccessToken: false,
	}
	err := database.CreateGroupAttribute(nil, groupAttribute)
	if err != nil {
		t.Fatalf("Failed to create test group attribute: %v", err)
	}
	return groupAttribute
}
