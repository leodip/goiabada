package datatests

import (
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/authserver/internal/models"
)

func TestCreateGroup(t *testing.T) {
	group := &models.Group{
		GroupIdentifier:      "test_group_" + gofakeit.LetterN(6),
		Description:          "Test Group",
		IncludeInIdToken:     true,
		IncludeInAccessToken: false,
	}

	err := database.CreateGroup(nil, group)
	if err != nil {
		t.Fatalf("Failed to create group: %v", err)
	}

	if group.Id == 0 {
		t.Error("Expected non-zero ID after creation")
	}
	if !group.CreatedAt.Valid || group.CreatedAt.Time.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
	if !group.UpdatedAt.Valid || group.UpdatedAt.Time.IsZero() {
		t.Error("Expected UpdatedAt to be set")
	}

	retrievedGroup, err := database.GetGroupById(nil, group.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve created group: %v", err)
	}

	if retrievedGroup.GroupIdentifier != group.GroupIdentifier {
		t.Errorf("Expected GroupIdentifier %s, got %s", group.GroupIdentifier, retrievedGroup.GroupIdentifier)
	}
	if retrievedGroup.Description != group.Description {
		t.Errorf("Expected Description %s, got %s", group.Description, retrievedGroup.Description)
	}
	if retrievedGroup.IncludeInIdToken != group.IncludeInIdToken {
		t.Errorf("Expected IncludeInIdToken %v, got %v", group.IncludeInIdToken, retrievedGroup.IncludeInIdToken)
	}
	if retrievedGroup.IncludeInAccessToken != group.IncludeInAccessToken {
		t.Errorf("Expected IncludeInAccessToken %v, got %v", group.IncludeInAccessToken, retrievedGroup.IncludeInAccessToken)
	}

	database.DeleteGroup(nil, group.Id)
}

func TestUpdateGroup(t *testing.T) {
	group := createTestGroup(t)

	group.Description = "Updated Description"
	group.IncludeInIdToken = false
	group.IncludeInAccessToken = true

	// Wait a moment to ensure UpdatedAt will be different
	time.Sleep(time.Millisecond * 100)

	err := database.UpdateGroup(nil, group)
	if err != nil {
		t.Fatalf("Failed to update group: %v", err)
	}

	updatedGroup, err := database.GetGroupById(nil, group.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve updated group: %v", err)
	}

	if updatedGroup.Description != group.Description {
		t.Errorf("Expected Description %s, got %s", group.Description, updatedGroup.Description)
	}
	if updatedGroup.IncludeInIdToken != group.IncludeInIdToken {
		t.Errorf("Expected IncludeInIdToken %v, got %v", group.IncludeInIdToken, updatedGroup.IncludeInIdToken)
	}
	if updatedGroup.IncludeInAccessToken != group.IncludeInAccessToken {
		t.Errorf("Expected IncludeInAccessToken %v, got %v", group.IncludeInAccessToken, updatedGroup.IncludeInAccessToken)
	}
	if !updatedGroup.UpdatedAt.Time.After(updatedGroup.CreatedAt.Time) {
		t.Error("Expected UpdatedAt to be after CreatedAt")
	}

	database.DeleteGroup(nil, group.Id)
}

func TestGetGroupById(t *testing.T) {
	group := createTestGroup(t)

	retrievedGroup, err := database.GetGroupById(nil, group.Id)
	if err != nil {
		t.Fatalf("Failed to get group by ID: %v", err)
	}

	if retrievedGroup.Id != group.Id {
		t.Errorf("Expected ID %d, got %d", group.Id, retrievedGroup.Id)
	}
	if retrievedGroup.GroupIdentifier != group.GroupIdentifier {
		t.Errorf("Expected GroupIdentifier %s, got %s", group.GroupIdentifier, retrievedGroup.GroupIdentifier)
	}

	nonExistentGroup, err := database.GetGroupById(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error for non-existent group, got: %v", err)
	}
	if nonExistentGroup != nil {
		t.Errorf("Expected nil for non-existent group, got a group with ID: %d", nonExistentGroup.Id)
	}

	database.DeleteGroup(nil, group.Id)
}

func TestGetGroupByGroupIdentifier(t *testing.T) {
	group := createTestGroup(t)

	retrievedGroup, err := database.GetGroupByGroupIdentifier(nil, group.GroupIdentifier)
	if err != nil {
		t.Fatalf("Failed to get group by identifier: %v", err)
	}

	if retrievedGroup.Id != group.Id {
		t.Errorf("Expected ID %d, got %d", group.Id, retrievedGroup.Id)
	}
	if retrievedGroup.GroupIdentifier != group.GroupIdentifier {
		t.Errorf("Expected GroupIdentifier %s, got %s", group.GroupIdentifier, retrievedGroup.GroupIdentifier)
	}

	nonExistentGroup, err := database.GetGroupByGroupIdentifier(nil, "non_existent_identifier")
	if err != nil {
		t.Errorf("Expected no error for non-existent group, got: %v", err)
	}
	if nonExistentGroup != nil {
		t.Errorf("Expected nil for non-existent group, got a group with ID: %d", nonExistentGroup.Id)
	}

	database.DeleteGroup(nil, group.Id)
}

func TestGetAllGroups(t *testing.T) {
	group1 := createTestGroup(t)
	group2 := createTestGroup(t)

	groups, err := database.GetAllGroups(nil)
	if err != nil {
		t.Fatalf("Failed to get all groups: %v", err)
	}

	if len(groups) < 2 {
		t.Errorf("Expected at least 2 groups, got %d", len(groups))
	}

	foundGroup1 := false
	foundGroup2 := false
	for _, group := range groups {
		if group.Id == group1.Id {
			foundGroup1 = true
		}
		if group.Id == group2.Id {
			foundGroup2 = true
		}
	}

	if !foundGroup1 || !foundGroup2 {
		t.Error("Not all created groups were found in GetAllGroups result")
	}

	database.DeleteGroup(nil, group1.Id)
	database.DeleteGroup(nil, group2.Id)
}

func TestGetAllGroupsPaginated(t *testing.T) {
	// Clean up existing groups
	existingGroups, _ := database.GetAllGroups(nil)
	for _, group := range existingGroups {
		database.DeleteGroup(nil, group.Id)
	}

	// Create a specific number of test groups
	numGroups := 25
	for i := 0; i < numGroups; i++ {
		createTestGroup(t)
	}

	// Test first page
	groups, total, err := database.GetAllGroupsPaginated(nil, 1, 10)
	if err != nil {
		t.Fatalf("Failed to get paginated groups: %v", err)
	}

	if len(groups) != 10 {
		t.Errorf("Expected 10 groups on the first page, got %d", len(groups))
	}

	if total != numGroups {
		t.Errorf("Expected total to be %d, got %d", numGroups, total)
	}

	// Test second page
	groups, total, err = database.GetAllGroupsPaginated(nil, 2, 10)
	if err != nil {
		t.Fatalf("Failed to get second page of paginated groups: %v", err)
	}

	if len(groups) != 10 {
		t.Errorf("Expected 10 groups on the second page, got %d", len(groups))
	}

	if total != numGroups {
		t.Errorf("Expected total to be %d, got %d", numGroups, total)
	}

	// Test last page
	groups, total, err = database.GetAllGroupsPaginated(nil, 3, 10)
	if err != nil {
		t.Fatalf("Failed to get last page of paginated groups: %v", err)
	}

	if len(groups) != 5 {
		t.Errorf("Expected 5 groups on the last page, got %d", len(groups))
	}

	if total != numGroups {
		t.Errorf("Expected total to be %d, got %d", numGroups, total)
	}

	// Test page beyond total
	groups, total, err = database.GetAllGroupsPaginated(nil, 4, 10)
	if err != nil {
		t.Fatalf("Failed to get page beyond total: %v", err)
	}

	if len(groups) != 0 {
		t.Errorf("Expected 0 groups on page beyond total, got %d", len(groups))
	}

	if total != numGroups {
		t.Errorf("Expected total to be %d, got %d", numGroups, total)
	}

	// Clean up
	allGroups, _ := database.GetAllGroups(nil)
	for _, group := range allGroups {
		database.DeleteGroup(nil, group.Id)
	}
}

func TestDeleteGroup(t *testing.T) {
	group := createTestGroup(t)

	err := database.DeleteGroup(nil, group.Id)
	if err != nil {
		t.Fatalf("Failed to delete group: %v", err)
	}

	deletedGroup, err := database.GetGroupById(nil, group.Id)
	if err != nil {
		t.Fatalf("Error while checking for deleted group: %v", err)
	}
	if deletedGroup != nil {
		t.Errorf("Group still exists after deletion")
	}

	err = database.DeleteGroup(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error when deleting non-existent group, got: %v", err)
	}
}

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
