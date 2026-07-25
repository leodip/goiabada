package datatests

import (
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/models"
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
}

func TestUpdateGroup(t *testing.T) {
	group := createTestGroup(t)

	group.Description = "Updated Description"
	group.IncludeInIdToken = false
	group.IncludeInAccessToken = true

	// Wait a moment to ensure UpdatedAt will be different
	time.Sleep(timestampTick)

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
}

// TestGetAllGroupsPaginated asserts the properties of pagination rather than the
// contents of fixed pages, because this reader spans the whole table and every
// other test in the package adds to it.
//
// It used to delete every group in the database first, to make the counts
// predictable. That worked only because nothing runs in parallel and no later test
// depended on a group created earlier, and it cascaded into users_groups,
// groups_permissions and group_attributes on the way. Asserting relative to a
// baseline needs no such wipe, and pins more than the old version did: that the
// pages tile the table with no gap or repeat, and that the ordering the reader
// promises actually holds.
func TestGetAllGroupsPaginated(t *testing.T) {
	const pageSize = 10
	const numGroups = 25

	// Page size 1 is the cheapest way to read the current total.
	_, baseline, err := database.GetAllGroupsPaginated(nil, 1, 1)
	if err != nil {
		t.Fatalf("Failed to read the baseline group count: %v", err)
	}

	created := make(map[string]bool, numGroups)
	for i := 0; i < numGroups; i++ {
		group := createTestGroup(t)
		created[group.GroupIdentifier] = true
		// Remove only what this test made. Unlike the old table-wide wipe this
		// touches nothing another test owns, and it keeps the table from growing by
		// 25 rows on every run of the three server databases, which are never reset.
		t.Cleanup(func() { _ = database.DeleteGroup(nil, group.Id) })
	}

	expectedTotal := baseline + numGroups

	// A full page, a partial last page, and the page past the end.
	lastPage := (expectedTotal + pageSize - 1) / pageSize
	expectedOnLastPage := expectedTotal - (lastPage-1)*pageSize

	for _, tc := range []struct {
		name     string
		page     int
		expected int
	}{
		{"first page is full", 1, pageSize},
		{"last page holds the remainder", lastPage, expectedOnLastPage},
		{"page past the end is empty", lastPage + 1, 0},
	} {
		groups, total, err := database.GetAllGroupsPaginated(nil, tc.page, pageSize)
		if err != nil {
			t.Fatalf("%s: failed to get page %d: %v", tc.name, tc.page, err)
		}
		if len(groups) != tc.expected {
			t.Errorf("%s: expected %d groups on page %d, got %d", tc.name, tc.expected, tc.page, len(groups))
		}
		// The total is a property of the query, not of the page, so it must not
		// change as the caller walks off the end.
		if total != expectedTotal {
			t.Errorf("%s: expected total %d on page %d, got %d", tc.name, expectedTotal, tc.page, total)
		}
	}

	// Read everything in one page, as the reference for what the pages should tile.
	all, total, err := database.GetAllGroupsPaginated(nil, 1, expectedTotal)
	if err != nil {
		t.Fatalf("Failed to read all groups in one page: %v", err)
	}
	if total != expectedTotal || len(all) != expectedTotal {
		t.Fatalf("Expected %d groups in one page, got %d (total reported %d)", expectedTotal, len(all), total)
	}

	// Every group created here comes back exactly once.
	seen := 0
	for _, group := range all {
		if created[group.GroupIdentifier] {
			seen++
			delete(created, group.GroupIdentifier) // so a repeat is not counted twice
		}
	}
	if seen != numGroups {
		t.Errorf("Expected all %d created groups to appear exactly once, found %d", numGroups, seen)
	}

	// The pages must tile that reference: page N holds exactly the slice the single
	// read put at that offset, with nothing skipped or repeated at the seam.
	//
	// Deliberately not asserted: what the order itself should be. The reader sorts
	// by group_identifier in the database, and the collation is not ours to assume.
	// MySQL's default (utf8mb4_0900_ai_ci) and SQL Server's are case-insensitive
	// while sqlite compares bytes, so a fixed expected order would be wrong on some
	// engine no matter which one we picked. Comparing the pages against the full
	// read tests the offset arithmetic without needing to know the collation.
	for _, page := range []int{1, 2} {
		groups, _, err := database.GetAllGroupsPaginated(nil, page, pageSize)
		if err != nil {
			t.Fatalf("Failed to get page %d: %v", page, err)
		}
		offset := (page - 1) * pageSize
		for i, group := range groups {
			if group.GroupIdentifier != all[offset+i].GroupIdentifier {
				t.Errorf("Page %d position %d: expected %q, got %q",
					page, i, all[offset+i].GroupIdentifier, group.GroupIdentifier)
			}
		}
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
