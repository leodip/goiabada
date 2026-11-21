package datatests

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
)

func TestCreateResource(t *testing.T) {
	resource := &record.Resource{
		ResourceIdentifier: "test_resource_" + fake.LetterN(6),
		Description:        "Test Resource",
	}

	err := database.CreateResource(context.Background(), nil, resource)
	if err != nil {
		t.Fatalf("Failed to create resource: %v", err)
	}

	if resource.ID == 0 {
		t.Error("Expected non-zero ID after creation")
	}
	if !resource.CreatedAt.Valid || resource.CreatedAt.Time.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
	if !resource.UpdatedAt.Valid || resource.UpdatedAt.Time.IsZero() {
		t.Error("Expected UpdatedAt to be set")
	}

	retrievedResource, err := database.GetResourceByID(context.Background(), nil, resource.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve created resource: %v", err)
	}

	if retrievedResource.ResourceIdentifier != resource.ResourceIdentifier {
		t.Errorf("Expected ResourceIdentifier %s, got %s", resource.ResourceIdentifier, retrievedResource.ResourceIdentifier)
	}
	if retrievedResource.Description != resource.Description {
		t.Errorf("Expected Description %s, got %s", resource.Description, retrievedResource.Description)
	}
}

func TestUpdateResource(t *testing.T) {
	resource := createTestResource(t)

	resource.ResourceIdentifier = "updated_resource_identifier_" + fake.LetterN(6)
	resource.Description = "Updated Description"

	time.Sleep(timestampTick)

	err := database.UpdateResource(context.Background(), nil, resource)
	if err != nil {
		t.Fatalf("Failed to update resource: %v", err)
	}

	updatedResource, err := database.GetResourceByID(context.Background(), nil, resource.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve updated resource: %v", err)
	}

	if updatedResource.Description != resource.Description {
		t.Errorf("Expected Description %s, got %s", resource.Description, updatedResource.Description)
	}
	if updatedResource.ResourceIdentifier != resource.ResourceIdentifier {
		t.Errorf("Expected ResourceIdentifier %s, got %s", resource.ResourceIdentifier, updatedResource.ResourceIdentifier)
	}
	if !updatedResource.UpdatedAt.Time.After(updatedResource.CreatedAt.Time) {
		t.Error("Expected UpdatedAt to be after CreatedAt")
	}
}

func TestGetResourceByID(t *testing.T) {
	resource := createTestResource(t)

	retrievedResource, err := database.GetResourceByID(context.Background(), nil, resource.ID)
	if err != nil {
		t.Fatalf("Failed to get resource by ID: %v", err)
	}

	if retrievedResource.ID != resource.ID {
		t.Errorf("Expected ID %d, got %d", resource.ID, retrievedResource.ID)
	}
	if retrievedResource.ResourceIdentifier != resource.ResourceIdentifier {
		t.Errorf("Expected ResourceIdentifier %s, got %s", resource.ResourceIdentifier, retrievedResource.ResourceIdentifier)
	}

	nonExistentResource, err := database.GetResourceByID(context.Background(), nil, 99999)
	if err != nil {
		t.Errorf("Expected no error for non-existent resource, got: %v", err)
	}
	if nonExistentResource != nil {
		t.Errorf("Expected nil for non-existent resource, got a resource with ID: %d", nonExistentResource.ID)
	}
}

func TestGetResourceByResourceIdentifier(t *testing.T) {
	resource := createTestResource(t)

	retrievedResource, err := database.GetResourceByResourceIdentifier(context.Background(), nil, resource.ResourceIdentifier)
	if err != nil {
		t.Fatalf("Failed to get resource by identifier: %v", err)
	}

	if retrievedResource.ID != resource.ID {
		t.Errorf("Expected ID %d, got %d", resource.ID, retrievedResource.ID)
	}
	if retrievedResource.ResourceIdentifier != resource.ResourceIdentifier {
		t.Errorf("Expected ResourceIdentifier %s, got %s", resource.ResourceIdentifier, retrievedResource.ResourceIdentifier)
	}

	nonExistentResource, err := database.GetResourceByResourceIdentifier(context.Background(), nil, "non_existent_identifier")
	if err != nil {
		t.Errorf("Expected no error for non-existent resource, got: %v", err)
	}
	if nonExistentResource != nil {
		t.Errorf("Expected nil for non-existent resource, got a resource with ID: %d", nonExistentResource.ID)
	}
}

func TestGetResourcesByIDs(t *testing.T) {
	resource1 := createTestResource(t)
	resource2 := createTestResource(t)

	ids := []int64{resource1.ID, resource2.ID}
	resources, err := database.GetResourcesByIDs(context.Background(), nil, ids)
	if err != nil {
		t.Fatalf("Failed to get resources by IDs: %v", err)
	}

	if len(resources) != 2 {
		t.Errorf("Expected 2 resources, got %d", len(resources))
	}

	foundResource1 := false
	foundResource2 := false
	for _, resource := range resources {
		if resource.ID == resource1.ID {
			foundResource1 = true
		}
		if resource.ID == resource2.ID {
			foundResource2 = true
		}
	}

	if !foundResource1 || !foundResource2 {
		t.Error("Not all created resources were found in GetResourcesByIDs result")
	}
}

func TestGetAllResources(t *testing.T) {
	// Clean the database first
	existingResources, err := database.GetAllResources(context.Background(), nil)
	if err != nil {
		t.Fatalf("Failed to get existing resources: %v", err)
	}
	for _, resource := range existingResources {
		deleteResourceErr := database.DeleteResource(context.Background(), nil, resource.ID)
		if deleteResourceErr != nil {
			t.Fatalf("Failed to delete existing resource: %v", deleteResourceErr)
		}
	}

	// Create 3 test resources
	resource1 := createTestResource(t)
	resource2 := createTestResource(t)
	resource3 := createTestResource(t)

	// Get all resources
	resources, err := database.GetAllResources(context.Background(), nil)
	if err != nil {
		t.Fatalf("Failed to get all resources: %v", err)
	}

	// Check if we got exactly 3 resources
	if len(resources) != 3 {
		t.Errorf("Expected exactly 3 resources, got %d", len(resources))
	}

	// Check if all created resources are in the result
	foundResource1 := false
	foundResource2 := false
	foundResource3 := false
	for _, resource := range resources {
		switch resource.ID {
		case resource1.ID:
			foundResource1 = true
		case resource2.ID:
			foundResource2 = true
		case resource3.ID:
			foundResource3 = true
		}
	}

	if !foundResource1 {
		t.Error("Resource 1 was not found in GetAllResources result")
	}
	if !foundResource2 {
		t.Error("Resource 2 was not found in GetAllResources result")
	}
	if !foundResource3 {
		t.Error("Resource 3 was not found in GetAllResources result")
	}
}

func TestDeleteResource(t *testing.T) {
	resource := createTestResource(t)

	err := database.DeleteResource(context.Background(), nil, resource.ID)
	if err != nil {
		t.Fatalf("Failed to delete resource: %v", err)
	}

	deletedResource, err := database.GetResourceByID(context.Background(), nil, resource.ID)
	if err != nil {
		t.Fatalf("Error while checking for deleted resource: %v", err)
	}
	if deletedResource != nil {
		t.Errorf("Resource still exists after deletion")
	}

	err = database.DeleteResource(context.Background(), nil, 99999)
	if err != nil {
		t.Errorf("Expected no error when deleting non-existent resource, got: %v", err)
	}
}

func createTestResource(t *testing.T) *record.Resource {
	resource := &record.Resource{
		// The identifier is unique across the tier's shared database, so the suffix is long enough
		// that two draws do not meet. The whole stays inside the column's 40 characters.
		ResourceIdentifier: "test_resource_" + fake.LetterN(12),
		Description:        "Test Resource",
	}
	err := database.CreateResource(context.Background(), nil, resource)
	if err != nil {
		t.Fatalf("Failed to create test resource: %v", err)
	}
	return resource
}

// TestGetResourceByResourceIdentifierIsCaseSensitive is the client test's property for
// resources, and this lookup is the one RFC 6749 section 3.3 reaches: a scope is
// "resource-identifier:permission-identifier" and the section says the scope parameter is
// "expressed as a list of space-delimited, case-sensitive strings". The permission half is
// already resolved in Go, by comparing against the resource's own permissions, so this
// lookup is the whole of the scope string's exposure to the collation.
//
// The padded lookup covers the fold no collation reaches: SQL Server pads for `=`, so the
// row comes back and the data layer discards it (commondb.engineFoldedTheMatch). See
// TestGetClientByClientIdentifierIsCaseSensitive for the whole of the reasoning.
func TestGetResourceByResourceIdentifierIsCaseSensitive(t *testing.T) {
	lower := "case_resource_" + strings.ToLower(fake.LetterN(6))
	upper := strings.ToUpper(lower)

	lowerResource := &record.Resource{ResourceIdentifier: lower, Description: "lowercase"}
	if err := database.CreateResource(context.Background(), nil, lowerResource); err != nil {
		t.Fatalf("Failed to create the lowercase resource: %v", err)
	}

	// A second resource differing from the first only by case, which MySQL and SQL Server
	// refused before 000040.
	upperResource := &record.Resource{ResourceIdentifier: upper, Description: "uppercase"}
	if err := database.CreateResource(context.Background(), nil, upperResource); err != nil {
		t.Fatalf("Failed to create a resource differing only by case, which every engine must now accept: %v", err)
	}

	for _, tc := range []struct {
		name   string
		lookup string
		wantID int64
	}{
		{"the lowercase name resolves the lowercase resource", lower, lowerResource.ID},
		{"the uppercase name resolves the uppercase resource", upper, upperResource.ID},
		{"a mis-cased name resolves nothing", "Case_Resource_" + strings.ToUpper(lower[14:]), 0},
		{"a trailing space resolves nothing, which SQL Server's padding would otherwise defeat", lower + " ", 0},
	} {
		got, err := database.GetResourceByResourceIdentifier(context.Background(), nil, tc.lookup)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", tc.name, err)
		}
		if tc.wantID == 0 {
			if got != nil {
				t.Errorf("%s: expected nil, got the resource with id %d and identifier %q",
					tc.name, got.ID, got.ResourceIdentifier)
			}
			continue
		}
		if got == nil {
			t.Fatalf("%s: expected the resource with id %d, got nil", tc.name, tc.wantID)
		}
		if got.ID != tc.wantID {
			t.Errorf("%s: expected the resource with id %d, got id %d (identifier %q)",
				tc.name, tc.wantID, got.ID, got.ResourceIdentifier)
		}
	}
}

// TestGetIdentifiersSharedByClientsAndResources pins the read behind the startup warning of
// #151: it answers an identifier both a client and a resource hold, and nothing for a client
// alone, a pair differing only by case, or a pair differing only by a trailing space, which SQL
// Server's padding joins and the data layer discards (commondb.engineFoldedTheMatch). The shared
// database holds other tests' rows, so only the identifiers this test wrote are compared.
func TestGetIdentifiersSharedByClientsAndResources(t *testing.T) {
	prefix := "shared_" + strings.ToLower(fake.LetterN(6)) + "_"
	shared := prefix + "both"

	clients := []string{shared, prefix + "client_only", prefix + "Cased", prefix + "padded"}
	resources := []string{shared, prefix + "resource_only", prefix + "cased", prefix + "padded "}
	for _, identifier := range clients {
		client := &record.Client{ClientIdentifier: identifier, Description: "Test Client"}
		if err := database.CreateClient(context.Background(), nil, client); err != nil {
			t.Fatalf("Failed to create the client %q: %v", identifier, err)
		}
		t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.ID) })
	}
	for _, identifier := range resources {
		resource := &record.Resource{ResourceIdentifier: identifier, Description: "Test Resource"}
		if err := database.CreateResource(context.Background(), nil, resource); err != nil {
			t.Fatalf("Failed to create the resource %q: %v", identifier, err)
		}
		t.Cleanup(func() { _ = database.DeleteResource(context.Background(), nil, resource.ID) })
	}

	identifiers, err := database.GetIdentifiersSharedByClientsAndResources(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var ours []string
	for _, identifier := range identifiers {
		if strings.HasPrefix(identifier, prefix) {
			ours = append(ours, identifier)
		}
	}
	if len(ours) != 1 || ours[0] != shared {
		t.Errorf("expected exactly %q among this test's identifiers, got %q", shared, ours)
	}
}
