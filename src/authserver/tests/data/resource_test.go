package datatests

import (
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/models"
)

func TestCreateResource(t *testing.T) {
	resource := &models.Resource{
		ResourceIdentifier: "test_resource_" + gofakeit.LetterN(6),
		Description:        "Test Resource",
	}

	err := database.CreateResource(nil, resource)
	if err != nil {
		t.Fatalf("Failed to create resource: %v", err)
	}

	if resource.Id == 0 {
		t.Error("Expected non-zero ID after creation")
	}
	if !resource.CreatedAt.Valid || resource.CreatedAt.Time.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
	if !resource.UpdatedAt.Valid || resource.UpdatedAt.Time.IsZero() {
		t.Error("Expected UpdatedAt to be set")
	}

	retrievedResource, err := database.GetResourceById(nil, resource.Id)
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

	resource.ResourceIdentifier = "updated_resource_identifier_" + gofakeit.LetterN(6)
	resource.Description = "Updated Description"

	time.Sleep(time.Millisecond * 100)

	err := database.UpdateResource(nil, resource)
	if err != nil {
		t.Fatalf("Failed to update resource: %v", err)
	}

	updatedResource, err := database.GetResourceById(nil, resource.Id)
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

func TestGetResourceById(t *testing.T) {
	resource := createTestResource(t)

	retrievedResource, err := database.GetResourceById(nil, resource.Id)
	if err != nil {
		t.Fatalf("Failed to get resource by ID: %v", err)
	}

	if retrievedResource.Id != resource.Id {
		t.Errorf("Expected ID %d, got %d", resource.Id, retrievedResource.Id)
	}
	if retrievedResource.ResourceIdentifier != resource.ResourceIdentifier {
		t.Errorf("Expected ResourceIdentifier %s, got %s", resource.ResourceIdentifier, retrievedResource.ResourceIdentifier)
	}

	nonExistentResource, err := database.GetResourceById(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error for non-existent resource, got: %v", err)
	}
	if nonExistentResource != nil {
		t.Errorf("Expected nil for non-existent resource, got a resource with ID: %d", nonExistentResource.Id)
	}
}

func TestGetResourceByResourceIdentifier(t *testing.T) {
	resource := createTestResource(t)

	retrievedResource, err := database.GetResourceByResourceIdentifier(nil, resource.ResourceIdentifier)
	if err != nil {
		t.Fatalf("Failed to get resource by identifier: %v", err)
	}

	if retrievedResource.Id != resource.Id {
		t.Errorf("Expected ID %d, got %d", resource.Id, retrievedResource.Id)
	}
	if retrievedResource.ResourceIdentifier != resource.ResourceIdentifier {
		t.Errorf("Expected ResourceIdentifier %s, got %s", resource.ResourceIdentifier, retrievedResource.ResourceIdentifier)
	}

	nonExistentResource, err := database.GetResourceByResourceIdentifier(nil, "non_existent_identifier")
	if err != nil {
		t.Errorf("Expected no error for non-existent resource, got: %v", err)
	}
	if nonExistentResource != nil {
		t.Errorf("Expected nil for non-existent resource, got a resource with ID: %d", nonExistentResource.Id)
	}
}

func TestGetResourcesByIds(t *testing.T) {
	resource1 := createTestResource(t)
	resource2 := createTestResource(t)

	ids := []int64{resource1.Id, resource2.Id}
	resources, err := database.GetResourcesByIds(nil, ids)
	if err != nil {
		t.Fatalf("Failed to get resources by IDs: %v", err)
	}

	if len(resources) != 2 {
		t.Errorf("Expected 2 resources, got %d", len(resources))
	}

	foundResource1 := false
	foundResource2 := false
	for _, resource := range resources {
		if resource.Id == resource1.Id {
			foundResource1 = true
		}
		if resource.Id == resource2.Id {
			foundResource2 = true
		}
	}

	if !foundResource1 || !foundResource2 {
		t.Error("Not all created resources were found in GetResourcesByIds result")
	}
}

func TestGetAllResources(t *testing.T) {
	// Clean the database first
	existingResources, err := database.GetAllResources(nil)
	if err != nil {
		t.Fatalf("Failed to get existing resources: %v", err)
	}
	for _, resource := range existingResources {
		err := database.DeleteResource(nil, resource.Id)
		if err != nil {
			t.Fatalf("Failed to delete existing resource: %v", err)
		}
	}

	// Create 3 test resources
	resource1 := createTestResource(t)
	resource2 := createTestResource(t)
	resource3 := createTestResource(t)

	// Get all resources
	resources, err := database.GetAllResources(nil)
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
		switch resource.Id {
		case resource1.Id:
			foundResource1 = true
		case resource2.Id:
			foundResource2 = true
		case resource3.Id:
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

	err := database.DeleteResource(nil, resource.Id)
	if err != nil {
		t.Fatalf("Failed to delete resource: %v", err)
	}

	deletedResource, err := database.GetResourceById(nil, resource.Id)
	if err != nil {
		t.Fatalf("Error while checking for deleted resource: %v", err)
	}
	if deletedResource != nil {
		t.Errorf("Resource still exists after deletion")
	}

	err = database.DeleteResource(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error when deleting non-existent resource, got: %v", err)
	}
}

func createTestResource(t *testing.T) *models.Resource {
	resource := &models.Resource{
		ResourceIdentifier: "test_resource" + gofakeit.LetterN(4),
		Description:        "Test Resource",
	}
	err := database.CreateResource(nil, resource)
	if err != nil {
		t.Fatalf("Failed to create test resource: %v", err)
	}
	return resource
}
