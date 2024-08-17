package datatests

import (
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/authserver/internal/models"
)

func TestCreateWebOrigin(t *testing.T) {
	client := createTestClient(t)
	webOrigin := &models.WebOrigin{
		Origin:   "https://example.com",
		ClientId: client.Id,
	}

	err := database.CreateWebOrigin(nil, webOrigin)
	if err != nil {
		t.Fatalf("Failed to create web origin: %v", err)
	}

	if webOrigin.Id == 0 {
		t.Error("Expected non-zero ID after creation")
	}
	if !webOrigin.CreatedAt.Valid || webOrigin.CreatedAt.Time.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}

	retrievedWebOrigin, err := database.GetWebOriginById(nil, webOrigin.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve created web origin: %v", err)
	}

	if retrievedWebOrigin.Origin != webOrigin.Origin {
		t.Errorf("Expected Origin %s, got %s", webOrigin.Origin, retrievedWebOrigin.Origin)
	}
	if retrievedWebOrigin.ClientId != webOrigin.ClientId {
		t.Errorf("Expected ClientId %d, got %d", webOrigin.ClientId, retrievedWebOrigin.ClientId)
	}

	database.DeleteWebOrigin(nil, webOrigin.Id)
	database.DeleteClient(nil, client.Id)
}

func TestGetWebOriginById(t *testing.T) {
	client := createTestClient(t)
	webOrigin := createTestWebOrigin(t, client.Id)

	retrievedWebOrigin, err := database.GetWebOriginById(nil, webOrigin.Id)
	if err != nil {
		t.Fatalf("Failed to get web origin by ID: %v", err)
	}

	if retrievedWebOrigin.Id != webOrigin.Id {
		t.Errorf("Expected ID %d, got %d", webOrigin.Id, retrievedWebOrigin.Id)
	}
	if retrievedWebOrigin.Origin != webOrigin.Origin {
		t.Errorf("Expected Origin %s, got %s", webOrigin.Origin, retrievedWebOrigin.Origin)
	}

	nonExistentWebOrigin, err := database.GetWebOriginById(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error for non-existent web origin, got: %v", err)
	}
	if nonExistentWebOrigin != nil {
		t.Errorf("Expected nil for non-existent web origin, got a web origin with ID: %d", nonExistentWebOrigin.Id)
	}

	database.DeleteWebOrigin(nil, webOrigin.Id)
	database.DeleteClient(nil, client.Id)
}

func TestGetWebOriginsByClientId(t *testing.T) {
	client := createTestClient(t)
	webOrigin1 := createTestWebOrigin(t, client.Id)
	webOrigin2 := createTestWebOrigin(t, client.Id)

	webOrigins, err := database.GetWebOriginsByClientId(nil, client.Id)
	if err != nil {
		t.Fatalf("Failed to get web origins by client ID: %v", err)
	}

	if len(webOrigins) != 2 {
		t.Errorf("Expected 2 web origins, got %d", len(webOrigins))
	}

	foundWebOrigin1 := false
	foundWebOrigin2 := false
	for _, webOrigin := range webOrigins {
		if webOrigin.Id == webOrigin1.Id {
			foundWebOrigin1 = true
		}
		if webOrigin.Id == webOrigin2.Id {
			foundWebOrigin2 = true
		}
	}

	if !foundWebOrigin1 || !foundWebOrigin2 {
		t.Error("Not all created web origins were found in GetWebOriginsByClientId result")
	}

	database.DeleteWebOrigin(nil, webOrigin1.Id)
	database.DeleteWebOrigin(nil, webOrigin2.Id)
	database.DeleteClient(nil, client.Id)
}

func TestGetAllWebOrigins(t *testing.T) {
	// First, delete all existing web origins
	existingWebOrigins, err := database.GetAllWebOrigins(nil)
	if err != nil {
		t.Fatalf("Failed to get existing web origins: %v", err)
	}
	for _, webOrigin := range existingWebOrigins {
		err := database.DeleteWebOrigin(nil, webOrigin.Id)
		if err != nil {
			t.Fatalf("Failed to delete existing web origin: %v", err)
		}
	}

	// Create a client and two web origins for testing
	client := createTestClient(t)
	webOrigin1 := createTestWebOrigin(t, client.Id)
	webOrigin2 := createTestWebOrigin(t, client.Id)

	webOrigins, err := database.GetAllWebOrigins(nil)
	if err != nil {
		t.Fatalf("Failed to get all web origins: %v", err)
	}

	if len(webOrigins) != 2 {
		t.Errorf("Expected exactly 2 web origins, got %d", len(webOrigins))
	}

	foundWebOrigin1 := false
	foundWebOrigin2 := false
	for _, webOrigin := range webOrigins {
		if webOrigin.Id == webOrigin1.Id {
			foundWebOrigin1 = true
		}
		if webOrigin.Id == webOrigin2.Id {
			foundWebOrigin2 = true
		}
	}

	if !foundWebOrigin1 || !foundWebOrigin2 {
		t.Error("Not all created web origins were found in GetAllWebOrigins result")
	}

	// Clean up
	database.DeleteWebOrigin(nil, webOrigin1.Id)
	database.DeleteWebOrigin(nil, webOrigin2.Id)
	database.DeleteClient(nil, client.Id)
}

func TestDeleteWebOrigin(t *testing.T) {
	client := createTestClient(t)
	webOrigin := createTestWebOrigin(t, client.Id)

	err := database.DeleteWebOrigin(nil, webOrigin.Id)
	if err != nil {
		t.Fatalf("Failed to delete web origin: %v", err)
	}

	deletedWebOrigin, err := database.GetWebOriginById(nil, webOrigin.Id)
	if err != nil {
		t.Fatalf("Error while checking for deleted web origin: %v", err)
	}
	if deletedWebOrigin != nil {
		t.Errorf("Web origin still exists after deletion")
	}

	err = database.DeleteWebOrigin(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error when deleting non-existent web origin, got: %v", err)
	}

	database.DeleteClient(nil, client.Id)
}

func createTestWebOrigin(t *testing.T, clientId int64) *models.WebOrigin {
	random := gofakeit.LetterN(6)
	webOrigin := &models.WebOrigin{
		Origin:   "https://" + random + ".example.com",
		ClientId: clientId,
	}
	err := database.CreateWebOrigin(nil, webOrigin)
	if err != nil {
		t.Fatalf("Failed to create test web origin: %v", err)
	}
	return webOrigin
}
