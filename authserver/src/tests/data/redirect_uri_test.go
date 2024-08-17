package datatests

import (
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/authserver/internal/models"
)

func TestCreateRedirectURI(t *testing.T) {
	client := createTestClient(t)
	redirectURI := &models.RedirectURI{
		URI:      "https://example.com/callback",
		ClientId: client.Id,
	}

	err := database.CreateRedirectURI(nil, redirectURI)
	if err != nil {
		t.Fatalf("Failed to create redirect URI: %v", err)
	}

	if redirectURI.Id == 0 {
		t.Error("Expected non-zero ID after creation")
	}
	if !redirectURI.CreatedAt.Valid || redirectURI.CreatedAt.Time.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}

	retrievedRedirectURI, err := database.GetRedirectURIById(nil, redirectURI.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve created redirect URI: %v", err)
	}

	if retrievedRedirectURI.URI != redirectURI.URI {
		t.Errorf("Expected URI %s, got %s", redirectURI.URI, retrievedRedirectURI.URI)
	}
	if retrievedRedirectURI.ClientId != redirectURI.ClientId {
		t.Errorf("Expected ClientId %d, got %d", redirectURI.ClientId, retrievedRedirectURI.ClientId)
	}
}

func TestGetRedirectURIById(t *testing.T) {
	client := createTestClient(t)
	redirectURI := createTestRedirectURI(t, client.Id)

	retrievedRedirectURI, err := database.GetRedirectURIById(nil, redirectURI.Id)
	if err != nil {
		t.Fatalf("Failed to get redirect URI by ID: %v", err)
	}

	if retrievedRedirectURI.Id != redirectURI.Id {
		t.Errorf("Expected ID %d, got %d", redirectURI.Id, retrievedRedirectURI.Id)
	}
	if retrievedRedirectURI.URI != redirectURI.URI {
		t.Errorf("Expected URI %s, got %s", redirectURI.URI, retrievedRedirectURI.URI)
	}

	nonExistentRedirectURI, err := database.GetRedirectURIById(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error for non-existent redirect URI, got: %v", err)
	}
	if nonExistentRedirectURI != nil {
		t.Errorf("Expected nil for non-existent redirect URI, got a redirect URI with ID: %d", nonExistentRedirectURI.Id)
	}
}

func TestGetRedirectURIsByClientId(t *testing.T) {
	client := createTestClient(t)
	redirectURI1 := createTestRedirectURI(t, client.Id)
	redirectURI2 := createTestRedirectURI(t, client.Id)

	redirectURIs, err := database.GetRedirectURIsByClientId(nil, client.Id)
	if err != nil {
		t.Fatalf("Failed to get redirect URIs by client ID: %v", err)
	}

	if len(redirectURIs) != 2 {
		t.Errorf("Expected 2 redirect URIs, got %d", len(redirectURIs))
	}

	foundURI1 := false
	foundURI2 := false
	for _, uri := range redirectURIs {
		if uri.Id == redirectURI1.Id {
			foundURI1 = true
		}
		if uri.Id == redirectURI2.Id {
			foundURI2 = true
		}
	}

	if !foundURI1 || !foundURI2 {
		t.Error("Not all created redirect URIs were found in GetRedirectURIsByClientId result")
	}
}

func TestDeleteRedirectURI(t *testing.T) {
	client := createTestClient(t)
	redirectURI := createTestRedirectURI(t, client.Id)

	err := database.DeleteRedirectURI(nil, redirectURI.Id)
	if err != nil {
		t.Fatalf("Failed to delete redirect URI: %v", err)
	}

	deletedRedirectURI, err := database.GetRedirectURIById(nil, redirectURI.Id)
	if err != nil {
		t.Fatalf("Error while checking for deleted redirect URI: %v", err)
	}
	if deletedRedirectURI != nil {
		t.Errorf("Redirect URI still exists after deletion")
	}

	err = database.DeleteRedirectURI(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error when deleting non-existent redirect URI, got: %v", err)
	}
}

func createTestRedirectURI(t *testing.T, clientId int64) *models.RedirectURI {
	redirectURI := &models.RedirectURI{
		URI:      "https://example.com/callback_" + gofakeit.LetterN(6),
		ClientId: clientId,
	}
	err := database.CreateRedirectURI(nil, redirectURI)
	if err != nil {
		t.Fatalf("Failed to create test redirect URI: %v", err)
	}
	return redirectURI
}
