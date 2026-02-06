package datatests

import (
	"bytes"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/models"
)

func TestCreateClientLogo(t *testing.T) {
	client := createTestClient(t)
	clientLogo := createTestClientLogo(t, client.Id)

	if clientLogo.Id == 0 {
		t.Error("Expected non-zero ID after creation")
	}
	if !clientLogo.CreatedAt.Valid || clientLogo.CreatedAt.Time.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
	if !clientLogo.UpdatedAt.Valid || clientLogo.UpdatedAt.Time.IsZero() {
		t.Error("Expected UpdatedAt to be set")
	}

	retrieved, err := database.GetClientLogoByClientId(nil, client.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve created client logo: %v", err)
	}

	if retrieved.Id != clientLogo.Id {
		t.Errorf("Expected ID %d, got %d", clientLogo.Id, retrieved.Id)
	}
	if retrieved.ClientId != clientLogo.ClientId {
		t.Errorf("Expected ClientId %d, got %d", clientLogo.ClientId, retrieved.ClientId)
	}
	if retrieved.ContentType != clientLogo.ContentType {
		t.Errorf("Expected ContentType %s, got %s", clientLogo.ContentType, retrieved.ContentType)
	}
	if !bytes.Equal(retrieved.Logo, clientLogo.Logo) {
		t.Error("Expected Logo data to match")
	}
}

func TestCreateClientLogo_ZeroClientId(t *testing.T) {
	clientLogo := &models.ClientLogo{
		ClientId:    0,
		Logo:        createTestPNG(100, 100),
		ContentType: "image/png",
	}

	err := database.CreateClientLogo(nil, clientLogo)
	if err == nil {
		t.Error("Expected error when creating client logo with zero ClientId")
	}
}

func TestUpdateClientLogo(t *testing.T) {
	client := createTestClient(t)
	clientLogo := createTestClientLogo(t, client.Id)

	// Update the logo
	newLogoData := createTestPNG(200, 200)
	clientLogo.Logo = newLogoData
	clientLogo.ContentType = "image/jpeg"

	time.Sleep(time.Millisecond * 100)

	err := database.UpdateClientLogo(nil, clientLogo)
	if err != nil {
		t.Fatalf("Failed to update client logo: %v", err)
	}

	updated, err := database.GetClientLogoByClientId(nil, client.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve updated client logo: %v", err)
	}

	if updated.ContentType != "image/jpeg" {
		t.Errorf("Expected ContentType 'image/jpeg', got %s", updated.ContentType)
	}
	if !bytes.Equal(updated.Logo, newLogoData) {
		t.Error("Expected Logo data to match updated data")
	}
	if !updated.UpdatedAt.Time.After(updated.CreatedAt.Time) {
		t.Error("Expected UpdatedAt to be after CreatedAt")
	}
}

func TestUpdateClientLogo_ZeroId(t *testing.T) {
	clientLogo := &models.ClientLogo{
		Id:          0,
		ClientId:    1,
		Logo:        createTestPNG(100, 100),
		ContentType: "image/png",
	}

	err := database.UpdateClientLogo(nil, clientLogo)
	if err == nil {
		t.Error("Expected error when updating client logo with zero ID")
	}
}

func TestGetClientLogoByClientId(t *testing.T) {
	client := createTestClient(t)
	clientLogo := createTestClientLogo(t, client.Id)

	retrieved, err := database.GetClientLogoByClientId(nil, client.Id)
	if err != nil {
		t.Fatalf("Failed to get client logo by client ID: %v", err)
	}

	if retrieved == nil {
		t.Fatal("Expected client logo to be found")
	}
	if retrieved.Id != clientLogo.Id {
		t.Errorf("Expected ID %d, got %d", clientLogo.Id, retrieved.Id)
	}
	if retrieved.ClientId != client.Id {
		t.Errorf("Expected ClientId %d, got %d", client.Id, retrieved.ClientId)
	}
}

func TestGetClientLogoByClientId_NotFound(t *testing.T) {
	// Use a client ID that doesn't have a logo
	retrieved, err := database.GetClientLogoByClientId(nil, 99999999)
	if err != nil {
		t.Errorf("Expected no error for non-existent client logo, got: %v", err)
	}
	if retrieved != nil {
		t.Errorf("Expected nil for non-existent client logo, got ID: %d", retrieved.Id)
	}
}

func TestDeleteClientLogo(t *testing.T) {
	client := createTestClient(t)
	_ = createTestClientLogo(t, client.Id)

	// Verify it exists
	exists, err := database.ClientHasLogo(nil, client.Id)
	if err != nil {
		t.Fatalf("Failed to check if client has logo: %v", err)
	}
	if !exists {
		t.Fatal("Expected client logo to exist before deletion")
	}

	// Delete it
	err = database.DeleteClientLogo(nil, client.Id)
	if err != nil {
		t.Fatalf("Failed to delete client logo: %v", err)
	}

	// Verify it's gone
	deleted, err := database.GetClientLogoByClientId(nil, client.Id)
	if err != nil {
		t.Fatalf("Error while checking for deleted client logo: %v", err)
	}
	if deleted != nil {
		t.Error("Client logo still exists after deletion")
	}
}

func TestDeleteClientLogo_NotExist(t *testing.T) {
	// Deleting a non-existent client logo should not return an error
	err := database.DeleteClientLogo(nil, 99999999)
	if err != nil {
		t.Errorf("Expected no error when deleting non-existent client logo, got: %v", err)
	}
}

func TestClientHasLogo_True(t *testing.T) {
	client := createTestClient(t)
	_ = createTestClientLogo(t, client.Id)

	hasLogo, err := database.ClientHasLogo(nil, client.Id)
	if err != nil {
		t.Fatalf("Failed to check if client has logo: %v", err)
	}
	if !hasLogo {
		t.Error("Expected ClientHasLogo to return true")
	}
}

func TestClientHasLogo_False(t *testing.T) {
	client := createTestClient(t)
	// Don't create a logo for this client

	hasLogo, err := database.ClientHasLogo(nil, client.Id)
	if err != nil {
		t.Fatalf("Failed to check if client has logo: %v", err)
	}
	if hasLogo {
		t.Error("Expected ClientHasLogo to return false")
	}
}

func TestClientHasLogo_NonExistentClient(t *testing.T) {
	hasLogo, err := database.ClientHasLogo(nil, 99999999)
	if err != nil {
		t.Fatalf("Failed to check if client has logo: %v", err)
	}
	if hasLogo {
		t.Error("Expected ClientHasLogo to return false for non-existent client")
	}
}

func TestClientLogo_MultipleClients(t *testing.T) {
	// Create two clients with logos
	client1 := createTestClient(t)
	client2 := createTestClient(t)

	logo1Data := createTestPNG(50, 50)
	logo2Data := createTestPNG(100, 100)

	logo1 := &models.ClientLogo{
		ClientId:    client1.Id,
		Logo:        logo1Data,
		ContentType: "image/png",
	}
	err := database.CreateClientLogo(nil, logo1)
	if err != nil {
		t.Fatalf("Failed to create logo for client1: %v", err)
	}

	logo2 := &models.ClientLogo{
		ClientId:    client2.Id,
		Logo:        logo2Data,
		ContentType: "image/png",
	}
	err = database.CreateClientLogo(nil, logo2)
	if err != nil {
		t.Fatalf("Failed to create logo for client2: %v", err)
	}

	// Verify each client has their own logo
	retrieved1, err := database.GetClientLogoByClientId(nil, client1.Id)
	if err != nil {
		t.Fatalf("Failed to get logo for client1: %v", err)
	}
	if !bytes.Equal(retrieved1.Logo, logo1Data) {
		t.Error("Client1's logo data doesn't match")
	}

	retrieved2, err := database.GetClientLogoByClientId(nil, client2.Id)
	if err != nil {
		t.Fatalf("Failed to get logo for client2: %v", err)
	}
	if !bytes.Equal(retrieved2.Logo, logo2Data) {
		t.Error("Client2's logo data doesn't match")
	}

	// Deleting client1's logo shouldn't affect client2's logo
	err = database.DeleteClientLogo(nil, client1.Id)
	if err != nil {
		t.Fatalf("Failed to delete client1's logo: %v", err)
	}

	client2StillHasLogo, err := database.ClientHasLogo(nil, client2.Id)
	if err != nil {
		t.Fatalf("Failed to check if client2 has logo: %v", err)
	}
	if !client2StillHasLogo {
		t.Error("Client2's logo was deleted when client1's was deleted")
	}
}

func TestClientLogo_LargeLogoData(t *testing.T) {
	client := createTestClient(t)

	// Create a larger image (512x512)
	largeLogoData := createTestPNG(512, 512)

	clientLogo := &models.ClientLogo{
		ClientId:    client.Id,
		Logo:        largeLogoData,
		ContentType: "image/png",
	}

	err := database.CreateClientLogo(nil, clientLogo)
	if err != nil {
		t.Fatalf("Failed to create client logo with large data: %v", err)
	}

	retrieved, err := database.GetClientLogoByClientId(nil, client.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve large client logo: %v", err)
	}

	if !bytes.Equal(retrieved.Logo, largeLogoData) {
		t.Error("Large logo data doesn't match after retrieval")
	}
}

func createTestClientLogo(t *testing.T, clientId int64) *models.ClientLogo {
	logoData := createTestPNG(100, 100)
	clientLogo := &models.ClientLogo{
		ClientId:    clientId,
		Logo:        logoData,
		ContentType: "image/png",
	}
	err := database.CreateClientLogo(nil, clientLogo)
	if err != nil {
		t.Fatalf("Failed to create test client logo: %v", err)
	}
	return clientLogo
}
