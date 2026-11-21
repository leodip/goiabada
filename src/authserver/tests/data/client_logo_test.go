package datatests

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
)

func TestCreateClientLogo(t *testing.T) {
	client := createTestClient(t)
	clientLogo := createTestClientLogo(t, client.ID)

	if clientLogo.ID == 0 {
		t.Error("Expected non-zero ID after creation")
	}
	if !clientLogo.CreatedAt.Valid || clientLogo.CreatedAt.Time.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
	if !clientLogo.UpdatedAt.Valid || clientLogo.UpdatedAt.Time.IsZero() {
		t.Error("Expected UpdatedAt to be set")
	}

	retrieved, err := database.GetClientLogoByClientID(context.Background(), nil, client.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve created client logo: %v", err)
	}

	if retrieved.ID != clientLogo.ID {
		t.Errorf("Expected ID %d, got %d", clientLogo.ID, retrieved.ID)
	}
	if retrieved.ClientID != clientLogo.ClientID {
		t.Errorf("Expected ClientID %d, got %d", clientLogo.ClientID, retrieved.ClientID)
	}
	if retrieved.ContentType != clientLogo.ContentType {
		t.Errorf("Expected ContentType %s, got %s", clientLogo.ContentType, retrieved.ContentType)
	}
	if !bytes.Equal(retrieved.Logo, clientLogo.Logo) {
		t.Error("Expected Logo data to match")
	}
}

func TestCreateClientLogo_ZeroClientID(t *testing.T) {
	clientLogo := &record.ClientLogo{
		ClientID:    0,
		Logo:        createTestPNG(100, 100),
		ContentType: "image/png",
	}

	err := database.CreateClientLogo(context.Background(), nil, clientLogo)
	if err == nil {
		t.Error("Expected error when creating client logo with zero ClientID")
	}
}

func TestUpdateClientLogo(t *testing.T) {
	client := createTestClient(t)
	clientLogo := createTestClientLogo(t, client.ID)

	// Update the logo
	newLogoData := createTestPNG(200, 200)
	clientLogo.Logo = newLogoData
	clientLogo.ContentType = "image/jpeg"

	time.Sleep(timestampTick)

	err := database.UpdateClientLogo(context.Background(), nil, clientLogo)
	if err != nil {
		t.Fatalf("Failed to update client logo: %v", err)
	}

	updated, err := database.GetClientLogoByClientID(context.Background(), nil, client.ID)
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

func TestUpdateClientLogo_ZeroID(t *testing.T) {
	clientLogo := &record.ClientLogo{
		ID:          0,
		ClientID:    1,
		Logo:        createTestPNG(100, 100),
		ContentType: "image/png",
	}

	err := database.UpdateClientLogo(context.Background(), nil, clientLogo)
	if err == nil {
		t.Error("Expected error when updating client logo with zero ID")
	}
}

func TestGetClientLogoByClientID(t *testing.T) {
	client := createTestClient(t)
	clientLogo := createTestClientLogo(t, client.ID)

	retrieved, err := database.GetClientLogoByClientID(context.Background(), nil, client.ID)
	if err != nil {
		t.Fatalf("Failed to get client logo by client ID: %v", err)
	}

	if retrieved == nil {
		t.Fatal("Expected client logo to be found")
	}
	if retrieved.ID != clientLogo.ID {
		t.Errorf("Expected ID %d, got %d", clientLogo.ID, retrieved.ID)
	}
	if retrieved.ClientID != client.ID {
		t.Errorf("Expected ClientID %d, got %d", client.ID, retrieved.ClientID)
	}
}

func TestGetClientLogoByClientID_NotFound(t *testing.T) {
	// Use a client ID that doesn't have a logo
	retrieved, err := database.GetClientLogoByClientID(context.Background(), nil, 99999999)
	if err != nil {
		t.Errorf("Expected no error for non-existent client logo, got: %v", err)
	}
	if retrieved != nil {
		t.Errorf("Expected nil for non-existent client logo, got ID: %d", retrieved.ID)
	}
}

func TestDeleteClientLogo(t *testing.T) {
	client := createTestClient(t)
	_ = createTestClientLogo(t, client.ID)

	// Verify it exists
	exists, err := database.ClientHasLogo(context.Background(), nil, client.ID)
	if err != nil {
		t.Fatalf("Failed to check if client has logo: %v", err)
	}
	if !exists {
		t.Fatal("Expected client logo to exist before deletion")
	}

	// Delete it
	err = database.DeleteClientLogo(context.Background(), nil, client.ID)
	if err != nil {
		t.Fatalf("Failed to delete client logo: %v", err)
	}

	// Verify it's gone
	deleted, err := database.GetClientLogoByClientID(context.Background(), nil, client.ID)
	if err != nil {
		t.Fatalf("Error while checking for deleted client logo: %v", err)
	}
	if deleted != nil {
		t.Error("Client logo still exists after deletion")
	}
}

func TestDeleteClientLogo_NotExist(t *testing.T) {
	// Deleting a non-existent client logo should not return an error
	err := database.DeleteClientLogo(context.Background(), nil, 99999999)
	if err != nil {
		t.Errorf("Expected no error when deleting non-existent client logo, got: %v", err)
	}
}

func TestClientHasLogo_True(t *testing.T) {
	client := createTestClient(t)
	_ = createTestClientLogo(t, client.ID)

	hasLogo, err := database.ClientHasLogo(context.Background(), nil, client.ID)
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

	hasLogo, err := database.ClientHasLogo(context.Background(), nil, client.ID)
	if err != nil {
		t.Fatalf("Failed to check if client has logo: %v", err)
	}
	if hasLogo {
		t.Error("Expected ClientHasLogo to return false")
	}
}

func TestClientHasLogo_NonExistentClient(t *testing.T) {
	hasLogo, err := database.ClientHasLogo(context.Background(), nil, 99999999)
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

	logo1 := &record.ClientLogo{
		ClientID:    client1.ID,
		Logo:        logo1Data,
		ContentType: "image/png",
	}
	err := database.CreateClientLogo(context.Background(), nil, logo1)
	if err != nil {
		t.Fatalf("Failed to create logo for client1: %v", err)
	}

	logo2 := &record.ClientLogo{
		ClientID:    client2.ID,
		Logo:        logo2Data,
		ContentType: "image/png",
	}
	err = database.CreateClientLogo(context.Background(), nil, logo2)
	if err != nil {
		t.Fatalf("Failed to create logo for client2: %v", err)
	}

	// Verify each client has their own logo
	retrieved1, err := database.GetClientLogoByClientID(context.Background(), nil, client1.ID)
	if err != nil {
		t.Fatalf("Failed to get logo for client1: %v", err)
	}
	if !bytes.Equal(retrieved1.Logo, logo1Data) {
		t.Error("Client1's logo data doesn't match")
	}

	retrieved2, err := database.GetClientLogoByClientID(context.Background(), nil, client2.ID)
	if err != nil {
		t.Fatalf("Failed to get logo for client2: %v", err)
	}
	if !bytes.Equal(retrieved2.Logo, logo2Data) {
		t.Error("Client2's logo data doesn't match")
	}

	// Deleting client1's logo shouldn't affect client2's logo
	err = database.DeleteClientLogo(context.Background(), nil, client1.ID)
	if err != nil {
		t.Fatalf("Failed to delete client1's logo: %v", err)
	}

	client2StillHasLogo, err := database.ClientHasLogo(context.Background(), nil, client2.ID)
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

	clientLogo := &record.ClientLogo{
		ClientID:    client.ID,
		Logo:        largeLogoData,
		ContentType: "image/png",
	}

	err := database.CreateClientLogo(context.Background(), nil, clientLogo)
	if err != nil {
		t.Fatalf("Failed to create client logo with large data: %v", err)
	}

	retrieved, err := database.GetClientLogoByClientID(context.Background(), nil, client.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve large client logo: %v", err)
	}

	if !bytes.Equal(retrieved.Logo, largeLogoData) {
		t.Error("Large logo data doesn't match after retrieval")
	}
}

func createTestClientLogo(t *testing.T, clientID int64) *record.ClientLogo {
	logoData := createTestPNG(100, 100)
	clientLogo := &record.ClientLogo{
		ClientID:    clientID,
		Logo:        logoData,
		ContentType: "image/png",
	}
	err := database.CreateClientLogo(context.Background(), nil, clientLogo)
	if err != nil {
		t.Fatalf("Failed to create test client logo: %v", err)
	}
	return clientLogo
}
