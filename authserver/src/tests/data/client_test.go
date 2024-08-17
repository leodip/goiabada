package datatests

import (
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/authserver/internal/enums"
	"github.com/leodip/goiabada/authserver/internal/models"
)

func TestCreateClient(t *testing.T) {
	random := gofakeit.LetterN(6)
	client := &models.Client{
		ClientIdentifier:                        "test_client_" + random,
		ClientSecretEncrypted:                   []byte("encrypted_secret"),
		Description:                             "Test Client Description",
		Enabled:                                 true,
		ConsentRequired:                         true,
		IsPublic:                                false,
		AuthorizationCodeEnabled:                true,
		ClientCredentialsEnabled:                true,
		TokenExpirationInSeconds:                3600,
		RefreshTokenOfflineIdleTimeoutInSeconds: 86400,
		RefreshTokenOfflineMaxLifetimeInSeconds: 2592000,
		IncludeOpenIDConnectClaimsInAccessToken: enums.ThreeStateSettingDefault.String(),
		DefaultAcrLevel:                         enums.AcrLevel1,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Verify the client was created
	createdClient, err := database.GetClientByClientIdentifier(nil, client.ClientIdentifier)
	if err != nil {
		t.Fatalf("Failed to retrieve created client: %v", err)
	}

	// Check all properties
	if createdClient.ClientIdentifier != client.ClientIdentifier {
		t.Errorf("Expected ClientIdentifier '%s', got '%s'", client.ClientIdentifier, createdClient.ClientIdentifier)
	}
	if string(createdClient.ClientSecretEncrypted) != string(client.ClientSecretEncrypted) {
		t.Errorf("ClientSecretEncrypted does not match")
	}
	if createdClient.Description != client.Description {
		t.Errorf("Expected Description '%s', got '%s'", client.Description, createdClient.Description)
	}
	if createdClient.Enabled != client.Enabled {
		t.Errorf("Expected Enabled %v, got %v", client.Enabled, createdClient.Enabled)
	}
	if createdClient.ConsentRequired != client.ConsentRequired {
		t.Errorf("Expected ConsentRequired %v, got %v", client.ConsentRequired, createdClient.ConsentRequired)
	}
	if createdClient.IsPublic != client.IsPublic {
		t.Errorf("Expected IsPublic %v, got %v", client.IsPublic, createdClient.IsPublic)
	}
	if createdClient.AuthorizationCodeEnabled != client.AuthorizationCodeEnabled {
		t.Errorf("Expected AuthorizationCodeEnabled %v, got %v", client.AuthorizationCodeEnabled, createdClient.AuthorizationCodeEnabled)
	}
	if createdClient.ClientCredentialsEnabled != client.ClientCredentialsEnabled {
		t.Errorf("Expected ClientCredentialsEnabled %v, got %v", client.ClientCredentialsEnabled, createdClient.ClientCredentialsEnabled)
	}
	if createdClient.TokenExpirationInSeconds != client.TokenExpirationInSeconds {
		t.Errorf("Expected TokenExpirationInSeconds %d, got %d", client.TokenExpirationInSeconds, createdClient.TokenExpirationInSeconds)
	}
	if createdClient.RefreshTokenOfflineIdleTimeoutInSeconds != client.RefreshTokenOfflineIdleTimeoutInSeconds {
		t.Errorf("Expected RefreshTokenOfflineIdleTimeoutInSeconds %d, got %d", client.RefreshTokenOfflineIdleTimeoutInSeconds, createdClient.RefreshTokenOfflineIdleTimeoutInSeconds)
	}
	if createdClient.RefreshTokenOfflineMaxLifetimeInSeconds != client.RefreshTokenOfflineMaxLifetimeInSeconds {
		t.Errorf("Expected RefreshTokenOfflineMaxLifetimeInSeconds %d, got %d", client.RefreshTokenOfflineMaxLifetimeInSeconds, createdClient.RefreshTokenOfflineMaxLifetimeInSeconds)
	}
	if createdClient.IncludeOpenIDConnectClaimsInAccessToken != client.IncludeOpenIDConnectClaimsInAccessToken {
		t.Errorf("Expected IncludeOpenIDConnectClaimsInAccessToken '%s', got '%s'", client.IncludeOpenIDConnectClaimsInAccessToken, createdClient.IncludeOpenIDConnectClaimsInAccessToken)
	}
	if createdClient.DefaultAcrLevel != client.DefaultAcrLevel {
		t.Errorf("Expected DefaultAcrLevel %v, got %v", client.DefaultAcrLevel, createdClient.DefaultAcrLevel)
	}
	if !createdClient.CreatedAt.Valid || createdClient.CreatedAt.Time.IsZero() {
		t.Errorf("CreatedAt is not set properly")
	}
	if !createdClient.UpdatedAt.Valid || createdClient.UpdatedAt.Time.IsZero() {
		t.Errorf("UpdatedAt is not set properly")
	}
}

func TestUpdateClient(t *testing.T) {
	random := gofakeit.LetterN(6)
	originalClient := &models.Client{
		ClientIdentifier:                        "test_client_" + random,
		ClientSecretEncrypted:                   []byte("original_secret"),
		Description:                             "Original Description",
		Enabled:                                 true,
		ConsentRequired:                         true,
		IsPublic:                                false,
		AuthorizationCodeEnabled:                true,
		ClientCredentialsEnabled:                true,
		TokenExpirationInSeconds:                3600,
		RefreshTokenOfflineIdleTimeoutInSeconds: 86400,
		RefreshTokenOfflineMaxLifetimeInSeconds: 2592000,
		IncludeOpenIDConnectClaimsInAccessToken: enums.ThreeStateSettingDefault.String(),
		DefaultAcrLevel:                         enums.AcrLevel1,
	}

	err := database.CreateClient(nil, originalClient)
	if err != nil {
		t.Fatalf("Failed to create initial client: %v", err)
	}

	updatedClient := &models.Client{
		Id:                                      originalClient.Id,
		ClientIdentifier:                        "updated_client_" + random,
		ClientSecretEncrypted:                   []byte("updated_secret"),
		Description:                             "Updated Description",
		Enabled:                                 false,
		ConsentRequired:                         false,
		IsPublic:                                true,
		AuthorizationCodeEnabled:                false,
		ClientCredentialsEnabled:                false,
		TokenExpirationInSeconds:                7200,
		RefreshTokenOfflineIdleTimeoutInSeconds: 172800,
		RefreshTokenOfflineMaxLifetimeInSeconds: 5184000,
		IncludeOpenIDConnectClaimsInAccessToken: enums.ThreeStateSettingOn.String(),
		DefaultAcrLevel:                         enums.AcrLevel2,
	}

	err = database.UpdateClient(nil, updatedClient)
	if err != nil {
		t.Fatalf("Failed to update client: %v", err)
	}

	// Retrieve the updated client
	retrievedClient, err := database.GetClientById(nil, originalClient.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve updated client: %v", err)
	}

	// Check all properties
	if retrievedClient.ClientIdentifier != updatedClient.ClientIdentifier {
		t.Errorf("Expected ClientIdentifier '%s', got '%s'", updatedClient.ClientIdentifier, retrievedClient.ClientIdentifier)
	}
	if string(retrievedClient.ClientSecretEncrypted) != string(updatedClient.ClientSecretEncrypted) {
		t.Errorf("ClientSecretEncrypted does not match")
	}
	if retrievedClient.Description != updatedClient.Description {
		t.Errorf("Expected Description '%s', got '%s'", updatedClient.Description, retrievedClient.Description)
	}
	if retrievedClient.Enabled != updatedClient.Enabled {
		t.Errorf("Expected Enabled %v, got %v", updatedClient.Enabled, retrievedClient.Enabled)
	}
	if retrievedClient.ConsentRequired != updatedClient.ConsentRequired {
		t.Errorf("Expected ConsentRequired %v, got %v", updatedClient.ConsentRequired, retrievedClient.ConsentRequired)
	}
	if retrievedClient.IsPublic != updatedClient.IsPublic {
		t.Errorf("Expected IsPublic %v, got %v", updatedClient.IsPublic, retrievedClient.IsPublic)
	}
	if retrievedClient.AuthorizationCodeEnabled != updatedClient.AuthorizationCodeEnabled {
		t.Errorf("Expected AuthorizationCodeEnabled %v, got %v", updatedClient.AuthorizationCodeEnabled, retrievedClient.AuthorizationCodeEnabled)
	}
	if retrievedClient.ClientCredentialsEnabled != updatedClient.ClientCredentialsEnabled {
		t.Errorf("Expected ClientCredentialsEnabled %v, got %v", updatedClient.ClientCredentialsEnabled, retrievedClient.ClientCredentialsEnabled)
	}
	if retrievedClient.TokenExpirationInSeconds != updatedClient.TokenExpirationInSeconds {
		t.Errorf("Expected TokenExpirationInSeconds %d, got %d", updatedClient.TokenExpirationInSeconds, retrievedClient.TokenExpirationInSeconds)
	}
	if retrievedClient.RefreshTokenOfflineIdleTimeoutInSeconds != updatedClient.RefreshTokenOfflineIdleTimeoutInSeconds {
		t.Errorf("Expected RefreshTokenOfflineIdleTimeoutInSeconds %d, got %d", updatedClient.RefreshTokenOfflineIdleTimeoutInSeconds, retrievedClient.RefreshTokenOfflineIdleTimeoutInSeconds)
	}
	if retrievedClient.RefreshTokenOfflineMaxLifetimeInSeconds != updatedClient.RefreshTokenOfflineMaxLifetimeInSeconds {
		t.Errorf("Expected RefreshTokenOfflineMaxLifetimeInSeconds %d, got %d", updatedClient.RefreshTokenOfflineMaxLifetimeInSeconds, retrievedClient.RefreshTokenOfflineMaxLifetimeInSeconds)
	}
	if retrievedClient.IncludeOpenIDConnectClaimsInAccessToken != updatedClient.IncludeOpenIDConnectClaimsInAccessToken {
		t.Errorf("Expected IncludeOpenIDConnectClaimsInAccessToken '%s', got '%s'", updatedClient.IncludeOpenIDConnectClaimsInAccessToken, retrievedClient.IncludeOpenIDConnectClaimsInAccessToken)
	}
	if retrievedClient.DefaultAcrLevel != updatedClient.DefaultAcrLevel {
		t.Errorf("Expected DefaultAcrLevel %v, got %v", updatedClient.DefaultAcrLevel, retrievedClient.DefaultAcrLevel)
	}
	if !retrievedClient.CreatedAt.Valid || retrievedClient.CreatedAt.Time.IsZero() {
		t.Errorf("CreatedAt is not set properly")
	}
	if !retrievedClient.UpdatedAt.Valid || retrievedClient.UpdatedAt.Time.IsZero() {
		t.Errorf("UpdatedAt is not set properly")
	}
	if retrievedClient.UpdatedAt.Time.Before(originalClient.CreatedAt.Time) || retrievedClient.UpdatedAt.Time.Equal(originalClient.CreatedAt.Time) {
		t.Errorf("UpdatedAt should be after CreatedAt")
	}

	// Check that UpdatedAt has changed
	if retrievedClient.UpdatedAt.Time.Equal(originalClient.UpdatedAt.Time) {
		t.Errorf("UpdatedAt should have changed")
	}

	// Small delay to ensure time difference
	time.Sleep(time.Millisecond * 100)

	// Update again to check if UpdatedAt changes
	updatedClient.Description = "Description updated again"
	err = database.UpdateClient(nil, updatedClient)
	if err != nil {
		t.Fatalf("Failed to update client second time: %v", err)
	}

	retrievedClientAgain, err := database.GetClientById(nil, originalClient.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve updated client second time: %v", err)
	}

	if retrievedClientAgain.UpdatedAt.Time.Equal(retrievedClient.UpdatedAt.Time) {
		t.Errorf("UpdatedAt should have changed after second update")
	}
}

func TestGetClientById(t *testing.T) {
	random := gofakeit.LetterN(6)
	client := &models.Client{
		ClientIdentifier:                        "test_client_" + random,
		ClientSecretEncrypted:                   []byte("encrypted_secret"),
		Description:                             "Test Client Description",
		Enabled:                                 true,
		ConsentRequired:                         true,
		IsPublic:                                false,
		AuthorizationCodeEnabled:                true,
		ClientCredentialsEnabled:                true,
		TokenExpirationInSeconds:                3600,
		RefreshTokenOfflineIdleTimeoutInSeconds: 86400,
		RefreshTokenOfflineMaxLifetimeInSeconds: 2592000,
		IncludeOpenIDConnectClaimsInAccessToken: enums.ThreeStateSettingDefault.String(),
		DefaultAcrLevel:                         enums.AcrLevel1,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatalf("Failed to create client for testing: %v", err)
	}

	// Test retrieving the client
	retrievedClient, err := database.GetClientById(nil, client.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve client by ID: %v", err)
	}

	// Check all properties
	if retrievedClient.Id != client.Id {
		t.Errorf("Expected Id %d, got %d", client.Id, retrievedClient.Id)
	}
	if retrievedClient.ClientIdentifier != client.ClientIdentifier {
		t.Errorf("Expected ClientIdentifier '%s', got '%s'", client.ClientIdentifier, retrievedClient.ClientIdentifier)
	}
	if string(retrievedClient.ClientSecretEncrypted) != string(client.ClientSecretEncrypted) {
		t.Errorf("ClientSecretEncrypted does not match")
	}
	if retrievedClient.Description != client.Description {
		t.Errorf("Expected Description '%s', got '%s'", client.Description, retrievedClient.Description)
	}
	if retrievedClient.Enabled != client.Enabled {
		t.Errorf("Expected Enabled %v, got %v", client.Enabled, retrievedClient.Enabled)
	}
	if retrievedClient.ConsentRequired != client.ConsentRequired {
		t.Errorf("Expected ConsentRequired %v, got %v", client.ConsentRequired, retrievedClient.ConsentRequired)
	}
	if retrievedClient.IsPublic != client.IsPublic {
		t.Errorf("Expected IsPublic %v, got %v", client.IsPublic, retrievedClient.IsPublic)
	}
	if retrievedClient.AuthorizationCodeEnabled != client.AuthorizationCodeEnabled {
		t.Errorf("Expected AuthorizationCodeEnabled %v, got %v", client.AuthorizationCodeEnabled, retrievedClient.AuthorizationCodeEnabled)
	}
	if retrievedClient.ClientCredentialsEnabled != client.ClientCredentialsEnabled {
		t.Errorf("Expected ClientCredentialsEnabled %v, got %v", client.ClientCredentialsEnabled, retrievedClient.ClientCredentialsEnabled)
	}
	if retrievedClient.TokenExpirationInSeconds != client.TokenExpirationInSeconds {
		t.Errorf("Expected TokenExpirationInSeconds %d, got %d", client.TokenExpirationInSeconds, retrievedClient.TokenExpirationInSeconds)
	}
	if retrievedClient.RefreshTokenOfflineIdleTimeoutInSeconds != client.RefreshTokenOfflineIdleTimeoutInSeconds {
		t.Errorf("Expected RefreshTokenOfflineIdleTimeoutInSeconds %d, got %d", client.RefreshTokenOfflineIdleTimeoutInSeconds, retrievedClient.RefreshTokenOfflineIdleTimeoutInSeconds)
	}
	if retrievedClient.RefreshTokenOfflineMaxLifetimeInSeconds != client.RefreshTokenOfflineMaxLifetimeInSeconds {
		t.Errorf("Expected RefreshTokenOfflineMaxLifetimeInSeconds %d, got %d", client.RefreshTokenOfflineMaxLifetimeInSeconds, retrievedClient.RefreshTokenOfflineMaxLifetimeInSeconds)
	}
	if retrievedClient.IncludeOpenIDConnectClaimsInAccessToken != client.IncludeOpenIDConnectClaimsInAccessToken {
		t.Errorf("Expected IncludeOpenIDConnectClaimsInAccessToken '%s', got '%s'", client.IncludeOpenIDConnectClaimsInAccessToken, retrievedClient.IncludeOpenIDConnectClaimsInAccessToken)
	}
	if retrievedClient.DefaultAcrLevel != client.DefaultAcrLevel {
		t.Errorf("Expected DefaultAcrLevel %v, got %v", client.DefaultAcrLevel, retrievedClient.DefaultAcrLevel)
	}
	if !retrievedClient.CreatedAt.Valid || retrievedClient.CreatedAt.Time.IsZero() {
		t.Errorf("CreatedAt is not set properly")
	}
	if !retrievedClient.UpdatedAt.Valid || retrievedClient.UpdatedAt.Time.IsZero() {
		t.Errorf("UpdatedAt is not set properly")
	}

	// Test retrieving a non-existent client
	nonExistentId := client.Id + 10000 // Assuming this ID doesn't exist
	nonExistentClient, err := database.GetClientById(nil, nonExistentId)
	if err != nil {
		t.Errorf("Expected no error for non-existent client, got: %v", err)
	}
	if nonExistentClient != nil {
		t.Errorf("Expected nil for non-existent client, got a client with ID: %d", nonExistentClient.Id)
	}

	// Test with invalid ID (e.g., negative ID)
	invalidClient, err := database.GetClientById(nil, -1)
	if err != nil {
		t.Errorf("Expected no error for invalid client ID, got: %v", err)
	}
	if invalidClient != nil {
		t.Errorf("Expected nil for invalid client ID, got a client with ID: %d", invalidClient.Id)
	}
}

func TestGetClientByClientIdentifier(t *testing.T) {
	random := gofakeit.LetterN(6)
	clientIdentifier := "test_client_" + random
	client := &models.Client{
		ClientIdentifier:                        clientIdentifier,
		ClientSecretEncrypted:                   []byte("encrypted_secret"),
		Description:                             "Test Client Description",
		Enabled:                                 true,
		ConsentRequired:                         true,
		IsPublic:                                false,
		AuthorizationCodeEnabled:                true,
		ClientCredentialsEnabled:                true,
		TokenExpirationInSeconds:                3600,
		RefreshTokenOfflineIdleTimeoutInSeconds: 86400,
		RefreshTokenOfflineMaxLifetimeInSeconds: 2592000,
		IncludeOpenIDConnectClaimsInAccessToken: enums.ThreeStateSettingDefault.String(),
		DefaultAcrLevel:                         enums.AcrLevel1,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatalf("Failed to create client for testing: %v", err)
	}

	// Test retrieving the client by client identifier
	retrievedClient, err := database.GetClientByClientIdentifier(nil, clientIdentifier)
	if err != nil {
		t.Fatalf("Failed to retrieve client by client identifier: %v", err)
	}

	// Check all properties
	if retrievedClient.Id != client.Id {
		t.Errorf("Expected Id %d, got %d", client.Id, retrievedClient.Id)
	}
	if retrievedClient.ClientIdentifier != client.ClientIdentifier {
		t.Errorf("Expected ClientIdentifier '%s', got '%s'", client.ClientIdentifier, retrievedClient.ClientIdentifier)
	}
	if string(retrievedClient.ClientSecretEncrypted) != string(client.ClientSecretEncrypted) {
		t.Errorf("ClientSecretEncrypted does not match")
	}
	if retrievedClient.Description != client.Description {
		t.Errorf("Expected Description '%s', got '%s'", client.Description, retrievedClient.Description)
	}
	if retrievedClient.Enabled != client.Enabled {
		t.Errorf("Expected Enabled %v, got %v", client.Enabled, retrievedClient.Enabled)
	}
	if retrievedClient.ConsentRequired != client.ConsentRequired {
		t.Errorf("Expected ConsentRequired %v, got %v", client.ConsentRequired, retrievedClient.ConsentRequired)
	}
	if retrievedClient.IsPublic != client.IsPublic {
		t.Errorf("Expected IsPublic %v, got %v", client.IsPublic, retrievedClient.IsPublic)
	}
	if retrievedClient.AuthorizationCodeEnabled != client.AuthorizationCodeEnabled {
		t.Errorf("Expected AuthorizationCodeEnabled %v, got %v", client.AuthorizationCodeEnabled, retrievedClient.AuthorizationCodeEnabled)
	}
	if retrievedClient.ClientCredentialsEnabled != client.ClientCredentialsEnabled {
		t.Errorf("Expected ClientCredentialsEnabled %v, got %v", client.ClientCredentialsEnabled, retrievedClient.ClientCredentialsEnabled)
	}
	if retrievedClient.TokenExpirationInSeconds != client.TokenExpirationInSeconds {
		t.Errorf("Expected TokenExpirationInSeconds %d, got %d", client.TokenExpirationInSeconds, retrievedClient.TokenExpirationInSeconds)
	}
	if retrievedClient.RefreshTokenOfflineIdleTimeoutInSeconds != client.RefreshTokenOfflineIdleTimeoutInSeconds {
		t.Errorf("Expected RefreshTokenOfflineIdleTimeoutInSeconds %d, got %d", client.RefreshTokenOfflineIdleTimeoutInSeconds, retrievedClient.RefreshTokenOfflineIdleTimeoutInSeconds)
	}
	if retrievedClient.RefreshTokenOfflineMaxLifetimeInSeconds != client.RefreshTokenOfflineMaxLifetimeInSeconds {
		t.Errorf("Expected RefreshTokenOfflineMaxLifetimeInSeconds %d, got %d", client.RefreshTokenOfflineMaxLifetimeInSeconds, retrievedClient.RefreshTokenOfflineMaxLifetimeInSeconds)
	}
	if retrievedClient.IncludeOpenIDConnectClaimsInAccessToken != client.IncludeOpenIDConnectClaimsInAccessToken {
		t.Errorf("Expected IncludeOpenIDConnectClaimsInAccessToken '%s', got '%s'", client.IncludeOpenIDConnectClaimsInAccessToken, retrievedClient.IncludeOpenIDConnectClaimsInAccessToken)
	}
	if retrievedClient.DefaultAcrLevel != client.DefaultAcrLevel {
		t.Errorf("Expected DefaultAcrLevel %v, got %v", client.DefaultAcrLevel, retrievedClient.DefaultAcrLevel)
	}
	if !retrievedClient.CreatedAt.Valid || retrievedClient.CreatedAt.Time.IsZero() {
		t.Errorf("CreatedAt is not set properly")
	}
	if !retrievedClient.UpdatedAt.Valid || retrievedClient.UpdatedAt.Time.IsZero() {
		t.Errorf("UpdatedAt is not set properly")
	}

	// Test retrieving a non-existent client
	nonExistentIdentifier := "non_existent_client_" + gofakeit.LetterN(6)
	nonExistentClient, err := database.GetClientByClientIdentifier(nil, nonExistentIdentifier)
	if err != nil {
		t.Errorf("Expected no error for non-existent client, got: %v", err)
	}
	if nonExistentClient != nil {
		t.Errorf("Expected nil for non-existent client, got a client with ID: %d", nonExistentClient.Id)
	}

	// Test with empty client identifier
	emptyIdentifierClient, err := database.GetClientByClientIdentifier(nil, "")
	if err != nil {
		t.Errorf("Expected no error for empty client identifier, got: %v", err)
	}
	if emptyIdentifierClient != nil {
		t.Errorf("Expected nil for empty client identifier, got a client with ID: %d", emptyIdentifierClient.Id)
	}
}

func TestClientLoadRedirectURIs(t *testing.T) {
	random := gofakeit.LetterN(6)
	client := &models.Client{
		ClientIdentifier:                        "test_client_" + random,
		ClientSecretEncrypted:                   []byte("encrypted_secret"),
		Description:                             "Test Client Description",
		Enabled:                                 true,
		ConsentRequired:                         true,
		IsPublic:                                false,
		AuthorizationCodeEnabled:                true,
		ClientCredentialsEnabled:                true,
		TokenExpirationInSeconds:                3600,
		RefreshTokenOfflineIdleTimeoutInSeconds: 86400,
		RefreshTokenOfflineMaxLifetimeInSeconds: 2592000,
		IncludeOpenIDConnectClaimsInAccessToken: enums.ThreeStateSettingDefault.String(),
		DefaultAcrLevel:                         enums.AcrLevel1,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatalf("Failed to create client for testing: %v", err)
	}

	// Create multiple redirect URIs for the client
	redirectURIs := []models.RedirectURI{
		{URI: "https://example.com/callback1", ClientId: client.Id},
		{URI: "https://example.com/callback2", ClientId: client.Id},
		{URI: "http://localhost:8080/callback", ClientId: client.Id},
	}

	for _, uri := range redirectURIs {
		err := database.CreateRedirectURI(nil, &uri)
		if err != nil {
			t.Fatalf("Failed to create redirect URI: %v", err)
		}
	}

	// Load redirect URIs for the client
	err = database.ClientLoadRedirectURIs(nil, client)
	if err != nil {
		t.Fatalf("Failed to load redirect URIs: %v", err)
	}

	// Check if the correct number of redirect URIs were loaded
	if len(client.RedirectURIs) != len(redirectURIs) {
		t.Errorf("Expected %d redirect URIs, got %d", len(redirectURIs), len(client.RedirectURIs))
	}

	// Check if all redirect URIs are present
	uriMap := make(map[string]bool)
	for _, uri := range client.RedirectURIs {
		uriMap[uri.URI] = true
	}

	for _, expectedURI := range redirectURIs {
		if !uriMap[expectedURI.URI] {
			t.Errorf("Expected URI %s not found in loaded redirect URIs", expectedURI.URI)
		}
	}

	// Test loading redirect URIs for a client with no URIs
	clientWithNoURIs := &models.Client{
		ClientIdentifier: "client_with_no_uris_" + gofakeit.LetterN(6),
	}
	err = database.CreateClient(nil, clientWithNoURIs)
	if err != nil {
		t.Fatalf("Failed to create client with no URIs: %v", err)
	}

	err = database.ClientLoadRedirectURIs(nil, clientWithNoURIs)
	if err != nil {
		t.Fatalf("Failed to load redirect URIs for client with no URIs: %v", err)
	}

	if len(clientWithNoURIs.RedirectURIs) != 0 {
		t.Errorf("Expected 0 redirect URIs for client with no URIs, got %d", len(clientWithNoURIs.RedirectURIs))
	}

	// Test loading redirect URIs for a nil client (should handle gracefully)
	err = database.ClientLoadRedirectURIs(nil, nil)
	if err != nil {
		t.Errorf("Expected no error when loading redirect URIs for nil client, got: %v", err)
	}
}

func TestClientLoadWebOrigins(t *testing.T) {
	random := gofakeit.LetterN(6)
	client := &models.Client{
		ClientIdentifier:                        "test_client_" + random,
		ClientSecretEncrypted:                   []byte("encrypted_secret"),
		Description:                             "Test Client Description",
		Enabled:                                 true,
		ConsentRequired:                         true,
		IsPublic:                                false,
		AuthorizationCodeEnabled:                true,
		ClientCredentialsEnabled:                true,
		TokenExpirationInSeconds:                3600,
		RefreshTokenOfflineIdleTimeoutInSeconds: 86400,
		RefreshTokenOfflineMaxLifetimeInSeconds: 2592000,
		IncludeOpenIDConnectClaimsInAccessToken: enums.ThreeStateSettingDefault.String(),
		DefaultAcrLevel:                         enums.AcrLevel1,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatalf("Failed to create client for testing: %v", err)
	}

	// Create multiple web origins for the client
	webOrigins := []models.WebOrigin{
		{Origin: "https://example.com", ClientId: client.Id},
		{Origin: "https://app.example.com", ClientId: client.Id},
		{Origin: "http://localhost:3000", ClientId: client.Id},
	}

	for _, origin := range webOrigins {
		err := database.CreateWebOrigin(nil, &origin)
		if err != nil {
			t.Fatalf("Failed to create web origin: %v", err)
		}
	}

	// Load web origins for the client
	err = database.ClientLoadWebOrigins(nil, client)
	if err != nil {
		t.Fatalf("Failed to load web origins: %v", err)
	}

	// Check if the correct number of web origins were loaded
	if len(client.WebOrigins) != len(webOrigins) {
		t.Errorf("Expected %d web origins, got %d", len(webOrigins), len(client.WebOrigins))
	}

	// Check if all web origins are present
	originMap := make(map[string]bool)
	for _, origin := range client.WebOrigins {
		originMap[origin.Origin] = true
	}

	for _, expectedOrigin := range webOrigins {
		if !originMap[expectedOrigin.Origin] {
			t.Errorf("Expected origin %s not found in loaded web origins", expectedOrigin.Origin)
		}
	}

	// Test loading web origins for a client with no origins
	clientWithNoOrigins := &models.Client{
		ClientIdentifier: "client_with_no_origins_" + gofakeit.LetterN(6),
	}
	err = database.CreateClient(nil, clientWithNoOrigins)
	if err != nil {
		t.Fatalf("Failed to create client with no origins: %v", err)
	}

	err = database.ClientLoadWebOrigins(nil, clientWithNoOrigins)
	if err != nil {
		t.Fatalf("Failed to load web origins for client with no origins: %v", err)
	}

	if len(clientWithNoOrigins.WebOrigins) != 0 {
		t.Errorf("Expected 0 web origins for client with no origins, got %d", len(clientWithNoOrigins.WebOrigins))
	}

	// Test loading web origins for a nil client (should handle gracefully)
	err = database.ClientLoadWebOrigins(nil, nil)
	if err != nil {
		t.Errorf("Expected no error when loading web origins for nil client, got: %v", err)
	}
}

func TestGetClientsByIds(t *testing.T) {
	// Create multiple test clients
	clients := make([]models.Client, 3)
	clientIds := make([]int64, 3)

	for i := 0; i < 3; i++ {
		random := gofakeit.LetterN(6)
		client := models.Client{
			ClientIdentifier:                        "test_client_" + random,
			ClientSecretEncrypted:                   []byte("encrypted_secret_" + random),
			Description:                             "Test Client Description " + random,
			Enabled:                                 i%2 == 0, // alternate between true and false
			ConsentRequired:                         i%2 == 1,
			IsPublic:                                i%2 == 0,
			AuthorizationCodeEnabled:                i%2 == 1,
			ClientCredentialsEnabled:                i%2 == 0,
			TokenExpirationInSeconds:                3600 + i*1800,
			RefreshTokenOfflineIdleTimeoutInSeconds: 86400 + i*43200,
			RefreshTokenOfflineMaxLifetimeInSeconds: 2592000 + i*1296000,
			IncludeOpenIDConnectClaimsInAccessToken: enums.ThreeStateSettingDefault.String(),
			DefaultAcrLevel:                         enums.AcrLevel1,
		}

		err := database.CreateClient(nil, &client)
		if err != nil {
			t.Fatalf("Failed to create test client %d: %v", i, err)
		}

		clients[i] = client
		clientIds[i] = client.Id
	}

	// Test retrieving all created clients
	retrievedClients, err := database.GetClientsByIds(nil, clientIds)
	if err != nil {
		t.Fatalf("Failed to retrieve clients by IDs: %v", err)
	}

	if len(retrievedClients) != len(clients) {
		t.Errorf("Expected %d clients, got %d", len(clients), len(retrievedClients))
	}

	// Check if all clients are retrieved correctly
	for i, client := range clients {
		found := false
		for _, retrievedClient := range retrievedClients {
			if retrievedClient.Id == client.Id {
				found = true
				// Check all properties
				if retrievedClient.ClientIdentifier != client.ClientIdentifier {
					t.Errorf("Client %d: Expected ClientIdentifier %s, got %s", i, client.ClientIdentifier, retrievedClient.ClientIdentifier)
				}
				if string(retrievedClient.ClientSecretEncrypted) != string(client.ClientSecretEncrypted) {
					t.Errorf("Client %d: ClientSecretEncrypted does not match", i)
				}
				if retrievedClient.Description != client.Description {
					t.Errorf("Client %d: Expected Description %s, got %s", i, client.Description, retrievedClient.Description)
				}
				if retrievedClient.Enabled != client.Enabled {
					t.Errorf("Client %d: Expected Enabled %v, got %v", i, client.Enabled, retrievedClient.Enabled)
				}
				// ... Add checks for other properties ...
				break
			}
		}
		if !found {
			t.Errorf("Client with ID %d not found in retrieved clients", client.Id)
		}
	}

	// Test retrieving a subset of clients
	subsetIds := clientIds[:2]
	subsetClients, err := database.GetClientsByIds(nil, subsetIds)
	if err != nil {
		t.Fatalf("Failed to retrieve subset of clients: %v", err)
	}
	if len(subsetClients) != len(subsetIds) {
		t.Errorf("Expected %d clients in subset, got %d", len(subsetIds), len(subsetClients))
	}

	// Test retrieving with some non-existent IDs
	nonExistentId := clientIds[len(clientIds)-1] + 1000 // Assume this ID doesn't exist
	mixedIds := append(clientIds[:2], nonExistentId)
	mixedClients, err := database.GetClientsByIds(nil, mixedIds)
	if err != nil {
		t.Fatalf("Failed to retrieve clients with mixed existing and non-existing IDs: %v", err)
	}
	if len(mixedClients) != len(clientIds[:2]) {
		t.Errorf("Expected %d clients when including non-existent ID, got %d", len(clientIds[:2]), len(mixedClients))
	}

	// Test with empty slice of IDs
	emptyClients, err := database.GetClientsByIds(nil, []int64{})
	if err != nil {
		t.Errorf("Expected no error for empty ID slice, got: %v", err)
	}
	if len(emptyClients) != 0 {
		t.Errorf("Expected empty slice for empty ID input, got %d clients", len(emptyClients))
	}

	// Test with nil slice of IDs
	nilClients, err := database.GetClientsByIds(nil, nil)
	if err != nil {
		t.Errorf("Expected no error for nil ID slice, got: %v", err)
	}
	if len(nilClients) != 0 {
		t.Errorf("Expected empty slice for nil ID input, got %d clients", len(emptyClients))
	}
}

func TestClientLoadPermissions(t *testing.T) {
	random := gofakeit.LetterN(6)
	client := &models.Client{
		ClientIdentifier:                        "test_client_" + random,
		ClientSecretEncrypted:                   []byte("encrypted_secret"),
		Description:                             "Test Client Description",
		Enabled:                                 true,
		ConsentRequired:                         true,
		IsPublic:                                false,
		AuthorizationCodeEnabled:                true,
		ClientCredentialsEnabled:                true,
		TokenExpirationInSeconds:                3600,
		RefreshTokenOfflineIdleTimeoutInSeconds: 86400,
		RefreshTokenOfflineMaxLifetimeInSeconds: 2592000,
		IncludeOpenIDConnectClaimsInAccessToken: enums.ThreeStateSettingDefault.String(),
		DefaultAcrLevel:                         enums.AcrLevel1,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatalf("Failed to create client for testing: %v", err)
	}

	// Create a test resource
	resource := &models.Resource{
		ResourceIdentifier: "test_resource_" + random,
		Description:        "Test Resource",
	}
	err = database.CreateResource(nil, resource)
	if err != nil {
		t.Fatalf("Failed to create resource for testing: %v", err)
	}

	// Create multiple permissions for the resource
	permissions := []models.Permission{
		{PermissionIdentifier: "read_" + random, Description: "Read Permission", ResourceId: resource.Id},
		{PermissionIdentifier: "write_" + random, Description: "Write Permission", ResourceId: resource.Id},
		{PermissionIdentifier: "delete_" + random, Description: "Delete Permission", ResourceId: resource.Id},
	}

	for i := range permissions {
		err := database.CreatePermission(nil, &permissions[i])
		if err != nil {
			t.Fatalf("Failed to create permission: %v", err)
		}
	}

	// Associate permissions with the client
	for _, perm := range permissions {
		clientPermission := &models.ClientPermission{
			ClientId:     client.Id,
			PermissionId: perm.Id,
		}
		err := database.CreateClientPermission(nil, clientPermission)
		if err != nil {
			t.Fatalf("Failed to create client permission: %v", err)
		}
	}

	// Load permissions for the client
	err = database.ClientLoadPermissions(nil, client)
	if err != nil {
		t.Fatalf("Failed to load permissions: %v", err)
	}

	// Check if the correct number of permissions were loaded
	if len(client.Permissions) != len(permissions) {
		t.Errorf("Expected %d permissions, got %d", len(permissions), len(client.Permissions))
	}

	// Check if all permissions are present and correct
	permMap := make(map[string]bool)
	for _, perm := range client.Permissions {
		permMap[perm.PermissionIdentifier] = true
		if perm.ResourceId != resource.Id {
			t.Errorf("Expected ResourceId %d, got %d for permission %s", resource.Id, perm.ResourceId, perm.PermissionIdentifier)
		}
	}

	for _, expectedPerm := range permissions {
		if !permMap[expectedPerm.PermissionIdentifier] {
			t.Errorf("Expected permission %s not found in loaded permissions", expectedPerm.PermissionIdentifier)
		}
	}

	// Test loading permissions for a client with no permissions
	clientWithNoPermissions := &models.Client{
		ClientIdentifier: "client_with_no_permissions_" + gofakeit.LetterN(6),
	}
	err = database.CreateClient(nil, clientWithNoPermissions)
	if err != nil {
		t.Fatalf("Failed to create client with no permissions: %v", err)
	}

	err = database.ClientLoadPermissions(nil, clientWithNoPermissions)
	if err != nil {
		t.Fatalf("Failed to load permissions for client with no permissions: %v", err)
	}

	if len(clientWithNoPermissions.Permissions) != 0 {
		t.Errorf("Expected 0 permissions for client with no permissions, got %d", len(clientWithNoPermissions.Permissions))
	}

	// Test loading permissions for a nil client (should handle gracefully)
	err = database.ClientLoadPermissions(nil, nil)
	if err != nil {
		t.Errorf("Expected no error when loading permissions for nil client, got: %v", err)
	}
}

func TestGetAllClients(t *testing.T) {
	// First, let's clear all existing clients to ensure a clean state
	allClients, err := database.GetAllClients(nil)
	if err != nil {
		t.Fatalf("Failed to get initial clients: %v", err)
	}
	for _, client := range allClients {
		err = database.DeleteClient(nil, client.Id)
		if err != nil {
			t.Fatalf("Failed to delete existing client: %v", err)
		}
	}

	// Create multiple test clients
	numClients := 5
	createdClients := make([]*models.Client, numClients)

	for i := 0; i < numClients; i++ {
		random := gofakeit.LetterN(6)
		client := &models.Client{
			ClientIdentifier:                        "test_client_" + random,
			ClientSecretEncrypted:                   []byte("encrypted_secret_" + random),
			Description:                             "Test Client Description " + random,
			Enabled:                                 i%2 == 0, // alternate between true and false
			ConsentRequired:                         i%2 == 1,
			IsPublic:                                i%2 == 0,
			AuthorizationCodeEnabled:                i%2 == 1,
			ClientCredentialsEnabled:                i%2 == 0,
			TokenExpirationInSeconds:                3600 + i*1800,
			RefreshTokenOfflineIdleTimeoutInSeconds: 86400 + i*43200,
			RefreshTokenOfflineMaxLifetimeInSeconds: 2592000 + i*1296000,
			IncludeOpenIDConnectClaimsInAccessToken: enums.ThreeStateSettingDefault.String(),
			DefaultAcrLevel:                         enums.AcrLevel1,
		}

		err := database.CreateClient(nil, client)
		if err != nil {
			t.Fatalf("Failed to create test client %d: %v", i, err)
		}

		createdClients[i] = client
	}

	// Retrieve all clients
	retrievedClients, err := database.GetAllClients(nil)
	if err != nil {
		t.Fatalf("Failed to retrieve all clients: %v", err)
	}

	// Check if the number of retrieved clients matches the number of created clients
	if len(retrievedClients) != numClients {
		t.Errorf("Expected %d clients, got %d", numClients, len(retrievedClients))
	}

	// Create a map of created clients for easy lookup
	createdClientMap := make(map[string]*models.Client)
	for _, client := range createdClients {
		createdClientMap[client.ClientIdentifier] = client
	}

	// Check if all created clients are in the retrieved list and their properties match
	for _, retrievedClient := range retrievedClients {
		createdClient, exists := createdClientMap[retrievedClient.ClientIdentifier]
		if !exists {
			t.Errorf("Retrieved unexpected client: %s", retrievedClient.ClientIdentifier)
			continue
		}

		// Check all properties
		if retrievedClient.Description != createdClient.Description {
			t.Errorf("Client %s: Expected Description %s, got %s", retrievedClient.ClientIdentifier, createdClient.Description, retrievedClient.Description)
		}
		if retrievedClient.Enabled != createdClient.Enabled {
			t.Errorf("Client %s: Expected Enabled %v, got %v", retrievedClient.ClientIdentifier, createdClient.Enabled, retrievedClient.Enabled)
		}
		if retrievedClient.ConsentRequired != createdClient.ConsentRequired {
			t.Errorf("Client %s: Expected ConsentRequired %v, got %v", retrievedClient.ClientIdentifier, createdClient.ConsentRequired, retrievedClient.ConsentRequired)
		}
		if retrievedClient.IsPublic != createdClient.IsPublic {
			t.Errorf("Client %s: Expected IsPublic %v, got %v", retrievedClient.ClientIdentifier, createdClient.IsPublic, retrievedClient.IsPublic)
		}
		if retrievedClient.AuthorizationCodeEnabled != createdClient.AuthorizationCodeEnabled {
			t.Errorf("Client %s: Expected AuthorizationCodeEnabled %v, got %v", retrievedClient.ClientIdentifier, createdClient.AuthorizationCodeEnabled, retrievedClient.AuthorizationCodeEnabled)
		}
		if retrievedClient.ClientCredentialsEnabled != createdClient.ClientCredentialsEnabled {
			t.Errorf("Client %s: Expected ClientCredentialsEnabled %v, got %v", retrievedClient.ClientIdentifier, createdClient.ClientCredentialsEnabled, retrievedClient.ClientCredentialsEnabled)
		}
		if retrievedClient.TokenExpirationInSeconds != createdClient.TokenExpirationInSeconds {
			t.Errorf("Client %s: Expected TokenExpirationInSeconds %d, got %d", retrievedClient.ClientIdentifier, createdClient.TokenExpirationInSeconds, retrievedClient.TokenExpirationInSeconds)
		}
		if retrievedClient.RefreshTokenOfflineIdleTimeoutInSeconds != createdClient.RefreshTokenOfflineIdleTimeoutInSeconds {
			t.Errorf("Client %s: Expected RefreshTokenOfflineIdleTimeoutInSeconds %d, got %d", retrievedClient.ClientIdentifier, createdClient.RefreshTokenOfflineIdleTimeoutInSeconds, retrievedClient.RefreshTokenOfflineIdleTimeoutInSeconds)
		}
		if retrievedClient.RefreshTokenOfflineMaxLifetimeInSeconds != createdClient.RefreshTokenOfflineMaxLifetimeInSeconds {
			t.Errorf("Client %s: Expected RefreshTokenOfflineMaxLifetimeInSeconds %d, got %d", retrievedClient.ClientIdentifier, createdClient.RefreshTokenOfflineMaxLifetimeInSeconds, retrievedClient.RefreshTokenOfflineMaxLifetimeInSeconds)
		}
		if retrievedClient.IncludeOpenIDConnectClaimsInAccessToken != createdClient.IncludeOpenIDConnectClaimsInAccessToken {
			t.Errorf("Client %s: Expected IncludeOpenIDConnectClaimsInAccessToken %s, got %s", retrievedClient.ClientIdentifier, createdClient.IncludeOpenIDConnectClaimsInAccessToken, retrievedClient.IncludeOpenIDConnectClaimsInAccessToken)
		}
		if retrievedClient.DefaultAcrLevel != createdClient.DefaultAcrLevel {
			t.Errorf("Client %s: Expected DefaultAcrLevel %v, got %v", retrievedClient.ClientIdentifier, createdClient.DefaultAcrLevel, retrievedClient.DefaultAcrLevel)
		}

		// Check if CreatedAt and UpdatedAt are set
		if !retrievedClient.CreatedAt.Valid || retrievedClient.CreatedAt.Time.IsZero() {
			t.Errorf("Client %s: CreatedAt is not set properly", retrievedClient.ClientIdentifier)
		}
		if !retrievedClient.UpdatedAt.Valid || retrievedClient.UpdatedAt.Time.IsZero() {
			t.Errorf("Client %s: UpdatedAt is not set properly", retrievedClient.ClientIdentifier)
		}

		// Remove the client from the map to mark it as found
		delete(createdClientMap, retrievedClient.ClientIdentifier)
	}

	// Check if there are any clients in the map that weren't retrieved
	if len(createdClientMap) > 0 {
		for clientIdentifier := range createdClientMap {
			t.Errorf("Client %s was created but not retrieved", clientIdentifier)
		}
	}

	// Test when there are no clients
	for _, client := range retrievedClients {
		err = database.DeleteClient(nil, client.Id)
		if err != nil {
			t.Fatalf("Failed to delete client during cleanup: %v", err)
		}
	}

	emptyClients, err := database.GetAllClients(nil)
	if err != nil {
		t.Fatalf("Failed to get clients after deletion: %v", err)
	}
	if len(emptyClients) != 0 {
		t.Errorf("Expected 0 clients after deletion, got %d", len(emptyClients))
	}
}

func TestDeleteClient(t *testing.T) {
	random := gofakeit.LetterN(6)
	client := &models.Client{
		ClientIdentifier:                        "test_client_" + random,
		ClientSecretEncrypted:                   []byte("encrypted_secret"),
		Description:                             "Test Client Description",
		Enabled:                                 true,
		ConsentRequired:                         true,
		IsPublic:                                false,
		AuthorizationCodeEnabled:                true,
		ClientCredentialsEnabled:                true,
		TokenExpirationInSeconds:                3600,
		RefreshTokenOfflineIdleTimeoutInSeconds: 86400,
		RefreshTokenOfflineMaxLifetimeInSeconds: 2592000,
		IncludeOpenIDConnectClaimsInAccessToken: enums.ThreeStateSettingDefault.String(),
		DefaultAcrLevel:                         enums.AcrLevel1,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatalf("Failed to create client for testing: %v", err)
	}

	// Create associated data
	// 1. Redirect URIs
	redirectURI := &models.RedirectURI{
		URI:      "https://example.com/callback",
		ClientId: client.Id,
	}
	err = database.CreateRedirectURI(nil, redirectURI)
	if err != nil {
		t.Fatalf("Failed to create redirect URI: %v", err)
	}

	// 2. Web Origins
	webOrigin := &models.WebOrigin{
		Origin:   "https://example.com",
		ClientId: client.Id,
	}
	err = database.CreateWebOrigin(nil, webOrigin)
	if err != nil {
		t.Fatalf("Failed to create web origin: %v", err)
	}

	// 3. Client Permissions
	resource := &models.Resource{
		ResourceIdentifier: "test_resource_" + random,
		Description:        "Test Resource",
	}
	err = database.CreateResource(nil, resource)
	if err != nil {
		t.Fatalf("Failed to create resource: %v", err)
	}

	permission := &models.Permission{
		PermissionIdentifier: "test_permission_" + random,
		Description:          "Test Permission",
		ResourceId:           resource.Id,
	}
	err = database.CreatePermission(nil, permission)
	if err != nil {
		t.Fatalf("Failed to create permission: %v", err)
	}

	clientPermission := &models.ClientPermission{
		ClientId:     client.Id,
		PermissionId: permission.Id,
	}
	err = database.CreateClientPermission(nil, clientPermission)
	if err != nil {
		t.Fatalf("Failed to create client permission: %v", err)
	}

	// Delete the client
	err = database.DeleteClient(nil, client.Id)
	if err != nil {
		t.Fatalf("Failed to delete client: %v", err)
	}

	// Verify that the client has been deleted
	deletedClient, err := database.GetClientById(nil, client.Id)
	if err != nil {
		t.Fatalf("Error while checking for deleted client: %v", err)
	}
	if deletedClient != nil {
		t.Errorf("Client still exists after deletion")
	}

	// Verify that associated data has been deleted
	// 1. Check Redirect URIs
	redirectURIs, err := database.GetRedirectURIsByClientId(nil, client.Id)
	if err != nil {
		t.Fatalf("Error while checking for deleted redirect URIs: %v", err)
	}
	if len(redirectURIs) > 0 {
		t.Errorf("Redirect URIs still exist after client deletion")
	}

	// 2. Check Web Origins
	webOrigins, err := database.GetWebOriginsByClientId(nil, client.Id)
	if err != nil {
		t.Fatalf("Error while checking for deleted web origins: %v", err)
	}
	if len(webOrigins) > 0 {
		t.Errorf("Web Origins still exist after client deletion")
	}

	// 3. Check Client Permissions
	clientPermissions, err := database.GetClientPermissionsByClientId(nil, client.Id)
	if err != nil {
		t.Fatalf("Error while checking for deleted client permissions: %v", err)
	}
	if len(clientPermissions) > 0 {
		t.Errorf("Client Permissions still exist after client deletion")
	}

	// Test deleting a non-existent client
	err = database.DeleteClient(nil, client.Id)
	if err != nil {
		t.Errorf("Expected no error when deleting non-existent client, got: %v", err)
	}

	// Test deleting a client with an invalid ID
	err = database.DeleteClient(nil, -1)
	if err != nil {
		t.Errorf("Expected no error when deleting client with invalid ID, got: %v", err)
	}
}

func createTestClient(t *testing.T) *models.Client {
	random := gofakeit.LetterN(6)
	client := &models.Client{
		ClientIdentifier: "test_client_" + random,
		Description:      "Test Client",
	}
	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatalf("Failed to create test client: %v", err)
	}
	return client
}
