package datatests

import (
	"context"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
	"github.com/stretchr/testify/require"
)

// redirectURIAtTheBound is one redirect URI of exactly models.RedirectURIMaxBytes bytes.
type redirectURIAtTheBound struct {
	name  string
	value string
}

// redirectURIsAtTheBound returns three redirect URIs of exactly models.RedirectURIMaxBytes bytes,
// each "https://example.com/" plus a fill of one-, two- or four-byte characters. The engines count
// a column's width differently, MySQL and PostgreSQL in code points and SQL Server in UTF-16 units,
// and the handlers bound a URI in bytes because a string is never fewer bytes than either, so these
// three are the values that prove the bound fits every column: the ASCII one at the most characters
// the bound admits, and the other two at the most UTF-16 units per byte (#428).
func redirectURIsAtTheBound(t *testing.T) []redirectURIAtTheBound {
	t.Helper()
	const prefix = "https://example.com/"
	fill := models.RedirectURIMaxBytes - len(prefix)
	values := []redirectURIAtTheBound{
		{"ascii", prefix + strings.Repeat("a", fill)},
		{"two-byte characters", prefix + strings.Repeat("é", fill/2)},
		{"four-byte characters", prefix + strings.Repeat("😀", fill/4)},
	}
	for _, v := range values {
		require.Len(t, v.value, models.RedirectURIMaxBytes, "%s is off the bound, so the case no longer observes the column's edge", v.name)
	}
	return values
}

// TestCreateRedirectURI_AURIAtTheBoundRoundTrips is what the handlers' byte bound stands on: a URI
// they admit is stored and read back unchanged on every engine, rather than refused by a column
// narrower than the bound (#428).
func TestCreateRedirectURI_AURIAtTheBoundRoundTrips(t *testing.T) {
	for _, tc := range redirectURIsAtTheBound(t) {
		t.Run(tc.name, func(t *testing.T) {
			client := createTestClient(t)
			redirectURI := &models.RedirectURI{URI: tc.value, ClientId: client.Id}

			err := database.CreateRedirectURI(context.Background(), nil, redirectURI)
			require.NoError(t, err, "a redirect URI of %d bytes was refused by the column", models.RedirectURIMaxBytes)

			stored, err := database.GetRedirectURIById(context.Background(), nil, redirectURI.Id)
			require.NoError(t, err)
			require.NotNil(t, stored)
			require.Equal(t, tc.value, stored.URI, "the redirect URI did not round-trip unchanged")
		})
	}
}

func TestCreateRedirectURI(t *testing.T) {
	client := createTestClient(t)
	redirectURI := &models.RedirectURI{
		URI:      "https://example.com/callback",
		ClientId: client.Id,
	}

	err := database.CreateRedirectURI(context.Background(), nil, redirectURI)
	if err != nil {
		t.Fatalf("Failed to create redirect URI: %v", err)
	}

	if redirectURI.Id == 0 {
		t.Error("Expected non-zero ID after creation")
	}
	if !redirectURI.CreatedAt.Valid || redirectURI.CreatedAt.Time.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}

	retrievedRedirectURI, err := database.GetRedirectURIById(context.Background(), nil, redirectURI.Id)
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

	retrievedRedirectURI, err := database.GetRedirectURIById(context.Background(), nil, redirectURI.Id)
	if err != nil {
		t.Fatalf("Failed to get redirect URI by ID: %v", err)
	}

	if retrievedRedirectURI.Id != redirectURI.Id {
		t.Errorf("Expected ID %d, got %d", redirectURI.Id, retrievedRedirectURI.Id)
	}
	if retrievedRedirectURI.URI != redirectURI.URI {
		t.Errorf("Expected URI %s, got %s", redirectURI.URI, retrievedRedirectURI.URI)
	}

	nonExistentRedirectURI, err := database.GetRedirectURIById(context.Background(), nil, 99999)
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

	redirectURIs, err := database.GetRedirectURIsByClientId(context.Background(), nil, client.Id)
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

	err := database.DeleteRedirectURI(context.Background(), nil, redirectURI.Id)
	if err != nil {
		t.Fatalf("Failed to delete redirect URI: %v", err)
	}

	deletedRedirectURI, err := database.GetRedirectURIById(context.Background(), nil, redirectURI.Id)
	if err != nil {
		t.Fatalf("Error while checking for deleted redirect URI: %v", err)
	}
	if deletedRedirectURI != nil {
		t.Errorf("Redirect URI still exists after deletion")
	}

	err = database.DeleteRedirectURI(context.Background(), nil, 99999)
	if err != nil {
		t.Errorf("Expected no error when deleting non-existent redirect URI, got: %v", err)
	}
}

func createTestRedirectURI(t *testing.T, clientId int64) *models.RedirectURI {
	redirectURI := &models.RedirectURI{
		URI:      "https://example.com/callback_" + fake.LetterN(6),
		ClientId: clientId,
	}
	err := database.CreateRedirectURI(context.Background(), nil, redirectURI)
	if err != nil {
		t.Fatalf("Failed to create test redirect URI: %v", err)
	}
	return redirectURI
}
