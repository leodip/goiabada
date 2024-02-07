package integrationtests

import (
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/internal/datav2"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/initialization"
	"github.com/stretchr/testify/assert"
)

var databasev2 datav2.Database

func TestDatabase_MySQL_Setup(t *testing.T) {
	initialization.InitViper()
	var err error
	databasev2, err = datav2.NewDatabase()
	if err != nil {
		t.Fatal(err)
	}
}

func TestDatabase_MySQL_Client(t *testing.T) {
	TestDatabase_MySQL_Setup(t)

	client := entitiesv2.Client{
		ClientIdentifier:                        gofakeit.UUID(),
		ClientSecretEncrypted:                   []byte{1, 2, 3, 4, 5},
		Description:                             gofakeit.Sentence(10),
		Enabled:                                 true,
		ConsentRequired:                         true,
		IsPublic:                                true,
		AuthorizationCodeEnabled:                true,
		ClientCredentialsEnabled:                true,
		TokenExpirationInSeconds:                3600,
		RefreshTokenOfflineIdleTimeoutInSeconds: 3600,
		RefreshTokenOfflineMaxLifetimeInSeconds: 3600,
		IncludeOpenIDConnectClaimsInAccessToken: enums.ThreeStateSettingDefault.String(),
		DefaultAcrLevel:                         "acr-level-1",
	}

	createdClient, err := databasev2.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	assert.Greater(t, createdClient.Id, int64(0))
	assert.WithinDuration(t, createdClient.CreatedAt, createdClient.UpdatedAt, 2*time.Second)

	retrievedClient, err := databasev2.GetClientById(nil, createdClient.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, createdClient.Id, retrievedClient.Id)
	assert.WithinDuration(t, retrievedClient.CreatedAt, retrievedClient.UpdatedAt, 2*time.Second)
	assert.Equal(t, client.ClientIdentifier, retrievedClient.ClientIdentifier)
	assert.Equal(t, client.ClientSecretEncrypted, retrievedClient.ClientSecretEncrypted)
	assert.Equal(t, client.Description, retrievedClient.Description)
	assert.Equal(t, client.Enabled, retrievedClient.Enabled)
	assert.Equal(t, client.ConsentRequired, retrievedClient.ConsentRequired)
	assert.Equal(t, client.IsPublic, retrievedClient.IsPublic)
	assert.Equal(t, client.AuthorizationCodeEnabled, retrievedClient.AuthorizationCodeEnabled)
	assert.Equal(t, client.ClientCredentialsEnabled, retrievedClient.ClientCredentialsEnabled)
	assert.Equal(t, client.TokenExpirationInSeconds, retrievedClient.TokenExpirationInSeconds)
	assert.Equal(t, client.RefreshTokenOfflineIdleTimeoutInSeconds, retrievedClient.RefreshTokenOfflineIdleTimeoutInSeconds)
	assert.Equal(t, client.RefreshTokenOfflineMaxLifetimeInSeconds, retrievedClient.RefreshTokenOfflineMaxLifetimeInSeconds)
	assert.Equal(t, client.IncludeOpenIDConnectClaimsInAccessToken, retrievedClient.IncludeOpenIDConnectClaimsInAccessToken)
	assert.Equal(t, client.DefaultAcrLevel, retrievedClient.DefaultAcrLevel)

	retrievedClient.ClientIdentifier = gofakeit.UUID()
	retrievedClient.ClientSecretEncrypted = []byte{5, 4, 3, 2, 1}
	retrievedClient.Description = gofakeit.Sentence(10)
	retrievedClient.Enabled = false
	retrievedClient.ConsentRequired = false
	retrievedClient.IsPublic = false
	retrievedClient.AuthorizationCodeEnabled = false
	retrievedClient.ClientCredentialsEnabled = false
	retrievedClient.TokenExpirationInSeconds = 7200
	retrievedClient.RefreshTokenOfflineIdleTimeoutInSeconds = 7200
	retrievedClient.RefreshTokenOfflineMaxLifetimeInSeconds = 7200
	retrievedClient.IncludeOpenIDConnectClaimsInAccessToken = enums.ThreeStateSettingOff.String()
	retrievedClient.DefaultAcrLevel = "acr-level-2"

	time.Sleep(300 * time.Millisecond)
	updatedClient, err := databasev2.UpdateClient(nil, *retrievedClient)
	if err != nil {
		t.Fatal(err)
	}

	updatedClient, err = databasev2.GetClientById(nil, updatedClient.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, retrievedClient.Id, updatedClient.Id)
	assert.WithinDuration(t, updatedClient.CreatedAt, updatedClient.UpdatedAt, 2*time.Second)
	assert.Greater(t, updatedClient.UpdatedAt.UnixNano(), retrievedClient.UpdatedAt.UnixNano())
	assert.Equal(t, retrievedClient.ClientIdentifier, updatedClient.ClientIdentifier)
	assert.Equal(t, retrievedClient.ClientSecretEncrypted, updatedClient.ClientSecretEncrypted)
	assert.Equal(t, retrievedClient.Description, updatedClient.Description)
	assert.Equal(t, retrievedClient.Enabled, updatedClient.Enabled)
	assert.Equal(t, retrievedClient.ConsentRequired, updatedClient.ConsentRequired)
	assert.Equal(t, retrievedClient.IsPublic, updatedClient.IsPublic)
	assert.Equal(t, retrievedClient.AuthorizationCodeEnabled, updatedClient.AuthorizationCodeEnabled)
	assert.Equal(t, retrievedClient.ClientCredentialsEnabled, updatedClient.ClientCredentialsEnabled)
	assert.Equal(t, retrievedClient.TokenExpirationInSeconds, updatedClient.TokenExpirationInSeconds)
	assert.Equal(t, retrievedClient.RefreshTokenOfflineIdleTimeoutInSeconds, updatedClient.RefreshTokenOfflineIdleTimeoutInSeconds)
	assert.Equal(t, retrievedClient.RefreshTokenOfflineMaxLifetimeInSeconds, updatedClient.RefreshTokenOfflineMaxLifetimeInSeconds)
	assert.Equal(t, retrievedClient.IncludeOpenIDConnectClaimsInAccessToken, updatedClient.IncludeOpenIDConnectClaimsInAccessToken)
	assert.Equal(t, retrievedClient.DefaultAcrLevel, updatedClient.DefaultAcrLevel)
}
