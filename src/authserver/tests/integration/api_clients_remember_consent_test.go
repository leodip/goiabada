package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/securerandom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Remember consent as every writer of a client stores it and as the admin API answers it (#711
// decisions 4 to 7). Each test reads both the stored row and the admin API's answer: the row is what
// the consent decisions read, and the answer is what scripts and the console are shown.

// clientRememberConsentAnswer reads one client's rememberConsent off a decoded admin API client
// object, failing when the key is missing: the response always carries it (decision 6).
func clientRememberConsentAnswer(t *testing.T, client map[string]any) bool {
	t.Helper()
	value, ok := client["rememberConsent"]
	require.True(t, ok, "the admin API's client response must carry rememberConsent")
	remember, ok := value.(bool)
	require.Truef(t, ok, "rememberConsent must be a boolean, got %T", value)
	return remember
}

// adminRequestClient sends one admin API request answering {"client": {...}} and returns that
// client object, after asserting the status.
func adminRequestClient(t *testing.T, method, path, accessToken string, body any, wantStatus int) map[string]any {
	t.Helper()
	resp := makeAPIRequest(t, method, appConfig.AuthServer.BaseURL+path, accessToken, body)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, wantStatus, resp.StatusCode)

	var decoded map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&decoded))
	client, ok := decoded["client"].(map[string]any)
	require.True(t, ok, "the response must carry a client object")
	return client
}

func storedRememberConsent(t *testing.T, clientId int64) bool {
	t.Helper()
	client, err := database.GetClientById(context.Background(), nil, clientId)
	require.NoError(t, err)
	require.NotNil(t, client)
	return client.RememberConsent
}

func clientPath(clientId int64) string {
	return "/api/v1/admin/clients/" + strconv.FormatInt(clientId, 10)
}

// createRememberConsentClient stores a client with Remember consent as given, through the data
// layer, so a test starts from a value no endpoint under test chose.
func createRememberConsentClient(t *testing.T, isPublic, remember bool) *record.Client {
	t.Helper()
	client := &record.Client{
		ClientIdentifier:         "remember-" + strings.ToLower(fake.LetterN(10)),
		Enabled:                  true,
		IsPublic:                 isPublic,
		AuthorizationCodeEnabled: true,
		RememberConsent:          remember,
	}
	if !isPublic {
		enc, err := dataCipher.Encrypt(securerandom.String(60))
		require.NoError(t, err)
		client.ClientSecretEncrypted = enc
	}
	client.ApplyPublicClientInvariants()
	require.NoError(t, database.CreateClient(context.Background(), nil, client))
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })
	return client
}

// TestAPIClientCreate_StoresRememberConsentOn: the create request makes a confidential client, and a
// confidential client always remembers consent (decision 4).
func TestAPIClientCreate_StoresRememberConsentOn(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	created := adminRequestClient(t, "POST", "/api/v1/admin/clients", accessToken, api.CreateClientRequest{
		ClientIdentifier:         "remember-create-" + strings.ToLower(fake.LetterN(8)),
		AuthorizationCodeEnabled: true,
	}, http.StatusCreated)
	id := int64(created["id"].(float64))
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, id) })

	assert.True(t, clientRememberConsentAnswer(t, created), "the create's answer")
	assert.True(t, storedRememberConsent(t, id), "the stored row")
	assert.True(t, clientRememberConsentAnswer(t,
		adminRequestClient(t, "GET", clientPath(id), accessToken, nil, http.StatusOK)), "the client read back")
}

// TestAPIClients_ListAnswersRememberConsent: every client in the list carries rememberConsent, the
// stored value, public and confidential alike (decision 6).
func TestAPIClients_ListAnswersRememberConsent(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	publicOn := createRememberConsentClient(t, true, true)
	publicOff := createRememberConsentClient(t, true, false)
	confidential := createRememberConsentClient(t, false, true)
	want := map[int64]bool{publicOn.Id: true, publicOff.Id: false, confidential.Id: true}

	resp := makeAPIRequest(t, "GET", appConfig.AuthServer.BaseURL+"/api/v1/admin/clients", accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var decoded struct {
		Clients []map[string]any `json:"clients"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&decoded))
	seen := 0
	for _, c := range decoded.Clients {
		_, hasKey := c["rememberConsent"]
		assert.Truef(t, hasKey, "client %v must carry rememberConsent", c["clientIdentifier"])
		if w, ok := want[int64(c["id"].(float64))]; ok {
			seen++
			assert.Equalf(t, w, clientRememberConsentAnswer(t, c), "client %v", c["clientIdentifier"])
		}
	}
	assert.Equal(t, 3, seen)
}

// TestDCR_StoresRememberConsentOffForPublicOnForConfidential: a self-registered public client
// cannot prove its identity, so it starts off; a confidential one authenticates and starts on
// (decisions 1 and 4).
func TestDCR_StoresRememberConsentOffForPublicOnForConfidential(t *testing.T) {
	enableDCR(t)
	adminToken, _ := createAdminClientWithToken(t)

	register := func(t *testing.T, authMethod, redirectURI string) int64 {
		t.Helper()
		resp := makeDCRRequest(t, oidc.DynamicClientRegistrationRequest{
			RedirectURIs:            []string{redirectURI},
			TokenEndpointAuthMethod: authMethod,
			GrantTypes:              []string{"authorization_code"},
			ClientName:              "Remember consent " + authMethod,
		})
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusCreated, resp.StatusCode)

		var registered oidc.DynamicClientRegistrationResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&registered))
		client, err := database.GetClientByClientIdentifier(context.Background(), nil, registered.ClientID)
		require.NoError(t, err)
		require.NotNil(t, client)
		t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })
		return client.Id
	}

	t.Run("public", func(t *testing.T) {
		id := register(t, "none", "http://localhost:8080/callback")
		assert.False(t, storedRememberConsent(t, id))
		assert.False(t, clientRememberConsentAnswer(t,
			adminRequestClient(t, "GET", clientPath(id), adminToken, nil, http.StatusOK)))
	})

	t.Run("confidential", func(t *testing.T) {
		id := register(t, "client_secret_post", "https://app.example.com/callback")
		assert.True(t, storedRememberConsent(t, id))
		assert.True(t, clientRememberConsentAnswer(t,
			adminRequestClient(t, "GET", clientPath(id), adminToken, nil, http.StatusOK)))
	})
}

// TestAPIClientAuthenticationPut_SwitchToPublic_TurnsRememberConsentOff: the save that makes a
// confidential client public turns Remember consent off (decision 5).
func TestAPIClientAuthenticationPut_SwitchToPublic_TurnsRememberConsentOff(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	client := createRememberConsentClient(t, false, true)

	answer := adminRequestClient(t, "PUT", clientPath(client.Id)+"/authentication", accessToken,
		api.UpdateClientAuthenticationRequest{IsPublic: true}, http.StatusOK)

	assert.False(t, clientRememberConsentAnswer(t, answer), "the switch's answer")
	assert.False(t, storedRememberConsent(t, client.Id), "the stored row")
}

// TestAPIClientAuthenticationPut_SavingAnAlreadyPublicClient_KeepsRememberConsent: saving a public
// client as public again is no switch, and keeps the administrator's choice either way (decision 5).
func TestAPIClientAuthenticationPut_SavingAnAlreadyPublicClient_KeepsRememberConsent(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	for _, stored := range []bool{true, false} {
		client := createRememberConsentClient(t, true, stored)

		answer := adminRequestClient(t, "PUT", clientPath(client.Id)+"/authentication", accessToken,
			api.UpdateClientAuthenticationRequest{IsPublic: true}, http.StatusOK)

		assert.Equalf(t, stored, clientRememberConsentAnswer(t, answer), "the save's answer, stored %v", stored)
		assert.Equalf(t, stored, storedRememberConsent(t, client.Id), "the stored row, stored %v", stored)
	}
}

// TestAPIClientAuthenticationPut_SwitchToConfidential_TurnsRememberConsentOn: a confidential client
// always remembers consent, so the switch to confidential turns it on (decision 4).
func TestAPIClientAuthenticationPut_SwitchToConfidential_TurnsRememberConsentOn(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	client := createRememberConsentClient(t, true, false)

	answer := adminRequestClient(t, "PUT", clientPath(client.Id)+"/authentication", accessToken,
		api.UpdateClientAuthenticationRequest{IsPublic: false, ClientSecret: securerandom.String(60)}, http.StatusOK)

	assert.True(t, clientRememberConsentAnswer(t, answer), "the switch's answer")
	assert.True(t, storedRememberConsent(t, client.Id), "the stored row")
}

// TestAPIClient_SavesThatDoNotOwnRememberConsentLeaveItAlone: the settings save without
// rememberConsent, the OAuth2 flows save and the Tokens save never write the column, whichever value
// a public client holds (decision 5).
func TestAPIClient_SavesThatDoNotOwnRememberConsentLeaveItAlone(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	saves := []struct {
		name   string
		suffix string
		body   func(client *record.Client) any
	}{
		{"settings", "", func(client *record.Client) any {
			return api.UpdateClientSettingsRequest{
				ClientIdentifier: client.ClientIdentifier,
				Description:      "saved without rememberConsent",
				Enabled:          true,
				ConsentRequired:  true,
			}
		}},
		{"oauth2 flows", "/oauth2-flows", func(*record.Client) any {
			return api.UpdateClientOAuth2FlowsRequest{AuthorizationCodeEnabled: true}
		}},
		{"tokens", "/tokens", func(*record.Client) any {
			return api.UpdateClientTokensRequest{
				TokenExpirationInSeconds:                3600,
				RefreshTokenOfflineIdleTimeoutInSeconds: 1000,
				RefreshTokenOfflineMaxLifetimeInSeconds: 2000,
				IncludeOpenIDConnectClaimsInAccessToken: "default",
				IncludeOpenIDConnectClaimsInIdToken:     "default",
			}
		}},
	}

	for _, save := range saves {
		for _, stored := range []bool{true, false} {
			t.Run(save.name+" stored "+strconv.FormatBool(stored), func(t *testing.T) {
				client := createRememberConsentClient(t, true, stored)

				answer := adminRequestClient(t, "PUT", clientPath(client.Id)+save.suffix, accessToken,
					save.body(client), http.StatusOK)

				assert.Equal(t, stored, clientRememberConsentAnswer(t, answer), "the save's answer")
				assert.Equal(t, stored, storedRememberConsent(t, client.Id), "the stored row")
			})
		}
	}
}

// TestAPIClientSettingsPut_PublicClient_AppliesRememberConsent: the settings save's rememberConsent
// turns a public client's Remember consent on and off, and the answer and the stored row say so
// (decisions 5 and 6). The body is written as JSON by hand, so the field's wire name is checked too.
func TestAPIClientSettingsPut_PublicClient_AppliesRememberConsent(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	client := createRememberConsentClient(t, true, false)

	save := func(remember bool) map[string]any {
		return adminRequestClient(t, "PUT", clientPath(client.Id), accessToken, map[string]any{
			"clientIdentifier": client.ClientIdentifier,
			"enabled":          true,
			"consentRequired":  true,
			"rememberConsent":  remember,
		}, http.StatusOK)
	}

	assert.True(t, clientRememberConsentAnswer(t, save(true)), "the save's answer, turned on")
	assert.True(t, storedRememberConsent(t, client.Id), "the stored row, turned on")

	assert.False(t, clientRememberConsentAnswer(t, save(false)), "the save's answer, turned off")
	assert.False(t, storedRememberConsent(t, client.Id), "the stored row, turned off")
}

// TestAPIClientSettingsPut_ConfidentialClient_StoresRememberConsentOn: a confidential client always
// remembers consent, so a settings save sending rememberConsent false is stored and answered as on
// rather than refused (decision 4). The row starts off, written past the API, so the save's own
// write shows.
func TestAPIClientSettingsPut_ConfidentialClient_StoresRememberConsentOn(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	client := createRememberConsentClient(t, false, false)

	answer := adminRequestClient(t, "PUT", clientPath(client.Id), accessToken, map[string]any{
		"clientIdentifier": client.ClientIdentifier,
		"enabled":          true,
		"rememberConsent":  false,
	}, http.StatusOK)

	assert.True(t, clientRememberConsentAnswer(t, answer), "the save's answer")
	assert.True(t, storedRememberConsent(t, client.Id), "the stored row")
}
