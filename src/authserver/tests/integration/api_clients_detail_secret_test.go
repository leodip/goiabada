package integrationtests

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

// Verifies confidential client secret is returned in detail but not in list, and that neither
// response may be stored.
//
// The cache assertions are here rather than in cache_directives_test.go because this is the test
// that establishes what the detail response contains. GET /api/v1/admin/clients/{id} is the second
// of the two API responses that carry a credential outright (#247), and the only place the
// decrypted client secret is ever emitted, so RFC 6749 section 5.1's MUST reaches it exactly as it
// reaches the TOTP enrolment seed.
//
// It cannot be inherited from the route sweep in internal/server/routes_no_store_test.go. That
// sweep calls every registered route WITHOUT credentials, so it never reaches a handler at all: a
// handler that set its own Cache-Control would win, because Header().Set replaces, and the sweep
// would stay green. An authenticated success response is the only seam that can observe it, which
// is why the two credential-bearing ones each carry the assertion themselves.
func TestAPIClientGet_ConfidentialIncludesSecretInDetailButNotList(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Create confidential client with encrypted secret
	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	enc, err := encryption.EncryptData(clientSecret)
	assert.NoError(t, err)

	client := &models.Client{
		ClientIdentifier:         "secret-client-" + strings.ToLower(gofakeit.LetterN(8)),
		Enabled:                  true,
		ClientCredentialsEnabled: true,
		IsPublic:                 false,
		ClientSecretEncrypted:    enc,
	}
	err = database.CreateClient(nil, client)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(nil, client.Id) }()

	// Detail should include clientSecret
	detailURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10)
	resp := makeAPIRequest(t, "GET", detailURL, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var getResp api.GetClientResponse
	err = json.NewDecoder(resp.Body).Decode(&getResp)
	assert.NoError(t, err)
	assert.Equal(t, client.Id, getResp.Client.Id)
	assert.NotEmpty(t, getResp.Client.ClientSecret)

	// The body really did carry the decrypted secret, asserted immediately above, so this is the
	// credential-bearing response rather than an error body that happens to be uncacheable.
	assertNotStorable(t, resp, "the admin client detail carrying the decrypted client secret")

	// List should not include clientSecret
	listURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients"
	resp2 := makeAPIRequest(t, "GET", listURL, accessToken, nil)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)
	var listResp api.GetClientsResponse
	err = json.NewDecoder(resp2.Body).Decode(&listResp)
	assert.NoError(t, err)
	found := false
	for _, c := range listResp.Clients {
		if c.Id == client.Id {
			found = true
			assert.Empty(t, c.ClientSecret)
			break
		}
	}
	assert.True(t, found, "newly created client should be in list")

	// The list carries no credential, and it is asserted anyway: it is an authenticated SUCCESS
	// response, which is the half of the API surface the unauthenticated route sweep structurally
	// cannot reach. One line here covers a non-credential success alongside the two credential
	// ones, so "every route the router registers" is observed on both sides of the guards.
	assertNotStorable(t, resp2, "the admin client list")
}
