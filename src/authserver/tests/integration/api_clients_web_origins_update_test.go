package integrationtests

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/stringutil"
	"github.com/stretchr/testify/assert"
)

// PUT /api/v1/admin/clients/{id}/web-origins

func TestAPIClientWebOriginsPut_Success_AddRemoveAndNormalize(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Create a confidential client with auth code enabled
	clientSecret := stringutil.GenerateSecurityRandomString(60)
	enc, err := encryption.EncryptData(clientSecret)
	assert.NoError(t, err)
	client := &models.Client{
		ClientIdentifier:         "weborig-succ-" + strings.ToLower(gofakeit.LetterN(8)),
		Enabled:                  true,
		ConsentRequired:          false,
		IsPublic:                 false,
		ClientSecretEncrypted:    enc,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: false,
	}
	err = database.CreateClient(nil, client)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(nil, client.Id) }()

	// Seed existing web origins
	originA := "https://a.example.com"
	originB := "https://b.example.com"
	err = database.CreateWebOrigin(nil, &models.WebOrigin{ClientId: client.Id, Origin: originA})
	assert.NoError(t, err)
	err = database.CreateWebOrigin(nil, &models.WebOrigin{ClientId: client.Id, Origin: originB})
	assert.NoError(t, err)

	// Desired: keep A (with spaces and uppercase to test trimming+lowercasing), remove B, add C
	originAMixed := "  HTTPS://A.EXAMPLE.COM  "
	originC := "https://c.example.com"
	reqBody := api.UpdateClientWebOriginsRequest{WebOrigins: []string{originAMixed, originC}}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/web-origins"
	resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var updateResp api.UpdateClientResponse
	err = json.NewDecoder(resp.Body).Decode(&updateResp)
	assert.NoError(t, err)

	// Response should include exactly a.example.com and c.example.com in lowercase
	got := map[string]bool{}
	for _, wo := range updateResp.Client.WebOrigins {
		got[wo.Origin] = true
	}
	assert.Len(t, updateResp.Client.WebOrigins, 2)
	assert.True(t, got["https://a.example.com"])
	assert.True(t, got[originC])

	// Verify DB reflects the change
	refreshed, err := database.GetClientById(nil, client.Id)
	assert.NoError(t, err)
	err = database.ClientLoadWebOrigins(nil, refreshed)
	assert.NoError(t, err)
	gotDB := map[string]bool{}
	for _, wo := range refreshed.WebOrigins {
		gotDB[wo.Origin] = true
	}
	assert.Len(t, refreshed.WebOrigins, 2)
	assert.True(t, gotDB["https://a.example.com"])
	assert.True(t, gotDB[originC])
	assert.False(t, gotDB[originB])
}

// The flow gate is gone, so any client may have web origins. This test was the reverse of itself
// until #250: the same fixture, with the authorization code flow off, asserting a 400 saying
// "Authorization code flow is disabled for this client."
//
// Needing a web origin means the client's app is JavaScript running in a browser, which no flow
// flag expresses. This fixture is the case the old gate got wrong in the least exotic way: an ROPC
// client whose single-page app calls /auth/token from the browser, which needs an origin and
// enables no redirect-based flow at all.
func TestAPIClientWebOriginsPut_AuthCodeDisabledAccepted(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	client := &models.Client{
		ClientIdentifier:         "weborig-noauthcode-" + strings.ToLower(gofakeit.LetterN(8)),
		Enabled:                  true,
		ConsentRequired:          false,
		IsPublic:                 true,
		AuthorizationCodeEnabled: false,
		ClientCredentialsEnabled: false,
	}
	err := database.CreateClient(nil, client)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(nil, client.Id) }()

	origin := "https://spa-" + strings.ToLower(gofakeit.LetterN(8)) + ".example.com"
	reqBody := api.UpdateClientWebOriginsRequest{WebOrigins: []string{origin}}
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/web-origins"
	resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var updateResp api.UpdateClientResponse
	err = json.NewDecoder(resp.Body).Decode(&updateResp)
	assert.NoError(t, err)
	assert.Len(t, updateResp.Client.WebOrigins, 1)
	assert.Equal(t, origin, updateResp.Client.WebOrigins[0].Origin)

	// And it really landed, rather than being echoed back from the request.
	refreshed, err := database.GetClientById(nil, client.Id)
	assert.NoError(t, err)
	err = database.ClientLoadWebOrigins(nil, refreshed)
	assert.NoError(t, err)
	assert.Len(t, refreshed.WebOrigins, 1)
	assert.Equal(t, origin, refreshed.WebOrigins[0].Origin)
}

// The endpoint stores the canonical origin, which is the string MiddlewareCors compares to the
// browser's Origin header byte for byte. urlutil.CanonicalOrigin owns the table of cases; these
// two exist to prove the handler calls it at all, and they are the two an administrator produces
// by accident: a URL copied out of a browser bar, which carries a trailing slash and whatever case
// was typed, and an explicit default port, which a browser never sends (#250).
func TestAPIClientWebOriginsPut_StoresTheCanonicalOrigin(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	client := &models.Client{
		ClientIdentifier:         "weborig-canon-" + strings.ToLower(gofakeit.LetterN(8)),
		Enabled:                  true,
		ConsentRequired:          false,
		IsPublic:                 true,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: false,
	}
	err := database.CreateClient(nil, client)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(nil, client.Id) }()

	host := "canon-" + strings.ToLower(gofakeit.LetterN(8)) + ".example.com"
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/web-origins"

	testCases := []struct {
		name string
		sent string
		want string
	}{
		{
			name: "a URL copied from a browser bar keeps neither its case nor its trailing slash",
			sent: "https://" + strings.ToUpper(host) + "/",
			want: "https://" + host,
		},
		{
			name: "an explicit default port is dropped, because a browser never sends one",
			sent: "https://" + host + ":443",
			want: "https://" + host,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reqBody := api.UpdateClientWebOriginsRequest{WebOrigins: []string{tc.sent}}
			resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
			defer func() { _ = resp.Body.Close() }()
			assert.Equal(t, http.StatusOK, resp.StatusCode)

			refreshed, err := database.GetClientById(nil, client.Id)
			assert.NoError(t, err)
			err = database.ClientLoadWebOrigins(nil, refreshed)
			assert.NoError(t, err)
			assert.Len(t, refreshed.WebOrigins, 1)
			assert.Equal(t, tc.want, refreshed.WebOrigins[0].Origin)
		})
	}
}

func TestAPIClientWebOriginsPut_SystemLevelClientAllowed(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Get system-level client
	resp := makeAPIRequest(t, "GET", config.GetAuthServer().BaseURL+"/api/v1/admin/clients", accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	var listResp api.GetClientsResponse
	err := json.NewDecoder(resp.Body).Decode(&listResp)
	assert.NoError(t, err)

	var sysId int64
	for _, c := range listResp.Clients {
		if c.ClientIdentifier == constants.AdminConsoleClientIdentifier {
			sysId = c.Id
			break
		}
	}
	if sysId == 0 {
		t.Skip("system-level client not found")
	}

	// Update web origins (should succeed)
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(sysId, 10) + "/web-origins"
	reqBody := api.UpdateClientWebOriginsRequest{WebOrigins: []string{"https://example.com", "https://localhost:3000"}}
	resp2 := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)
}

func TestAPIClientWebOriginsPut_ValidationErrors(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Create a client with auth code enabled
	client := &models.Client{
		ClientIdentifier:         "weborig-valid-" + strings.ToLower(gofakeit.LetterN(8)),
		Enabled:                  true,
		ConsentRequired:          false,
		IsPublic:                 true,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: false,
	}
	err := database.CreateClient(nil, client)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(nil, client.Id) }()

	baseURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/web-origins"

	// Sub-test: Empty web origin value
	t.Run("EmptyOrigin", func(t *testing.T) {
		reqBody := api.UpdateClientWebOriginsRequest{WebOrigins: []string{"https://example.com", "  "}}
		resp := makeAPIRequest(t, "PUT", baseURL, accessToken, reqBody)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		var errResp api.ErrorResponse
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		assert.Equal(t, "Web origin cannot be empty", errResp.ErrorDescription)
	})

	// Everything that is not a canonical origin is refused with one message that names the value
	// and says what an origin looks like, rather than the three the old validator had. The
	// scheme case is no longer separate: urlutil.CanonicalOrigin refuses "ftp://example.com" for
	// the same reason it refuses "not-a-url", and an administrator needs the same sentence for
	// both (#250).
	for _, sent := range []string{"not-a-url", "ftp://example.com", "https://user@example.com", "https://[2001:db8::1]"} {
		t.Run("Refused_"+sent, func(t *testing.T) {
			reqBody := api.UpdateClientWebOriginsRequest{WebOrigins: []string{sent}}
			resp := makeAPIRequest(t, "PUT", baseURL, accessToken, reqBody)
			defer func() { _ = resp.Body.Close() }()
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

			var errResp api.ErrorResponse
			_ = json.NewDecoder(resp.Body).Decode(&errResp)
			assert.Contains(t, errResp.ErrorDescription, "Invalid web origin: "+sent)
			// The refusal has to say what to type instead, or the administrator is left
			// guessing at an endpoint that used to accept the value silently.
			assert.Contains(t, errResp.ErrorDescription, "https://www.example.com")
		})
	}

	// Sub-test: Duplicate web origins, now colliding on the canonical form rather than on case
	// alone. "https://example.com/" and "https://example.com" are one origin to a browser, and
	// storing both is storing one row that can never match.
	t.Run("DuplicateOrigins", func(t *testing.T) {
		reqBody := api.UpdateClientWebOriginsRequest{WebOrigins: []string{"https://example.com", "HTTPS://EXAMPLE.COM/"}}
		resp := makeAPIRequest(t, "PUT", baseURL, accessToken, reqBody)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		var errResp api.ErrorResponse
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		assert.Equal(t, "Duplicate web origins are not allowed", errResp.ErrorDescription)
	})
}

func TestAPIClientWebOriginsPut_NotFound_InvalidId_InvalidBody_Unauthorized(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Not found
	urlNF := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/999999/web-origins"
	resp := makeAPIRequest(t, "PUT", urlNF, accessToken, api.UpdateClientWebOriginsRequest{WebOrigins: []string{"https://example.com"}})
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	var nf map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&nf)
	if nf["error_description"] != nil {
		msg := nf["error_description"].(string)
		assert.Equal(t, "Client not found", msg)
	}

	// Invalid id (non-numeric)
	urlBad := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/abc/web-origins"
	resp2 := makeAPIRequest(t, "PUT", urlBad, accessToken, api.UpdateClientWebOriginsRequest{WebOrigins: []string{"https://example.com"}})
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
	var bad map[string]interface{}
	_ = json.NewDecoder(resp2.Body).Decode(&bad)
	if bad["error_description"] != nil {
		msg := bad["error_description"].(string)
		assert.Equal(t, "Invalid client ID", msg)
	}

	// Invalid body
	client2 := &models.Client{
		ClientIdentifier:         "weborig-bad-body-" + strings.ToLower(gofakeit.LetterN(8)),
		Enabled:                  true,
		ConsentRequired:          false,
		IsPublic:                 true,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: false,
	}
	err := database.CreateClient(nil, client2)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(nil, client2.Id) }()

	urlIB := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client2.Id, 10) + "/web-origins"
	req, err := http.NewRequest("PUT", urlIB, nil)
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	httpClient := createHttpClient(t)
	resp3, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp3.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp3.StatusCode)
	var ib map[string]interface{}
	_ = json.NewDecoder(resp3.Body).Decode(&ib)
	if ib["error_description"] != nil {
		msg := ib["error_description"].(string)
		assert.Equal(t, "Invalid request body", msg)
	}

	// Unauthorized
	req2, err := http.NewRequest("PUT", urlIB, nil)
	assert.NoError(t, err)
	resp4, err := httpClient.Do(req2)
	assert.NoError(t, err)
	defer func() { _ = resp4.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp4.StatusCode)
}

func TestAPIClientWebOriginsPut_InsufficientScope(t *testing.T) {
	// Create a client with only authserver:userinfo scope
	clientSecret := stringutil.GenerateSecurityRandomString(60)
	enc, err := encryption.EncryptData(clientSecret)
	assert.NoError(t, err)

	client := &models.Client{
		ClientIdentifier:         "weborig-inscope-" + strings.ToLower(gofakeit.LetterN(8)),
		Enabled:                  true,
		ClientCredentialsEnabled: true,
		IsPublic:                 false,
		ClientSecretEncrypted:    enc,
	}
	err = database.CreateClient(nil, client)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(nil, client.Id) }()

	// Grant auth-server:userinfo permission only
	authRes, err := database.GetResourceByResourceIdentifier(nil, constants.AuthServerResourceIdentifier)
	assert.NoError(t, err)
	perms, err := database.GetPermissionsByResourceId(nil, authRes.Id)
	assert.NoError(t, err)
	var userinfoPerm *models.Permission
	for i := range perms {
		if perms[i].PermissionIdentifier == constants.UserinfoPermissionIdentifier {
			userinfoPerm = &perms[i]
			break
		}
	}
	assert.NotNil(t, userinfoPerm)
	err = database.CreateClientPermission(nil, &models.ClientPermission{ClientId: client.Id, PermissionId: userinfoPerm.Id})
	assert.NoError(t, err)

	// Get token with only authserver:userinfo scope
	httpClient := createHttpClient(t)
	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"
	formData := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"scope":         {constants.AuthServerResourceIdentifier + ":" + constants.UserinfoPermissionIdentifier},
	}
	data := postToTokenEndpoint(t, httpClient, destUrl, formData)
	accessToken, ok := data["access_token"].(string)
	assert.True(t, ok)
	assert.NotEmpty(t, accessToken)

	// Create a target client with auth code enabled
	target := &models.Client{
		ClientIdentifier:         "weborig-target-" + strings.ToLower(gofakeit.LetterN(8)),
		Enabled:                  true,
		IsPublic:                 true,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: false,
	}
	err = database.CreateClient(nil, target)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(nil, target.Id) }()

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(target.Id, 10) + "/web-origins"
	reqBody := api.UpdateClientWebOriginsRequest{WebOrigins: []string{"https://example.com"}}
	resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}
