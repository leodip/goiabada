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

// PUT /api/v1/admin/clients/{id}/redirect-uris

func TestAPIClientRedirectURIsPut_Success_AddRemoveAndTrim(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Create a confidential client with auth code enabled
	clientSecret := stringutil.GenerateSecurityRandomString(60)
	enc, err := encryption.EncryptData(clientSecret)
	assert.NoError(t, err)
	client := &models.Client{
		ClientIdentifier:         "redir-succ-" + strings.ToLower(gofakeit.LetterN(8)),
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

	// Seed existing redirect URIs
	uriA := "https://a.example.com/callback"
	uriB := "https://b.example.com/callback"
	err = database.CreateRedirectURI(nil, &models.RedirectURI{ClientId: client.Id, URI: uriA})
	assert.NoError(t, err)
	err = database.CreateRedirectURI(nil, &models.RedirectURI{ClientId: client.Id, URI: uriB})
	assert.NoError(t, err)

	// Desired: keep A (with spaces to test trimming), remove B, add C
	uriC := "https://c.example.com/newcb"
	reqBody := api.UpdateClientRedirectURIsRequest{RedirectURIs: []string{"  " + uriA + "  ", uriC}}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/redirect-uris"
	resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var updateResp api.UpdateClientResponse
	err = json.NewDecoder(resp.Body).Decode(&updateResp)
	assert.NoError(t, err)

	// Response should include exactly A and C after trimming
	got := map[string]bool{}
	for _, ru := range updateResp.Client.RedirectURIs {
		got[ru.URI] = true
	}
	assert.Len(t, updateResp.Client.RedirectURIs, 2)
	assert.True(t, got[uriA])
	assert.True(t, got[uriC])

	// Verify DB reflects the change
	refreshed, err := database.GetClientById(nil, client.Id)
	assert.NoError(t, err)
	err = database.ClientLoadRedirectURIs(nil, refreshed)
	assert.NoError(t, err)
	gotDB := map[string]bool{}
	for _, ru := range refreshed.RedirectURIs {
		gotDB[ru.URI] = true
	}
	assert.Len(t, refreshed.RedirectURIs, 2)
	assert.True(t, gotDB[uriA])
	assert.True(t, gotDB[uriC])
	assert.False(t, gotDB[uriB])
}

// The gate asks whether the client redirects at all, so what is refused here is a client with
// NEITHER redirect-based flow, not one that merely lacks the authorization code flow (#250).
//
// ImplicitGrantEnabled is set explicitly rather than left to inherit: nil would resolve against
// the global setting, which other tests in this package turn on and restore, so an inheriting
// fixture would make the refusal depend on what ran before it.
func TestAPIClientRedirectURIsPut_NoRedirectFlowRejected(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	implicitDisabled := false
	client := &models.Client{
		ClientIdentifier:         "redir-disabled-" + strings.ToLower(gofakeit.LetterN(8)),
		Enabled:                  true,
		ConsentRequired:          false,
		IsPublic:                 true,
		AuthorizationCodeEnabled: false,
		ImplicitGrantEnabled:     &implicitDisabled,
		ClientCredentialsEnabled: false,
	}
	err := database.CreateClient(nil, client)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(nil, client.Id) }()

	reqBody := api.UpdateClientRedirectURIsRequest{RedirectURIs: []string{"https://example.com/cb"}}
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/redirect-uris"
	resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var body map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["error_description"] != nil {
		msg := body["error_description"].(string)
		assert.Equal(t, "Redirect URIs are used by the authorization code with PKCE flow and by the implicit flow, and neither is enabled for this client.", msg)
	}
}

// An implicit-only client's callback is the one setting that makes it work, and RFC 6749 section
// 3.1.2.2 makes registering it a MUST. Until this change the endpoint answered 400, so an
// administrator could not add, rotate or urgently remove one without first enabling a flow the
// client does not use (#250).
func TestAPIClientRedirectURIsPut_ImplicitOnlyClientAllowed(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	implicitEnabled := true
	client := &models.Client{
		ClientIdentifier:         "redir-implicit-" + strings.ToLower(gofakeit.LetterN(8)),
		Enabled:                  true,
		ConsentRequired:          false,
		IsPublic:                 true,
		AuthorizationCodeEnabled: false,
		ImplicitGrantEnabled:     &implicitEnabled,
		ClientCredentialsEnabled: false,
	}
	err := database.CreateClient(nil, client)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(nil, client.Id) }()

	uri := "https://implicit-app.example.com/cb"
	reqBody := api.UpdateClientRedirectURIsRequest{RedirectURIs: []string{uri}}
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/redirect-uris"
	resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var updateResp api.UpdateClientResponse
	err = json.NewDecoder(resp.Body).Decode(&updateResp)
	assert.NoError(t, err)

	got := make([]string, 0, len(updateResp.Client.RedirectURIs))
	for _, ru := range updateResp.Client.RedirectURIs {
		got = append(got, ru.URI)
	}
	assert.Equal(t, []string{uri}, got)
}

func TestAPIClientRedirectURIsPut_SystemLevelClientAllowed(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Find system-level admin console client id
	listURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients"
	resp := makeAPIRequest(t, "GET", listURL, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
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

	// Update redirect URIs (should succeed)
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(sysId, 10) + "/redirect-uris"
	reqBody := api.UpdateClientRedirectURIsRequest{RedirectURIs: []string{"https://example.com/callback", "https://localhost:3000/cb"}}
	resp2 := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)
}

func TestAPIClientRedirectURIsPut_DuplicateAndInvalidURLs(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Auth code enabled client
	client := &models.Client{
		ClientIdentifier:         "redir-vali-" + strings.ToLower(gofakeit.LetterN(8)),
		Enabled:                  true,
		ConsentRequired:          false,
		IsPublic:                 true,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: false,
	}
	err := database.CreateClient(nil, client)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(nil, client.Id) }()

	baseURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/redirect-uris"

	// Duplicate
	reqDup := api.UpdateClientRedirectURIsRequest{RedirectURIs: []string{"https://dup.example/cb", "https://dup.example/cb"}}
	resp := makeAPIRequest(t, "PUT", baseURL, accessToken, reqDup)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var bodyDup map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&bodyDup)
	if bodyDup["error_description"] != nil {
		msg := bodyDup["error_description"].(string)
		assert.Equal(t, "Duplicate redirect URIs are not allowed", msg)
	}

	// Invalid URL
	reqInv := api.UpdateClientRedirectURIsRequest{RedirectURIs: []string{"not-a-url"}}
	resp2 := makeAPIRequest(t, "PUT", baseURL, accessToken, reqInv)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
	var bodyInv map[string]interface{}
	_ = json.NewDecoder(resp2.Body).Decode(&bodyInv)
	if bodyInv["error_description"] != nil {
		msg := bodyInv["error_description"].(string)
		assert.Equal(t, "Invalid redirect URI: not-a-url", msg)
	}

	// Empty (or whitespace only)
	reqEmpty := api.UpdateClientRedirectURIsRequest{RedirectURIs: []string{"  "}}
	resp3 := makeAPIRequest(t, "PUT", baseURL, accessToken, reqEmpty)
	defer func() { _ = resp3.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp3.StatusCode)
	var bodyEmpty map[string]interface{}
	_ = json.NewDecoder(resp3.Body).Decode(&bodyEmpty)
	if bodyEmpty["error_description"] != nil {
		msg := bodyEmpty["error_description"].(string)
		assert.Equal(t, "Redirect URI cannot be empty", msg)
	}

	// Not an absolute URI (#122). url.ParseRequestURI accepts every value below, so this
	// gate is the only thing that refuses them, and before it they were stored and later
	// emitted verbatim into a Location header.
	//
	// This endpoint is the exhaustive tier for that gate by necessity rather than by
	// preference: handler_api_clients_test.go does not exist, and the validation loop is
	// inline in the handler rather than a pure function, so there is no unit seam to own it.
	//
	// The message is asserted unconditionally, unlike the cases above, which wrap the
	// assertion in a nil check that passes when the field is absent entirely.
	notAbsolute := []struct {
		uri    string
		reason string
	}{
		{"//evil.example/cb", "scheme-relative: the reported shape, resolved against the server's own scheme"},
		{"/relative/cb", "path-absolute with no scheme"},
		{"https:///evil.example/cb", "a valid absolute-URI with no host: only the host rule refuses it"},
		{"https://legit.example/cb#frag", "a fragment breaks the callback even on a legitimate host"},
	}
	for _, tc := range notAbsolute {
		t.Run(tc.uri, func(t *testing.T) {
			req := api.UpdateClientRedirectURIsRequest{RedirectURIs: []string{tc.uri}}
			resp := makeAPIRequest(t, "PUT", baseURL, accessToken, req)
			defer func() { _ = resp.Body.Close() }()
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode, tc.reason)
			var body map[string]interface{}
			_ = json.NewDecoder(resp.Body).Decode(&body)
			msg, ok := body["error_description"].(string)
			assert.True(t, ok, "the response must carry an error_description")
			assert.Equal(t, "Redirect URI must be an absolute URI (a scheme is required, a fragment is not permitted, percent-escapes must be well formed, and an http or https URI must name a host): "+tc.uri, msg)
		})
	}

	// The gate must not have swallowed the legitimate shapes. A private-use scheme URI is
	// hostless by design (RFC 8252 section 7.1) and an administrator has legitimate reason
	// to register one, so this is the row that catches the host rule being widened past
	// http and https.
	reqOK := api.UpdateClientRedirectURIsRequest{RedirectURIs: []string{
		"https://legit.example/cb?a=1",
		"com.example.app:/oauth2redirect/example-provider",
	}}
	respOK := makeAPIRequest(t, "PUT", baseURL, accessToken, reqOK)
	defer func() { _ = respOK.Body.Close() }()
	assert.Equal(t, http.StatusOK, respOK.StatusCode, "valid redirect URIs must still be accepted")
}

func TestAPIClientRedirectURIsPut_NotFound_InvalidId_InvalidBody_Unauthorized(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Not found
	urlNF := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/999999/redirect-uris"
	resp := makeAPIRequest(t, "PUT", urlNF, accessToken, api.UpdateClientRedirectURIsRequest{RedirectURIs: []string{"https://example.com/cb"}})
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	var nf map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&nf)
	if nf["error_description"] != nil {
		msg := nf["error_description"].(string)
		assert.Equal(t, "Client not found", msg)
	}

	// Invalid id (non-numeric)
	urlBad := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/abc/redirect-uris"
	resp2 := makeAPIRequest(t, "PUT", urlBad, accessToken, api.UpdateClientRedirectURIsRequest{RedirectURIs: []string{"https://example.com/cb"}})
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
		ClientIdentifier:         "redir-bad-body-" + strings.ToLower(gofakeit.LetterN(8)),
		Enabled:                  true,
		ConsentRequired:          false,
		IsPublic:                 true,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: false,
	}
	err := database.CreateClient(nil, client2)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(nil, client2.Id) }()

	urlIB := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client2.Id, 10) + "/redirect-uris"
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

func TestAPIClientRedirectURIsPut_InsufficientScope(t *testing.T) {
	// Create a client with only authserver:userinfo scope
	clientSecret := stringutil.GenerateSecurityRandomString(60)
	enc, err := encryption.EncryptData(clientSecret)
	assert.NoError(t, err)

	client := &models.Client{
		ClientIdentifier:         "redir-inscope-" + strings.ToLower(gofakeit.LetterN(8)),
		Enabled:                  true,
		ClientCredentialsEnabled: true,
		IsPublic:                 false,
		ClientSecretEncrypted:    enc,
	}
	err = database.CreateClient(nil, client)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(nil, client.Id) }()

	// Grant auth-server:userinfo permission
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
		ClientIdentifier:         "redir-target-" + strings.ToLower(gofakeit.LetterN(8)),
		Enabled:                  true,
		IsPublic:                 true,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: false,
	}
	err = database.CreateClient(nil, target)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(nil, target.Id) }()

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(target.Id, 10) + "/redirect-uris"
	reqBody := api.UpdateClientRedirectURIsRequest{RedirectURIs: []string{"https://example.com/cb"}}
	resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}
