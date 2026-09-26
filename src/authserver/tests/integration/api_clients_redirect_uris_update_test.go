package integrationtests

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/stringutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// PUT /api/v1/admin/clients/{id}/redirect-uris

// readRedirectURIs is the client's redirect URI list as the admin API reads it, which is what a
// save sends as expectedRedirectURIs: the list it loaded. Never nil, so an empty list goes on the
// wire as [] (#428).
func readRedirectURIs(t *testing.T, accessToken string, clientId int64) []string {
	t.Helper()
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(clientId, 10)
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var got api.GetClientResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	uris := make([]string, 0, len(got.Client.RedirectURIs))
	for _, ru := range got.Client.RedirectURIs {
		uris = append(uris, ru.URI)
	}
	return uris
}

// newRedirectURIsClient creates a client whose authorization code flow is on, so its redirect URIs
// can be saved, and removes it when the test ends.
func newRedirectURIsClient(t *testing.T, prefix string) *models.Client {
	t.Helper()
	client := &models.Client{
		ClientIdentifier:         prefix + strings.ToLower(fake.LetterN(8)),
		Enabled:                  true,
		IsPublic:                 true,
		AuthorizationCodeEnabled: true,
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, client))
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })
	return client
}

// redirectURIOfBytes is an absolute https redirect URI of exactly n bytes, distinct per tag.
func redirectURIOfBytes(t *testing.T, n int, tag string) string {
	t.Helper()
	prefix := "https://" + tag + ".example.com/"
	uri := prefix + strings.Repeat("p", n-len(prefix))
	require.Len(t, uri, n)
	return uri
}

// The bounds are one number at both doors (#428): 60 URIs, each at most 2048 bytes, which every
// engine's column holds. A save at both bounds at once succeeds and reads back whole through the
// API; one URI over either is refused and leaves the stored list as it was. Integration runs on all
// four engines in CI, which is what shows the widened column takes the longest URI everywhere.
func TestAPIClientRedirectURIsPut_TheBoundsAt60And2048(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	client := newRedirectURIsClient(t, "redir-bounds-")
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/redirect-uris"

	sixty := make([]string, 60)
	for i := range sixty {
		sixty[i] = redirectURIOfBytes(t, 2048, fmt.Sprintf("app%02d", i))
	}
	resp := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateClientRedirectURIsRequest{
		RedirectURIs: sixty, ExpectedRedirectURIs: readRedirectURIs(t, accessToken, client.Id)})
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.ElementsMatch(t, sixty, readRedirectURIs(t, accessToken, client.Id))

	refusals := []struct {
		name            string
		uris            []string
		wantDescription string
	}{
		{name: "61 redirect URIs", uris: append(append([]string{}, sixty...), "https://one-more.example.com/cb"),
			wantDescription: "A client can have at most 60 redirect URIs, and this list has 61."},
		{name: "a URI of 2049 bytes", uris: []string{redirectURIOfBytes(t, 2049, "long")},
			wantDescription: "Redirect URI is too long (2049 bytes, the maximum is 2048)"},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			resp := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateClientRedirectURIsRequest{
				RedirectURIs: tc.uris, ExpectedRedirectURIs: readRedirectURIs(t, accessToken, client.Id)})
			defer func() { _ = resp.Body.Close() }()
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			var body map[string]interface{}
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
			assert.Equal(t, "VALIDATION_ERROR", body["error_code"])
			assert.Contains(t, body["error_description"], tc.wantDescription)
			assert.ElementsMatch(t, sixty, readRedirectURIs(t, accessToken, client.Id), "a refused save changes nothing")
		})
	}
}

// The list as loaded is required: absent or null is refused before anything is written, naming the
// field, so no caller can save a whole list without saying what it replaces (#428).
func TestAPIClientRedirectURIsPut_TheLoadedListIsRequired(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	client := newRedirectURIsClient(t, "redir-expected-")
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/redirect-uris"

	bodies := map[string]interface{}{
		"absent": map[string]interface{}{"redirectURIs": []string{"https://a.example.com/cb"}},
		"null":   map[string]interface{}{"redirectURIs": []string{"https://a.example.com/cb"}, "expectedRedirectURIs": nil},
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			resp := makeAPIRequest(t, "PUT", url, accessToken, body)
			defer func() { _ = resp.Body.Close() }()
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			var got map[string]interface{}
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
			assert.Equal(t, "VALIDATION_ERROR", got["error_code"])
			assert.Contains(t, got["error_description"], "expectedRedirectURIs is required")
			assert.Empty(t, readRedirectURIs(t, accessToken, client.Id))
		})
	}
}

// A save from an outdated page: two saves both read the same list, the first commits, and the
// second, still carrying the list as it was before the first, is refused 409 CONCURRENT_UPDATE with
// nothing written, where it used to replace the first save's list with its own and undo a change its
// author never saw (#428).
func TestAPIClientRedirectURIsPut_AnOutdatedLoadedListIsRefused(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	client := newRedirectURIsClient(t, "redir-outdated-")
	require.NoError(t, database.CreateRedirectURI(context.Background(), nil,
		&models.RedirectURI{ClientId: client.Id, URI: "https://a.example.com/cb"}))
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/redirect-uris"

	loadedByBoth := readRedirectURIs(t, accessToken, client.Id)

	first := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateClientRedirectURIsRequest{
		RedirectURIs:         []string{"https://a.example.com/cb", "https://b.example.com/cb"},
		ExpectedRedirectURIs: loadedByBoth})
	defer func() { _ = first.Body.Close() }()
	require.Equal(t, http.StatusOK, first.StatusCode)

	second := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateClientRedirectURIsRequest{
		RedirectURIs:         []string{"https://c.example.com/cb"},
		ExpectedRedirectURIs: loadedByBoth})
	defer func() { _ = second.Body.Close() }()
	assert.Equal(t, http.StatusConflict, second.StatusCode)
	var body map[string]interface{}
	require.NoError(t, json.NewDecoder(second.Body).Decode(&body))
	assert.Equal(t, "CONCURRENT_UPDATE", body["error_code"])
	assert.Contains(t, body["error_description"], "reload it")

	assert.ElementsMatch(t, []string{"https://a.example.com/cb", "https://b.example.com/cb"},
		readRedirectURIs(t, accessToken, client.Id), "the refused save wrote nothing")
}

func TestAPIClientRedirectURIsPut_Success_AddRemoveAndTrim(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Create a confidential client with auth code enabled
	clientSecret := stringutil.GenerateSecurityRandomString(60)
	enc, err := encryption.EncryptData(clientSecret)
	assert.NoError(t, err)
	client := &models.Client{
		ClientIdentifier:         "redir-succ-" + strings.ToLower(fake.LetterN(8)),
		Enabled:                  true,
		ConsentRequired:          false,
		IsPublic:                 false,
		ClientSecretEncrypted:    enc,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: false,
	}
	err = database.CreateClient(context.Background(), nil, client)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(context.Background(), nil, client.Id) }()

	// Seed existing redirect URIs
	uriA := "https://a.example.com/callback"
	uriB := "https://b.example.com/callback"
	err = database.CreateRedirectURI(context.Background(), nil, &models.RedirectURI{ClientId: client.Id, URI: uriA})
	assert.NoError(t, err)
	err = database.CreateRedirectURI(context.Background(), nil, &models.RedirectURI{ClientId: client.Id, URI: uriB})
	assert.NoError(t, err)

	// Desired: keep A (with spaces to test trimming), remove B, add C
	uriC := "https://c.example.com/newcb"
	reqBody := api.UpdateClientRedirectURIsRequest{RedirectURIs: []string{"  " + uriA + "  ", uriC},
		ExpectedRedirectURIs: readRedirectURIs(t, accessToken, client.Id)}

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
	refreshed, err := database.GetClientById(context.Background(), nil, client.Id)
	assert.NoError(t, err)
	err = database.ClientLoadRedirectURIs(context.Background(), nil, refreshed)
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
		ClientIdentifier:         "redir-disabled-" + strings.ToLower(fake.LetterN(8)),
		Enabled:                  true,
		ConsentRequired:          false,
		IsPublic:                 true,
		AuthorizationCodeEnabled: false,
		ImplicitGrantEnabled:     &implicitDisabled,
		ClientCredentialsEnabled: false,
	}
	err := database.CreateClient(context.Background(), nil, client)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(context.Background(), nil, client.Id) }()

	reqBody := api.UpdateClientRedirectURIsRequest{RedirectURIs: []string{"https://example.com/cb"},
		ExpectedRedirectURIs: readRedirectURIs(t, accessToken, client.Id)}
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
		ClientIdentifier:         "redir-implicit-" + strings.ToLower(fake.LetterN(8)),
		Enabled:                  true,
		ConsentRequired:          false,
		IsPublic:                 true,
		AuthorizationCodeEnabled: false,
		ImplicitGrantEnabled:     &implicitEnabled,
		ClientCredentialsEnabled: false,
	}
	err := database.CreateClient(context.Background(), nil, client)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(context.Background(), nil, client.Id) }()

	uri := "https://implicit-app.example.com/cb"
	reqBody := api.UpdateClientRedirectURIsRequest{RedirectURIs: []string{uri},
		ExpectedRedirectURIs: readRedirectURIs(t, accessToken, client.Id)}
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
	reqBody := api.UpdateClientRedirectURIsRequest{RedirectURIs: []string{"https://example.com/callback", "https://localhost:3000/cb"},
		ExpectedRedirectURIs: readRedirectURIs(t, accessToken, sysId)}
	resp2 := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)
}

func TestAPIClientRedirectURIsPut_DuplicateAndInvalidURLs(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Auth code enabled client
	client := &models.Client{
		ClientIdentifier:         "redir-vali-" + strings.ToLower(fake.LetterN(8)),
		Enabled:                  true,
		ConsentRequired:          false,
		IsPublic:                 true,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: false,
	}
	err := database.CreateClient(context.Background(), nil, client)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(context.Background(), nil, client.Id) }()

	baseURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/redirect-uris"

	// Duplicate
	loaded := readRedirectURIs(t, accessToken, client.Id)
	reqDup := api.UpdateClientRedirectURIsRequest{RedirectURIs: []string{"https://dup.example/cb", "https://dup.example/cb"}, ExpectedRedirectURIs: loaded}
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
	reqInv := api.UpdateClientRedirectURIsRequest{RedirectURIs: []string{"not-a-url"}, ExpectedRedirectURIs: loaded}
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
	reqEmpty := api.UpdateClientRedirectURIsRequest{RedirectURIs: []string{"  "}, ExpectedRedirectURIs: loaded}
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
			req := api.UpdateClientRedirectURIsRequest{RedirectURIs: []string{tc.uri}, ExpectedRedirectURIs: loaded}
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
	}, ExpectedRedirectURIs: loaded}
	respOK := makeAPIRequest(t, "PUT", baseURL, accessToken, reqOK)
	defer func() { _ = respOK.Body.Close() }()
	assert.Equal(t, http.StatusOK, respOK.StatusCode, "valid redirect URIs must still be accepted")
}

func TestAPIClientRedirectURIsPut_NotFound_InvalidId_InvalidBody_Unauthorized(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Not found
	urlNF := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/999999/redirect-uris"
	resp := makeAPIRequest(t, "PUT", urlNF, accessToken, api.UpdateClientRedirectURIsRequest{RedirectURIs: []string{"https://example.com/cb"}, ExpectedRedirectURIs: []string{}})
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
	resp2 := makeAPIRequest(t, "PUT", urlBad, accessToken, api.UpdateClientRedirectURIsRequest{RedirectURIs: []string{"https://example.com/cb"}, ExpectedRedirectURIs: []string{}})
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
		ClientIdentifier:         "redir-bad-body-" + strings.ToLower(fake.LetterN(8)),
		Enabled:                  true,
		ConsentRequired:          false,
		IsPublic:                 true,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: false,
	}
	err := database.CreateClient(context.Background(), nil, client2)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(context.Background(), nil, client2.Id) }()

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
	// A valid token whose only scope is one no route grants, so the route answers 403
	accessToken := createClientCredentialsTokenWithoutRouteScope(t)

	// Create a target client with auth code enabled
	target := &models.Client{
		ClientIdentifier:         "redir-target-" + strings.ToLower(fake.LetterN(8)),
		Enabled:                  true,
		IsPublic:                 true,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: false,
	}
	err := database.CreateClient(context.Background(), nil, target)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(context.Background(), nil, target.Id) }()

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(target.Id, 10) + "/redirect-uris"
	reqBody := api.UpdateClientRedirectURIsRequest{RedirectURIs: []string{"https://example.com/cb"}, ExpectedRedirectURIs: []string{}}
	resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}
