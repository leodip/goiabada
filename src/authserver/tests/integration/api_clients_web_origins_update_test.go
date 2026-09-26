package integrationtests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
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

// PUT /api/v1/admin/clients/{id}/web-origins

func TestAPIClientWebOriginsPut_Success_AddRemoveAndNormalize(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Create a confidential client with auth code enabled
	clientSecret := stringutil.GenerateSecurityRandomString(60)
	enc, err := encryption.EncryptData(clientSecret)
	assert.NoError(t, err)
	client := &models.Client{
		ClientIdentifier:         "weborig-succ-" + strings.ToLower(fake.LetterN(8)),
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

	// Seed existing web origins
	originA := "https://a.example.com"
	originB := "https://b.example.com"
	err = database.CreateWebOrigin(context.Background(), nil, &models.WebOrigin{ClientId: client.Id, Origin: originA})
	assert.NoError(t, err)
	err = database.CreateWebOrigin(context.Background(), nil, &models.WebOrigin{ClientId: client.Id, Origin: originB})
	assert.NoError(t, err)

	// Desired: keep A (with spaces and uppercase to test trimming+lowercasing), remove B, add C
	originAMixed := "  HTTPS://A.EXAMPLE.COM  "
	originC := "https://c.example.com"
	reqBody := api.UpdateClientWebOriginsRequest{WebOrigins: []string{originAMixed, originC},
		ExpectedWebOrigins: getClientWebOrigins(t, accessToken, client.Id)}

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
	refreshed, err := database.GetClientById(context.Background(), nil, client.Id)
	assert.NoError(t, err)
	err = database.ClientLoadWebOrigins(context.Background(), nil, refreshed)
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
		ClientIdentifier:         "weborig-noauthcode-" + strings.ToLower(fake.LetterN(8)),
		Enabled:                  true,
		ConsentRequired:          false,
		IsPublic:                 true,
		AuthorizationCodeEnabled: false,
		ClientCredentialsEnabled: false,
	}
	err := database.CreateClient(context.Background(), nil, client)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(context.Background(), nil, client.Id) }()

	origin := "https://spa-" + strings.ToLower(fake.LetterN(8)) + ".example.com"
	reqBody := api.UpdateClientWebOriginsRequest{WebOrigins: []string{origin}, ExpectedWebOrigins: getClientWebOrigins(t, accessToken, client.Id)}
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
	refreshed, err := database.GetClientById(context.Background(), nil, client.Id)
	assert.NoError(t, err)
	err = database.ClientLoadWebOrigins(context.Background(), nil, refreshed)
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
		ClientIdentifier:         "weborig-canon-" + strings.ToLower(fake.LetterN(8)),
		Enabled:                  true,
		ConsentRequired:          false,
		IsPublic:                 true,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: false,
	}
	err := database.CreateClient(context.Background(), nil, client)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(context.Background(), nil, client.Id) }()

	host := "canon-" + strings.ToLower(fake.LetterN(8)) + ".example.com"
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
			reqBody := api.UpdateClientWebOriginsRequest{WebOrigins: []string{tc.sent}, ExpectedWebOrigins: getClientWebOrigins(t, accessToken, client.Id)}
			resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
			defer func() { _ = resp.Body.Close() }()
			assert.Equal(t, http.StatusOK, resp.StatusCode)

			refreshed, err := database.GetClientById(context.Background(), nil, client.Id)
			assert.NoError(t, err)
			err = database.ClientLoadWebOrigins(context.Background(), nil, refreshed)
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
	reqBody := api.UpdateClientWebOriginsRequest{WebOrigins: []string{"https://example.com", "https://localhost:3000"},
		ExpectedWebOrigins: getClientWebOrigins(t, accessToken, sysId)}
	resp2 := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)
}

func TestAPIClientWebOriginsPut_ValidationErrors(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Create a client with auth code enabled
	client := &models.Client{
		ClientIdentifier:         "weborig-valid-" + strings.ToLower(fake.LetterN(8)),
		Enabled:                  true,
		ConsentRequired:          false,
		IsPublic:                 true,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: false,
	}
	err := database.CreateClient(context.Background(), nil, client)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(context.Background(), nil, client.Id) }()

	baseURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/web-origins"
	loaded := getClientWebOrigins(t, accessToken, client.Id)

	// Sub-test: Empty web origin value
	t.Run("EmptyOrigin", func(t *testing.T) {
		reqBody := api.UpdateClientWebOriginsRequest{WebOrigins: []string{"https://example.com", "  "}, ExpectedWebOrigins: loaded}
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
			reqBody := api.UpdateClientWebOriginsRequest{WebOrigins: []string{sent}, ExpectedWebOrigins: loaded}
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
		reqBody := api.UpdateClientWebOriginsRequest{WebOrigins: []string{"https://example.com", "HTTPS://EXAMPLE.COM/"}, ExpectedWebOrigins: loaded}
		resp := makeAPIRequest(t, "PUT", baseURL, accessToken, reqBody)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		var errResp api.ErrorResponse
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		assert.Equal(t, "Duplicate web origins are not allowed", errResp.ErrorDescription)
	})
}

// webOriginOfLength is a canonical origin of exactly n bytes: "https://" plus a host of
// 63-character labels and one shorter label, plus ":65535".
func webOriginOfLength(t *testing.T, n int) string {
	t.Helper()
	const prefix, port = "https://", ":65535"
	hostLen := n - len(prefix) - len(port)
	var labels []string
	for hostLen > 63 {
		labels = append(labels, strings.Repeat("a", 63))
		hostLen -= 64 // the label and the dot after it
	}
	labels = append(labels, strings.Repeat("b", hostLen))
	origin := prefix + strings.Join(labels, ".") + port
	assert.Len(t, origin, n)
	return origin
}

// getClientWebOrigins reads a client's web origins back through the admin API.
func getClientWebOrigins(t *testing.T, accessToken string, clientId int64) []string {
	t.Helper()
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(clientId, 10)
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var body api.GetClientResponse
	assert.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	origins := []string{}
	for _, wo := range body.Client.WebOrigins {
		origins = append(origins, wo.Origin)
	}
	return origins
}

// The web-origin bound is the column's width on every engine: the longest standards-valid origin,
// 267 bytes, is saved and reads back, and one byte more is refused with nothing written. On SQLite,
// which this tier runs locally, the column has no width, so the 268-byte refusal is the handler's
// own; the four-engine run is what shows the 267-byte value fits the widened column (#428).
func TestAPIClientWebOriginsPut_TheBoundIsTheLongestStandardOrigin(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	client := &models.Client{
		ClientIdentifier:         "weborig-bound-" + strings.ToLower(fake.LetterN(8)),
		Enabled:                  true,
		IsPublic:                 true,
		AuthorizationCodeEnabled: true,
	}
	err := database.CreateClient(context.Background(), nil, client)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(context.Background(), nil, client.Id) }()

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/web-origins"

	atTheBound := webOriginOfLength(t, 267)
	resp := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateClientWebOriginsRequest{WebOrigins: []string{atTheBound},
		ExpectedWebOrigins: getClientWebOrigins(t, accessToken, client.Id)})
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "a 267-byte origin is the longest standards-valid one and must be admitted")
	assert.Equal(t, []string{atTheBound}, getClientWebOrigins(t, accessToken, client.Id))

	overTheBound := webOriginOfLength(t, 268)
	resp = makeAPIRequest(t, "PUT", url, accessToken, api.UpdateClientWebOriginsRequest{WebOrigins: []string{overTheBound},
		ExpectedWebOrigins: getClientWebOrigins(t, accessToken, client.Id)})
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var errResp api.ErrorResponse
	assert.NoError(t, json.NewDecoder(resp.Body).Decode(&errResp))
	assert.Equal(t, "VALIDATION_ERROR", errResp.ErrorCode)
	assert.Contains(t, errResp.ErrorDescription, "too long")
	assert.Equal(t, []string{atTheBound}, getClientWebOrigins(t, accessToken, client.Id),
		"a refused save must leave the stored list as it was")
}

// newWebOriginsClient creates a client for a web-origins save and removes it when the test ends.
func newWebOriginsClient(t *testing.T, prefix string) *models.Client {
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

// The list as loaded is required: absent or null is refused before anything is written, naming the
// field, so no caller can save a whole list without saying what it replaces (#428).
func TestAPIClientWebOriginsPut_TheLoadedListIsRequired(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	client := newWebOriginsClient(t, "weborig-expected-")
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/web-origins"

	bodies := map[string]interface{}{
		"absent": map[string]interface{}{"webOrigins": []string{"https://a.example.com"}},
		"null":   map[string]interface{}{"webOrigins": []string{"https://a.example.com"}, "expectedWebOrigins": nil},
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			resp := makeAPIRequest(t, "PUT", url, accessToken, body)
			defer func() { _ = resp.Body.Close() }()
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			var got map[string]interface{}
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
			assert.Equal(t, "VALIDATION_ERROR", got["error_code"])
			assert.Contains(t, got["error_description"], "expectedWebOrigins is required")
			assert.Empty(t, getClientWebOrigins(t, accessToken, client.Id))
		})
	}
}

// A save from an outdated page: two saves both read the same list, the first commits, and the
// second, still carrying the list as it was before the first, is refused 409 CONCURRENT_UPDATE with
// nothing written, where it used to replace the first save's list with its own and undo a change its
// author never saw (#428). The loaded list is compared in canonical form, so the first save's
// copy, spelled as a browser bar would give it, still matches.
func TestAPIClientWebOriginsPut_AnOutdatedLoadedListIsRefused(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	client := newWebOriginsClient(t, "weborig-outdated-")
	require.NoError(t, database.CreateWebOrigin(context.Background(), nil,
		&models.WebOrigin{ClientId: client.Id, Origin: "https://a.example.com"}))
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/web-origins"

	loadedByBoth := getClientWebOrigins(t, accessToken, client.Id)

	first := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateClientWebOriginsRequest{
		WebOrigins:         []string{"https://a.example.com", "https://b.example.com"},
		ExpectedWebOrigins: []string{"HTTPS://A.Example.com/"}})
	defer func() { _ = first.Body.Close() }()
	require.Equal(t, http.StatusOK, first.StatusCode)

	second := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateClientWebOriginsRequest{
		WebOrigins:         []string{"https://c.example.com"},
		ExpectedWebOrigins: loadedByBoth})
	defer func() { _ = second.Body.Close() }()
	assert.Equal(t, http.StatusConflict, second.StatusCode)
	var body map[string]interface{}
	require.NoError(t, json.NewDecoder(second.Body).Decode(&body))
	assert.Equal(t, "CONCURRENT_UPDATE", body["error_code"])
	assert.Contains(t, body["error_description"], "reload it")

	assert.ElementsMatch(t, []string{"https://a.example.com", "https://b.example.com"},
		getClientWebOrigins(t, accessToken, client.Id), "the refused save wrote nothing")
}

func TestAPIClientWebOriginsPut_NotFound_InvalidId_InvalidBody_Unauthorized(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Not found
	urlNF := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/999999/web-origins"
	resp := makeAPIRequest(t, "PUT", urlNF, accessToken, api.UpdateClientWebOriginsRequest{WebOrigins: []string{"https://example.com"}, ExpectedWebOrigins: []string{}})
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
	resp2 := makeAPIRequest(t, "PUT", urlBad, accessToken, api.UpdateClientWebOriginsRequest{WebOrigins: []string{"https://example.com"}, ExpectedWebOrigins: []string{}})
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
		ClientIdentifier:         "weborig-bad-body-" + strings.ToLower(fake.LetterN(8)),
		Enabled:                  true,
		ConsentRequired:          false,
		IsPublic:                 true,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: false,
	}
	err := database.CreateClient(context.Background(), nil, client2)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(context.Background(), nil, client2.Id) }()

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
		ClientIdentifier:         "weborig-inscope-" + strings.ToLower(fake.LetterN(8)),
		Enabled:                  true,
		ClientCredentialsEnabled: true,
		IsPublic:                 false,
		ClientSecretEncrypted:    enc,
	}
	err = database.CreateClient(context.Background(), nil, client)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(context.Background(), nil, client.Id) }()

	// Grant auth-server:userinfo permission only
	authRes, err := database.GetResourceByResourceIdentifier(context.Background(), nil, constants.AuthServerResourceIdentifier)
	assert.NoError(t, err)
	perms, err := database.GetPermissionsByResourceId(context.Background(), nil, authRes.Id)
	assert.NoError(t, err)
	var userinfoPerm *models.Permission
	for i := range perms {
		if perms[i].PermissionIdentifier == constants.UserinfoPermissionIdentifier {
			userinfoPerm = &perms[i]
			break
		}
	}
	assert.NotNil(t, userinfoPerm)
	err = database.CreateClientPermission(context.Background(), nil, &models.ClientPermission{ClientId: client.Id, PermissionId: userinfoPerm.Id})
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
		ClientIdentifier:         "weborig-target-" + strings.ToLower(fake.LetterN(8)),
		Enabled:                  true,
		IsPublic:                 true,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: false,
	}
	err = database.CreateClient(context.Background(), nil, target)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(context.Background(), nil, target.Id) }()

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(target.Id, 10) + "/web-origins"
	reqBody := api.UpdateClientWebOriginsRequest{WebOrigins: []string{"https://example.com"}, ExpectedWebOrigins: []string{}}
	resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}
