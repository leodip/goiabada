package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// PUT /api/v1/admin/clients/{id}/post-logout-redirect-uris saves a client's sign-out redirect URIs
// under the rules of the redirect URI save, and every client the admin API answers carries the list
// as postLogoutRedirectURIs (#147 decisions 4 and 5).

// readPostLogoutRedirectURIs is the client's sign-out list as GET /clients/{id} reads it, which is
// what a save sends as expectedPostLogoutRedirectURIs. Never nil, so an empty list goes on the wire
// as [].
func readPostLogoutRedirectURIs(t *testing.T, accessToken string, clientId int64) []string {
	t.Helper()
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(clientId, 10)
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var got api.GetClientResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	require.NotNil(t, got.Client.PostLogoutRedirectURIs, "the detail loads the list, so it reads [] rather than null when empty")
	uris := make([]string, 0, len(got.Client.PostLogoutRedirectURIs))
	for _, row := range got.Client.PostLogoutRedirectURIs {
		uris = append(uris, row.URI)
	}
	return uris
}

// storedPostLogoutRedirectURIs is the client's sign-out list as the database holds it, one entry
// per row, so a duplicate shows twice.
func storedPostLogoutRedirectURIs(t *testing.T, clientId int64) []string {
	t.Helper()
	rows, err := database.GetPostLogoutRedirectURIsByClientId(context.Background(), nil, clientId)
	require.NoError(t, err)
	uris := make([]string, 0, len(rows))
	for _, row := range rows {
		uris = append(uris, row.URI)
	}
	return uris
}

// postLogoutRedirectURIsURL is the save's address for a client.
func postLogoutRedirectURIsURL(clientId int64) string {
	return appConfig.AuthServer.BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(clientId, 10) + "/post-logout-redirect-uris"
}

// savePostLogoutRedirectURIs sends one save and decodes the error envelope when there is one.
func savePostLogoutRedirectURIs(t *testing.T, accessToken string, clientId int64, wanted, expected []string) (int, map[string]any) {
	t.Helper()
	resp := makeAPIRequest(t, "PUT", postLogoutRedirectURIsURL(clientId), accessToken, api.UpdateClientPostLogoutRedirectURIsRequest{
		PostLogoutRedirectURIs: wanted, ExpectedPostLogoutRedirectURIs: expected})
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	return resp.StatusCode, body
}

// The save adds, removes and trims, answers the whole client with its new list, and leaves the
// client's redirect URIs exactly as they were: the two lists are kept apart (#147 decision 2).
func TestAPIClientPostLogoutRedirectURIsPut_SavesTheListAndLeavesTheRedirectURIsAlone(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	client := newRedirectURIsClient(t, "signout-save-")
	callback := "https://app.example.com/callback"
	require.NoError(t, database.CreateRedirectURI(context.Background(), nil, &record.RedirectURI{ClientId: client.Id, URI: callback}))
	for _, uri := range []string{"https://app.example.com/bye", "https://app.example.com/retired"} {
		require.NoError(t, database.CreatePostLogoutRedirectURI(context.Background(), nil,
			&record.PostLogoutRedirectURI{ClientId: client.Id, URI: uri}))
	}
	loaded := readPostLogoutRedirectURIs(t, accessToken, client.Id)
	assert.ElementsMatch(t, []string{"https://app.example.com/bye", "https://app.example.com/retired"}, loaded)

	resp := makeAPIRequest(t, "PUT", postLogoutRedirectURIsURL(client.Id), accessToken, api.UpdateClientPostLogoutRedirectURIsRequest{
		PostLogoutRedirectURIs:         []string{"  https://app.example.com/bye  ", "https://app.example.com/signed-out?state=fixed"},
		ExpectedPostLogoutRedirectURIs: loaded,
	})
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var answer api.UpdateClientResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&answer))
	assert.Equal(t, client.Id, answer.Client.Id)
	answered := make([]string, 0, len(answer.Client.PostLogoutRedirectURIs))
	for _, row := range answer.Client.PostLogoutRedirectURIs {
		answered = append(answered, row.URI)
		assert.Equal(t, client.Id, row.ClientId)
		assert.NotZero(t, row.Id)
		assert.NotNil(t, row.CreatedAt)
	}
	assert.ElementsMatch(t, []string{"https://app.example.com/bye", "https://app.example.com/signed-out?state=fixed"}, answered)
	require.Len(t, answer.Client.RedirectURIs, 1)
	assert.Equal(t, callback, answer.Client.RedirectURIs[0].URI)

	assert.ElementsMatch(t, []string{"https://app.example.com/bye", "https://app.example.com/signed-out?state=fixed"},
		storedPostLogoutRedirectURIs(t, client.Id))
	assert.Equal(t, []string{callback}, readRedirectURIs(t, accessToken, client.Id), "the redirect URIs are untouched")
}

// The list reaches the client listing as well as the detail.
func TestAPIClientPostLogoutRedirectURIsPut_TheListingCarriesTheList(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	client := newRedirectURIsClient(t, "signout-list-")
	status, body := savePostLogoutRedirectURIs(t, accessToken, client.Id, []string{"https://listed.example.com/bye"}, []string{})
	require.Equal(t, http.StatusOK, status, body)

	resp := makeAPIRequest(t, "GET", appConfig.AuthServer.BaseURL+"/api/v1/admin/clients", accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var listing api.GetClientsResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&listing))
	for _, listed := range listing.Clients {
		if listed.Id != client.Id {
			continue
		}
		require.Len(t, listed.PostLogoutRedirectURIs, 1)
		assert.Equal(t, "https://listed.example.com/bye", listed.PostLogoutRedirectURIs[0].URI)
		return
	}
	t.Fatalf("client %d is not in the listing", client.Id)
}

// The bounds are the redirect URI save's, counted apart from the redirect URIs: a client already
// holding 60 redirect URIs saves 60 sign-out redirect URIs of 2048 bytes each, and one more or one
// byte more is refused with the stored list left as it was (#147 decision 4).
func TestAPIClientPostLogoutRedirectURIsPut_TheBoundsAt60And2048CountedApart(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	client := newRedirectURIsClient(t, "signout-bounds-")
	for i := 0; i < 60; i++ {
		require.NoError(t, database.CreateRedirectURI(context.Background(), nil,
			&record.RedirectURI{ClientId: client.Id, URI: fmt.Sprintf("https://cb%02d.example.com/callback", i)}))
	}

	sixty := make([]string, 60)
	for i := range sixty {
		sixty[i] = redirectURIOfBytes(t, 2048, fmt.Sprintf("bye%02d", i))
	}
	status, body := savePostLogoutRedirectURIs(t, accessToken, client.Id, sixty, []string{})
	require.Equal(t, http.StatusOK, status, body)
	assert.ElementsMatch(t, sixty, readPostLogoutRedirectURIs(t, accessToken, client.Id))

	refusals := []struct {
		name            string
		uris            []string
		wantDescription string
	}{
		{name: "61 sign-out redirect URIs", uris: append(append([]string{}, sixty...), "https://one-more.example.com/bye"),
			wantDescription: "A client can have at most 60 sign-out redirect URIs, and this list has 61."},
		{name: "a URI of 2049 bytes", uris: []string{redirectURIOfBytes(t, 2049, "long")},
			wantDescription: "Sign-out redirect URI is too long (2049 bytes, the maximum is 2048)"},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			status, body := savePostLogoutRedirectURIs(t, accessToken, client.Id, tc.uris, sixty)
			assert.Equal(t, http.StatusBadRequest, status)
			assert.Regexp(t, `^handler\.client_post_logout_redirect_uris\.[a-z_]+$`, body["error_code"])
			assert.Contains(t, body["error_description"], tc.wantDescription)
			assert.ElementsMatch(t, sixty, readPostLogoutRedirectURIs(t, accessToken, client.Id), "a refused save changes nothing")
		})
	}
}

// The list as loaded is required: absent or null is refused before anything is written, naming the
// field.
func TestAPIClientPostLogoutRedirectURIsPut_TheLoadedListIsRequired(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	client := newRedirectURIsClient(t, "signout-expected-")

	bodies := map[string]any{
		"absent": map[string]any{"postLogoutRedirectURIs": []string{"https://a.example.com/bye"}},
		"null":   map[string]any{"postLogoutRedirectURIs": []string{"https://a.example.com/bye"}, "expectedPostLogoutRedirectURIs": nil},
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			resp := makeAPIRequest(t, "PUT", postLogoutRedirectURIsURL(client.Id), accessToken, body)
			defer func() { _ = resp.Body.Close() }()
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			var got map[string]any
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
			assert.Equal(t, "VALIDATION_ERROR", got["error_code"])
			assert.Equal(t, "expectedPostLogoutRedirectURIs is required: send the sign-out redirect URIs as you last read them, or [] if there were none.",
				got["error_description"])
			assert.Empty(t, storedPostLogoutRedirectURIs(t, client.Id))
		})
	}
}

// Two saves both read the same list, the first commits, and the second, still carrying the list as
// it was before the first, is refused 409 CONCURRENT_UPDATE with nothing written.
func TestAPIClientPostLogoutRedirectURIsPut_AnOutdatedLoadedListIsRefused(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	client := newRedirectURIsClient(t, "signout-outdated-")
	require.NoError(t, database.CreatePostLogoutRedirectURI(context.Background(), nil,
		&record.PostLogoutRedirectURI{ClientId: client.Id, URI: "https://a.example.com/bye"}))

	loadedByBoth := readPostLogoutRedirectURIs(t, accessToken, client.Id)

	status, body := savePostLogoutRedirectURIs(t, accessToken, client.Id,
		[]string{"https://a.example.com/bye", "https://b.example.com/bye"}, loadedByBoth)
	require.Equal(t, http.StatusOK, status, body)

	status, body = savePostLogoutRedirectURIs(t, accessToken, client.Id, []string{"https://c.example.com/bye"}, loadedByBoth)
	assert.Equal(t, http.StatusConflict, status)
	assert.Equal(t, "CONCURRENT_UPDATE", body["error_code"])
	assert.Contains(t, body["error_description"], "reload it")

	assert.ElementsMatch(t, []string{"https://a.example.com/bye", "https://b.example.com/bye"},
		storedPostLogoutRedirectURIs(t, client.Id), "the refused save wrote nothing")
}

// The gate asks whether the client signs users in through a browser at all: a client with neither
// redirect-based flow is refused, an implicit-only one is not. ImplicitGrantEnabled is set
// explicitly, since nil would resolve against a global setting other tests change.
func TestAPIClientPostLogoutRedirectURIsPut_TheRedirectFlowGate(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	newClient := func(t *testing.T, prefix string, implicit bool) *record.Client {
		client := &record.Client{
			ClientIdentifier:         prefix + strings.ToLower(fake.LetterN(8)),
			Enabled:                  true,
			IsPublic:                 true,
			AuthorizationCodeEnabled: false,
			ImplicitGrantEnabled:     &implicit,
		}
		require.NoError(t, database.CreateClient(context.Background(), nil, client))
		t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })
		return client
	}

	t.Run("neither flow", func(t *testing.T) {
		client := newClient(t, "signout-noflow-", false)
		status, body := savePostLogoutRedirectURIs(t, accessToken, client.Id, []string{"https://app.example.com/bye"}, []string{})
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, "handler.client_post_logout_redirect_uris.no_redirect_flow", body["error_code"])
		assert.Equal(t, "Sign-out redirect URIs are used by clients that sign users in through the authorization code with PKCE flow or the implicit flow, and neither is enabled for this client.",
			body["error_description"])
		assert.Empty(t, storedPostLogoutRedirectURIs(t, client.Id))
	})

	t.Run("the implicit flow alone", func(t *testing.T) {
		client := newClient(t, "signout-implicit-", true)
		status, body := savePostLogoutRedirectURIs(t, accessToken, client.Id, []string{"https://app.example.com/bye"}, []string{})
		require.Equal(t, http.StatusOK, status, body)
		assert.Equal(t, []string{"https://app.example.com/bye"}, storedPostLogoutRedirectURIs(t, client.Id))
	})
}

// Each entry rule refuses its shape with the sign-out list's own sentence, and the shapes the rules
// admit save together: https with a query carrying state, loopback http on each spelling and any
// port, and a custom scheme (#147 decision 4).
func TestAPIClientPostLogoutRedirectURIsPut_TheEntryRules(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	client := newRedirectURIsClient(t, "signout-rules-")

	refused := []struct {
		uris            []string
		wantCode        string
		wantDescription string
	}{
		{[]string{"https://dup.example/bye", " https://dup.example/bye "}, "duplicate", "Duplicate sign-out redirect URIs are not allowed"},
		{[]string{"  "}, "empty", "Sign-out redirect URI cannot be empty"},
		{[]string{"not-a-url"}, "invalid", "Invalid sign-out redirect URI: not-a-url"},
		{[]string{"//evil.example/bye"}, "not_absolute", "Sign-out redirect URI must be an absolute URI (a scheme is required, a fragment is not permitted, percent-escapes must be well formed, and an http or https URI must name a host): //evil.example/bye"},
		{[]string{"https:///evil.example/bye"}, "not_absolute", "Sign-out redirect URI must be an absolute URI (a scheme is required, a fragment is not permitted, percent-escapes must be well formed, and an http or https URI must name a host): https:///evil.example/bye"},
		{[]string{"https://app.example/bye#done"}, "not_absolute", "Sign-out redirect URI must be an absolute URI (a scheme is required, a fragment is not permitted, percent-escapes must be well formed, and an http or https URI must name a host): https://app.example/bye#done"},
		{[]string{"com.example.app:%zz"}, "not_absolute", "Sign-out redirect URI must be an absolute URI (a scheme is required, a fragment is not permitted, percent-escapes must be well formed, and an http or https URI must name a host): com.example.app:%zz"},
		{[]string{"http://app.example.com/bye"}, "insecure_http", "Sign-out redirect URI must not use plain http on a host other than the loopback interface (127.0.0.1, [::1] or localhost): http://app.example.com/bye"},
		{[]string{"http://192.168.1.50/bye"}, "insecure_http", "Sign-out redirect URI must not use plain http on a host other than the loopback interface (127.0.0.1, [::1] or localhost): http://192.168.1.50/bye"},
		{[]string{"HTTP://app.example.com/bye"}, "insecure_http", "Sign-out redirect URI must not use plain http on a host other than the loopback interface (127.0.0.1, [::1] or localhost): HTTP://app.example.com/bye"},
	}
	for _, tc := range refused {
		t.Run(tc.uris[0], func(t *testing.T) {
			status, body := savePostLogoutRedirectURIs(t, accessToken, client.Id, tc.uris, []string{})
			assert.Equal(t, http.StatusBadRequest, status)
			assert.Equal(t, "handler.client_post_logout_redirect_uris."+tc.wantCode, body["error_code"])
			assert.Equal(t, tc.wantDescription, body["error_description"])
			assert.Empty(t, storedPostLogoutRedirectURIs(t, client.Id))
		})
	}

	admitted := []string{
		"https://app.example.com/bye?state=fixed",
		"http://127.0.0.1:8765/bye",
		"http://[::1]/bye",
		"http://localhost:3000/bye",
		"com.example.app:/signed-out",
	}
	status, body := savePostLogoutRedirectURIs(t, accessToken, client.Id, admitted, []string{})
	require.Equal(t, http.StatusOK, status, body)
	assert.ElementsMatch(t, admitted, storedPostLogoutRedirectURIs(t, client.Id))
}

// A plain-http URI stored before the rule still saves when the save carries it back; adding a second
// is refused by name, and naming one as loaded that is not stored is answered 409 with nothing
// written.
func TestAPIClientPostLogoutRedirectURIsPut_AStoredPlainHTTPURIDoesNotBlockTheSave(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	client := newRedirectURIsClient(t, "signout-legacy-http-")
	legacy := "http://intranet.example.com/bye"
	for _, uri := range []string{legacy, "https://retired.example.com/bye"} {
		require.NoError(t, database.CreatePostLogoutRedirectURI(context.Background(), nil,
			&record.PostLogoutRedirectURI{ClientId: client.Id, URI: uri}))
	}
	loaded := readPostLogoutRedirectURIs(t, accessToken, client.Id)

	kept := []string{legacy, "https://replacement.example.com/bye"}
	status, body := savePostLogoutRedirectURIs(t, accessToken, client.Id, kept, loaded)
	require.Equal(t, http.StatusOK, status, body)
	assert.ElementsMatch(t, kept, storedPostLogoutRedirectURIs(t, client.Id))

	added := "http://other.example.com/bye"
	status, body = savePostLogoutRedirectURIs(t, accessToken, client.Id, append([]string{added}, kept...), kept)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "Sign-out redirect URI must not use plain http on a host other than the loopback interface (127.0.0.1, [::1] or localhost): "+added,
		body["error_description"])

	status, body = savePostLogoutRedirectURIs(t, accessToken, client.Id, append([]string{added}, kept...), append([]string{added}, kept...))
	assert.Equal(t, http.StatusConflict, status)
	assert.Equal(t, "CONCURRENT_UPDATE", body["error_code"])
	assert.ElementsMatch(t, kept, storedPostLogoutRedirectURIs(t, client.Id), "a refused save writes nothing")
}

// A committed save leaves one updated_post_logout_redirect_uris row naming the client and the caller;
// a refused one leaves none.
func TestAPIClientPostLogoutRedirectURIsPut_TheSaveIsAudited(t *testing.T) {
	requireDatabaseAuditLogs(t)
	accessToken, caller := createAdminClientWithToken(t)
	client := newRedirectURIsClient(t, "signout-audit-")

	resp, requestId := sendAdmin(t, accessToken, http.MethodPut, fmt.Sprintf("/api/v1/admin/clients/%d/post-logout-redirect-uris", client.Id),
		map[string]any{"postLogoutRedirectURIs": []string{"https://app.example.com/bye"}, "expectedPostLogoutRedirectURIs": []string{}})
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, []map[string]any{{"client_id": float64(client.Id), "logged_in_user": caller.ClientIdentifier}},
		auditRows(t, accessToken, "updated_post_logout_redirect_uris", requestId))

	resp, requestId = sendAdmin(t, accessToken, http.MethodPut, fmt.Sprintf("/api/v1/admin/clients/%d/post-logout-redirect-uris", client.Id),
		map[string]any{"postLogoutRedirectURIs": []string{"http://app.example.com/bye"}, "expectedPostLogoutRedirectURIs": []string{"https://app.example.com/bye"}})
	_ = resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Empty(t, auditRows(t, accessToken, "updated_post_logout_redirect_uris", requestId))
}

// The request's own refusals, and the route's scope.
func TestAPIClientPostLogoutRedirectURIsPut_NotFound_InvalidId_InvalidBody_Unauthorized_InsufficientScope(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	status, body := savePostLogoutRedirectURIs(t, accessToken, 999999, []string{"https://example.com/bye"}, []string{})
	assert.Equal(t, http.StatusNotFound, status)
	assert.Equal(t, "Client not found", body["error_description"])

	resp := makeAPIRequest(t, "PUT", appConfig.AuthServer.BaseURL+"/api/v1/admin/clients/abc/post-logout-redirect-uris", accessToken,
		api.UpdateClientPostLogoutRedirectURIsRequest{PostLogoutRedirectURIs: []string{}, ExpectedPostLogoutRedirectURIs: []string{}})
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var bad map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&bad))
	assert.Equal(t, "Invalid client ID", bad["error_description"])

	client := newRedirectURIsClient(t, "signout-request-")
	httpClient := createHttpClient(t)

	req, err := http.NewRequest("PUT", postLogoutRedirectURIsURL(client.Id), nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	emptyBody, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = emptyBody.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, emptyBody.StatusCode)
	var invalid map[string]any
	require.NoError(t, json.NewDecoder(emptyBody.Body).Decode(&invalid))
	assert.Equal(t, "Invalid request body", invalid["error_description"])

	unauthenticated, err := http.NewRequest("PUT", postLogoutRedirectURIsURL(client.Id), nil)
	require.NoError(t, err)
	noToken, err := httpClient.Do(unauthenticated)
	require.NoError(t, err)
	defer func() { _ = noToken.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, noToken.StatusCode)

	wrongScope := createClientCredentialsTokenWithoutRouteScope(t)
	forbidden := makeAPIRequest(t, "PUT", postLogoutRedirectURIsURL(client.Id), wrongScope,
		api.UpdateClientPostLogoutRedirectURIsRequest{PostLogoutRedirectURIs: []string{"https://example.com/bye"}, ExpectedPostLogoutRedirectURIs: []string{}})
	defer func() { _ = forbidden.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, forbidden.StatusCode)
	assert.Empty(t, storedPostLogoutRedirectURIs(t, client.Id))
}
