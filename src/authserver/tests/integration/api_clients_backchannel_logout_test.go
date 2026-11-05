package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// PUT /api/v1/admin/clients/{id}/backchannel-logout sets a client's back-channel logout URI and
// whether it requires the session identifier, under OpenID Connect Back-Channel Logout 1.0 section
// 2.2's rules with http for a confidential client (#784 decisions 6 and 9), and only an
// authserver:manage token sets or changes the URI (#784 decision 15). Every client the admin API
// answers carries both fields.

const backchannelLogoutRoute = "/api/v1/admin/clients/{id}/backchannel-logout"

// backchannelLogoutPath is the save's path for a client.
func backchannelLogoutPath(clientId int64) string {
	return "/api/v1/admin/clients/" + strconv.FormatInt(clientId, 10) + "/backchannel-logout"
}

// backchannelLogoutBody is a body carrying both fields.
func backchannelLogoutBody(uri string, sessionRequired bool) map[string]any {
	return map[string]any{"backchannelLogoutUri": uri, "backchannelLogoutSessionRequired": sessionRequired}
}

// saveBackchannelLogout sends one save and decodes the answer as a JSON object.
func saveBackchannelLogout(t *testing.T, accessToken string, clientId int64, body any) (int, map[string]any, string) {
	t.Helper()
	resp, requestId := sendAdmin(t, accessToken, http.MethodPut, backchannelLogoutPath(clientId), body)
	defer func() { _ = resp.Body.Close() }()
	var decoded map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&decoded))
	return resp.StatusCode, decoded, requestId
}

// newBackchannelLogoutClient creates a client with the authorization code flow on, confidential or
// public, holding the back-channel logout settings given, and removes it when the test ends.
func newBackchannelLogoutClient(t *testing.T, prefix string, public bool, uri string, sessionRequired bool) *record.Client {
	t.Helper()
	return createBackchannelLogoutClient(t, newBackchannelLogoutClientRecord(t, prefix, public, uri, sessionRequired), false)
}

// newBackchannelLogoutClientRecord is the client newBackchannelLogoutClient creates, not yet stored.
func newBackchannelLogoutClientRecord(t *testing.T, prefix string, public bool, uri string, sessionRequired bool) *record.Client {
	t.Helper()
	client := &record.Client{
		ClientIdentifier:                 prefix + strings.ToLower(fake.LetterN(8)),
		Enabled:                          true,
		IsPublic:                         public,
		AuthorizationCodeEnabled:         true,
		DefaultAcrLevel:                  record.AcrLevel2Optional,
		BackchannelLogoutURI:             uri,
		BackchannelLogoutSessionRequired: sessionRequired,
	}
	if !public {
		secret, err := dataCipher.Encrypt(fake.Password(60))
		require.NoError(t, err)
		client.ClientSecretEncrypted = secret
	}
	return client
}

// createBackchannelLogoutClient stores client, as registered through dynamic client registration
// when selfRegistered, and deletes it when the test ends.
func createBackchannelLogoutClient(t *testing.T, client *record.Client, selfRegistered bool) *record.Client {
	t.Helper()
	client.CreatedViaDCR = selfRegistered
	require.NoError(t, database.CreateClient(context.Background(), nil, client))
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })
	return client
}

// storedBackchannelLogout is the client's two settings as the database holds them.
func storedBackchannelLogout(t *testing.T, clientId int64) (string, bool) {
	t.Helper()
	client := storedClient(t, clientId)
	require.NotNil(t, client)
	return client.BackchannelLogoutURI, client.BackchannelLogoutSessionRequired
}

// readBackchannelLogout is the client's two settings as GET /clients/{id} answers them.
func readBackchannelLogout(t *testing.T, accessToken string, clientId int64) (string, bool) {
	t.Helper()
	resp := makeAPIRequest(t, http.MethodGet, appConfig.AuthServer.BaseURL+"/api/v1/admin/clients/"+strconv.FormatInt(clientId, 10), accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var got api.GetClientResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	return got.Client.BackchannelLogoutURI, got.Client.BackchannelLogoutSessionRequired
}

// A confidential client takes an http URI on any host, with its query kept as sent; the answer, the
// detail, the listing and the row all carry both settings; and an empty URI clears it.
func TestAPIClientBackchannelLogoutPut_SavesClearsAndAnswersBothSettings(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	client := newBackchannelLogoutClient(t, "bcl-save-", false, "", false)
	uri := "http://testapp.internal:3000/backchannel-logout?tenant=a&v=%2F1"

	status, body, _ := saveBackchannelLogout(t, accessToken, client.Id, backchannelLogoutBody(uri, true))
	require.Equal(t, http.StatusOK, status, body)
	answered := body["client"].(map[string]any)
	assert.InDelta(t, float64(client.Id), answered["id"], 0)
	assert.Equal(t, uri, answered["backchannelLogoutUri"])
	assert.Equal(t, true, answered["backchannelLogoutSessionRequired"])

	storedURI, storedRequired := storedBackchannelLogout(t, client.Id)
	assert.Equal(t, uri, storedURI)
	assert.True(t, storedRequired)
	readURI, readRequired := readBackchannelLogout(t, accessToken, client.Id)
	assert.Equal(t, uri, readURI)
	assert.True(t, readRequired)

	listing := makeAPIRequest(t, http.MethodGet, appConfig.AuthServer.BaseURL+"/api/v1/admin/clients", accessToken, nil)
	defer func() { _ = listing.Body.Close() }()
	require.Equal(t, http.StatusOK, listing.StatusCode)
	var clients api.GetClientsResponse
	require.NoError(t, json.NewDecoder(listing.Body).Decode(&clients))
	found := false
	for _, listed := range clients.Clients {
		if listed.Id == client.Id {
			found = true
			assert.Equal(t, uri, listed.BackchannelLogoutURI)
			assert.True(t, listed.BackchannelLogoutSessionRequired)
		}
	}
	assert.True(t, found, "client %d is in the listing", client.Id)

	status, body, _ = saveBackchannelLogout(t, accessToken, client.Id, backchannelLogoutBody("", false))
	require.Equal(t, http.StatusOK, status, body)
	storedURI, storedRequired = storedBackchannelLogout(t, client.Id)
	assert.Empty(t, storedURI, "an empty URI clears it")
	assert.False(t, storedRequired)
}

// Decision 6's rules for an administrator: https on any client, http only on a confidential one an
// administrator created, and each refusal its own catalog key, with nothing written. A client that
// registered itself is held to https whatever its type, whoever sets its URI.
func TestAPIClientBackchannelLogoutPut_TheURIRules(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	confidential := newBackchannelLogoutClient(t, "bcl-rules-conf-", false, "", false)
	public := newBackchannelLogoutClient(t, "bcl-rules-pub-", true, "", false)
	selfRegistered := createBackchannelLogoutClient(t, newBackchannelLogoutClientRecord(t, "bcl-rules-dcr-", false, "", false), true)
	overlong := "https://app.example.com/" + strings.Repeat("x", 2049-len("https://app.example.com/"))

	refused := []struct {
		name            string
		client          *record.Client
		uri             string
		wantCode        string
		wantDescription string
	}{
		{"http on a public client", public, "http://app.internal:3000/bcl", "uri_http_public_client",
			"Back-channel logout URI must use https on a public client. Plain http is allowed only on a confidential client an administrator created: http://app.internal:3000/bcl"},
		{"http on loopback on a public client", public, "http://127.0.0.1:8080/bcl", "uri_http_public_client",
			"Back-channel logout URI must use https on a public client. Plain http is allowed only on a confidential client an administrator created: http://127.0.0.1:8080/bcl"},
		{"http on a confidential client that registered itself", selfRegistered, "http://app.internal:3000/bcl", "uri_http_self_registered",
			"Back-channel logout URI must use https on a client that registered itself, whatever its type. Plain http is allowed only on a confidential client an administrator created: http://app.internal:3000/bcl"},
		{"another scheme", confidential, "ftp://app.example.com/bcl", "uri_scheme_invalid",
			"Back-channel logout URI must use https or http: ftp://app.example.com/bcl"},
		{"a custom scheme", confidential, "com.example.app:/bcl", "uri_scheme_invalid",
			"Back-channel logout URI must use https or http: com.example.app:/bcl"},
		{"userinfo", confidential, "https://user:secret@app.example.com/bcl", "uri_userinfo",
			"Back-channel logout URI must not carry a user name or password: https://user:secret@app.example.com/bcl"},
		{"a fragment", confidential, "https://app.example.com/bcl#done", "uri_invalid",
			"Back-channel logout URI must be an absolute URI that names a host, with no fragment, well-formed percent-escapes and no spaces or characters a URI excludes: https://app.example.com/bcl#done"},
		{"no host", confidential, "https:///bcl", "uri_invalid",
			"Back-channel logout URI must be an absolute URI that names a host, with no fragment, well-formed percent-escapes and no spaces or characters a URI excludes: https:///bcl"},
		{"a relative reference", confidential, "/backchannel-logout", "uri_invalid",
			"Back-channel logout URI must be an absolute URI that names a host, with no fragment, well-formed percent-escapes and no spaces or characters a URI excludes: /backchannel-logout"},
		{"a malformed escape", confidential, "https://app.example.com/bcl?x=%zz", "uri_invalid",
			"Back-channel logout URI must be an absolute URI that names a host, with no fragment, well-formed percent-escapes and no spaces or characters a URI excludes: https://app.example.com/bcl?x=%zz"},
		{"an excluded character", confidential, "https://app.example.com/<b>", "uri_invalid",
			"Back-channel logout URI must be an absolute URI that names a host, with no fragment, well-formed percent-escapes and no spaces or characters a URI excludes: https://app.example.com/<b>"},
		{"2049 bytes", confidential, overlong, "uri_too_long",
			"Back-channel logout URI is too long (2049 bytes, the maximum is 2048): https://app.example.com/" + strings.Repeat("x", 56) + "..."},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			status, body, _ := saveBackchannelLogout(t, accessToken, tc.client.Id, backchannelLogoutBody(tc.uri, true))
			assert.Equal(t, http.StatusBadRequest, status)
			assert.Equal(t, "handler.client_backchannel_logout."+tc.wantCode, body["error_code"])
			assert.Equal(t, tc.wantDescription, body["error_description"])
			storedURI, storedRequired := storedBackchannelLogout(t, tc.client.Id)
			assert.Empty(t, storedURI, "a refused save writes nothing")
			assert.False(t, storedRequired, "a refused save writes nothing")
		})
	}

	admitted := []struct {
		name   string
		client *record.Client
		uri    string
	}{
		{"https on a public client", public, "https://spa.example.com/bcl"},
		{"https on a confidential client", confidential, "https://app.example.com:8443/bcl?tenant=a"},
		{"http on a confidential client", confidential, "http://10.0.0.7/bcl"},
		{"https on a confidential client that registered itself", selfRegistered, "https://app.example.com/dcr-bcl"},
		{"2048 bytes", confidential, overlong[:2048]},
		{"surrounding spaces trimmed", confidential, "  https://app.example.com/trimmed  "},
	}
	for _, tc := range admitted {
		t.Run(tc.name, func(t *testing.T) {
			status, body, _ := saveBackchannelLogout(t, accessToken, tc.client.Id, backchannelLogoutBody(tc.uri, false))
			require.Equal(t, http.StatusOK, status, body)
			storedURI, _ := storedBackchannelLogout(t, tc.client.Id)
			assert.Equal(t, strings.TrimSpace(tc.uri), storedURI)
		})
	}
}

// Both fields are required: a body leaving one out, or sending null, is refused by name rather than
// clearing what it did not mention.
func TestAPIClientBackchannelLogoutPut_BothFieldsAreRequired(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	client := newBackchannelLogoutClient(t, "bcl-required-", false, "https://kept.example.com/bcl", true)

	cases := []struct {
		name     string
		body     map[string]any
		wantCode string
	}{
		{"no URI", map[string]any{"backchannelLogoutSessionRequired": false}, "handler.client_backchannel_logout.uri_required"},
		{"a null URI", map[string]any{"backchannelLogoutUri": nil, "backchannelLogoutSessionRequired": false}, "handler.client_backchannel_logout.uri_required"},
		{"no flag", map[string]any{"backchannelLogoutUri": ""}, "handler.client_backchannel_logout.session_required_required"},
		{"a null flag", map[string]any{"backchannelLogoutUri": "", "backchannelLogoutSessionRequired": nil}, "handler.client_backchannel_logout.session_required_required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, body, _ := saveBackchannelLogout(t, accessToken, client.Id, tc.body)
			assert.Equal(t, http.StatusBadRequest, status)
			assert.Equal(t, tc.wantCode, body["error_code"])
			storedURI, storedRequired := storedBackchannelLogout(t, client.Id)
			assert.Equal(t, "https://kept.example.com/bcl", storedURI)
			assert.True(t, storedRequired)
		})
	}
}

// A back-channel logout URI is refused on a client with neither the authorization code nor the
// implicit flow, as the sign-out redirect URIs are; the implicit flow alone is enough, and clearing
// the URI of such a client is always allowed. ImplicitGrantEnabled is set explicitly, since nil
// would resolve against a global setting other tests change.
func TestAPIClientBackchannelLogoutPut_TheSignInFlowGate(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	newClient := func(t *testing.T, prefix string, implicit bool, uri string) *record.Client {
		client := &record.Client{
			ClientIdentifier:         prefix + strings.ToLower(fake.LetterN(8)),
			Enabled:                  true,
			IsPublic:                 true,
			AuthorizationCodeEnabled: false,
			ImplicitGrantEnabled:     &implicit,
			BackchannelLogoutURI:     uri,
		}
		require.NoError(t, database.CreateClient(context.Background(), nil, client))
		t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })
		return client
	}

	t.Run("neither flow", func(t *testing.T) {
		client := newClient(t, "bcl-noflow-", false, "")
		status, body, _ := saveBackchannelLogout(t, accessToken, client.Id, backchannelLogoutBody("https://app.example.com/bcl", false))
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, "handler.client_backchannel_logout.no_sign_in_flow", body["error_code"])
		assert.Equal(t, "A back-channel logout URI is used by clients that sign users in through the authorization code with PKCE flow or the implicit flow, and neither is enabled for this client.",
			body["error_description"])
		storedURI, _ := storedBackchannelLogout(t, client.Id)
		assert.Empty(t, storedURI)
	})

	t.Run("neither flow, clearing a stored URI", func(t *testing.T) {
		client := newClient(t, "bcl-noflow-clear-", false, "https://old.example.com/bcl")
		status, body, _ := saveBackchannelLogout(t, accessToken, client.Id, backchannelLogoutBody("", false))
		require.Equal(t, http.StatusOK, status, body)
		storedURI, _ := storedBackchannelLogout(t, client.Id)
		assert.Empty(t, storedURI)
	})

	t.Run("the implicit flow alone", func(t *testing.T) {
		client := newClient(t, "bcl-implicit-", true, "")
		status, body, _ := saveBackchannelLogout(t, accessToken, client.Id, backchannelLogoutBody("https://app.example.com/bcl", false))
		require.Equal(t, http.StatusOK, status, body)
		storedURI, _ := storedBackchannelLogout(t, client.Id)
		assert.Equal(t, "https://app.example.com/bcl", storedURI)
	})
}

// assertRefusedByTheBackchannelLogoutURICeiling holds one answered save to decision 15's refusal: 403
// MANAGE_SCOPE_REQUIRED with the insufficient_scope challenge, one administrator_change_refused row
// under ceiling backchannel_logout_uri naming the client, and no record of a save.
func assertRefusedByTheBackchannelLogoutURICeiling(t *testing.T, status int, body map[string]any, requestId, readerToken string,
	caller *record.Client, clientId int64) {
	t.Helper()
	assert.Equal(t, http.StatusForbidden, status)
	assert.Equal(t, "MANAGE_SCOPE_REQUIRED", body["error_code"])
	assert.Contains(t, body["error_description"], "authserver:manage")

	rows := refusalRows(t, readerToken, requestId)
	require.Len(t, rows, 1, "exactly one administrator_change_refused row for the refused request")
	assert.Equal(t, map[string]any{
		"logged_in_user": caller.ClientIdentifier,
		"method":         http.MethodPut,
		"route":          backchannelLogoutRoute,
		"ceiling":        "backchannel_logout_uri",
		"target_kind":    "client",
		"target_id":      float64(clientId),
	}, rows[0])
	assert.Empty(t, auditRows(t, readerToken, "updated_client_backchannel_logout", requestId), "no record of a save that was not made")
}

// Decision 15: a token without authserver:manage cannot set a URI or change the stored one, on an
// ordinary client, and is refused with the challenge naming authserver:manage. It still clears the
// URI and changes the session-required flag alone, and authserver:manage sets and changes the URI.
func TestAPIClientBackchannelLogoutPut_OnlyManageSetsOrChangesTheURI(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)
	granularToken, caller := createClientWithGranularScope(t, builtin.ManageClientsPermissionIdentifier)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, caller.Id) })

	t.Run("setting a URI on a client with none", func(t *testing.T) {
		client := newBackchannelLogoutClient(t, "bcl-ceiling-set-", false, "", false)
		resp, requestId := sendAdmin(t, granularToken, http.MethodPut, backchannelLogoutPath(client.Id),
			backchannelLogoutBody("http://metadata.internal/latest", false))
		defer func() { _ = resp.Body.Close() }()
		challenge := resp.Header.Get("WWW-Authenticate")
		assert.True(t, strings.HasPrefix(challenge, `Bearer realm="`), "a Bearer challenge with its realm: %q", challenge)
		assert.Contains(t, challenge, `error="insufficient_scope"`)
		assert.Contains(t, challenge, `scope="authserver:manage"`)
		var body map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		assertRefusedByTheBackchannelLogoutURICeiling(t, resp.StatusCode, body, requestId, manageToken, caller, client.Id)
		storedURI, _ := storedBackchannelLogout(t, client.Id)
		assert.Empty(t, storedURI)
	})

	t.Run("changing the stored URI", func(t *testing.T) {
		client := newBackchannelLogoutClient(t, "bcl-ceiling-change-", false, "https://app.example.com/bcl", false)
		status, body, requestId := saveBackchannelLogout(t, granularToken, client.Id,
			backchannelLogoutBody("https://elsewhere.example.com/bcl", false))
		assertRefusedByTheBackchannelLogoutURICeiling(t, status, body, requestId, manageToken, caller, client.Id)
		storedURI, _ := storedBackchannelLogout(t, client.Id)
		assert.Equal(t, "https://app.example.com/bcl", storedURI)
	})

	t.Run("changing the flag alone", func(t *testing.T) {
		client := newBackchannelLogoutClient(t, "bcl-ceiling-flag-", false, "https://app.example.com/bcl", false)
		status, body, requestId := saveBackchannelLogout(t, granularToken, client.Id,
			backchannelLogoutBody("https://app.example.com/bcl", true))
		require.Equal(t, http.StatusOK, status, body)
		storedURI, storedRequired := storedBackchannelLogout(t, client.Id)
		assert.Equal(t, "https://app.example.com/bcl", storedURI)
		assert.True(t, storedRequired)
		assert.Empty(t, refusalRows(t, manageToken, requestId))
	})

	t.Run("clearing the URI", func(t *testing.T) {
		client := newBackchannelLogoutClient(t, "bcl-ceiling-clear-", false, "https://app.example.com/bcl", true)
		status, body, requestId := saveBackchannelLogout(t, granularToken, client.Id, backchannelLogoutBody("", false))
		require.Equal(t, http.StatusOK, status, body)
		storedURI, storedRequired := storedBackchannelLogout(t, client.Id)
		assert.Empty(t, storedURI)
		assert.False(t, storedRequired)
		assert.Empty(t, refusalRows(t, manageToken, requestId))
	})

	t.Run("the request's own 400 comes first", func(t *testing.T) {
		client := newBackchannelLogoutClient(t, "bcl-ceiling-400-", false, "", false)
		status, body, requestId := saveBackchannelLogout(t, granularToken, client.Id, backchannelLogoutBody("ftp://app.example.com/bcl", false))
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, "handler.client_backchannel_logout.uri_scheme_invalid", body["error_code"])
		assert.Empty(t, refusalRows(t, manageToken, requestId))
	})

	t.Run("authserver:manage sets and changes it", func(t *testing.T) {
		client := newBackchannelLogoutClient(t, "bcl-ceiling-manage-", false, "", false)
		for _, uri := range []string{"http://app.internal:3000/bcl", "https://app.example.com/bcl"} {
			status, body, requestId := saveBackchannelLogout(t, manageToken, client.Id, backchannelLogoutBody(uri, false))
			require.Equal(t, http.StatusOK, status, body)
			storedURI, _ := storedBackchannelLogout(t, client.Id)
			assert.Equal(t, uri, storedURI)
			assert.Empty(t, refusalRows(t, manageToken, requestId))
		}
	})
}

// A committed save leaves one updated_client_backchannel_logout row naming the client and the
// caller; a refused one leaves none.
func TestAPIClientBackchannelLogoutPut_TheSaveIsAudited(t *testing.T) {
	requireDatabaseAuditLogs(t)
	accessToken, caller := createAdminClientWithToken(t)
	client := newBackchannelLogoutClient(t, "bcl-audit-", false, "", false)

	status, body, requestId := saveBackchannelLogout(t, accessToken, client.Id, backchannelLogoutBody("https://app.example.com/bcl", true))
	require.Equal(t, http.StatusOK, status, body)
	assert.Equal(t, []map[string]any{{"client_id": float64(client.Id), "logged_in_user": caller.ClientIdentifier}},
		auditRows(t, accessToken, "updated_client_backchannel_logout", requestId))

	status, _, requestId = saveBackchannelLogout(t, accessToken, client.Id, backchannelLogoutBody("ftp://app.example.com/bcl", true))
	require.Equal(t, http.StatusBadRequest, status)
	assert.Empty(t, auditRows(t, accessToken, "updated_client_backchannel_logout", requestId))
}

// The request's own refusals, and the route's scopes: admin-read reads both fields and cannot save.
func TestAPIClientBackchannelLogoutPut_NotFound_InvalidId_InvalidBody_Unauthorized_InsufficientScope(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	status, body, _ := saveBackchannelLogout(t, accessToken, 999999, backchannelLogoutBody("https://app.example.com/bcl", false))
	assert.Equal(t, http.StatusNotFound, status)
	assert.Equal(t, "Client not found", body["error_description"])

	resp, _ := sendAdmin(t, accessToken, http.MethodPut, "/api/v1/admin/clients/abc/backchannel-logout", backchannelLogoutBody("", false))
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var bad map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&bad))
	assert.Equal(t, "Invalid client ID", bad["error_description"])

	client := newBackchannelLogoutClient(t, "bcl-request-", false, "https://app.example.com/bcl", false)
	httpClient := createHttpClient(t)
	url := appConfig.AuthServer.BaseURL + backchannelLogoutPath(client.Id)

	req, err := http.NewRequest(http.MethodPut, url, strings.NewReader("{not json"))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	invalidBody, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = invalidBody.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, invalidBody.StatusCode)
	var invalid map[string]any
	require.NoError(t, json.NewDecoder(invalidBody.Body).Decode(&invalid))
	assert.Equal(t, "Invalid request body", invalid["error_description"])

	unauthenticated, err := http.NewRequest(http.MethodPut, url, nil)
	require.NoError(t, err)
	noToken, err := httpClient.Do(unauthenticated)
	require.NoError(t, err)
	defer func() { _ = noToken.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, noToken.StatusCode)

	readToken, reader := createClientWithGranularScope(t, builtin.AdminReadPermissionIdentifier)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, reader.Id) })
	readURI, _ := readBackchannelLogout(t, readToken, client.Id)
	assert.Equal(t, "https://app.example.com/bcl", readURI, "admin-read reads the URI")
	status, body, _ = saveBackchannelLogout(t, readToken, client.Id, backchannelLogoutBody("", false))
	assert.Equal(t, http.StatusForbidden, status)
	assert.Equal(t, "INSUFFICIENT_SCOPE", body["error_code"])
	storedURI, _ := storedBackchannelLogout(t, client.Id)
	assert.Equal(t, "https://app.example.com/bcl", storedURI, "nothing changed")
}
