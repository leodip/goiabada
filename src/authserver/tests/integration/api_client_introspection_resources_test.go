package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/securerandom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A client's introspection resources through the admin API (#676 decision 14): read and replaced
// whole at /api/v1/admin/clients/{id}/introspection-resources, held to the client permissions'
// scopes, with listing the authserver resource reserved to authserver:manage, a non-empty list
// refused for a public client, the list cleared when a client is made public, and every save
// recorded as updated_client_introspection_resources.

func introspectionResourcesPath(clientId int64) string {
	return fmt.Sprintf("/api/v1/admin/clients/%d/introspection-resources", clientId)
}

// newIntrospectingClient is a confidential client, removed when the test ends.
func newIntrospectingClient(t *testing.T) *record.Client {
	t.Helper()
	enc, err := dataCipher.Encrypt(fake.Password(32))
	require.NoError(t, err)
	client := &record.Client{
		ClientIdentifier:      "introspect-" + strings.ToLower(fake.LetterN(8)),
		Enabled:               true,
		ClientSecretEncrypted: enc,
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, client))
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })
	return client
}

// newPublicClient is a public client, removed when the test ends.
func newPublicClient(t *testing.T) *record.Client {
	t.Helper()
	client := &record.Client{
		ClientIdentifier:         "introspect-pub-" + strings.ToLower(fake.LetterN(8)),
		Enabled:                  true,
		IsPublic:                 true,
		AuthorizationCodeEnabled: true,
	}
	client.ApplyPublicClientInvariants()
	require.NoError(t, database.CreateClient(context.Background(), nil, client))
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })
	return client
}

// newAPIResource is a resource, removed when the test ends.
func newAPIResource(t *testing.T) *record.Resource {
	t.Helper()
	resource := createTestResource(t, "intro-api-"+strings.ToLower(fake.LetterN(8)), "An API")
	t.Cleanup(func() { _ = database.DeleteResource(context.Background(), nil, resource.Id) })
	return resource
}

func authServerResourceId(t *testing.T) int64 {
	t.Helper()
	resource, err := database.GetResourceByResourceIdentifier(context.Background(), nil, builtin.AuthServerResourceIdentifier)
	require.NoError(t, err)
	require.NotNil(t, resource)
	return resource.Id
}

// storedIntrospectionResourceIds is the client's list as the database holds it.
func storedIntrospectionResourceIds(t *testing.T, clientId int64) []int64 {
	t.Helper()
	links, err := database.GetClientIntrospectionResourcesByClientId(context.Background(), nil, clientId)
	require.NoError(t, err)
	ids := []int64{}
	for _, link := range links {
		ids = append(ids, link.ResourceId)
	}
	return ids
}

func listIntrospectionResource(t *testing.T, clientId, resourceId int64) {
	t.Helper()
	require.NoError(t, database.CreateClientIntrospectionResource(context.Background(), nil,
		&record.ClientIntrospectionResource{ClientId: clientId, ResourceId: resourceId}))
}

// putIntrospectionResources sends a save under its own request id, so the audit rows it leaves can
// be read back by that id alone. A nil expected is sent as JSON null.
func putIntrospectionResources(t *testing.T, accessToken string, clientId int64, wanted, expected []int64) (*http.Response, string) {
	t.Helper()
	if wanted == nil {
		wanted = []int64{}
	}
	body, err := json.Marshal(map[string]any{"resourceIds": wanted, "expectedResourceIds": expected})
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPut, appConfig.AuthServer.BaseURL+introspectionResourcesPath(clientId), bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	requestId := "introspect-" + fake.LetterN(16)
	req.Header.Set("X-Request-Id", requestId)

	resp, err := createHttpClient(t).Do(req)
	require.NoError(t, err)
	return resp, requestId
}

func getIntrospectionResources(t *testing.T, accessToken string, clientId int64) (*http.Response, []byte) {
	t.Helper()
	resp := makeAPIRequest(t, http.MethodGet, appConfig.AuthServer.BaseURL+introspectionResourcesPath(clientId), accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp, raw
}

// errorEnvelope decodes an admin API error answer and closes its body.
func errorEnvelope(t *testing.T, resp *http.Response) (code, description string) {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	var envelope struct {
		ErrorCode        string `json:"error_code"`
		ErrorDescription string `json:"error_description"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&envelope))
	return envelope.ErrorCode, envelope.ErrorDescription
}

// idsOf reads a JSON list of ids out of an audit row.
func idsOf(t *testing.T, value any) []int64 {
	t.Helper()
	raw, ok := value.([]any)
	require.True(t, ok, "a list of ids, never null: %#v", value)
	ids := []int64{}
	for _, id := range raw {
		ids = append(ids, int64(id.(float64)))
	}
	return ids
}

func TestAPIClientIntrospectionResources_GetAnswersTheClientAndItsList(t *testing.T) {
	manageToken, _ := createAdminClientWithToken(t)
	client := newIntrospectingClient(t)
	first := newAPIResource(t)
	second := newAPIResource(t)
	listIntrospectionResource(t, client.Id, first.Id)
	listIntrospectionResource(t, client.Id, second.Id)

	resp, raw := getIntrospectionResources(t, manageToken, client.Id)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var body api.GetClientIntrospectionResourcesResponse
	require.NoError(t, json.Unmarshal(raw, &body))
	assert.Equal(t, client.Id, body.Client.Id)
	assert.Equal(t, client.ClientIdentifier, body.Client.ClientIdentifier)
	assert.ElementsMatch(t, []api.ResourceResponse{
		{Id: first.Id, ResourceIdentifier: first.ResourceIdentifier, Description: "An API"},
		{Id: second.Id, ResourceIdentifier: second.ResourceIdentifier, Description: "An API"},
	}, body.Resources)
}

func TestAPIClientIntrospectionResources_GetAnswersAnEmptyListAsAnArray(t *testing.T) {
	manageToken, _ := createAdminClientWithToken(t)
	client := newIntrospectingClient(t)

	resp, raw := getIntrospectionResources(t, manageToken, client.Id)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	var body map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &body))
	assert.Equal(t, "[]", string(body["resources"]), "a client listing nothing answers [], never null")
}

func TestAPIClientIntrospectionResources_GetRefusesABadIdAndAnUnknownClient(t *testing.T) {
	manageToken, _ := createAdminClientWithToken(t)

	resp := makeAPIRequest(t, http.MethodGet, appConfig.AuthServer.BaseURL+"/api/v1/admin/clients/abc/introspection-resources", manageToken, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	code, description := errorEnvelope(t, resp)
	assert.Equal(t, "VALIDATION_ERROR", code)
	assert.Equal(t, "Invalid client ID format", description)

	resp = makeAPIRequest(t, http.MethodGet, appConfig.AuthServer.BaseURL+introspectionResourcesPath(99999999), manageToken, nil)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	code, description = errorEnvelope(t, resp)
	assert.Equal(t, "NOT_FOUND", code)
	assert.Equal(t, "Client not found", description)
}

// A save replaces the list whole and records what it added and removed, once it has committed.
func TestAPIClientIntrospectionResources_PutReplacesTheListAndRecordsTheChange(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)
	clientsToken, caller := createClientWithGranularScope(t, builtin.ManageClientsPermissionIdentifier)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, caller.Id) })
	client := newIntrospectingClient(t)
	kept := newAPIResource(t)
	dropped := newAPIResource(t)
	added := newAPIResource(t)

	resp, requestId := putIntrospectionResources(t, clientsToken, client.Id, []int64{kept.Id, dropped.Id, kept.Id}, []int64{})
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "authserver:manage-clients edits a client's list")
	assert.ElementsMatch(t, []int64{kept.Id, dropped.Id}, storedIntrospectionResourceIds(t, client.Id), "a repeated id is listed once")
	rows := auditRows(t, manageToken, "updated_client_introspection_resources", requestId)
	require.Len(t, rows, 1, "one record for the save")
	assert.InDelta(t, float64(client.Id), rows[0]["client_id"], 0)
	assert.Equal(t, []int64{kept.Id, dropped.Id}, idsOf(t, rows[0]["added_resource_ids"]), "in the order the save named them")
	assert.Equal(t, []int64{}, idsOf(t, rows[0]["removed_resource_ids"]))
	assert.Equal(t, caller.ClientIdentifier, rows[0]["logged_in_user"])

	resp, requestId = putIntrospectionResources(t, clientsToken, client.Id, []int64{kept.Id, added.Id}, []int64{dropped.Id, kept.Id})
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.ElementsMatch(t, []int64{kept.Id, added.Id}, storedIntrospectionResourceIds(t, client.Id))
	rows = auditRows(t, manageToken, "updated_client_introspection_resources", requestId)
	require.Len(t, rows, 1)
	assert.Equal(t, []int64{added.Id}, idsOf(t, rows[0]["added_resource_ids"]))
	assert.Equal(t, []int64{dropped.Id}, idsOf(t, rows[0]["removed_resource_ids"]))

	resp, raw := getIntrospectionResources(t, clientsToken, client.Id)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	var body api.GetClientIntrospectionResourcesResponse
	require.NoError(t, json.Unmarshal(raw, &body))
	var identifiers []string
	for _, resource := range body.Resources {
		identifiers = append(identifiers, resource.ResourceIdentifier)
	}
	assert.ElementsMatch(t, []string{kept.ResourceIdentifier, added.ResourceIdentifier}, identifiers, "the read answers what the save stored")

	resp, _ = putIntrospectionResources(t, clientsToken, client.Id, []int64{}, []int64{kept.Id, added.Id})
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, storedIntrospectionResourceIds(t, client.Id), "and an empty list empties it")
}

func TestAPIClientIntrospectionResources_PutRefusesWhatItCannotSave(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)
	client := newIntrospectingClient(t)
	listed := newAPIResource(t)
	other := newAPIResource(t)
	listIntrospectionResource(t, client.Id, listed.Id)

	t.Run("expectedResourceIds is required", func(t *testing.T) {
		resp, requestId := putIntrospectionResources(t, manageToken, client.Id, []int64{other.Id}, nil)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		code, _ := errorEnvelope(t, resp)
		assert.Equal(t, "VALIDATION_ERROR", code)
		assert.Equal(t, []int64{listed.Id}, storedIntrospectionResourceIds(t, client.Id), "nothing was saved")
		assert.Empty(t, auditRows(t, manageToken, "updated_client_introspection_resources", requestId))
	})

	t.Run("a list read before another save is a 409", func(t *testing.T) {
		resp, requestId := putIntrospectionResources(t, manageToken, client.Id, []int64{other.Id}, []int64{})
		assert.Equal(t, http.StatusConflict, resp.StatusCode)
		code, _ := errorEnvelope(t, resp)
		assert.Equal(t, "CONCURRENT_UPDATE", code)
		assert.Equal(t, []int64{listed.Id}, storedIntrospectionResourceIds(t, client.Id), "nothing was saved")
		assert.Empty(t, auditRows(t, manageToken, "updated_client_introspection_resources", requestId))
	})

	t.Run("an unknown resource is a 404", func(t *testing.T) {
		resp, _ := putIntrospectionResources(t, manageToken, client.Id, []int64{listed.Id, 99999999}, []int64{listed.Id})
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		code, description := errorEnvelope(t, resp)
		assert.Equal(t, "NOT_FOUND", code)
		assert.Equal(t, "Resource not found", description)
		assert.Equal(t, []int64{listed.Id}, storedIntrospectionResourceIds(t, client.Id), "nothing was saved")
	})

	t.Run("an unknown client is a 404", func(t *testing.T) {
		resp, _ := putIntrospectionResources(t, manageToken, 99999999, []int64{listed.Id}, []int64{})
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		code, description := errorEnvelope(t, resp)
		assert.Equal(t, "NOT_FOUND", code)
		assert.Equal(t, "Client not found", description)
	})
}

// A public client cannot authenticate, so it never introspects: a list for one is refused, while
// saving its empty list is not.
func TestAPIClientIntrospectionResources_APublicClientListsNothing(t *testing.T) {
	manageToken, _ := createAdminClientWithToken(t)
	client := newPublicClient(t)
	resource := newAPIResource(t)

	resp, _ := putIntrospectionResources(t, manageToken, client.Id, []int64{resource.Id}, []int64{})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	code, description := errorEnvelope(t, resp)
	assert.Equal(t, "handler.client_introspection_resources.public_client", code)
	assert.Equal(t, "A public client can't introspect tokens, so it can't list introspection resources.", description)
	assert.Empty(t, storedIntrospectionResourceIds(t, client.Id), "nothing was saved")

	resp, _ = putIntrospectionResources(t, manageToken, client.Id, []int64{}, []int64{})
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "an empty list is a public client's own")
}

// Making a client public clears its list, in the transaction that revokes its grants.
func TestAPIClientIntrospectionResources_MakingTheClientPublicClearsTheList(t *testing.T) {
	manageToken, _ := createAdminClientWithToken(t)
	client := newIntrospectingClient(t)
	other := newIntrospectingClient(t)
	resource := newAPIResource(t)
	listIntrospectionResource(t, client.Id, resource.Id)
	listIntrospectionResource(t, other.Id, resource.Id)

	resp := makeAPIRequest(t, http.MethodPut,
		fmt.Sprintf("%s/api/v1/admin/clients/%d/authentication", appConfig.AuthServer.BaseURL, client.Id),
		manageToken, api.UpdateClientAuthenticationRequest{IsPublic: true})
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	assert.Empty(t, storedIntrospectionResourceIds(t, client.Id), "the client made public lists nothing")
	assert.Equal(t, []int64{resource.Id}, storedIntrospectionResourceIds(t, other.Id), "another client keeps its list")

	// Made confidential again, the client starts with an empty list rather than its old one.
	resp = makeAPIRequest(t, http.MethodPut,
		fmt.Sprintf("%s/api/v1/admin/clients/%d/authentication", appConfig.AuthServer.BaseURL, client.Id),
		manageToken, api.UpdateClientAuthenticationRequest{IsPublic: false, ClientSecret: securerandom.String(60)})
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, storedIntrospectionResourceIds(t, client.Id))
}

// Listing the authserver resource lets a client read the claims of every sign-in token, so only
// authserver:manage adds it (#676 decision 14).
func TestAPIClientIntrospectionResources_OnlyManageListsTheAuthServerResource(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)
	clientsToken, caller := createClientWithGranularScope(t, builtin.ManageClientsPermissionIdentifier)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, caller.Id) })
	authServer := authServerResourceId(t)
	ordinary := newAPIResource(t)

	t.Run("manage-clients is refused", func(t *testing.T) {
		client := newIntrospectingClient(t)

		resp, requestId := putIntrospectionResources(t, clientsToken, client.Id, []int64{ordinary.Id, authServer}, []int64{})

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		challenge := resp.Header.Get("WWW-Authenticate")
		assert.Contains(t, challenge, `error="insufficient_scope"`)
		assert.Contains(t, challenge, `scope="authserver:manage"`)
		code, _ := errorEnvelope(t, resp)
		assert.Equal(t, "MANAGE_SCOPE_REQUIRED", code)
		assert.Empty(t, storedIntrospectionResourceIds(t, client.Id), "the refused save wrote nothing, the ordinary resource included")
		assert.Empty(t, auditRows(t, manageToken, "updated_client_introspection_resources", requestId))

		rows := auditRows(t, manageToken, "administrator_change_refused", requestId)
		require.Len(t, rows, 1, "exactly one administrator_change_refused row")
		assert.Equal(t, caller.ClientIdentifier, rows[0]["logged_in_user"])
		assert.Equal(t, http.MethodPut, rows[0]["method"])
		assert.Equal(t, "/api/v1/admin/clients/{id}/introspection-resources", rows[0]["route"])
		assert.Equal(t, "grant", rows[0]["ceiling"])
		assert.Equal(t, "client", rows[0]["target_kind"])
		assert.InDelta(t, float64(client.Id), rows[0]["target_id"], 0)
		assert.Equal(t, []int64{authServer}, idsOf(t, rows[0]["resource_ids"]))
		assert.NotContains(t, rows[0], "permission_ids")
	})

	t.Run("manage lists it", func(t *testing.T) {
		client := newIntrospectingClient(t)

		resp, requestId := putIntrospectionResources(t, manageToken, client.Id, []int64{authServer}, []int64{})
		_ = resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, []int64{authServer}, storedIntrospectionResourceIds(t, client.Id))
		assert.Empty(t, auditRows(t, manageToken, "administrator_change_refused", requestId))
	})

	t.Run("manage-clients edits the rest of a list that already holds it, and removes it", func(t *testing.T) {
		client := newIntrospectingClient(t)
		listIntrospectionResource(t, client.Id, authServer)

		resp, _ := putIntrospectionResources(t, clientsToken, client.Id, []int64{authServer, ordinary.Id}, []int64{authServer})
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode, "keeping authserver listed adds nothing the ceiling guards")
		assert.ElementsMatch(t, []int64{authServer, ordinary.Id}, storedIntrospectionResourceIds(t, client.Id))

		resp, _ = putIntrospectionResources(t, clientsToken, client.Id, []int64{ordinary.Id}, []int64{authServer, ordinary.Id})
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode, "removing it takes nothing away from anyone's sign-in")
		assert.Equal(t, []int64{ordinary.Id}, storedIntrospectionResourceIds(t, client.Id))
	})
}

// A client listed for the authserver resource introspects every sign-in, and whoever reads or sets
// its secret authenticates as it, so only authserver:manage does either, as only it lists the
// resource (#676 decision 14). manage-clients can still take the reach away by making the client
// public, which clears the list, and reads the secret of a client listed for other resources only.
func TestAPIClientIntrospectionResources_OnlyManageReadsOrSetsAnAuthServerIntrospectorsSecret(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)
	clientsToken, caller := createClientWithGranularScope(t, builtin.ManageClientsPermissionIdentifier)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, caller.Id) })
	authServer := authServerResourceId(t)
	secretPath := func(client *record.Client) string {
		return fmt.Sprintf("%s/api/v1/admin/clients/%d/secret", appConfig.AuthServer.BaseURL, client.Id)
	}
	authenticationPath := func(client *record.Client) string {
		return fmt.Sprintf("%s/api/v1/admin/clients/%d/authentication", appConfig.AuthServer.BaseURL, client.Id)
	}
	// send makes the request under its own request id, so the audit rows it leaves can be read back
	// by that id alone.
	send := func(t *testing.T, method, url, accessToken string, body any) (*http.Response, string) {
		t.Helper()
		var reader io.Reader
		if body != nil {
			encoded, err := json.Marshal(body)
			require.NoError(t, err)
			reader = bytes.NewReader(encoded)
		}
		req, err := http.NewRequest(method, url, reader)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")
		requestId := "introspect-secret-" + fake.LetterN(16)
		req.Header.Set("X-Request-Id", requestId)
		resp, err := createHttpClient(t).Do(req)
		require.NoError(t, err)
		return resp, requestId
	}
	assertRefused := func(t *testing.T, resp *http.Response, requestId string, client *record.Client, route string) {
		t.Helper()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		assert.Contains(t, resp.Header.Get("WWW-Authenticate"), `scope="authserver:manage"`)
		code, _ := errorEnvelope(t, resp)
		assert.Equal(t, "MANAGE_SCOPE_REQUIRED", code)
		rows := auditRows(t, manageToken, "administrator_change_refused", requestId)
		require.Len(t, rows, 1, "exactly one administrator_change_refused row")
		assert.Equal(t, caller.ClientIdentifier, rows[0]["logged_in_user"])
		assert.Equal(t, route, rows[0]["route"])
		assert.Equal(t, "target", rows[0]["ceiling"])
		assert.Equal(t, "client", rows[0]["target_kind"])
		assert.InDelta(t, float64(client.Id), rows[0]["target_id"], 0)
	}

	t.Run("manage-clients cannot read its secret", func(t *testing.T) {
		client := newIntrospectingClient(t)
		listIntrospectionResource(t, client.Id, authServer)

		resp, requestId := send(t, http.MethodGet, secretPath(client), clientsToken, nil)
		defer func() { _ = resp.Body.Close() }()

		assertRefused(t, resp, requestId, client, "/api/v1/admin/clients/{id}/secret")
	})

	t.Run("manage-clients cannot set its secret", func(t *testing.T) {
		client := newIntrospectingClient(t)
		listIntrospectionResource(t, client.Id, authServer)

		resp, requestId := send(t, http.MethodPut, authenticationPath(client), clientsToken,
			api.UpdateClientAuthenticationRequest{IsPublic: false, ClientSecret: securerandom.String(60)})
		defer func() { _ = resp.Body.Close() }()

		assertRefused(t, resp, requestId, client, "/api/v1/admin/clients/{id}/authentication")
		stored, err := database.GetClientById(context.Background(), nil, client.Id)
		require.NoError(t, err)
		assert.Equal(t, client.ClientSecretEncrypted, stored.ClientSecretEncrypted, "the secret is the one it had")
	})

	t.Run("manage reads and sets it", func(t *testing.T) {
		client := newIntrospectingClient(t)
		listIntrospectionResource(t, client.Id, authServer)

		resp := makeAPIRequest(t, http.MethodGet, secretPath(client), manageToken, nil)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp = makeAPIRequest(t, http.MethodPut, authenticationPath(client), manageToken,
			api.UpdateClientAuthenticationRequest{IsPublic: false, ClientSecret: securerandom.String(60)})
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("manage-clients makes it public, which clears the list", func(t *testing.T) {
		client := newIntrospectingClient(t)
		listIntrospectionResource(t, client.Id, authServer)

		resp := makeAPIRequest(t, http.MethodPut, authenticationPath(client), clientsToken,
			api.UpdateClientAuthenticationRequest{IsPublic: true})
		_ = resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Empty(t, storedIntrospectionResourceIds(t, client.Id))
	})

	t.Run("manage-clients reads the secret of a client listed for another resource", func(t *testing.T) {
		client := newIntrospectingClient(t)
		listIntrospectionResource(t, client.Id, newAPIResource(t).Id)

		resp := makeAPIRequest(t, http.MethodGet, secretPath(client), clientsToken, nil)
		_ = resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

// The route is held to the client permissions' scopes: admin-read reads, manage-clients writes, and
// another domain's scope reaches neither.
func TestAPIClientIntrospectionResources_HeldToTheClientsScopes(t *testing.T) {
	client := newIntrospectingClient(t)
	resource := newAPIResource(t)

	readToken, reader := createClientWithGranularScope(t, builtin.AdminReadPermissionIdentifier)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, reader.Id) })
	usersToken, users := createClientWithGranularScope(t, builtin.ManageUsersPermissionIdentifier)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, users.Id) })

	resp, raw := getIntrospectionResources(t, readToken, client.Id)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "admin-read reads the list: %s", raw)

	resp, _ = putIntrospectionResources(t, readToken, client.Id, []int64{resource.Id}, []int64{})
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	code, _ := errorEnvelope(t, resp)
	assert.Equal(t, "INSUFFICIENT_SCOPE", code, "admin-read writes nothing")

	resp, _ = getIntrospectionResources(t, usersToken, client.Id)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "manage-users reaches no client")
	resp, _ = putIntrospectionResources(t, usersToken, client.Id, []int64{resource.Id}, []int64{})
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	code, _ = errorEnvelope(t, resp)
	assert.Equal(t, "INSUFFICIENT_SCOPE", code)

	assert.Empty(t, storedIntrospectionResourceIds(t, client.Id))
}

// A write to an administrator client is authserver:manage's, this one included (#402 decision 1).
func TestAPIClientIntrospectionResources_AGranularTokenCannotEditAnAdministratorClient(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)
	clientsToken, caller := createClientWithGranularScope(t, builtin.ManageClientsPermissionIdentifier)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, caller.Id) })
	client := newIntrospectingClient(t)
	require.NoError(t, database.CreateClientPermission(context.Background(), nil, &record.ClientPermission{
		ClientId: client.Id, PermissionId: authServerPermissionId(t, builtin.AdminReadPermissionIdentifier),
	}))
	resource := newAPIResource(t)

	resp, requestId := putIntrospectionResources(t, clientsToken, client.Id, []int64{resource.Id}, []int64{})

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	code, _ := errorEnvelope(t, resp)
	assert.Equal(t, "MANAGE_SCOPE_REQUIRED", code)
	assert.Empty(t, storedIntrospectionResourceIds(t, client.Id))
	rows := auditRows(t, manageToken, "administrator_change_refused", requestId)
	require.Len(t, rows, 1)
	assert.Equal(t, "target", rows[0]["ceiling"])
	assert.Equal(t, "client", rows[0]["target_kind"])

	resp, _ = putIntrospectionResources(t, manageToken, client.Id, []int64{resource.Id}, []int64{})
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "authserver:manage edits it")
	assert.Equal(t, []int64{resource.Id}, storedIntrospectionResourceIds(t, client.Id))
}
