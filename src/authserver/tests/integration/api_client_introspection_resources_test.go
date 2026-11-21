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

func introspectionResourcesPath(clientID int64) string {
	return fmt.Sprintf("/api/v1/admin/clients/%d/introspection-resources", clientID)
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
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.ID) })
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
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.ID) })
	return client
}

// newAPIResource is a resource, removed when the test ends.
func newAPIResource(t *testing.T) *record.Resource {
	t.Helper()
	resource := createTestResource(t, "intro-api-"+strings.ToLower(fake.LetterN(8)), "An API")
	t.Cleanup(func() { _ = database.DeleteResource(context.Background(), nil, resource.ID) })
	return resource
}

func authServerResourceID(t *testing.T) int64 {
	t.Helper()
	resource, err := database.GetResourceByResourceIdentifier(context.Background(), nil, builtin.AuthServerResourceIdentifier)
	require.NoError(t, err)
	require.NotNil(t, resource)
	return resource.ID
}

// storedIntrospectionResourceIDs is the client's list as the database holds it.
func storedIntrospectionResourceIDs(t *testing.T, clientID int64) []int64 {
	t.Helper()
	links, err := database.GetClientIntrospectionResourcesByClientID(context.Background(), nil, clientID)
	require.NoError(t, err)
	ids := []int64{}
	for _, link := range links {
		ids = append(ids, link.ResourceID)
	}
	return ids
}

func listIntrospectionResource(t *testing.T, clientID, resourceID int64) {
	t.Helper()
	require.NoError(t, database.CreateClientIntrospectionResource(context.Background(), nil,
		&record.ClientIntrospectionResource{ClientID: clientID, ResourceID: resourceID}))
}

// putIntrospectionResources sends a save under its own request id, so the audit rows it leaves can
// be read back by that id alone. A nil expected is sent as JSON null.
func putIntrospectionResources(t *testing.T, accessToken string, clientID int64, wanted, expected []int64) (*http.Response, string) {
	t.Helper()
	if wanted == nil {
		wanted = []int64{}
	}
	body, err := json.Marshal(map[string]any{"resourceIds": wanted, "expectedResourceIds": expected})
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPut, appConfig.AuthServer.BaseURL+introspectionResourcesPath(clientID), bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	requestID := "introspect-" + fake.LetterN(16)
	req.Header.Set("X-Request-Id", requestID)

	resp, err := createHTTPClient(t).Do(req)
	require.NoError(t, err)
	return resp, requestID
}

func getIntrospectionResources(t *testing.T, accessToken string, clientID int64) (*http.Response, []byte) {
	t.Helper()
	resp := makeAPIRequest(t, http.MethodGet, appConfig.AuthServer.BaseURL+introspectionResourcesPath(clientID), accessToken, nil)
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
	listIntrospectionResource(t, client.ID, first.ID)
	listIntrospectionResource(t, client.ID, second.ID)

	resp, raw := getIntrospectionResources(t, manageToken, client.ID)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var body api.GetClientIntrospectionResourcesResponse
	require.NoError(t, json.Unmarshal(raw, &body))
	assert.Equal(t, client.ID, body.Client.ID)
	assert.Equal(t, client.ClientIdentifier, body.Client.ClientIdentifier)
	assert.ElementsMatch(t, []api.ResourceResponse{
		{ID: first.ID, ResourceIdentifier: first.ResourceIdentifier, Description: "An API"},
		{ID: second.ID, ResourceIdentifier: second.ResourceIdentifier, Description: "An API"},
	}, body.Resources)
}

func TestAPIClientIntrospectionResources_GetAnswersAnEmptyListAsAnArray(t *testing.T) {
	manageToken, _ := createAdminClientWithToken(t)
	client := newIntrospectingClient(t)

	resp, raw := getIntrospectionResources(t, manageToken, client.ID)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	var body map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &body))
	assert.Equal(t, "[]", string(body["resources"]), "a client listing nothing answers [], never null")
}

func TestAPIClientIntrospectionResources_GetRefusesABadIDAndAnUnknownClient(t *testing.T) {
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
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, caller.ID) })
	client := newIntrospectingClient(t)
	kept := newAPIResource(t)
	dropped := newAPIResource(t)
	added := newAPIResource(t)

	resp, requestID := putIntrospectionResources(t, clientsToken, client.ID, []int64{kept.ID, dropped.ID, kept.ID}, []int64{})
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "authserver:manage-clients edits a client's list")
	assert.ElementsMatch(t, []int64{kept.ID, dropped.ID}, storedIntrospectionResourceIDs(t, client.ID), "a repeated id is listed once")
	rows := auditRows(t, manageToken, "updated_client_introspection_resources", requestID)
	require.Len(t, rows, 1, "one record for the save")
	assert.InDelta(t, float64(client.ID), rows[0]["client_id"], 0)
	assert.Equal(t, []int64{kept.ID, dropped.ID}, idsOf(t, rows[0]["added_resource_ids"]), "in the order the save named them")
	assert.Equal(t, []int64{}, idsOf(t, rows[0]["removed_resource_ids"]))
	assert.Equal(t, caller.ClientIdentifier, rows[0]["logged_in_user"])

	resp, requestID = putIntrospectionResources(t, clientsToken, client.ID, []int64{kept.ID, added.ID}, []int64{dropped.ID, kept.ID})
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.ElementsMatch(t, []int64{kept.ID, added.ID}, storedIntrospectionResourceIDs(t, client.ID))
	rows = auditRows(t, manageToken, "updated_client_introspection_resources", requestID)
	require.Len(t, rows, 1)
	assert.Equal(t, []int64{added.ID}, idsOf(t, rows[0]["added_resource_ids"]))
	assert.Equal(t, []int64{dropped.ID}, idsOf(t, rows[0]["removed_resource_ids"]))

	resp, raw := getIntrospectionResources(t, clientsToken, client.ID)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	var body api.GetClientIntrospectionResourcesResponse
	require.NoError(t, json.Unmarshal(raw, &body))
	var identifiers []string
	for _, resource := range body.Resources {
		identifiers = append(identifiers, resource.ResourceIdentifier)
	}
	assert.ElementsMatch(t, []string{kept.ResourceIdentifier, added.ResourceIdentifier}, identifiers, "the read answers what the save stored")

	resp, _ = putIntrospectionResources(t, clientsToken, client.ID, []int64{}, []int64{kept.ID, added.ID})
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, storedIntrospectionResourceIDs(t, client.ID), "and an empty list empties it")
}

func TestAPIClientIntrospectionResources_PutRefusesWhatItCannotSave(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)
	client := newIntrospectingClient(t)
	listed := newAPIResource(t)
	other := newAPIResource(t)
	listIntrospectionResource(t, client.ID, listed.ID)

	t.Run("expectedResourceIds is required", func(t *testing.T) {
		resp, requestID := putIntrospectionResources(t, manageToken, client.ID, []int64{other.ID}, nil)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		code, _ := errorEnvelope(t, resp)
		assert.Equal(t, "VALIDATION_ERROR", code)
		assert.Equal(t, []int64{listed.ID}, storedIntrospectionResourceIDs(t, client.ID), "nothing was saved")
		assert.Empty(t, auditRows(t, manageToken, "updated_client_introspection_resources", requestID))
	})

	t.Run("a list read before another save is a 409", func(t *testing.T) {
		resp, requestID := putIntrospectionResources(t, manageToken, client.ID, []int64{other.ID}, []int64{})
		assert.Equal(t, http.StatusConflict, resp.StatusCode)
		code, _ := errorEnvelope(t, resp)
		assert.Equal(t, "CONCURRENT_UPDATE", code)
		assert.Equal(t, []int64{listed.ID}, storedIntrospectionResourceIDs(t, client.ID), "nothing was saved")
		assert.Empty(t, auditRows(t, manageToken, "updated_client_introspection_resources", requestID))
	})

	t.Run("an unknown resource is a 404", func(t *testing.T) {
		resp, _ := putIntrospectionResources(t, manageToken, client.ID, []int64{listed.ID, 99999999}, []int64{listed.ID})
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		code, description := errorEnvelope(t, resp)
		assert.Equal(t, "NOT_FOUND", code)
		assert.Equal(t, "Resource not found", description)
		assert.Equal(t, []int64{listed.ID}, storedIntrospectionResourceIDs(t, client.ID), "nothing was saved")
	})

	t.Run("an unknown client is a 404", func(t *testing.T) {
		resp, _ := putIntrospectionResources(t, manageToken, 99999999, []int64{listed.ID}, []int64{})
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

	resp, _ := putIntrospectionResources(t, manageToken, client.ID, []int64{resource.ID}, []int64{})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	code, description := errorEnvelope(t, resp)
	assert.Equal(t, "handler.client_introspection_resources.public_client", code)
	assert.Equal(t, "A public client can't introspect tokens, so it can't list introspection resources.", description)
	assert.Empty(t, storedIntrospectionResourceIDs(t, client.ID), "nothing was saved")

	resp, _ = putIntrospectionResources(t, manageToken, client.ID, []int64{}, []int64{})
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "an empty list is a public client's own")
}

// Making a client public clears its list, in the transaction that revokes its grants.
func TestAPIClientIntrospectionResources_MakingTheClientPublicClearsTheList(t *testing.T) {
	manageToken, _ := createAdminClientWithToken(t)
	client := newIntrospectingClient(t)
	other := newIntrospectingClient(t)
	resource := newAPIResource(t)
	listIntrospectionResource(t, client.ID, resource.ID)
	listIntrospectionResource(t, other.ID, resource.ID)

	resp := makeAPIRequest(t, http.MethodPut,
		fmt.Sprintf("%s/api/v1/admin/clients/%d/authentication", appConfig.AuthServer.BaseURL, client.ID),
		manageToken, api.UpdateClientAuthenticationRequest{IsPublic: true})
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	assert.Empty(t, storedIntrospectionResourceIDs(t, client.ID), "the client made public lists nothing")
	assert.Equal(t, []int64{resource.ID}, storedIntrospectionResourceIDs(t, other.ID), "another client keeps its list")

	// Made confidential again, the client starts with an empty list rather than its old one.
	resp = makeAPIRequest(t, http.MethodPut,
		fmt.Sprintf("%s/api/v1/admin/clients/%d/authentication", appConfig.AuthServer.BaseURL, client.ID),
		manageToken, api.UpdateClientAuthenticationRequest{IsPublic: false, ClientSecret: securerandom.String(60)})
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, storedIntrospectionResourceIDs(t, client.ID))
}

// Listing the authserver resource lets a client read the claims of every sign-in token, so only
// authserver:manage adds it (#676 decision 14).
func TestAPIClientIntrospectionResources_OnlyManageListsTheAuthServerResource(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)
	clientsToken, caller := createClientWithGranularScope(t, builtin.ManageClientsPermissionIdentifier)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, caller.ID) })
	authServer := authServerResourceID(t)
	ordinary := newAPIResource(t)

	t.Run("manage-clients is refused", func(t *testing.T) {
		client := newIntrospectingClient(t)

		resp, requestID := putIntrospectionResources(t, clientsToken, client.ID, []int64{ordinary.ID, authServer}, []int64{})

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		challenge := resp.Header.Get("WWW-Authenticate")
		assert.Contains(t, challenge, `error="insufficient_scope"`)
		assert.Contains(t, challenge, `scope="authserver:manage"`)
		code, _ := errorEnvelope(t, resp)
		assert.Equal(t, "MANAGE_SCOPE_REQUIRED", code)
		assert.Empty(t, storedIntrospectionResourceIDs(t, client.ID), "the refused save wrote nothing, the ordinary resource included")
		assert.Empty(t, auditRows(t, manageToken, "updated_client_introspection_resources", requestID))

		rows := auditRows(t, manageToken, "administrator_change_refused", requestID)
		require.Len(t, rows, 1, "exactly one administrator_change_refused row")
		assert.Equal(t, caller.ClientIdentifier, rows[0]["logged_in_user"])
		assert.Equal(t, http.MethodPut, rows[0]["method"])
		assert.Equal(t, "/api/v1/admin/clients/{id}/introspection-resources", rows[0]["route"])
		assert.Equal(t, "grant", rows[0]["ceiling"])
		assert.Equal(t, "client", rows[0]["target_kind"])
		assert.InDelta(t, float64(client.ID), rows[0]["target_id"], 0)
		assert.Equal(t, []int64{authServer}, idsOf(t, rows[0]["resource_ids"]))
		assert.NotContains(t, rows[0], "permission_ids")
	})

	t.Run("manage lists it", func(t *testing.T) {
		client := newIntrospectingClient(t)

		resp, requestID := putIntrospectionResources(t, manageToken, client.ID, []int64{authServer}, []int64{})
		_ = resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, []int64{authServer}, storedIntrospectionResourceIDs(t, client.ID))
		assert.Empty(t, auditRows(t, manageToken, "administrator_change_refused", requestID))
	})

	t.Run("manage-clients edits the rest of a list that already holds it, and removes it", func(t *testing.T) {
		client := newIntrospectingClient(t)
		listIntrospectionResource(t, client.ID, authServer)

		resp, _ := putIntrospectionResources(t, clientsToken, client.ID, []int64{authServer, ordinary.ID}, []int64{authServer})
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode, "keeping authserver listed adds nothing the ceiling guards")
		assert.ElementsMatch(t, []int64{authServer, ordinary.ID}, storedIntrospectionResourceIDs(t, client.ID))

		resp, _ = putIntrospectionResources(t, clientsToken, client.ID, []int64{ordinary.ID}, []int64{authServer, ordinary.ID})
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode, "removing it takes nothing away from anyone's sign-in")
		assert.Equal(t, []int64{ordinary.ID}, storedIntrospectionResourceIDs(t, client.ID))
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
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, caller.ID) })
	authServer := authServerResourceID(t)
	secretPath := func(client *record.Client) string {
		return fmt.Sprintf("%s/api/v1/admin/clients/%d/secret", appConfig.AuthServer.BaseURL, client.ID)
	}
	authenticationPath := func(client *record.Client) string {
		return fmt.Sprintf("%s/api/v1/admin/clients/%d/authentication", appConfig.AuthServer.BaseURL, client.ID)
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
		requestID := "introspect-secret-" + fake.LetterN(16)
		req.Header.Set("X-Request-Id", requestID)
		resp, err := createHTTPClient(t).Do(req)
		require.NoError(t, err)
		return resp, requestID
	}
	assertRefused := func(t *testing.T, resp *http.Response, requestID string, client *record.Client, route string) {
		t.Helper()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		assert.Contains(t, resp.Header.Get("WWW-Authenticate"), `scope="authserver:manage"`)
		code, _ := errorEnvelope(t, resp)
		assert.Equal(t, "MANAGE_SCOPE_REQUIRED", code)
		rows := auditRows(t, manageToken, "administrator_change_refused", requestID)
		require.Len(t, rows, 1, "exactly one administrator_change_refused row")
		assert.Equal(t, caller.ClientIdentifier, rows[0]["logged_in_user"])
		assert.Equal(t, route, rows[0]["route"])
		assert.Equal(t, "target", rows[0]["ceiling"])
		assert.Equal(t, "client", rows[0]["target_kind"])
		assert.InDelta(t, float64(client.ID), rows[0]["target_id"], 0)
	}

	t.Run("manage-clients cannot read its secret", func(t *testing.T) {
		client := newIntrospectingClient(t)
		listIntrospectionResource(t, client.ID, authServer)

		resp, requestID := send(t, http.MethodGet, secretPath(client), clientsToken, nil)
		defer func() { _ = resp.Body.Close() }()

		assertRefused(t, resp, requestID, client, "/api/v1/admin/clients/{id}/secret")
	})

	t.Run("manage-clients cannot set its secret", func(t *testing.T) {
		client := newIntrospectingClient(t)
		listIntrospectionResource(t, client.ID, authServer)

		resp, requestID := send(t, http.MethodPut, authenticationPath(client), clientsToken,
			api.UpdateClientAuthenticationRequest{IsPublic: false, ClientSecret: securerandom.String(60)})
		defer func() { _ = resp.Body.Close() }()

		assertRefused(t, resp, requestID, client, "/api/v1/admin/clients/{id}/authentication")
		stored, err := database.GetClientByID(context.Background(), nil, client.ID)
		require.NoError(t, err)
		assert.Equal(t, client.ClientSecretEncrypted, stored.ClientSecretEncrypted, "the secret is the one it had")
	})

	t.Run("manage reads and sets it", func(t *testing.T) {
		client := newIntrospectingClient(t)
		listIntrospectionResource(t, client.ID, authServer)

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
		listIntrospectionResource(t, client.ID, authServer)

		resp := makeAPIRequest(t, http.MethodPut, authenticationPath(client), clientsToken,
			api.UpdateClientAuthenticationRequest{IsPublic: true})
		_ = resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Empty(t, storedIntrospectionResourceIDs(t, client.ID))
	})

	t.Run("manage-clients reads the secret of a client listed for another resource", func(t *testing.T) {
		client := newIntrospectingClient(t)
		listIntrospectionResource(t, client.ID, newAPIResource(t).ID)

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
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, reader.ID) })
	usersToken, users := createClientWithGranularScope(t, builtin.ManageUsersPermissionIdentifier)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, users.ID) })

	resp, raw := getIntrospectionResources(t, readToken, client.ID)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "admin-read reads the list: %s", raw)

	resp, _ = putIntrospectionResources(t, readToken, client.ID, []int64{resource.ID}, []int64{})
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	code, _ := errorEnvelope(t, resp)
	assert.Equal(t, "INSUFFICIENT_SCOPE", code, "admin-read writes nothing")

	resp, _ = getIntrospectionResources(t, usersToken, client.ID)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "manage-users reaches no client")
	resp, _ = putIntrospectionResources(t, usersToken, client.ID, []int64{resource.ID}, []int64{})
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	code, _ = errorEnvelope(t, resp)
	assert.Equal(t, "INSUFFICIENT_SCOPE", code)

	assert.Empty(t, storedIntrospectionResourceIDs(t, client.ID))
}

// A write to an administrator client is authserver:manage's, this one included (#402 decision 1).
func TestAPIClientIntrospectionResources_AGranularTokenCannotEditAnAdministratorClient(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)
	clientsToken, caller := createClientWithGranularScope(t, builtin.ManageClientsPermissionIdentifier)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, caller.ID) })
	client := newIntrospectingClient(t)
	require.NoError(t, database.CreateClientPermission(context.Background(), nil, &record.ClientPermission{
		ClientID: client.ID, PermissionID: authServerPermissionID(t, builtin.AdminReadPermissionIdentifier),
	}))
	resource := newAPIResource(t)

	resp, requestID := putIntrospectionResources(t, clientsToken, client.ID, []int64{resource.ID}, []int64{})

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	code, _ := errorEnvelope(t, resp)
	assert.Equal(t, "MANAGE_SCOPE_REQUIRED", code)
	assert.Empty(t, storedIntrospectionResourceIDs(t, client.ID))
	rows := auditRows(t, manageToken, "administrator_change_refused", requestID)
	require.Len(t, rows, 1)
	assert.Equal(t, "target", rows[0]["ceiling"])
	assert.Equal(t, "client", rows[0]["target_kind"])

	resp, _ = putIntrospectionResources(t, manageToken, client.ID, []int64{resource.ID}, []int64{})
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "authserver:manage edits it")
	assert.Equal(t, []int64{resource.ID}, storedIntrospectionResourceIDs(t, client.ID))
}
