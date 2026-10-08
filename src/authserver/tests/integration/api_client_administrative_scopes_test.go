package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A client's allowance to request the administrative scopes, switched through its own Admin API
// route. Only authserver:manage switches it; manage-clients, which the route admits, is refused 403
// MANAGE_SCOPE_REQUIRED with the administrator_change_refused record every other #402 refusal
// leaves. An allowed client is an administrator client, so every other write to it is
// authserver:manage's too. The admin console's client is always allowed and cannot be switched off.
// Every client response carries the allowance, read-only (#499 decisions 4, 5 and 9).

// administrativeScopesRoute is the route's pattern, as a refusal records it.
const administrativeScopesRoute = "/api/v1/admin/clients/{id}/administrative-scopes"

// putAdministrativeScopes sends the switch for clientId with body, under its own request id.
func putAdministrativeScopes(t *testing.T, accessToken string, clientId int64, body any) (*http.Response, string) {
	t.Helper()
	return sendAdmin(t, accessToken, http.MethodPut, fmt.Sprintf("/api/v1/admin/clients/%d/administrative-scopes", clientId), body)
}

// switchedClient decodes a 200 from the switch, failing on any other answer.
func switchedClient(t *testing.T, resp *http.Response) api.ClientResponse {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	var decoded api.UpdateClientResponse
	require.NoError(t, json.Unmarshal(body, &decoded))
	return decoded.Client
}

// allowanceSwitchRows is the updated_client_administrative_scopes rows one request left, details
// decoded.
func allowanceSwitchRows(t *testing.T, readerToken, requestId string) []map[string]any {
	t.Helper()
	logs, resp := getAuditLogs(t, readerToken,
		"auditEvent=updated_client_administrative_scopes&requestId="+url.QueryEscape(requestId))
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	rows := []map[string]any{}
	for _, entry := range logs.AuditLogs {
		var details map[string]any
		require.NoError(t, json.Unmarshal([]byte(entry.Details), &details))
		rows = append(rows, details)
	}
	return rows
}

// errorCodeOf decodes an error answer's error_code, closing the body.
func errorCodeOf(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	var envelope struct {
		ErrorCode string `json:"error_code"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&envelope))
	return envelope.ErrorCode
}

// The switch, on and off, by authserver:manage: each answers the client as it now is, the store
// says the same, and each leaves one updated_client_administrative_scopes row naming the client, the
// new value and the caller.
func TestClientAdministrativeScopes_AManageTokenSwitchesTheAllowance(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, manageCaller := createAdminClientWithToken(t)
	f := newTargetClient(t)
	require.False(t, storedClient(t, f.clientId).AdministrativeScopesAllowed, "a new client starts not allowed")

	for _, allowed := range []bool{true, false} {
		resp, requestId := putAdministrativeScopes(t, manageToken, f.clientId, map[string]any{"allowed": allowed})
		client := switchedClient(t, resp)

		assert.Equal(t, f.clientId, client.Id)
		assert.Equal(t, allowed, client.AdministrativeScopesAllowed, "the answer is the client as switched")
		assert.Equal(t, allowed, storedClient(t, f.clientId).AdministrativeScopesAllowed, "the store is switched")

		rows := allowanceSwitchRows(t, manageToken, requestId)
		require.Len(t, rows, 1, "one updated_client_administrative_scopes row for the switch to %v", allowed)
		assert.Equal(t, map[string]any{
			"client_id":         float64(f.clientId),
			"client_identifier": f.identifier,
			"allowed":           allowed,
			"logged_in_user":    manageCaller.ClientIdentifier,
		}, rows[0])
		assert.Empty(t, refusalRows(t, manageToken, requestId))
	}
}

// manage-clients reaches the route, as it reaches every client write, and is refused whichever way
// it asks and whatever the client is: switching the allowance on is making an administrator, and
// off is changing one. Nothing is written and no switch is recorded.
func TestClientAdministrativeScopes_AGranularTokenIsRefused(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)
	granularToken, caller := createClientWithGranularScope(t, builtin.ManageClientsPermissionIdentifier)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, caller.Id) })

	for _, allowed := range []bool{true, false} {
		t.Run(fmt.Sprintf("an ordinary client switched to %v", allowed), func(t *testing.T) {
			f := newTargetClient(t)

			resp, requestId := putAdministrativeScopes(t, granularToken, f.clientId, map[string]any{"allowed": allowed})

			assertRefusedByTheTargetCeiling(t, resp, requestId, manageToken, caller,
				targetCeilingWrite{method: http.MethodPut, route: administrativeScopesRoute, kind: "client"}, f.clientId)
			assert.False(t, storedClient(t, f.clientId).AdministrativeScopesAllowed, "the refused switch wrote nothing")
			assert.Empty(t, allowanceSwitchRows(t, manageToken, requestId))
		})
	}

	t.Run("an allowed client switched off", func(t *testing.T) {
		f := newTargetClient(t)
		switchedClient(t, first(putAdministrativeScopes(t, manageToken, f.clientId, map[string]any{"allowed": true})))

		resp, requestId := putAdministrativeScopes(t, granularToken, f.clientId, map[string]any{"allowed": false})

		assertRefusedByTheTargetCeiling(t, resp, requestId, manageToken, caller,
			targetCeilingWrite{method: http.MethodPut, route: administrativeScopesRoute, kind: "client"}, f.clientId)
		assert.True(t, storedClient(t, f.clientId).AdministrativeScopesAllowed, "the refused switch wrote nothing")
		assert.Empty(t, allowanceSwitchRows(t, manageToken, requestId))
	})
}

// admin-read reads every client and writes none: the route gate refuses it, with its own code and
// no record of the policy's.
func TestClientAdministrativeScopes_AdminReadDoesNotReachTheRoute(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)
	readToken, caller := createClientWithGranularScope(t, builtin.AdminReadPermissionIdentifier)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, caller.Id) })
	f := newTargetClient(t)

	resp, requestId := putAdministrativeScopes(t, readToken, f.clientId, map[string]any{"allowed": true})

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, "INSUFFICIENT_SCOPE", errorCodeOf(t, resp))
	assert.False(t, storedClient(t, f.clientId).AdministrativeScopesAllowed)
	assert.Empty(t, refusalRows(t, manageToken, requestId))
}

// The admin console's client is always allowed: switching it off is refused 400 VALIDATION_ERROR,
// to authserver:manage as to anyone, and leaves it allowed; switching it on changes nothing and is
// answered as any switch is.
func TestClientAdministrativeScopes_TheAdminConsolesClientCannotBeSwitchedOff(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)
	console := consoleClient(t)
	require.True(t, storedClient(t, console.clientId).AdministrativeScopesAllowed, "the seed allows the admin console's client")

	resp, requestId := putAdministrativeScopes(t, manageToken, console.clientId, map[string]any{"allowed": false})

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "VALIDATION_ERROR", errorCodeOf(t, resp))
	assert.True(t, storedClient(t, console.clientId).AdministrativeScopesAllowed, "the admin console's client stays allowed")
	assert.Empty(t, allowanceSwitchRows(t, manageToken, requestId))

	client := switchedClient(t, first(putAdministrativeScopes(t, manageToken, console.clientId, map[string]any{"allowed": true})))
	assert.True(t, client.AdministrativeScopesAllowed)
	assert.True(t, client.IsSystemLevelClient)
}

// The request's own 400s and 404 come before the policy, and none of them writes.
func TestClientAdministrativeScopes_TheRouteAnswersItsOwnFourHundreds(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)
	f := newTargetClient(t)

	for _, c := range []struct {
		name   string
		path   string
		body   any
		status int
		code   string
	}{
		{"no allowed field", fmt.Sprintf("/api/v1/admin/clients/%d/administrative-scopes", f.clientId), map[string]any{}, http.StatusBadRequest, "VALIDATION_ERROR"},
		{"a null allowed", fmt.Sprintf("/api/v1/admin/clients/%d/administrative-scopes", f.clientId), map[string]any{"allowed": nil}, http.StatusBadRequest, "VALIDATION_ERROR"},
		{"a string allowed", fmt.Sprintf("/api/v1/admin/clients/%d/administrative-scopes", f.clientId), map[string]any{"allowed": "true"}, http.StatusBadRequest, "INVALID_REQUEST_BODY"},
		{"no body", fmt.Sprintf("/api/v1/admin/clients/%d/administrative-scopes", f.clientId), nil, http.StatusBadRequest, "INVALID_REQUEST_BODY"},
		{"an id that is no number", "/api/v1/admin/clients/abc/administrative-scopes", map[string]any{"allowed": true}, http.StatusBadRequest, "VALIDATION_ERROR"},
		{"a client that does not exist", "/api/v1/admin/clients/999999999/administrative-scopes", map[string]any{"allowed": true}, http.StatusNotFound, "NOT_FOUND"},
	} {
		t.Run(c.name, func(t *testing.T) {
			resp, requestId := sendAdmin(t, manageToken, http.MethodPut, c.path, c.body)

			assert.Equal(t, c.status, resp.StatusCode)
			assert.Equal(t, c.code, errorCodeOf(t, resp))
			assert.Empty(t, allowanceSwitchRows(t, manageToken, requestId))
		})
	}
	assert.False(t, storedClient(t, f.clientId).AdministrativeScopesAllowed, "no refused request wrote")
}

// An allowed client is an administrator client: once authserver:manage has allowed it, manage-clients
// is refused every write to it and its secret, exactly as for a client holding an administrative
// permission (#499 decision 4).
func TestClientAdministrativeScopes_AnAllowedClientIsAnAdministratorClient(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)
	granularToken, caller := createClientWithGranularScope(t, builtin.ManageClientsPermissionIdentifier)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, caller.Id) })
	ordinary := ordinaryPermission(t)

	for _, route := range clientTargetCeilingRoutes {
		t.Run(route.name, func(t *testing.T) {
			// It holds no permission at all: the allowance alone makes it an administrator.
			f := newTargetClient(t)
			switchedClient(t, first(putAdministrativeScopes(t, manageToken, f.clientId, map[string]any{"allowed": true})))
			f.ordinaryPermissionId = ordinary
			f.readerToken = manageToken
			route.prepare(t, f)

			resp, requestId := route.send(t, granularToken, f)

			assertClientRefusedByTheTargetCeiling(t, resp, requestId, manageToken, caller, route, f.clientId)
			assert.False(t, route.changed(t, f), "the refused request changed nothing")
		})
	}
}

// Every client response carries the allowance as it is, and no other request sets it: the settings
// save ignores the field, from authserver:manage too.
func TestClientAdministrativeScopes_EveryClientResponseCarriesTheAllowanceReadOnly(t *testing.T) {
	manageToken, _ := createAdminClientWithToken(t)
	allowed := newTargetClient(t)
	switchedClient(t, first(putAdministrativeScopes(t, manageToken, allowed.clientId, map[string]any{"allowed": true})))
	notAllowed := newTargetClient(t)
	console := consoleClient(t)
	want := map[int64]bool{allowed.clientId: true, notAllowed.clientId: false, console.clientId: true}

	for id, w := range want {
		resp, _ := sendAdmin(t, manageToken, http.MethodGet, fmt.Sprintf("/api/v1/admin/clients/%d", id), nil)
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
		assert.Containsf(t, string(body), fmt.Sprintf(`"administrativeScopesAllowed":%v`, w),
			"GET /clients/%d spells the field on the wire", id)
		var detail api.GetClientResponse
		require.NoError(t, json.Unmarshal(body, &detail))
		assert.Equalf(t, w, detail.Client.AdministrativeScopesAllowed, "GET /clients/%d", id)
	}

	resp, _ := sendAdmin(t, manageToken, http.MethodGet, "/api/v1/admin/clients", nil)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var list api.GetClientsResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&list))
	seen := 0
	for _, client := range list.Clients {
		if w, ok := want[client.Id]; ok {
			seen++
			assert.Equalf(t, w, client.AdministrativeScopesAllowed, "GET /clients, client %d", client.Id)
		}
	}
	assert.Equal(t, len(want), seen)

	for id, w := range map[int64]bool{allowed.clientId: true, notAllowed.clientId: false} {
		stored := storedClient(t, id)
		resp, _ := sendAdmin(t, manageToken, http.MethodPut, fmt.Sprintf("/api/v1/admin/clients/%d", id), map[string]any{
			"clientIdentifier": stored.ClientIdentifier, "description": "Saved", "enabled": true,
			"administrativeScopesAllowed": !w,
		})
		client := switchedClient(t, resp)
		assert.Equal(t, w, client.AdministrativeScopesAllowed, "the settings save answers the allowance as stored")
		assert.Equal(t, w, storedClient(t, id).AdministrativeScopesAllowed, "the settings save does not set the allowance")
	}
}

// The switch is what the authorization endpoint reads: the crafted link from a client
// authserver:manage has allowed gets its code, and once the allowance is switched off again the same
// link is refused invalid_scope.
func TestClientAdministrativeScopes_TheSwitchDecidesTheAuthorizationEndpointsAnswer(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)
	f := newAdministrativeScopeFixture(t, false)
	switchedClient(t, first(putAdministrativeScopes(t, manageToken, f.client.Id, map[string]any{"allowed": true})))

	resp := f.signInFrom(t, f.craftedLink("code", ""))
	codeVal, state := getCodeAndStateFromUrl(t, resp)
	_ = resp.Body.Close()
	assert.Equal(t, administrativeScopeState, state)
	assert.Equal(t, "openid authserver:manage", loadCodeFromDatabase(t, codeVal).Scope)

	switchedClient(t, first(putAdministrativeScopes(t, manageToken, f.client.Id, map[string]any{"allowed": false})))

	resp = f.get(t, f.craftedLink("code", ""))
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	location := resp.Header.Get("Location")
	assert.True(t, strings.HasPrefix(location, administrativeScopeRedirectURI+"?error=invalid_scope"), location)
	assert.NotContains(t, location, "code=")
}

// An allowance switched off through the route while a sign-in is under way takes effect at
// /auth/issue, the last hop before a code or a token is minted: the client is answered invalid_scope
// with nothing issued, and the refusal is recorded at the issue checkpoint (#499 decisions 6, 7 and
// 9). Consent is switched on so the ceremony parks on its consent screen, one hop from issuing, which
// is where the allowance is withdrawn; both flows run, because they reach different issuers behind the
// same check.
func TestClientAdministrativeScopes_AnAllowanceWithdrawnDuringTheSignInRefusesItAtIssue(t *testing.T) {
	for _, flow := range recheckFlows {
		t.Run(flow.name, func(t *testing.T) {
			requireDatabaseAuditLogs(t)
			manageToken, _ := createAdminClientWithToken(t)
			f := newAdministrativeScopeFixture(t, false)
			switchedClient(t, first(putAdministrativeScopes(t, manageToken, f.client.Id, map[string]any{"allowed": true})))
			f.client.ConsentRequired = true
			f.client.AdministrativeScopesAllowed = true
			require.NoError(t, database.UpdateClient(context.Background(), nil, f.client))

			resp := f.get(t, f.craftedLink(flow.responseType, ""))
			location := assertRedirect(t, resp, "/auth/level1")
			_ = resp.Body.Close()
			resp = loadPage(t, f.browser, location)
			location = assertRedirect(t, resp, "/auth/pwd")
			_ = resp.Body.Close()
			passwordPage := loadPage(t, f.browser, location)
			resp = authenticateWithPassword(t, f.browser, location, passwordPage, f.user.Email, f.password)
			_ = passwordPage.Body.Close()
			location = assertRedirect(t, resp, "/auth/level1completed")
			_ = resp.Body.Close()
			resp = loadPage(t, f.browser, location)
			location = assertRedirect(t, resp, "/auth/completed")
			_ = resp.Body.Close()
			resp = loadPage(t, f.browser, location)
			consentURL := assertRedirect(t, resp, "/auth/consent")
			_ = resp.Body.Close()
			consentPage := loadPage(t, f.browser, consentURL)
			require.Equal(t, http.StatusOK, consentPage.StatusCode)
			resp = postConsent(t, f.browser, consentURL, consentPage, []int{0, 1})
			_ = consentPage.Body.Close()
			issueURL := assertRedirect(t, resp, "/auth/issue")
			_ = resp.Body.Close()

			switchedClient(t, first(putAdministrativeScopes(t, manageToken, f.client.Id, map[string]any{"allowed": false})))

			resp = loadPage(t, f.browser, issueURL)
			defer func() { _ = resp.Body.Close() }()
			destination, params := clientAnswer(t, resp, flow.responseType)
			assert.Equal(t, administrativeScopeRedirectURI, destination)
			assert.Equal(t, "invalid_scope", params.Get("error"))
			assert.Equal(t, administrativeScopeRefusal, params.Get("error_description"))
			assert.Equal(t, administrativeScopeState, params.Get("state"))
			for _, field := range []string{"code", "access_token", "id_token"} {
				assert.Empty(t, params.Get(field), "no %s is issued", field)
			}

			rows := administrativeScopeRefusedRows(t, f.client.ClientIdentifier)
			require.Len(t, rows, 1)
			assert.Equal(t, "issue", rows[0]["checkpoint"])
			assert.Equal(t, float64(f.user.Id), rows[0]["user_id"])
			assert.Equal(t, []any{"authserver:manage"}, rows[0]["scopes"])
		})
	}
}

// first is a request's response, its request id dropped.
func first(resp *http.Response, _ string) *http.Response { return resp }
