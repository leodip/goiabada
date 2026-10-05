package integration

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The target ceiling on clients: a client holding one of the six administrative permissions is an
// administrator, and so is the admin console's own client. Only an authserver:manage token writes to
// one in any way, or reads its secret (#402 decisions 1, 2, 4, 5 and 8).
//
// Each route runs three ways: manage-clients against an administrator client is refused 403
// MANAGE_SCOPE_REQUIRED with the insufficient_scope challenge, changes nothing and leaves exactly
// one administrator_change_refused row under ceiling "target"; the same token against an ordinary
// client succeeds; and authserver:manage succeeds against an administrator client.

// clientTargetFixture is one target client and what a route acts on beside it.
type clientTargetFixture struct {
	clientId   int64
	identifier string
	// before is a value read before the route, which the route would change.
	before string
	// ordinaryPermissionId is a permission on a resource of the test's own, administrative to
	// nobody.
	ordinaryPermissionId int64
	// requestId is the request id the route was sent under, and readerToken a token that reads the
	// audit log.
	requestId   string
	readerToken string
}

// clientTargetCeilingRoute is one of the client routes the target ceiling guards.
type clientTargetCeilingRoute struct {
	name   string
	method string
	route  string
	// prepare puts in place what the route acts on.
	prepare func(t *testing.T, f *clientTargetFixture)
	send    func(t *testing.T, token string, f *clientTargetFixture) (*http.Response, string)
	// changed reports whether the route's effect is in the store: for the secret read, whether a
	// disclosure was recorded.
	changed func(t *testing.T, f *clientTargetFixture) bool
	// notOnTheConsoleClient says the route answers the admin console's own client before the
	// ceiling, as deleting a system-level client is answered 400.
	notOnTheConsoleClient bool
}

func storedClient(t *testing.T, clientId int64) *record.Client {
	t.Helper()
	client, err := database.GetClientById(context.Background(), nil, clientId)
	require.NoError(t, err)
	return client
}

func clientPermissionIds(t *testing.T, clientId int64) []int64 {
	t.Helper()
	rows, err := database.GetClientPermissionsByClientId(context.Background(), nil, clientId)
	require.NoError(t, err)
	ids := []int64{}
	for _, row := range rows {
		ids = append(ids, row.PermissionId)
	}
	return ids
}

func clientHasLogo(t *testing.T, clientId int64) bool {
	t.Helper()
	has, err := database.ClientHasLogo(context.Background(), nil, clientId)
	require.NoError(t, err)
	return has
}

// sendClientLogo uploads a logo under its own request id.
func sendClientLogo(t *testing.T, accessToken string, clientId int64) (*http.Response, string) {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("picture", "logo.png")
	require.NoError(t, err)
	_, err = io.Copy(part, bytes.NewReader(createTestPNGImage(64, 64)))
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	req, err := http.NewRequest(http.MethodPost, appConfig.AuthServer.BaseURL+fmt.Sprintf("/api/v1/admin/clients/%d/logo", clientId), &body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+accessToken)
	requestId := "client-target-" + fake.LetterN(16)
	req.Header.Set("X-Request-Id", requestId)

	resp, err := createHttpClient(t).Do(req)
	require.NoError(t, err)
	return resp, requestId
}

// keepClientLogoOff puts a logo on the client for the test and takes it off again afterwards, so a
// refused removal leaves no logo on a client other tests share.
func keepClientLogoOff(t *testing.T, f *clientTargetFixture) {
	t.Helper()
	require.NoError(t, database.CreateClientLogo(context.Background(), nil,
		&record.ClientLogo{ClientId: f.clientId, Logo: createTestPNGImage(32, 32), ContentType: "image/png"}))
	t.Cleanup(func() { _ = database.DeleteClientLogo(context.Background(), nil, f.clientId) })
}

var clientTargetCeilingRoutes = []clientTargetCeilingRoute{
	{
		name: "PUT clients", method: http.MethodPut, route: "/api/v1/admin/clients/{id}",
		prepare: func(t *testing.T, f *clientTargetFixture) { f.before = storedClient(t, f.clientId).Description },
		send: func(t *testing.T, token string, f *clientTargetFixture) (*http.Response, string) {
			return sendAdmin(t, token, http.MethodPut, fmt.Sprintf("/api/v1/admin/clients/%d", f.clientId),
				map[string]any{"clientIdentifier": f.identifier, "description": "Taken over", "enabled": true})
		},
		changed: func(t *testing.T, f *clientTargetFixture) bool {
			return storedClient(t, f.clientId).Description == "Taken over"
		},
	},
	{
		name: "PUT clients authentication", method: http.MethodPut, route: "/api/v1/admin/clients/{id}/authentication",
		prepare: func(t *testing.T, f *clientTargetFixture) {
			f.before = string(storedClient(t, f.clientId).ClientSecretEncrypted)
		},
		send: func(t *testing.T, token string, f *clientTargetFixture) (*http.Response, string) {
			return sendAdmin(t, token, http.MethodPut, fmt.Sprintf("/api/v1/admin/clients/%d/authentication", f.clientId),
				map[string]any{"isPublic": false, "clientSecret": strings.Repeat("k", 60)})
		},
		changed: func(t *testing.T, f *clientTargetFixture) bool {
			return string(storedClient(t, f.clientId).ClientSecretEncrypted) != f.before
		},
	},
	{
		name: "PUT clients oauth2 flows", method: http.MethodPut, route: "/api/v1/admin/clients/{id}/oauth2-flows",
		prepare: noClientPrepare,
		send: func(t *testing.T, token string, f *clientTargetFixture) (*http.Response, string) {
			return sendAdmin(t, token, http.MethodPut, fmt.Sprintf("/api/v1/admin/clients/%d/oauth2-flows", f.clientId),
				map[string]any{"authorizationCodeEnabled": true, "clientCredentialsEnabled": true, "implicitGrantEnabled": true})
		},
		changed: func(t *testing.T, f *clientTargetFixture) bool {
			enabled := storedClient(t, f.clientId).ImplicitGrantEnabled
			return enabled != nil && *enabled
		},
	},
	{
		name: "PUT clients redirect uris", method: http.MethodPut, route: "/api/v1/admin/clients/{id}/redirect-uris",
		prepare: func(t *testing.T, f *clientTargetFixture) {
			f.before = "https://attacker-" + strings.ToLower(fake.LetterN(8)) + ".example/cb"
		},
		send: func(t *testing.T, token string, f *clientTargetFixture) (*http.Response, string) {
			client := storedClient(t, f.clientId)
			require.NoError(t, database.ClientLoadRedirectURIs(context.Background(), nil, client))
			current := []string{}
			for _, uri := range client.RedirectURIs {
				current = append(current, uri.URI)
			}
			return sendAdmin(t, token, http.MethodPut, fmt.Sprintf("/api/v1/admin/clients/%d/redirect-uris", f.clientId),
				map[string]any{"redirectURIs": append(append([]string{}, current...), f.before), "expectedRedirectURIs": current})
		},
		changed: func(t *testing.T, f *clientTargetFixture) bool {
			client := storedClient(t, f.clientId)
			require.NoError(t, database.ClientLoadRedirectURIs(context.Background(), nil, client))
			for _, uri := range client.RedirectURIs {
				if uri.URI == f.before {
					return true
				}
			}
			return false
		},
	},
	{
		name: "PUT clients web origins", method: http.MethodPut, route: "/api/v1/admin/clients/{id}/web-origins",
		prepare: func(t *testing.T, f *clientTargetFixture) {
			f.before = "https://attacker-" + strings.ToLower(fake.LetterN(8)) + ".example"
		},
		send: func(t *testing.T, token string, f *clientTargetFixture) (*http.Response, string) {
			client := storedClient(t, f.clientId)
			require.NoError(t, database.ClientLoadWebOrigins(context.Background(), nil, client))
			current := []string{}
			for _, origin := range client.WebOrigins {
				current = append(current, origin.Origin)
			}
			return sendAdmin(t, token, http.MethodPut, fmt.Sprintf("/api/v1/admin/clients/%d/web-origins", f.clientId),
				map[string]any{"webOrigins": append(append([]string{}, current...), f.before), "expectedWebOrigins": current})
		},
		changed: func(t *testing.T, f *clientTargetFixture) bool {
			client := storedClient(t, f.clientId)
			require.NoError(t, database.ClientLoadWebOrigins(context.Background(), nil, client))
			for _, origin := range client.WebOrigins {
				if origin.Origin == f.before {
					return true
				}
			}
			return false
		},
	},
	{
		name: "PUT clients tokens", method: http.MethodPut, route: "/api/v1/admin/clients/{id}/tokens",
		prepare: noClientPrepare,
		send: func(t *testing.T, token string, f *clientTargetFixture) (*http.Response, string) {
			return sendAdmin(t, token, http.MethodPut, fmt.Sprintf("/api/v1/admin/clients/%d/tokens", f.clientId),
				map[string]any{"tokenExpirationInSeconds": 4321,
					"includeOpenIDConnectClaimsInAccessToken": "default", "includeOpenIDConnectClaimsInIdToken": "default"})
		},
		changed: func(t *testing.T, f *clientTargetFixture) bool {
			return storedClient(t, f.clientId).TokenExpirationInSeconds == 4321
		},
	},
	{
		name: "PUT clients permissions", method: http.MethodPut, route: "/api/v1/admin/clients/{id}/permissions",
		prepare: noClientPrepare,
		send: func(t *testing.T, token string, f *clientTargetFixture) (*http.Response, string) {
			current := clientPermissionIds(t, f.clientId)
			return sendAdmin(t, token, http.MethodPut, fmt.Sprintf("/api/v1/admin/clients/%d/permissions", f.clientId),
				map[string]any{"permissionIds": append(append([]int64{}, current...), f.ordinaryPermissionId), "expectedPermissionIds": current})
		},
		changed: func(t *testing.T, f *clientTargetFixture) bool {
			for _, id := range clientPermissionIds(t, f.clientId) {
				if id == f.ordinaryPermissionId {
					return true
				}
			}
			return false
		},
	},
	{
		name: "DELETE clients", method: http.MethodDelete, route: "/api/v1/admin/clients/{id}",
		prepare: noClientPrepare,
		send: func(t *testing.T, token string, f *clientTargetFixture) (*http.Response, string) {
			return sendAdmin(t, token, http.MethodDelete, fmt.Sprintf("/api/v1/admin/clients/%d", f.clientId), nil)
		},
		changed:               func(t *testing.T, f *clientTargetFixture) bool { return storedClient(t, f.clientId) == nil },
		notOnTheConsoleClient: true,
	},
	{
		name: "POST clients logo", method: http.MethodPost, route: "/api/v1/admin/clients/{id}/logo",
		prepare: func(t *testing.T, f *clientTargetFixture) {
			t.Cleanup(func() { _ = database.DeleteClientLogo(context.Background(), nil, f.clientId) })
			f.before = fmt.Sprint(clientHasLogo(t, f.clientId))
		},
		send: func(t *testing.T, token string, f *clientTargetFixture) (*http.Response, string) {
			return sendClientLogo(t, token, f.clientId)
		},
		changed: func(t *testing.T, f *clientTargetFixture) bool {
			return f.before == "false" && clientHasLogo(t, f.clientId)
		},
	},
	{
		name: "DELETE clients logo", method: http.MethodDelete, route: "/api/v1/admin/clients/{id}/logo",
		prepare: keepClientLogoOff,
		send: func(t *testing.T, token string, f *clientTargetFixture) (*http.Response, string) {
			return sendAdmin(t, token, http.MethodDelete, fmt.Sprintf("/api/v1/admin/clients/%d/logo", f.clientId), nil)
		},
		changed: func(t *testing.T, f *clientTargetFixture) bool { return !clientHasLogo(t, f.clientId) },
	},
	{
		name: "GET clients secret", method: http.MethodGet, route: "/api/v1/admin/clients/{id}/secret",
		prepare: noClientPrepare,
		send: func(t *testing.T, token string, f *clientTargetFixture) (*http.Response, string) {
			resp, requestId := sendAdmin(t, token, http.MethodGet, fmt.Sprintf("/api/v1/admin/clients/%d/secret", f.clientId), nil)
			f.requestId = requestId
			return resp, requestId
		},
		changed: func(t *testing.T, f *clientTargetFixture) bool {
			return len(viewedSecretRows(t, f.readerToken, f.requestId)) > 0
		},
	},
}

func noClientPrepare(t *testing.T, f *clientTargetFixture) {}

// viewedSecretRows is the viewed_client_secret rows one request left.
func viewedSecretRows(t *testing.T, readerToken, requestId string) []any {
	t.Helper()
	logs, resp := getAuditLogs(t, readerToken, "auditEvent=viewed_client_secret&requestId="+url.QueryEscape(requestId))
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	rows := []any{}
	for _, entry := range logs.AuditLogs {
		rows = append(rows, entry)
	}
	return rows
}

// newTargetClient is a fresh confidential client with the code and client credentials flows on,
// holding the permissions given.
func newTargetClient(t *testing.T, permissionIds ...int64) *clientTargetFixture {
	t.Helper()
	secret, err := dataCipher.Encrypt(fake.Password(60))
	require.NoError(t, err)
	client := &record.Client{
		ClientIdentifier:         "target-client-" + strings.ToLower(fake.LetterN(8)),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: true,
		ClientSecretEncrypted:    secret,
		DefaultAcrLevel:          record.AcrLevel2Optional,
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, client))
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })
	for _, permissionId := range permissionIds {
		require.NoError(t, database.CreateClientPermission(context.Background(), nil,
			&record.ClientPermission{ClientId: client.Id, PermissionId: permissionId}))
	}
	return &clientTargetFixture{clientId: client.Id, identifier: client.ClientIdentifier}
}

// consoleClient is the admin console's own client, as seeded.
func consoleClient(t *testing.T) *clientTargetFixture {
	t.Helper()
	client, err := database.GetClientByClientIdentifier(context.Background(), nil, builtin.AdminConsoleClientIdentifier)
	require.NoError(t, err)
	require.NotNil(t, client)
	return &clientTargetFixture{clientId: client.Id, identifier: client.ClientIdentifier}
}

// assertClientRefusedByTheTargetCeiling holds one answered request to decision 4's refusal and
// decision 5's one record under ceiling "target" naming the client.
func assertClientRefusedByTheTargetCeiling(t *testing.T, resp *http.Response, requestId, readerToken string,
	caller *record.Client, route clientTargetCeilingRoute, clientId int64) {
	t.Helper()
	assertRefusedByTheTargetCeiling(t, resp, requestId, readerToken, caller,
		targetCeilingWrite{name: route.name, method: route.method, route: route.route, kind: "client"}, clientId)
}

func TestClientTargetCeiling_AGranularTokenCannotWriteToAnAdministratorClient(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)
	granularToken, caller := createClientWithGranularScope(t, builtin.ManageClientsPermissionIdentifier)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, caller.Id) })
	ordinary := ordinaryPermission(t)

	for i, route := range clientTargetCeilingRoutes {
		// Each route meets a different administrative permission.
		identifier := administrativePermissionIdentifiers[i%len(administrativePermissionIdentifiers)]
		t.Run(route.name+"/"+identifier, func(t *testing.T) {
			f := newTargetClient(t, authServerPermissionId(t, identifier))
			f.ordinaryPermissionId = ordinary
			f.readerToken = manageToken
			route.prepare(t, f)

			resp, requestId := route.send(t, granularToken, f)

			assertClientRefusedByTheTargetCeiling(t, resp, requestId, manageToken, caller, route, f.clientId)
			assert.False(t, route.changed(t, f), "the refused request changed nothing")
		})
	}
}

// The admin console's own client is an administrator: a granular token cannot repoint its
// redirects, change its flows or its secret, or read it.
func TestClientTargetCeiling_AGranularTokenCannotWriteToTheAdminConsolesOwnClient(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)
	granularToken, caller := createClientWithGranularScope(t, builtin.ManageClientsPermissionIdentifier)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, caller.Id) })
	ordinary := ordinaryPermission(t)

	for _, route := range clientTargetCeilingRoutes {
		if route.notOnTheConsoleClient {
			continue
		}
		t.Run(route.name, func(t *testing.T) {
			f := consoleClient(t)
			f.ordinaryPermissionId = ordinary
			f.readerToken = manageToken
			route.prepare(t, f)

			resp, requestId := route.send(t, granularToken, f)

			assertClientRefusedByTheTargetCeiling(t, resp, requestId, manageToken, caller, route, f.clientId)
			assert.False(t, route.changed(t, f), "the refused request changed nothing")
		})
	}
}

func TestClientTargetCeiling_AGranularTokenStillWritesToOrdinaryClients(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)
	granularToken, caller := createClientWithGranularScope(t, builtin.ManageClientsPermissionIdentifier)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, caller.Id) })
	ordinary := ordinaryPermission(t)
	other := ordinaryPermission(t)

	for _, route := range clientTargetCeilingRoutes {
		t.Run(route.name, func(t *testing.T) {
			// manage-account, a permission of another resource: neither makes a client an
			// administrator.
			f := newTargetClient(t, authServerPermissionId(t, builtin.ManageAccountPermissionIdentifier), other)
			f.ordinaryPermissionId = ordinary
			f.readerToken = manageToken
			route.prepare(t, f)

			resp, requestId := route.send(t, granularToken, f)
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			assert.Less(t, resp.StatusCode, 300, "an ordinary client is written as before: %s", body)
			assert.True(t, route.changed(t, f))
			assert.Empty(t, refusalRows(t, manageToken, requestId))
		})
	}
}

func TestClientTargetCeiling_AManageTokenWritesToAdministratorClients(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)
	ordinary := ordinaryPermission(t)

	for _, route := range clientTargetCeilingRoutes {
		t.Run(route.name, func(t *testing.T) {
			f := newTargetClient(t, authServerPermissionId(t, builtin.ManagePermissionIdentifier))
			f.ordinaryPermissionId = ordinary
			f.readerToken = manageToken
			route.prepare(t, f)

			resp, requestId := route.send(t, manageToken, f)
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			assert.Less(t, resp.StatusCode, 300, string(body))
			assert.True(t, route.changed(t, f))
			assert.Empty(t, refusalRows(t, manageToken, requestId))
		})
	}
}
