package integration

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"slices"
	"strconv"
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
	clientID   int64
	identifier string
	// before is a value read before the route, which the route would change.
	before string
	// ordinaryPermissionID is a permission on a resource of the test's own, administrative to
	// nobody.
	ordinaryPermissionID int64
	// requestID is the request id the route was sent under, and readerToken a token that reads the
	// audit log.
	requestID   string
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

func storedClient(t *testing.T, clientID int64) *record.Client {
	t.Helper()
	client, err := database.GetClientByID(context.Background(), nil, clientID)
	require.NoError(t, err)
	return client
}

func clientPermissionIDs(t *testing.T, clientID int64) []int64 {
	t.Helper()
	rows, err := database.GetClientPermissionsByClientID(context.Background(), nil, clientID)
	require.NoError(t, err)
	ids := []int64{}
	for _, row := range rows {
		ids = append(ids, row.PermissionID)
	}
	return ids
}

func clientHasLogo(t *testing.T, clientID int64) bool {
	t.Helper()
	has, err := database.ClientHasLogo(context.Background(), nil, clientID)
	require.NoError(t, err)
	return has
}

// sendClientLogo uploads a logo under its own request id.
func sendClientLogo(t *testing.T, accessToken string, clientID int64) (*http.Response, string) {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("picture", "logo.png")
	require.NoError(t, err)
	_, err = io.Copy(part, bytes.NewReader(createTestPNGImage(64, 64)))
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	req, err := http.NewRequest(http.MethodPost, appConfig.AuthServer.BaseURL+fmt.Sprintf("/api/v1/admin/clients/%d/logo", clientID), &body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+accessToken)
	requestID := "client-target-" + fake.LetterN(16)
	req.Header.Set("X-Request-Id", requestID)

	resp, err := createHTTPClient(t).Do(req)
	require.NoError(t, err)
	return resp, requestID
}

// keepClientLogoOff puts a logo on the client for the test and takes it off again afterwards, so a
// refused removal leaves no logo on a client other tests share.
func keepClientLogoOff(t *testing.T, f *clientTargetFixture) {
	t.Helper()
	require.NoError(t, database.CreateClientLogo(context.Background(), nil,
		&record.ClientLogo{ClientID: f.clientID, Logo: createTestPNGImage(32, 32), ContentType: "image/png"}))
	t.Cleanup(func() { _ = database.DeleteClientLogo(context.Background(), nil, f.clientID) })
}

var clientTargetCeilingRoutes = []clientTargetCeilingRoute{
	{
		name: "PUT clients", method: http.MethodPut, route: "/api/v1/admin/clients/{id}",
		prepare: func(t *testing.T, f *clientTargetFixture) { f.before = storedClient(t, f.clientID).Description },
		send: func(t *testing.T, token string, f *clientTargetFixture) (*http.Response, string) {
			return sendAdmin(t, token, http.MethodPut, fmt.Sprintf("/api/v1/admin/clients/%d", f.clientID),
				map[string]any{"clientIdentifier": f.identifier, "description": "Taken over", "enabled": true})
		},
		changed: func(t *testing.T, f *clientTargetFixture) bool {
			return storedClient(t, f.clientID).Description == "Taken over"
		},
	},
	{
		name: "PUT clients authentication", method: http.MethodPut, route: "/api/v1/admin/clients/{id}/authentication",
		prepare: func(t *testing.T, f *clientTargetFixture) {
			f.before = string(storedClient(t, f.clientID).ClientSecretEncrypted)
		},
		send: func(t *testing.T, token string, f *clientTargetFixture) (*http.Response, string) {
			return sendAdmin(t, token, http.MethodPut, fmt.Sprintf("/api/v1/admin/clients/%d/authentication", f.clientID),
				map[string]any{"isPublic": false, "clientSecret": strings.Repeat("k", 60)})
		},
		changed: func(t *testing.T, f *clientTargetFixture) bool {
			return string(storedClient(t, f.clientID).ClientSecretEncrypted) != f.before
		},
	},
	{
		name: "PUT clients oauth2 flows", method: http.MethodPut, route: "/api/v1/admin/clients/{id}/oauth2-flows",
		prepare: noClientPrepare,
		send: func(t *testing.T, token string, f *clientTargetFixture) (*http.Response, string) {
			return sendAdmin(t, token, http.MethodPut, fmt.Sprintf("/api/v1/admin/clients/%d/oauth2-flows", f.clientID),
				map[string]any{"authorizationCodeEnabled": true, "clientCredentialsEnabled": true, "implicitGrantEnabled": true})
		},
		changed: func(t *testing.T, f *clientTargetFixture) bool {
			enabled := storedClient(t, f.clientID).ImplicitGrantEnabled
			return enabled != nil && *enabled
		},
	},
	{
		name: "PUT clients redirect uris", method: http.MethodPut, route: "/api/v1/admin/clients/{id}/redirect-uris",
		prepare: func(t *testing.T, f *clientTargetFixture) {
			f.before = "https://attacker-" + strings.ToLower(fake.LetterN(8)) + ".example/cb"
		},
		send: func(t *testing.T, token string, f *clientTargetFixture) (*http.Response, string) {
			client := storedClient(t, f.clientID)
			require.NoError(t, database.ClientLoadRedirectURIs(context.Background(), nil, client))
			current := []string{}
			for _, uri := range client.RedirectURIs {
				current = append(current, uri.URI)
			}
			return sendAdmin(t, token, http.MethodPut, fmt.Sprintf("/api/v1/admin/clients/%d/redirect-uris", f.clientID),
				map[string]any{"redirectURIs": append(append([]string{}, current...), f.before), "expectedRedirectURIs": current})
		},
		changed: func(t *testing.T, f *clientTargetFixture) bool {
			client := storedClient(t, f.clientID)
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
		name: "PUT clients post-logout redirect uris", method: http.MethodPut, route: "/api/v1/admin/clients/{id}/post-logout-redirect-uris",
		prepare: func(t *testing.T, f *clientTargetFixture) {
			f.before = "https://attacker-" + strings.ToLower(fake.LetterN(8)) + ".example/bye"
		},
		send: func(t *testing.T, token string, f *clientTargetFixture) (*http.Response, string) {
			current := storedPostLogoutRedirectURIs(t, f.clientID)
			return sendAdmin(t, token, http.MethodPut, fmt.Sprintf("/api/v1/admin/clients/%d/post-logout-redirect-uris", f.clientID),
				map[string]any{"postLogoutRedirectURIs": append(append([]string{}, current...), f.before), "expectedPostLogoutRedirectURIs": current})
		},
		changed: func(t *testing.T, f *clientTargetFixture) bool {
			return slices.Contains(storedPostLogoutRedirectURIs(t, f.clientID), f.before)
		},
	},
	{
		// The session-required flag alone, which a granular token may change on an ordinary client:
		// setting the URI would meet the back-channel logout URI ceiling instead (#784 decision 15).
		name: "PUT clients backchannel logout", method: http.MethodPut, route: "/api/v1/admin/clients/{id}/backchannel-logout",
		prepare: noClientPrepare,
		send: func(t *testing.T, token string, f *clientTargetFixture) (*http.Response, string) {
			return sendAdmin(t, token, http.MethodPut, fmt.Sprintf("/api/v1/admin/clients/%d/backchannel-logout", f.clientID),
				map[string]any{"backchannelLogoutUri": storedClient(t, f.clientID).BackchannelLogoutURI, "backchannelLogoutSessionRequired": true})
		},
		changed: func(t *testing.T, f *clientTargetFixture) bool {
			return storedClient(t, f.clientID).BackchannelLogoutSessionRequired
		},
	},
	{
		// Switching on "Require DPoP for token requests", which the admin console's own client is
		// refused before the ceiling (#42 decision 12).
		name: "PUT clients dpop", method: http.MethodPut, route: "/api/v1/admin/clients/{id}/dpop",
		prepare: noClientPrepare,
		send: func(t *testing.T, token string, f *clientTargetFixture) (*http.Response, string) {
			return sendAdmin(t, token, http.MethodPut, fmt.Sprintf("/api/v1/admin/clients/%d/dpop", f.clientID),
				map[string]any{"dpopBoundAccessTokens": true})
		},
		changed: func(t *testing.T, f *clientTargetFixture) bool {
			return storedClient(t, f.clientID).DPoPBoundAccessTokens
		},
		notOnTheConsoleClient: true,
	},
	{
		// Giving the client a brand of its own (#812 decision 2): the brand is made for the test.
		name: "PUT clients brand", method: http.MethodPut, route: "/api/v1/admin/clients/{id}/brand",
		prepare: func(t *testing.T, f *clientTargetFixture) {
			f.before = strconv.FormatInt(newBrandInStore(t, "Target").ID, 10)
		},
		send: func(t *testing.T, token string, f *clientTargetFixture) (*http.Response, string) {
			brandID, err := strconv.ParseInt(f.before, 10, 64)
			require.NoError(t, err)
			return sendAdmin(t, token, http.MethodPut, fmt.Sprintf("/api/v1/admin/clients/%d/brand", f.clientID),
				map[string]any{"brandId": brandID})
		},
		changed: func(t *testing.T, f *clientTargetFixture) bool {
			return strconv.FormatInt(storedBrandID(t, f.clientID), 10) == f.before
		},
	},
	{
		name: "PUT clients web origins", method: http.MethodPut, route: "/api/v1/admin/clients/{id}/web-origins",
		prepare: func(t *testing.T, f *clientTargetFixture) {
			f.before = "https://attacker-" + strings.ToLower(fake.LetterN(8)) + ".example"
		},
		send: func(t *testing.T, token string, f *clientTargetFixture) (*http.Response, string) {
			client := storedClient(t, f.clientID)
			require.NoError(t, database.ClientLoadWebOrigins(context.Background(), nil, client))
			current := []string{}
			for _, origin := range client.WebOrigins {
				current = append(current, origin.Origin)
			}
			return sendAdmin(t, token, http.MethodPut, fmt.Sprintf("/api/v1/admin/clients/%d/web-origins", f.clientID),
				map[string]any{"webOrigins": append(append([]string{}, current...), f.before), "expectedWebOrigins": current})
		},
		changed: func(t *testing.T, f *clientTargetFixture) bool {
			client := storedClient(t, f.clientID)
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
			return sendAdmin(t, token, http.MethodPut, fmt.Sprintf("/api/v1/admin/clients/%d/tokens", f.clientID),
				map[string]any{"tokenExpirationInSeconds": 4321,
					"includeOpenIDConnectClaimsInAccessToken": "default", "includeOpenIDConnectClaimsInIdToken": "default"})
		},
		changed: func(t *testing.T, f *clientTargetFixture) bool {
			return storedClient(t, f.clientID).TokenExpirationInSeconds == 4321
		},
	},
	{
		name: "PUT clients permissions", method: http.MethodPut, route: "/api/v1/admin/clients/{id}/permissions",
		prepare: noClientPrepare,
		send: func(t *testing.T, token string, f *clientTargetFixture) (*http.Response, string) {
			current := clientPermissionIDs(t, f.clientID)
			return sendAdmin(t, token, http.MethodPut, fmt.Sprintf("/api/v1/admin/clients/%d/permissions", f.clientID),
				map[string]any{"permissionIDs": append(append([]int64{}, current...), f.ordinaryPermissionID), "expectedPermissionIds": current})
		},
		changed: func(t *testing.T, f *clientTargetFixture) bool {
			for _, id := range clientPermissionIDs(t, f.clientID) {
				if id == f.ordinaryPermissionID {
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
			return sendAdmin(t, token, http.MethodDelete, fmt.Sprintf("/api/v1/admin/clients/%d", f.clientID), nil)
		},
		changed:               func(t *testing.T, f *clientTargetFixture) bool { return storedClient(t, f.clientID) == nil },
		notOnTheConsoleClient: true,
	},
	{
		name: "POST clients logo", method: http.MethodPost, route: "/api/v1/admin/clients/{id}/logo",
		prepare: func(t *testing.T, f *clientTargetFixture) {
			t.Cleanup(func() { _ = database.DeleteClientLogo(context.Background(), nil, f.clientID) })
			f.before = fmt.Sprint(clientHasLogo(t, f.clientID))
		},
		send: func(t *testing.T, token string, f *clientTargetFixture) (*http.Response, string) {
			return sendClientLogo(t, token, f.clientID)
		},
		changed: func(t *testing.T, f *clientTargetFixture) bool {
			return f.before == "false" && clientHasLogo(t, f.clientID)
		},
	},
	{
		name: "DELETE clients logo", method: http.MethodDelete, route: "/api/v1/admin/clients/{id}/logo",
		prepare: keepClientLogoOff,
		send: func(t *testing.T, token string, f *clientTargetFixture) (*http.Response, string) {
			return sendAdmin(t, token, http.MethodDelete, fmt.Sprintf("/api/v1/admin/clients/%d/logo", f.clientID), nil)
		},
		changed: func(t *testing.T, f *clientTargetFixture) bool { return !clientHasLogo(t, f.clientID) },
	},
	{
		name: "GET clients secret", method: http.MethodGet, route: "/api/v1/admin/clients/{id}/secret",
		prepare: noClientPrepare,
		send: func(t *testing.T, token string, f *clientTargetFixture) (*http.Response, string) {
			resp, requestID := sendAdmin(t, token, http.MethodGet, fmt.Sprintf("/api/v1/admin/clients/%d/secret", f.clientID), nil)
			f.requestID = requestID
			return resp, requestID
		},
		changed: func(t *testing.T, f *clientTargetFixture) bool {
			return len(viewedSecretRows(t, f.readerToken, f.requestID)) > 0
		},
	},
}

func noClientPrepare(t *testing.T, f *clientTargetFixture) {}

// viewedSecretRows is the viewed_client_secret rows one request left.
func viewedSecretRows(t *testing.T, readerToken, requestID string) []any {
	t.Helper()
	logs, resp := getAuditLogs(t, readerToken, "auditEvent=viewed_client_secret&requestId="+url.QueryEscape(requestID))
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
func newTargetClient(t *testing.T, permissionIDs ...int64) *clientTargetFixture {
	t.Helper()
	secret, err := dataCipher.Encrypt(fake.Password(60))
	require.NoError(t, err)
	client := &record.Client{
		ClientIdentifier:         "target-client-" + strings.ToLower(fake.LetterN(8)),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: true,
		ClientSecretEncrypted:    secret,
		DefaultACRLevel:          record.ACRLevel2Optional,
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, client))
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.ID) })
	for _, permissionID := range permissionIDs {
		require.NoError(t, database.CreateClientPermission(context.Background(), nil,
			&record.ClientPermission{ClientID: client.ID, PermissionID: permissionID}))
	}
	return &clientTargetFixture{clientID: client.ID, identifier: client.ClientIdentifier}
}

// consoleClient is the admin console's own client, as seeded.
func consoleClient(t *testing.T) *clientTargetFixture {
	t.Helper()
	client, err := database.GetClientByClientIdentifier(context.Background(), nil, builtin.AdminConsoleClientIdentifier)
	require.NoError(t, err)
	require.NotNil(t, client)
	return &clientTargetFixture{clientID: client.ID, identifier: client.ClientIdentifier}
}

// assertClientRefusedByTheTargetCeiling holds one answered request to decision 4's refusal and
// decision 5's one record under ceiling "target" naming the client.
func assertClientRefusedByTheTargetCeiling(t *testing.T, resp *http.Response, requestID, readerToken string,
	caller *record.Client, route clientTargetCeilingRoute, clientID int64) {
	t.Helper()
	assertRefusedByTheTargetCeiling(t, resp, requestID, readerToken, caller,
		targetCeilingWrite{name: route.name, method: route.method, route: route.route, kind: "client"}, clientID)
}

func TestClientTargetCeiling_AGranularTokenCannotWriteToAnAdministratorClient(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)
	granularToken, caller := createClientWithGranularScope(t, builtin.ManageClientsPermissionIdentifier)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, caller.ID) })
	ordinary := ordinaryPermission(t)

	for i, route := range clientTargetCeilingRoutes {
		// Each route meets a different administrative permission.
		identifier := administrativePermissionIdentifiers[i%len(administrativePermissionIdentifiers)]
		t.Run(route.name+"/"+identifier, func(t *testing.T) {
			f := newTargetClient(t, authServerPermissionID(t, identifier))
			f.ordinaryPermissionID = ordinary
			f.readerToken = manageToken
			route.prepare(t, f)

			resp, requestID := route.send(t, granularToken, f)

			assertClientRefusedByTheTargetCeiling(t, resp, requestID, manageToken, caller, route, f.clientID)
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
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, caller.ID) })
	ordinary := ordinaryPermission(t)

	for _, route := range clientTargetCeilingRoutes {
		if route.notOnTheConsoleClient {
			continue
		}
		t.Run(route.name, func(t *testing.T) {
			f := consoleClient(t)
			f.ordinaryPermissionID = ordinary
			f.readerToken = manageToken
			route.prepare(t, f)

			resp, requestID := route.send(t, granularToken, f)

			assertClientRefusedByTheTargetCeiling(t, resp, requestID, manageToken, caller, route, f.clientID)
			assert.False(t, route.changed(t, f), "the refused request changed nothing")
		})
	}
}

func TestClientTargetCeiling_AGranularTokenStillWritesToOrdinaryClients(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)
	granularToken, caller := createClientWithGranularScope(t, builtin.ManageClientsPermissionIdentifier)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, caller.ID) })
	ordinary := ordinaryPermission(t)
	other := ordinaryPermission(t)

	for _, route := range clientTargetCeilingRoutes {
		t.Run(route.name, func(t *testing.T) {
			// manage-account, a permission of another resource: neither makes a client an
			// administrator.
			f := newTargetClient(t, authServerPermissionID(t, builtin.ManageAccountPermissionIdentifier), other)
			f.ordinaryPermissionID = ordinary
			f.readerToken = manageToken
			route.prepare(t, f)

			resp, requestID := route.send(t, granularToken, f)
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			assert.Less(t, resp.StatusCode, 300, "an ordinary client is written as before: %s", body)
			assert.True(t, route.changed(t, f))
			assert.Empty(t, refusalRows(t, manageToken, requestID))
		})
	}
}

func TestClientTargetCeiling_AManageTokenWritesToAdministratorClients(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)
	ordinary := ordinaryPermission(t)

	for _, route := range clientTargetCeilingRoutes {
		t.Run(route.name, func(t *testing.T) {
			f := newTargetClient(t, authServerPermissionID(t, builtin.ManagePermissionIdentifier))
			f.ordinaryPermissionID = ordinary
			f.readerToken = manageToken
			route.prepare(t, f)

			resp, requestID := route.send(t, manageToken, f)
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			assert.Less(t, resp.StatusCode, 300, string(body))
			assert.True(t, route.changed(t, f))
			assert.Empty(t, refusalRows(t, manageToken, requestID))
		})
	}
}
