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

// The target ceiling on PUT /resources/{resourceId}/permissions: the description of an
// administrative permission is what an operator reads before granting it, and #402 decision 3
// rewrote the seeded ones to state the boundary, so only an authserver:manage token changes one.
// manage-settings, which the route admits, is refused 403 MANAGE_SCOPE_REQUIRED, leaves the stored
// text as it was and one administrator_change_refused row naming the resource and the permission;
// it still saves every other description and permission (#402 decisions 1 and 3).

// authServerResource is the seeded authserver resource, and the path its permissions are saved at.
func authServerResource(t *testing.T) (*record.Resource, string) {
	t.Helper()
	resource, err := database.GetResourceByResourceIdentifier(context.Background(), nil, builtin.AuthServerResourceIdentifier)
	require.NoError(t, err)
	require.NotNil(t, resource, "the seed creates the authserver resource")
	return resource, "/api/v1/admin/resources/" + strconv.FormatInt(resource.Id, 10) + "/permissions"
}

// restorePermissionRows puts back, when the test ends, the resource's permissions as they are now:
// each description, and no permission beside them.
func restorePermissionRows(t *testing.T, resourceId int64) {
	t.Helper()
	before, err := database.GetPermissionsByResourceId(context.Background(), nil, resourceId)
	require.NoError(t, err)
	t.Cleanup(func() {
		after, err := database.GetPermissionsByResourceId(context.Background(), nil, resourceId)
		require.NoError(t, err)
		kept := make(map[int64]record.Permission, len(before))
		for _, p := range before {
			kept[p.Id] = p
		}
		for _, p := range after {
			original, ok := kept[p.Id]
			if !ok {
				require.NoError(t, database.DeletePermission(context.Background(), nil, p.Id))
				continue
			}
			if p.Description != original.Description {
				require.NoError(t, database.UpdatePermission(context.Background(), nil, &original))
			}
		}
	})
}

// withDescription is entries with the description of the one whose identifier is named replaced.
func withDescription(entries []api.ResourcePermissionUpsert, identifier, description string) []api.ResourcePermissionUpsert {
	edited := make([]api.ResourcePermissionUpsert, len(entries))
	copy(edited, entries)
	for i := range edited {
		if edited[i].PermissionIdentifier == identifier {
			edited[i].Description = description
		}
	}
	return edited
}

func TestPermissionDescriptionCeiling_ManageSettingsCannotRewriteAnAdministrativeDescription(t *testing.T) {
	requireDatabaseAuditLogs(t)
	resource, path := authServerResource(t)
	restorePermissionRows(t, resource.Id)
	manageToken, _ := createAdminClientWithToken(t)
	granularToken, caller := createClientWithGranularScope(t, builtin.ManageSettingsPermissionIdentifier)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, caller.Id) })

	for _, identifier := range administrativePermissionIdentifiers {
		t.Run(identifier, func(t *testing.T) {
			loaded := storedPermissionEntries(t, resource.Id)
			permissionId := authServerPermissionId(t, identifier)

			resp, requestId := sendAdmin(t, granularToken, http.MethodPut, path, api.UpdateResourcePermissionsRequest{
				Permissions:         withDescription(loaded, identifier, "Read-only reporting"),
				ExpectedPermissions: loaded,
			})
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
			var envelope struct {
				ErrorCode        string `json:"error_code"`
				ErrorDescription string `json:"error_description"`
			}
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&envelope))
			assert.Equal(t, "MANAGE_SCOPE_REQUIRED", envelope.ErrorCode)
			assert.Contains(t, envelope.ErrorDescription, "authserver:manage")
			challenge := resp.Header.Get("WWW-Authenticate")
			assert.True(t, strings.HasPrefix(challenge, `Bearer realm="`), "a Bearer challenge with its realm: %q", challenge)
			assert.Contains(t, challenge, `error="insufficient_scope"`)
			assert.Contains(t, challenge, `scope="authserver:manage"`)

			assert.ElementsMatch(t, loaded, storedPermissionEntries(t, resource.Id), "the refused save wrote nothing")
			assert.Zero(t, eventRows(t, manageToken, "updated_resource_permissions", requestId), "no record of a save that was not made")

			rows := refusalRows(t, manageToken, requestId)
			require.Len(t, rows, 1, "exactly one administrator_change_refused row for the refused request")
			row := rows[0]
			assert.Equal(t, caller.ClientIdentifier, row["loggedInUser"], "the caller is the token's sub")
			assert.Equal(t, http.MethodPut, row["method"])
			assert.Equal(t, "/api/v1/admin/resources/{resourceId}/permissions", row["route"])
			assert.Equal(t, "target", row["ceiling"])
			assert.Equal(t, "resource", row["targetKind"])
			assert.Equal(t, float64(resource.Id), row["targetId"])
			assert.Equal(t, []any{float64(permissionId)}, row["permissionIds"])
		})
	}
}

// Everything else the save does stays with manage-settings: manage-account's description, a custom
// permission added to the authserver resource, and another resource's permissions.
func TestPermissionDescriptionCeiling_ManageSettingsStillSavesTheRest(t *testing.T) {
	requireDatabaseAuditLogs(t)
	authServer, authServerPath := authServerResource(t)
	restorePermissionRows(t, authServer.Id)
	other := createResource(t)
	t.Cleanup(func() { _ = database.DeleteResource(context.Background(), nil, other.Id) })
	createPermission(t, other.Id)
	manageToken, _ := createAdminClientWithToken(t)
	granularToken, caller := createClientWithGranularScope(t, builtin.ManageSettingsPermissionIdentifier)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, caller.Id) })

	t.Run("the authserver resource", func(t *testing.T) {
		loaded := storedPermissionEntries(t, authServer.Id)
		custom := "reporting-" + fake.LetterN(8)
		wanted := append(withDescription(loaded, builtin.ManageAccountPermissionIdentifier, "Edit your own account"),
			api.ResourcePermissionUpsert{PermissionIdentifier: custom, Description: "Read reports"})

		resp, requestId := sendAdmin(t, granularToken, http.MethodPut, authServerPath, api.UpdateResourcePermissionsRequest{
			Permissions: wanted, ExpectedPermissions: loaded,
		})
		_ = resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		stored := storedPermissionEntries(t, authServer.Id)
		descriptions := make(map[string]string, len(stored))
		for _, p := range stored {
			descriptions[p.PermissionIdentifier] = p.Description
		}
		assert.Equal(t, "Edit your own account", descriptions[builtin.ManageAccountPermissionIdentifier])
		assert.Equal(t, "Read reports", descriptions[custom])
		assert.Empty(t, refusalRows(t, manageToken, requestId))
	})

	t.Run("another resource", func(t *testing.T) {
		loaded := storedPermissionEntries(t, other.Id)
		wanted := withDescription(loaded, loaded[0].PermissionIdentifier, "Re-described")
		path := "/api/v1/admin/resources/" + strconv.FormatInt(other.Id, 10) + "/permissions"

		resp, requestId := sendAdmin(t, granularToken, http.MethodPut, path, api.UpdateResourcePermissionsRequest{
			Permissions: wanted, ExpectedPermissions: loaded,
		})
		_ = resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.ElementsMatch(t, wanted, storedPermissionEntries(t, other.Id))
		assert.Empty(t, refusalRows(t, manageToken, requestId))
	})
}

// authserver:manage rewrites every administrative description in one save, and is refused nothing.
func TestPermissionDescriptionCeiling_AManageTokenRewritesThem(t *testing.T) {
	requireDatabaseAuditLogs(t)
	resource, path := authServerResource(t)
	restorePermissionRows(t, resource.Id)
	manageToken, _ := createAdminClientWithToken(t)

	loaded := storedPermissionEntries(t, resource.Id)
	wanted := loaded
	for _, identifier := range administrativePermissionIdentifiers {
		wanted = withDescription(wanted, identifier, "Rewritten "+identifier)
	}

	resp, requestId := sendAdmin(t, manageToken, http.MethodPut, path, api.UpdateResourcePermissionsRequest{
		Permissions: wanted, ExpectedPermissions: loaded,
	})
	_ = resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.ElementsMatch(t, wanted, storedPermissionEntries(t, resource.Id))
	assert.Equal(t, 1, eventRows(t, manageToken, "updated_resource_permissions", requestId))
	assert.Empty(t, refusalRows(t, manageToken, requestId))
}
