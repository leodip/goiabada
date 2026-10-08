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

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every change to who is an administrator is alertable: a grant or revocation of an administrative
// permission, on a user, a group or a client, and a user joining or leaving a group that holds one,
// leaves one administrative_permission_changed row beside the rows the write already left. The
// client permission save's own row names what it granted and revoked. Deleting an administrative
// group keeps its own row alone (#402 decision 6).

// auditRows is the rows of event one request left, details decoded.
func auditRows(t *testing.T, readerToken, event, requestId string) []map[string]any {
	t.Helper()
	logs, resp := getAuditLogs(t, readerToken, "auditEvent="+url.QueryEscape(event)+"&requestId="+url.QueryEscape(requestId))
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var rows []map[string]any
	for _, entry := range logs.AuditLogs {
		var details map[string]any
		require.NoError(t, json.Unmarshal([]byte(entry.Details), &details))
		rows = append(rows, details)
	}
	return rows
}

// administrativeChangeRows is the administrative_permission_changed rows one request left.
func administrativeChangeRows(t *testing.T, readerToken, requestId string) []map[string]any {
	t.Helper()
	return auditRows(t, readerToken, "administrative_permission_changed", requestId)
}

func TestAdministrativePermissionChanged_GrantingAndRevokingAnAdministrativePermissionIsRecorded(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, manageClient := createAdminClientWithToken(t)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, manageClient.Id) })

	for _, target := range grantCeilingTargets {
		t.Run(target.kind, func(t *testing.T) {
			targetId := target.create(t)
			manage := authServerPermissionId(t, builtin.ManagePermissionIdentifier)
			manageClients := authServerPermissionId(t, builtin.ManageClientsPermissionIdentifier)
			manageAccount := authServerPermissionId(t, builtin.ManageAccountPermissionIdentifier)

			// Granting manage and manage-clients beside manage-account, which is not administrative.
			resp, requestId := putPermissions(t, manageToken, target.path(targetId), []int64{manage, manageAccount, manageClients}, []int64{})
			_ = resp.Body.Close()
			require.Equal(t, http.StatusOK, resp.StatusCode)

			rows := administrativeChangeRows(t, manageToken, requestId)
			require.Len(t, rows, 1, "one row for the grant")
			assert.Equal(t, map[string]any{
				"change":                 "granted",
				"target_kind":            target.kind,
				"target_id":              float64(targetId),
				"permission_identifiers": []any{"authserver:manage", "authserver:manage-clients"},
				"logged_in_user":         manageClient.ClientIdentifier,
			}, rows[0])

			// Revoking manage and keeping the rest.
			resp, requestId = putPermissions(t, manageToken, target.path(targetId),
				[]int64{manageAccount, manageClients}, []int64{manage, manageAccount, manageClients})
			_ = resp.Body.Close()
			require.Equal(t, http.StatusOK, resp.StatusCode)

			rows = administrativeChangeRows(t, manageToken, requestId)
			require.Len(t, rows, 1, "one row for the revocation")
			assert.Equal(t, map[string]any{
				"change":                 "revoked",
				"target_kind":            target.kind,
				"target_id":              float64(targetId),
				"permission_identifiers": []any{"authserver:manage"},
				"logged_in_user":         manageClient.ClientIdentifier,
			}, rows[0])
		})
	}
}

// The new row is written beside the save's own rows, never instead of them, so a filter on those
// still sees every grant.
func TestAdministrativePermissionChanged_TheSavesOwnRowsAreStillWritten(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, manageClient := createAdminClientWithToken(t)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, manageClient.Id) })

	ownEvent := map[string]string{
		"user":   "added_user_permission",
		"group":  "added_group_permission",
		"client": "updated_client_permissions",
	}
	for _, target := range grantCeilingTargets {
		t.Run(target.kind, func(t *testing.T) {
			targetId := target.create(t)
			manage := authServerPermissionId(t, builtin.ManagePermissionIdentifier)

			resp, requestId := putPermissions(t, manageToken, target.path(targetId), []int64{manage}, []int64{})
			_ = resp.Body.Close()
			require.Equal(t, http.StatusOK, resp.StatusCode)

			assert.Len(t, auditRows(t, manageToken, ownEvent[target.kind], requestId), 1)
			assert.Len(t, administrativeChangeRows(t, manageToken, requestId), 1)
		})
	}
}

// A save changing only permissions that are not administrative leaves no
// administrative_permission_changed row, whoever makes it.
func TestAdministrativePermissionChanged_AnOrdinaryChangeIsNotRecorded(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, manageClient := createAdminClientWithToken(t)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, manageClient.Id) })

	authServer, err := database.GetResourceByResourceIdentifier(context.Background(), nil, builtin.AuthServerResourceIdentifier)
	require.NoError(t, err)
	custom := createTestPermission(t, authServer.Id, "alert-custom-"+strings.ToLower(fake.LetterN(6)), "An operator's own permission")
	t.Cleanup(func() { _ = database.DeletePermission(context.Background(), nil, custom.Id) })
	manageAccount := authServerPermissionId(t, builtin.ManageAccountPermissionIdentifier)

	for _, target := range grantCeilingTargets {
		granularToken, caller := createClientWithGranularScope(t, target.granularScope)
		t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, caller.Id) })

		for _, token := range []struct{ name, value string }{{"manage", manageToken}, {"granular", granularToken}} {
			t.Run(target.kind+"/"+token.name, func(t *testing.T) {
				targetId := target.create(t)

				resp, requestId := putPermissions(t, token.value, target.path(targetId), []int64{manageAccount, custom.Id}, []int64{})
				_ = resp.Body.Close()
				require.Equal(t, http.StatusOK, resp.StatusCode)
				assert.Empty(t, administrativeChangeRows(t, manageToken, requestId))

				resp, requestId = putPermissions(t, token.value, target.path(targetId), []int64{}, []int64{manageAccount, custom.Id})
				_ = resp.Body.Close()
				require.Equal(t, http.StatusOK, resp.StatusCode)
				assert.Empty(t, administrativeChangeRows(t, manageToken, requestId))
			})
		}
	}
}

// updated_client_permissions names the permissions the save granted and those it revoked, where it
// named only the client, so a grant of authserver:manage to a client says which permission it was.
func TestAdministrativePermissionChanged_TheClientPermissionsRowNamesWhatChanged(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, manageClient := createAdminClientWithToken(t)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, manageClient.Id) })

	target := grantCeilingTargets[2]
	require.Equal(t, "client", target.kind)
	targetId := target.create(t)
	manage := authServerPermissionId(t, builtin.ManagePermissionIdentifier)
	manageAccount := authServerPermissionId(t, builtin.ManageAccountPermissionIdentifier)
	adminRead := authServerPermissionId(t, builtin.AdminReadPermissionIdentifier)
	target.grant(t, targetId, adminRead)
	target.grant(t, targetId, manageAccount)

	resp, requestId := putPermissions(t, manageToken, target.path(targetId), []int64{manage, manageAccount}, []int64{adminRead, manageAccount})
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	rows := auditRows(t, manageToken, "updated_client_permissions", requestId)
	require.Len(t, rows, 1)
	assert.Equal(t, map[string]any{
		"client_id":              float64(targetId),
		"granted_permission_ids": []any{float64(manage)},
		"revoked_permission_ids": []any{float64(adminRead)},
		"logged_in_user":         manageClient.ClientIdentifier,
	}, rows[0])
}

// Joining or leaving an administrative group grants or revokes what it holds, so each of the four
// membership changes leaves one row naming the user, the group and the group's administrative
// permissions, not its other one. A group holding none leaves no row.
func TestAdministrativePermissionChanged_MovingAUserThroughAnAdministrativeGroupIsRecorded(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, manageClient := createAdminClientWithToken(t)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, manageClient.Id) })

	change := map[string]string{
		"PUT users groups joining": "granted",
		"PUT users groups leaving": "revoked",
		"POST group members":       "granted",
		"DELETE group member":      "revoked",
	}
	for _, membership := range membershipCeilingChanges {
		if membership.targetKind != "user" {
			continue
		}
		t.Run(membership.name, func(t *testing.T) {
			require.Contains(t, change, membership.name)
			userId := newMembershipUser(t)
			groupId := newGroupHolding(t,
				authServerPermissionId(t, builtin.ManageUsersPermissionIdentifier),
				authServerPermissionId(t, builtin.ManageAccountPermissionIdentifier))
			membership.prepare(t, userId, groupId)

			resp, requestId := membership.send(t, manageToken, userId, groupId)
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			require.Less(t, resp.StatusCode, 300, string(body))
			require.True(t, membership.done(t, userId, groupId))

			rows := administrativeChangeRows(t, manageToken, requestId)
			require.Len(t, rows, 1)
			assert.Equal(t, map[string]any{
				"change":                 change[membership.name],
				"target_kind":            "user",
				"target_id":              float64(userId),
				"group_id":               float64(groupId),
				"permission_identifiers": []any{"authserver:manage-users"},
				"logged_in_user":         manageClient.ClientIdentifier,
			}, rows[0])
		})

		t.Run(membership.name+"/ordinary group", func(t *testing.T) {
			userId := newMembershipUser(t)
			groupId := ordinaryGroup(t)
			membership.prepare(t, userId, groupId)

			resp, requestId := membership.send(t, manageToken, userId, groupId)
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			require.Less(t, resp.StatusCode, 300, string(body))
			assert.Empty(t, administrativeChangeRows(t, manageToken, requestId))
		})
	}
}

// Deleting an administrative group keeps its own deleted_group row, and is not doubled.
func TestAdministrativePermissionChanged_DeletingAnAdministrativeGroupIsNotDoubled(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, manageClient := createAdminClientWithToken(t)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, manageClient.Id) })

	userId := newMembershipUser(t)
	groupId := newGroupHolding(t, authServerPermissionId(t, builtin.ManagePermissionIdentifier))
	joinGroup(t, userId, groupId)

	resp, requestId := sendAdmin(t, manageToken, http.MethodDelete, fmt.Sprintf("/api/v1/admin/groups/%d", groupId), nil)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.Less(t, resp.StatusCode, 300, string(body))
	require.False(t, groupExists(t, groupId))

	assert.Len(t, auditRows(t, manageToken, "deleted_group", requestId), 1)
	assert.Empty(t, administrativeChangeRows(t, manageToken, requestId))
}
