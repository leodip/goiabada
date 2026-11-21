package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The grant ceiling on PUT /users/{id}/permissions, PUT /groups/{id}/permissions and
// PUT /clients/{id}/permissions: only an authserver:manage token grants or revokes one of the six
// administrative permissions (#402 decisions 1, 2, 4 and 5).
//
// Each row runs three ways: the save's granular scope against an administrative permission is
// refused 403 MANAGE_SCOPE_REQUIRED with the insufficient_scope challenge, writes nothing and leaves
// exactly one administrator_change_refused row; the same token against ordinary permissions
// succeeds; and authserver:manage succeeds against both.

// administrativePermissionIdentifiers is decision 2's set, written out here rather than read from
// the code under test.
var administrativePermissionIdentifiers = []string{
	"manage",
	"admin-read",
	"manage-users",
	"manage-clients",
	"manage-settings",
	"browser-sessions",
}

// authServerPermissionID is the id of a built-in permission on the authserver resource.
func authServerPermissionID(t *testing.T, identifier string) int64 {
	t.Helper()
	resource, err := database.GetResourceByResourceIdentifier(context.Background(), nil, builtin.AuthServerResourceIdentifier)
	require.NoError(t, err)
	permissions, err := database.GetPermissionsByResourceID(context.Background(), nil, resource.ID)
	require.NoError(t, err)
	for _, permission := range permissions {
		if permission.PermissionIdentifier == identifier {
			return permission.ID
		}
	}
	t.Fatalf("the authserver resource has no permission %q", identifier)
	return 0
}

// grantCeilingTarget is one of the three saves, with a fresh target of its kind.
type grantCeilingTarget struct {
	kind          string
	granularScope string
	create        func(t *testing.T) int64
	path          func(id int64) string
	stored        func(t *testing.T, id int64) []int64
	grant         func(t *testing.T, id int64, permissionID int64)
}

var grantCeilingTargets = []grantCeilingTarget{
	{
		kind:          "user",
		granularScope: builtin.ManageUsersPermissionIdentifier,
		create: func(t *testing.T) int64 {
			user := &record.User{Subject: fake.UUID(), Enabled: true, Email: uniqueEmail("ceiling@grants.test"), GivenName: "Ceiling"}
			require.NoError(t, database.CreateUser(context.Background(), nil, user))
			t.Cleanup(func() { _ = database.DeleteUser(context.Background(), nil, user.ID) })
			return user.ID
		},
		path: func(id int64) string { return fmt.Sprintf("/api/v1/admin/users/%d/permissions", id) },
		stored: func(t *testing.T, id int64) []int64 {
			rows, err := database.GetUserPermissionsByUserID(context.Background(), nil, id)
			require.NoError(t, err)
			var ids []int64
			for _, row := range rows {
				ids = append(ids, row.PermissionID)
			}
			return ids
		},
		grant: func(t *testing.T, id int64, permissionID int64) {
			require.NoError(t, database.CreateUserPermission(context.Background(), nil, &record.UserPermission{UserID: id, PermissionID: permissionID}))
		},
	},
	{
		kind:          "group",
		granularScope: builtin.ManageUsersPermissionIdentifier,
		create: func(t *testing.T) int64 {
			group := createTestGroup(t)
			t.Cleanup(func() { _ = database.DeleteGroup(context.Background(), nil, group.ID) })
			return group.ID
		},
		path: func(id int64) string { return fmt.Sprintf("/api/v1/admin/groups/%d/permissions", id) },
		stored: func(t *testing.T, id int64) []int64 {
			rows, err := database.GetGroupPermissionsByGroupID(context.Background(), nil, id)
			require.NoError(t, err)
			var ids []int64
			for _, row := range rows {
				ids = append(ids, row.PermissionID)
			}
			return ids
		},
		grant: func(t *testing.T, id int64, permissionID int64) {
			require.NoError(t, database.CreateGroupPermission(context.Background(), nil, &record.GroupPermission{GroupID: id, PermissionID: permissionID}))
		},
	},
	{
		kind:          "client",
		granularScope: builtin.ManageClientsPermissionIdentifier,
		create: func(t *testing.T) int64 {
			client := &record.Client{
				ClientIdentifier:         "ceiling-target-" + strings.ToLower(fake.LetterN(8)),
				Enabled:                  true,
				ClientCredentialsEnabled: true,
			}
			require.NoError(t, database.CreateClient(context.Background(), nil, client))
			t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.ID) })
			return client.ID
		},
		path: func(id int64) string { return fmt.Sprintf("/api/v1/admin/clients/%d/permissions", id) },
		stored: func(t *testing.T, id int64) []int64 {
			rows, err := database.GetClientPermissionsByClientID(context.Background(), nil, id)
			require.NoError(t, err)
			var ids []int64
			for _, row := range rows {
				ids = append(ids, row.PermissionID)
			}
			return ids
		},
		grant: func(t *testing.T, id int64, permissionID int64) {
			require.NoError(t, database.CreateClientPermission(context.Background(), nil, &record.ClientPermission{ClientID: id, PermissionID: permissionID}))
		},
	},
}

// putPermissions sends a permission save under its own request id, so the audit rows it leaves can
// be read back by that id alone.
func putPermissions(t *testing.T, accessToken, path string, wanted, expected []int64) (*http.Response, string) {
	t.Helper()
	if wanted == nil {
		wanted = []int64{}
	}
	if expected == nil {
		expected = []int64{}
	}
	body, err := json.Marshal(map[string]any{"permissionIDs": wanted, "expectedPermissionIds": expected})
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPut, appConfig.AuthServer.BaseURL+path, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	requestID := "ceiling-" + fake.LetterN(16)
	req.Header.Set("X-Request-Id", requestID)

	resp, err := createHTTPClient(t).Do(req)
	require.NoError(t, err)
	return resp, requestID
}

// assertUserIDNamesAUserTarget holds a refusal row's user_id to its target: the target's id when
// the target is a user, and no user_id at all for a group, client or resource (#780 decision 5).
func assertUserIDNamesAUserTarget(t *testing.T, row map[string]any, kind string, targetID int64) {
	t.Helper()
	if kind == "user" {
		assert.InDelta(t, float64(targetID), row["user_id"], 0, "a user target is named by user_id")
	} else {
		assert.NotContains(t, row, "user_id", "a %s target names no user", kind)
	}
}

// refusalRows is the administrator_change_refused rows one request left, details decoded.
func refusalRows(t *testing.T, readerToken, requestID string) []map[string]any {
	t.Helper()
	logs, resp := getAuditLogs(t, readerToken, "auditEvent=administrator_change_refused&requestId="+url.QueryEscape(requestID))
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

func sortedIDs(ids []int64) []int64 {
	out := append([]int64{}, ids...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// assertRefusedByTheGrantCeiling holds one answered request to decision 4's refusal and decision
// 5's one record.
func assertRefusedByTheGrantCeiling(t *testing.T, resp *http.Response, requestID, readerToken string,
	caller *record.Client, target grantCeilingTarget, targetID int64, causes []int64) {
	t.Helper()
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

	rows := refusalRows(t, readerToken, requestID)
	require.Len(t, rows, 1, "exactly one administrator_change_refused row for the refused request")
	row := rows[0]
	assert.Equal(t, caller.ClientIdentifier, row["logged_in_user"], "the caller is the token's sub")
	assert.Equal(t, http.MethodPut, row["method"])
	assert.Equal(t, "/api/v1/admin/"+target.kind+"s/{id}/permissions", row["route"])
	assert.Equal(t, "grant", row["ceiling"])
	assert.Equal(t, target.kind, row["target_kind"])
	assert.InDelta(t, float64(targetID), row["target_id"], 0)
	assertUserIDNamesAUserTarget(t, row, target.kind, targetID)
	var named []int64
	if raw, ok := row["permission_ids"].([]any); assert.True(t, ok, "permissionIds is a list: %v", row["permission_ids"]) {
		for _, id := range raw {
			named = append(named, int64(id.(float64)))
		}
	}
	assert.Equal(t, sortedIDs(causes), sortedIDs(named))
}

func TestGrantCeiling_AGranularTokenCannotGrantAnAdministrativePermission(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)

	for _, target := range grantCeilingTargets {
		granularToken, caller := createClientWithGranularScope(t, target.granularScope)
		t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, caller.ID) })

		for _, identifier := range administrativePermissionIdentifiers {
			t.Run(target.kind+"/"+identifier, func(t *testing.T) {
				targetID := target.create(t)
				permissionID := authServerPermissionID(t, identifier)

				resp, requestID := putPermissions(t, granularToken, target.path(targetID), []int64{permissionID}, []int64{})

				assertRefusedByTheGrantCeiling(t, resp, requestID, manageToken, caller, target, targetID, []int64{permissionID})
				assert.Empty(t, target.stored(t, targetID), "the refused save wrote nothing")
			})
		}
	}
}

func TestGrantCeiling_AGranularTokenCannotRevokeAnAdministrativePermission(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)

	for _, target := range grantCeilingTargets {
		granularToken, caller := createClientWithGranularScope(t, target.granularScope)
		t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, caller.ID) })

		t.Run(target.kind, func(t *testing.T) {
			targetID := target.create(t)
			adminRead := authServerPermissionID(t, builtin.AdminReadPermissionIdentifier)
			manageAccount := authServerPermissionID(t, builtin.ManageAccountPermissionIdentifier)
			target.grant(t, targetID, adminRead)
			target.grant(t, targetID, manageAccount)

			// Revoking admin-read and keeping manage-account: the revocation alone is what is refused.
			resp, requestID := putPermissions(t, granularToken, target.path(targetID),
				[]int64{manageAccount}, []int64{adminRead, manageAccount})

			assertRefusedByTheGrantCeiling(t, resp, requestID, manageToken, caller, target, targetID, []int64{adminRead})
			assert.ElementsMatch(t, []int64{adminRead, manageAccount}, target.stored(t, targetID), "the refused save wrote nothing")
		})
	}
}

func TestGrantCeiling_AGranularTokenStillChangesOrdinaryPermissions(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)

	resource := createTestResource(t, "ceiling-res-"+strings.ToLower(fake.LetterN(6)), "Grant ceiling")
	t.Cleanup(func() { _ = database.DeleteResource(context.Background(), nil, resource.ID) })
	ordinary := createTestPermission(t, resource.ID, "read", "Read")
	authServer, err := database.GetResourceByResourceIdentifier(context.Background(), nil, builtin.AuthServerResourceIdentifier)
	require.NoError(t, err)
	custom := createTestPermission(t, authServer.ID, "ceiling-custom-"+strings.ToLower(fake.LetterN(6)), "An operator's own permission")
	t.Cleanup(func() { _ = database.DeletePermission(context.Background(), nil, custom.ID) })
	manageAccount := authServerPermissionID(t, builtin.ManageAccountPermissionIdentifier)

	for _, target := range grantCeilingTargets {
		granularToken, caller := createClientWithGranularScope(t, target.granularScope)
		t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, caller.ID) })

		t.Run(target.kind, func(t *testing.T) {
			targetID := target.create(t)

			resp, requestID := putPermissions(t, granularToken, target.path(targetID),
				[]int64{manageAccount, custom.ID, ordinary.ID}, []int64{})
			_ = resp.Body.Close()
			assert.Equal(t, http.StatusOK, resp.StatusCode, "manage-account, a custom authserver permission and another resource's are not administrative")
			assert.ElementsMatch(t, []int64{manageAccount, custom.ID, ordinary.ID}, target.stored(t, targetID))
			assert.Empty(t, refusalRows(t, manageToken, requestID))

			resp, _ = putPermissions(t, granularToken, target.path(targetID),
				[]int64{}, []int64{manageAccount, custom.ID, ordinary.ID})
			_ = resp.Body.Close()
			assert.Equal(t, http.StatusOK, resp.StatusCode, "and revoking them is as open")
			assert.Empty(t, target.stored(t, targetID))
		})
	}
}

func TestGrantCeiling_AManageTokenGrantsAndRevokesAdministrativePermissions(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)

	for _, target := range grantCeilingTargets {
		t.Run(target.kind, func(t *testing.T) {
			targetID := target.create(t)
			var all []int64
			for _, identifier := range administrativePermissionIdentifiers {
				all = append(all, authServerPermissionID(t, identifier))
			}

			resp, requestID := putPermissions(t, manageToken, target.path(targetID), all, []int64{})
			_ = resp.Body.Close()
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.ElementsMatch(t, all, target.stored(t, targetID))
			assert.Empty(t, refusalRows(t, manageToken, requestID))

			resp, _ = putPermissions(t, manageToken, target.path(targetID), []int64{}, all)
			_ = resp.Body.Close()
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Empty(t, target.stored(t, targetID))
		})
	}
}
