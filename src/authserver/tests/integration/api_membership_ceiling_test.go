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
	"github.com/leodip/goiabada/core/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The grant ceiling on group membership and group deletion: joining or leaving a group that holds
// an administrative permission grants or revokes it, so only an authserver:manage token moves a
// user into or out of such a group, by either membership route, or deletes one (#402 decisions 1,
// 2, 4 and 5).
//
// Each row runs three ways: manage-users against an administrative group is refused 403
// MANAGE_SCOPE_REQUIRED with the insufficient_scope challenge, changes nothing and leaves exactly
// one administrator_change_refused row; the same token against an ordinary group succeeds; and
// authserver:manage succeeds against an administrative group.

// newMembershipUser is a fresh user no group holds.
func newMembershipUser(t *testing.T) int64 {
	t.Helper()
	user := &record.User{Subject: fake.UUID(), Enabled: true, Email: uniqueEmail("ceiling@members.test"), GivenName: "Member"}
	require.NoError(t, database.CreateUser(context.Background(), nil, user))
	t.Cleanup(func() { _ = database.DeleteUser(context.Background(), nil, user.Id) })
	return user.Id
}

// newGroupHolding is a fresh group granted the given permissions.
func newGroupHolding(t *testing.T, permissionIds ...int64) int64 {
	t.Helper()
	group := createTestGroup(t)
	t.Cleanup(func() { _ = database.DeleteGroup(context.Background(), nil, group.Id) })
	for _, permissionId := range permissionIds {
		require.NoError(t, database.CreateGroupPermission(context.Background(), nil,
			&record.GroupPermission{GroupId: group.Id, PermissionId: permissionId}))
	}
	return group.Id
}

// ordinaryGroup is a fresh group holding manage-account and an operator's custom authserver
// permission, neither of them administrative.
func ordinaryGroup(t *testing.T) int64 {
	t.Helper()
	authServer, err := database.GetResourceByResourceIdentifier(context.Background(), nil, builtin.AuthServerResourceIdentifier)
	require.NoError(t, err)
	custom := createTestPermission(t, authServer.Id, "members-custom-"+strings.ToLower(fake.LetterN(6)), "An operator's own permission")
	t.Cleanup(func() { _ = database.DeletePermission(context.Background(), nil, custom.Id) })
	return newGroupHolding(t, authServerPermissionId(t, builtin.ManageAccountPermissionIdentifier), custom.Id)
}

func joinGroup(t *testing.T, userId, groupId int64) {
	t.Helper()
	require.NoError(t, database.CreateUserGroup(context.Background(), nil, &record.UserGroup{UserId: userId, GroupId: groupId}))
}

func memberOf(t *testing.T, userId, groupId int64) bool {
	t.Helper()
	membership, err := database.GetUserGroupByUserIdAndGroupId(context.Background(), nil, userId, groupId)
	require.NoError(t, err)
	return membership != nil
}

func groupExists(t *testing.T, groupId int64) bool {
	t.Helper()
	group, err := database.GetGroupById(context.Background(), nil, groupId)
	require.NoError(t, err)
	return group != nil
}

// sendAdmin sends one admin API request under its own request id, so the audit rows it leaves can
// be read back by that id alone.
func sendAdmin(t *testing.T, accessToken, method, path string, body any) (*http.Response, string) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequest(method, appConfig.AuthServer.BaseURL+path, reader)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	requestId := "members-" + fake.LetterN(16)
	req.Header.Set("X-Request-Id", requestId)

	resp, err := createHttpClient(t).Do(req)
	require.NoError(t, err)
	return resp, requestId
}

// membershipCeilingChange is one of the five writes the ceiling guards.
type membershipCeilingChange struct {
	name   string
	method string
	route  string
	// prepare puts the state the write changes in place: the user in the group, for a removal.
	prepare func(t *testing.T, userId, groupId int64)
	send    func(t *testing.T, token string, userId, groupId int64) (*http.Response, string)
	// done reports whether the write's effect is in the store.
	done func(t *testing.T, userId, groupId int64) bool
	// targetKind is the target a refusal names: the user whose memberships change, or the group.
	targetKind string
}

func (c membershipCeilingChange) targetId(userId, groupId int64) int64 {
	if c.targetKind == "group" {
		return groupId
	}
	return userId
}

var membershipCeilingChanges = []membershipCeilingChange{
	{
		name:    "PUT users groups joining",
		method:  http.MethodPut,
		route:   "/api/v1/admin/users/{id}/groups",
		prepare: func(t *testing.T, userId, groupId int64) {},
		send: func(t *testing.T, token string, userId, groupId int64) (*http.Response, string) {
			return sendAdmin(t, token, http.MethodPut, fmt.Sprintf("/api/v1/admin/users/%d/groups", userId),
				map[string]any{"groupIds": []int64{groupId}, "expectedGroupIds": []int64{}})
		},
		done:       func(t *testing.T, userId, groupId int64) bool { return memberOf(t, userId, groupId) },
		targetKind: "user",
	},
	{
		name:    "PUT users groups leaving",
		method:  http.MethodPut,
		route:   "/api/v1/admin/users/{id}/groups",
		prepare: joinGroup,
		send: func(t *testing.T, token string, userId, groupId int64) (*http.Response, string) {
			return sendAdmin(t, token, http.MethodPut, fmt.Sprintf("/api/v1/admin/users/%d/groups", userId),
				map[string]any{"groupIds": []int64{}, "expectedGroupIds": []int64{groupId}})
		},
		done:       func(t *testing.T, userId, groupId int64) bool { return !memberOf(t, userId, groupId) },
		targetKind: "user",
	},
	{
		name:    "POST group members",
		method:  http.MethodPost,
		route:   "/api/v1/admin/groups/{id}/members",
		prepare: func(t *testing.T, userId, groupId int64) {},
		send: func(t *testing.T, token string, userId, groupId int64) (*http.Response, string) {
			return sendAdmin(t, token, http.MethodPost, fmt.Sprintf("/api/v1/admin/groups/%d/members", groupId),
				map[string]any{"userId": userId})
		},
		done:       func(t *testing.T, userId, groupId int64) bool { return memberOf(t, userId, groupId) },
		targetKind: "user",
	},
	{
		name:    "DELETE group member",
		method:  http.MethodDelete,
		route:   "/api/v1/admin/groups/{id}/members/{userId}",
		prepare: joinGroup,
		send: func(t *testing.T, token string, userId, groupId int64) (*http.Response, string) {
			return sendAdmin(t, token, http.MethodDelete, fmt.Sprintf("/api/v1/admin/groups/%d/members/%d", groupId, userId), nil)
		},
		done:       func(t *testing.T, userId, groupId int64) bool { return !memberOf(t, userId, groupId) },
		targetKind: "user",
	},
	{
		name:    "DELETE group",
		method:  http.MethodDelete,
		route:   "/api/v1/admin/groups/{id}",
		prepare: func(t *testing.T, userId, groupId int64) {},
		send: func(t *testing.T, token string, userId, groupId int64) (*http.Response, string) {
			return sendAdmin(t, token, http.MethodDelete, fmt.Sprintf("/api/v1/admin/groups/%d", groupId), nil)
		},
		done:       func(t *testing.T, userId, groupId int64) bool { return !groupExists(t, groupId) },
		targetKind: "group",
	},
}

func TestMembershipCeiling_AGranularTokenCannotMoveAUserThroughAnAdministrativeGroup(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)
	granularToken, caller := createClientWithGranularScope(t, builtin.ManageUsersPermissionIdentifier)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, caller.Id) })

	for _, change := range membershipCeilingChanges {
		for _, identifier := range administrativePermissionIdentifiers {
			t.Run(change.name+"/"+identifier, func(t *testing.T) {
				userId := newMembershipUser(t)
				administrative := authServerPermissionId(t, identifier)
				// Beside an ordinary permission the group also holds, which the refusal does not name.
				groupId := newGroupHolding(t, administrative, authServerPermissionId(t, builtin.ManageAccountPermissionIdentifier))
				change.prepare(t, userId, groupId)

				resp, requestId := change.send(t, granularToken, userId, groupId)
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

				assert.False(t, change.done(t, userId, groupId), "the refused request changed nothing")

				rows := refusalRows(t, manageToken, requestId)
				require.Len(t, rows, 1, "exactly one administrator_change_refused row for the refused request")
				row := rows[0]
				assert.Equal(t, caller.ClientIdentifier, row["logged_in_user"], "the caller is the token's sub")
				assert.Equal(t, change.method, row["method"])
				assert.Equal(t, change.route, row["route"])
				assert.Equal(t, "grant", row["ceiling"])
				assert.Equal(t, change.targetKind, row["target_kind"])
				assert.Equal(t, float64(change.targetId(userId, groupId)), row["target_id"])
				assert.Equal(t, []any{float64(administrative)}, row["permission_ids"], "the administrative permission the group holds")
				if change.targetKind == "user" {
					assert.Equal(t, []any{float64(groupId)}, row["group_ids"], "the group whose membership was refused")
				} else {
					assert.NotContains(t, row, "group_ids")
				}
			})
		}
	}
}

func TestMembershipCeiling_AGranularTokenStillChangesOrdinaryGroups(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)
	granularToken, caller := createClientWithGranularScope(t, builtin.ManageUsersPermissionIdentifier)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, caller.Id) })

	for _, change := range membershipCeilingChanges {
		t.Run(change.name, func(t *testing.T) {
			userId := newMembershipUser(t)
			groupId := ordinaryGroup(t)
			change.prepare(t, userId, groupId)

			resp, requestId := change.send(t, granularToken, userId, groupId)
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			assert.Less(t, resp.StatusCode, 300, "manage-account and a custom authserver permission are not administrative: %s", body)
			assert.True(t, change.done(t, userId, groupId))
			assert.Empty(t, refusalRows(t, manageToken, requestId))
		})
	}
}

func TestMembershipCeiling_AManageTokenChangesAdministrativeGroups(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)

	for _, change := range membershipCeilingChanges {
		t.Run(change.name, func(t *testing.T) {
			userId := newMembershipUser(t)
			groupId := newGroupHolding(t, authServerPermissionId(t, builtin.ManagePermissionIdentifier))
			change.prepare(t, userId, groupId)

			resp, requestId := change.send(t, manageToken, userId, groupId)
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			assert.Less(t, resp.StatusCode, 300, string(body))
			assert.True(t, change.done(t, userId, groupId))
			assert.Empty(t, refusalRows(t, manageToken, requestId))
		})
	}
}
