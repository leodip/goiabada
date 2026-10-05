package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The last-administrator guard: an administrator remains while at least one enabled user holds
// authserver:manage, directly or through a group, and each of the writes that can end that is
// refused 409 LAST_ADMINISTRATOR, with nothing written and no audit record, when it would bring the
// count to zero (#402 decisions 10 and 12). Revoking manage from a user or from a group, removing a
// user from a group that gives it by either membership route, deleting such a group, disabling a
// user and deleting one: each is refused for the last holder and allowed for one of two.
//
// The tier's server is seeded with an administrator, and other tests make more, so each case first
// disables every other enabled holder, directly in the database, and enables them again when it
// ends. The token every case calls with belongs to a client holding manage, which is also the
// proof that clients do not count.

// lastAdministratorDescription is decision 12's sentence, written out here rather than read from
// the code under test.
const lastAdministratorDescription = "This change would leave no enabled user holding authserver:manage. Grant it to another user first."

// disableOtherAdministrators disables every enabled user holding manage, directly or through a
// group, and registers their re-enabling, so the user a case makes an administrator next is the
// only one.
func disableOtherAdministrators(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	manage := authServerPermissionId(t, builtin.ManagePermissionIdentifier)

	holders := map[int64]bool{}
	direct, _, err := database.GetUsersByPermissionIdPaginated(ctx, nil, manage, 1, 10000)
	require.NoError(t, err)
	for _, user := range direct {
		holders[user.Id] = true
	}
	groups, err := database.GetAllGroups(ctx, nil)
	require.NoError(t, err)
	for _, group := range groups {
		grant, grantErr := database.GetGroupPermissionByGroupIdAndPermissionId(ctx, nil, group.Id, manage)
		require.NoError(t, grantErr)
		if grant == nil {
			continue
		}
		members, _, membersErr := database.GetGroupMembersPaginated(ctx, nil, group.Id, 1, 10000)
		require.NoError(t, membersErr)
		for _, member := range members {
			holders[member.Id] = true
		}
	}

	for userId := range holders {
		flipped, flipErr := database.TrySetUserEnabled(ctx, nil, userId, true, false)
		require.NoError(t, flipErr)
		if flipped {
			t.Cleanup(func() {
				_, _ = database.TrySetUserEnabled(context.Background(), nil, userId, false, true)
			})
		}
	}
}

// lastAdministratorFixture is one administrator, and the group that gives them manage where the
// write is about a group.
type lastAdministratorFixture struct {
	userId  int64
	groupId int64
	manage  int64
}

// newAdministrator creates an enabled user holding manage directly.
func newAdministrator(t *testing.T, manage int64) int64 {
	t.Helper()
	user := &record.User{Subject: fake.UUID(), Enabled: true, Email: uniqueEmail("last@administrators.test"), GivenName: "Last"}
	require.NoError(t, database.CreateUser(context.Background(), nil, user))
	t.Cleanup(func() { _ = database.DeleteUser(context.Background(), nil, user.Id) })
	require.NoError(t, database.CreateUserPermission(context.Background(), nil, &record.UserPermission{UserId: user.Id, PermissionId: manage}))
	return user.Id
}

// newAdministratorThroughGroup creates an enabled user holding manage only through a group.
func newAdministratorThroughGroup(t *testing.T, manage int64) (userId, groupId int64) {
	t.Helper()
	user := &record.User{Subject: fake.UUID(), Enabled: true, Email: uniqueEmail("last@administrators.test"), GivenName: "Last"}
	require.NoError(t, database.CreateUser(context.Background(), nil, user))
	t.Cleanup(func() { _ = database.DeleteUser(context.Background(), nil, user.Id) })
	group := createTestGroup(t)
	t.Cleanup(func() { _ = database.DeleteGroup(context.Background(), nil, group.Id) })
	require.NoError(t, database.CreateGroupPermission(context.Background(), nil, &record.GroupPermission{GroupId: group.Id, PermissionId: manage}))
	require.NoError(t, database.CreateUserGroup(context.Background(), nil, &record.UserGroup{UserId: user.Id, GroupId: group.Id}))
	return user.Id, group.Id
}

// lastAdministratorWrite is one of the guarded writes.
type lastAdministratorWrite struct {
	name string
	// prepare makes the administrator the write would remove.
	prepare func(t *testing.T, manage int64) lastAdministratorFixture
	method  string
	path    func(f lastAdministratorFixture) string
	body    func(f lastAdministratorFixture) any
	// removed reports whether the write's effect is in the store.
	removed func(t *testing.T, f lastAdministratorFixture) bool
}

func directAdministrator(t *testing.T, manage int64) lastAdministratorFixture {
	return lastAdministratorFixture{userId: newAdministrator(t, manage), manage: manage}
}

func groupAdministrator(t *testing.T, manage int64) lastAdministratorFixture {
	userId, groupId := newAdministratorThroughGroup(t, manage)
	return lastAdministratorFixture{userId: userId, groupId: groupId, manage: manage}
}

func userGone(t *testing.T, userId int64) bool {
	t.Helper()
	user, err := database.GetUserById(context.Background(), nil, userId)
	require.NoError(t, err)
	return user == nil
}

func groupGone(t *testing.T, groupId int64) bool {
	t.Helper()
	group, err := database.GetGroupById(context.Background(), nil, groupId)
	require.NoError(t, err)
	return group == nil
}

var lastAdministratorWrites = []lastAdministratorWrite{
	{
		name:    "revoking manage from a user",
		prepare: directAdministrator,
		method:  http.MethodPut,
		path: func(f lastAdministratorFixture) string {
			return fmt.Sprintf("/api/v1/admin/users/%d/permissions", f.userId)
		},
		body: func(f lastAdministratorFixture) any {
			return map[string]any{"permissionIds": []int64{}, "expectedPermissionIds": []int64{f.manage}}
		},
		removed: func(t *testing.T, f lastAdministratorFixture) bool {
			return len(userPermissionIds(t, f.userId)) == 0
		},
	},
	{
		name:    "revoking manage from a group",
		prepare: groupAdministrator,
		method:  http.MethodPut,
		path: func(f lastAdministratorFixture) string {
			return fmt.Sprintf("/api/v1/admin/groups/%d/permissions", f.groupId)
		},
		body: func(f lastAdministratorFixture) any {
			return map[string]any{"permissionIds": []int64{}, "expectedPermissionIds": []int64{f.manage}}
		},
		removed: func(t *testing.T, f lastAdministratorFixture) bool {
			return len(groupPermissionIds(t, f.groupId)) == 0
		},
	},
	{
		name:    "removing a user from the group through the user's groups",
		prepare: groupAdministrator,
		method:  http.MethodPut,
		path:    func(f lastAdministratorFixture) string { return fmt.Sprintf("/api/v1/admin/users/%d/groups", f.userId) },
		body: func(f lastAdministratorFixture) any {
			return map[string]any{"groupIds": []int64{}, "expectedGroupIds": []int64{f.groupId}}
		},
		removed: func(t *testing.T, f lastAdministratorFixture) bool {
			return len(userGroupIds(t, f.userId)) == 0
		},
	},
	{
		name:    "removing a user from the group through the group's members",
		prepare: groupAdministrator,
		method:  http.MethodDelete,
		path: func(f lastAdministratorFixture) string {
			return fmt.Sprintf("/api/v1/admin/groups/%d/members/%d", f.groupId, f.userId)
		},
		removed: func(t *testing.T, f lastAdministratorFixture) bool {
			return len(userGroupIds(t, f.userId)) == 0
		},
	},
	{
		name:    "deleting the group",
		prepare: groupAdministrator,
		method:  http.MethodDelete,
		path:    func(f lastAdministratorFixture) string { return fmt.Sprintf("/api/v1/admin/groups/%d", f.groupId) },
		removed: func(t *testing.T, f lastAdministratorFixture) bool {
			return groupGone(t, f.groupId)
		},
	},
	{
		name:    "disabling the user",
		prepare: directAdministrator,
		method:  http.MethodPut,
		path: func(f lastAdministratorFixture) string {
			return fmt.Sprintf("/api/v1/admin/users/%d/enabled", f.userId)
		},
		body: func(f lastAdministratorFixture) any { return map[string]any{"enabled": false} },
		removed: func(t *testing.T, f lastAdministratorFixture) bool {
			return !storedUser(t, f.userId).Enabled
		},
	},
	{
		name:    "deleting the user",
		prepare: directAdministrator,
		method:  http.MethodDelete,
		path:    func(f lastAdministratorFixture) string { return fmt.Sprintf("/api/v1/admin/users/%d", f.userId) },
		removed: func(t *testing.T, f lastAdministratorFixture) bool {
			return userGone(t, f.userId)
		},
	},
}

// sendAdminRequest sends one admin API request under its own request id, so the audit rows it
// leaves can be read back by that id alone.
func sendAdminRequest(t *testing.T, accessToken, method, path string, body any) (*http.Response, string) {
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
	requestId := "last-admin-" + fake.LetterN(16)
	req.Header.Set("X-Request-Id", requestId)

	resp, err := createHttpClient(t).Do(req)
	require.NoError(t, err)
	return resp, requestId
}

// auditRowsOfRequest is every audit row one request left, whatever its event.
func auditRowsOfRequest(t *testing.T, readerToken, requestId string) int {
	t.Helper()
	logs, resp := getAuditLogs(t, readerToken, "requestId="+url.QueryEscape(requestId))
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return len(logs.AuditLogs)
}

func TestLastAdministrator_EachGuardedWriteIsRefusedForTheLastHolder(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)
	manage := authServerPermissionId(t, builtin.ManagePermissionIdentifier)

	for _, write := range lastAdministratorWrites {
		t.Run(write.name, func(t *testing.T) {
			disableOtherAdministrators(t)
			f := write.prepare(t, manage)

			var body any
			if write.body != nil {
				body = write.body(f)
			}
			resp, requestId := sendAdminRequest(t, manageToken, write.method, write.path(f), body)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusConflict, resp.StatusCode)
			var envelope struct {
				ErrorCode        string `json:"error_code"`
				ErrorDescription string `json:"error_description"`
			}
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&envelope))
			assert.Equal(t, "LAST_ADMINISTRATOR", envelope.ErrorCode)
			assert.Equal(t, lastAdministratorDescription, envelope.ErrorDescription)

			assert.False(t, write.removed(t, f), "the refused write changed nothing")
			assert.Zero(t, auditRowsOfRequest(t, manageToken, requestId), "a refusal under the guard is not audited")
		})
	}
}

func TestLastAdministrator_EachGuardedWriteIsAllowedForOneOfTwo(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)
	manage := authServerPermissionId(t, builtin.ManagePermissionIdentifier)

	for _, write := range lastAdministratorWrites {
		t.Run(write.name, func(t *testing.T) {
			disableOtherAdministrators(t)
			f := write.prepare(t, manage)
			newAdministrator(t, manage)

			var body any
			if write.body != nil {
				body = write.body(f)
			}
			resp, _ := sendAdminRequest(t, manageToken, write.method, write.path(f), body)
			respBody, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			assert.Equal(t, http.StatusOK, resp.StatusCode, "another administrator remains: %s", respBody)
			assert.True(t, write.removed(t, f), "the write took effect")
		})
	}
}

// The guard counts holders, not grants: a user who keeps manage through a group may lose the direct
// grant, and a disabled holder is no administrator, so neither keeps nor needs the guard.
func TestLastAdministrator_ItCountsEnabledHoldersNotGrants(t *testing.T) {
	manageToken, _ := createAdminClientWithToken(t)
	manage := authServerPermissionId(t, builtin.ManagePermissionIdentifier)

	t.Run("revoking the direct grant of a user who keeps manage through a group", func(t *testing.T) {
		disableOtherAdministrators(t)
		userId, _ := newAdministratorThroughGroup(t, manage)
		require.NoError(t, database.CreateUserPermission(context.Background(), nil, &record.UserPermission{UserId: userId, PermissionId: manage}))

		resp, _ := sendAdminRequest(t, manageToken, http.MethodPut, fmt.Sprintf("/api/v1/admin/users/%d/permissions", userId),
			map[string]any{"permissionIds": []int64{}, "expectedPermissionIds": []int64{manage}})
		respBody, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode, "they remain an administrator through the group: %s", respBody)
	})

	t.Run("disabling the only enabled holder while a disabled one also holds manage", func(t *testing.T) {
		disableOtherAdministrators(t)
		dormant := newAdministrator(t, manage)
		flipped, err := database.TrySetUserEnabled(context.Background(), nil, dormant, true, false)
		require.NoError(t, err)
		require.True(t, flipped)
		last := newAdministrator(t, manage)

		resp, _ := sendAdminRequest(t, manageToken, http.MethodPut, fmt.Sprintf("/api/v1/admin/users/%d/enabled", last),
			map[string]any{"enabled": false})
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusConflict, resp.StatusCode, "a disabled holder is no administrator")
		assert.True(t, storedUser(t, last).Enabled)
	})
}
