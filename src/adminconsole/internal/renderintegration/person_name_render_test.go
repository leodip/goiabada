package renderintegration

import (
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/admingrouphandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminresourcehandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminuserhandlers"
	"github.com/leodip/goiabada/adminconsole/internal/pagination"
	"github.com/leodip/goiabada/core/api"

	"github.com/stretchr/testify/assert"
)

// The three lists write a user's full name through core/personname, as every other place the
// console shows one does: a name in kanji family name first with no space, and a Latin name as
// before (#662 decisions 1 and 2).
var listedUsers = []api.UserResponse{
	{ID: 1, Username: "yamada", Email: "yamada@example.com", GivenName: "太郎", FamilyName: "山田"},
	{ID: 2, Username: "jdoe", Email: "jane@example.com", GivenName: "Jane", MiddleName: "Q", FamilyName: "Doe"},
}

func TestRender_AdminUsersListWritesTheFullName(t *testing.T) {
	out := renderMenuPageIn(t, "/admin_users.html", map[string]interface{}{
		"pageResult":    adminuserhandlers.PageResult{Users: listedUsers, Total: 2, Page: 1, PageSize: 10},
		"paginator":     pagination.New(2, 10, 1, 5),
		"paginatorLink": "/admin/users",
	}, "en", true)

	assert.Contains(t, out, "山田太郎")
	assert.Contains(t, out, "Jane Q Doe")
	assert.NotContains(t, out, "太郎 山田")
}

func TestRender_AdminGroupMembersWritesTheFullName(t *testing.T) {
	out := renderMenuPageIn(t, "/admin_groups_members.html", map[string]interface{}{
		"groupId":         int64(3),
		"groupIdentifier": "staff",
		"pageResult":      admingrouphandlers.PageResult{Users: listedUsers, Total: 2, Page: 1, PageSize: 10},
		"paginator":       pagination.New(2, 10, 1, 5),
		"description":     "",
	}, "en", true)

	assert.Contains(t, out, `<span class="cell-secondary">山田太郎 · yamada</span>`)
	assert.Contains(t, out, `<span class="cell-secondary">Jane Q Doe · jdoe</span>`)
}

func TestRender_AdminUsersWithPermissionWritesTheFullName(t *testing.T) {
	permissions := []api.PermissionResponse{{ID: 6, PermissionIdentifier: "read"}}
	out := renderMenuPageIn(t, "/admin_resources_users_with_permission.html", map[string]interface{}{
		"resourceId":                   int64(4),
		"resourceIdentifier":           "orders-api",
		"description":                  "",
		"isSystemLevelResource":        false,
		"permissions":                  permissions,
		"permissionChoices":            nil,
		"selectedPermission":           int64(6),
		"selectedPermissionIdentifier": "read",
		"pageResult":                   adminresourcehandlers.UsersWithPermissionPageResult{Users: listedUsers, Total: 2, Page: 1, PageSize: 10},
		"paginator":                    pagination.New(2, 10, 1, 5),
	}, "en", true)

	assert.Contains(t, out, `<span class="cell-secondary">山田太郎 · yamada</span>`)
	assert.Contains(t, out, `<span class="cell-secondary">Jane Q Doe · jdoe</span>`)
}

// A user with a username and no name is drawn with the username alone, and one with neither with
// nothing, as before.
func TestRender_AdminGroupMembersWithNoName(t *testing.T) {
	out := renderMenuPageIn(t, "/admin_groups_members.html", map[string]interface{}{
		"groupId":         int64(3),
		"groupIdentifier": "staff",
		"pageResult": admingrouphandlers.PageResult{Users: []api.UserResponse{
			{ID: 1, Username: "anon", Email: "anon@example.com"},
			{ID: 2, Email: "nobody@example.com"},
		}, Total: 2, Page: 1, PageSize: 10},
		"paginator":   pagination.New(2, 10, 1, 5),
		"description": "",
	}, "en", true)

	assert.Contains(t, out, `<span class="cell-secondary">anon</span>`)
	assert.NotContains(t, out, `<span class="cell-secondary"></span>`)
	assert.NotContains(t, out, `<span class="cell-secondary"> · `)
}
