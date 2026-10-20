package renderintegration

import (
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminuserhandlers"
	"github.com/leodip/goiabada/adminconsole/internal/pagination"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/core/api"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The user permissions page draws the grants it loaded as rows, which permission-list.js reads
// once, as it loads, and sends with every save (#428).
func TestRender_AdminUsersPermissions_SendsTheLoadedList(t *testing.T) {
	out := renderMenuPage(t, "/admin_users_permissions.html", map[string]interface{}{
		"user": &api.UserResponse{Id: 5, Email: "someone@example.com"},
		"granted": []struct {
			Id    int64
			Scope string
		}{{Id: 3, Scope: "some-resource:read"}, {Id: 4, Scope: "some-resource:write"}},
		"resources":         []render.Choice{},
		"page":              "2",
		"query":             "",
		"savedSuccessfully": false,
	})

	assert.Contains(t, out, `<tr data-id="3">`)
	assert.Contains(t, out, `<tr data-id="4">`)
	assert.Contains(t, out, `data-save-url="/admin/users/5/permissions" data-reload-url="/admin/users/5/permissions?page=2"`)
	assert.Contains(t, out, `data-list-key="assignedPermissionsIds" data-expected-key="expectedPermissionIds"`)
	assert.NotContains(t, out, "data-owner-key", "the route names the user, so the body does not")
	assert.Contains(t, out, `src="/static/pages/permission-list.js`)
	assertListScriptSendsTheLoadedList(t, "pages/permission-list.js", "loadedIds", "grantedIds()")
}

// The user groups page draws the memberships it loaded as rows, which user-groups.js reads once, as
// it loads, and sends with every save, so the auth server can refuse a save from an outdated page
// rather than undo another administrator's change (#428).
func TestRender_AdminUsersGroups_SendsTheLoadedList(t *testing.T) {
	out := renderMenuPage(t, "/admin_users_groups.html", map[string]interface{}{
		"user": &api.UserResponse{Id: 5, Email: "someone@example.com"},
		"memberships": []struct {
			Id              int64
			GroupIdentifier string
		}{{Id: 3, GroupIdentifier: "admins"}, {Id: 4, GroupIdentifier: "auditors"}},
		"groupChoices":      []render.Choice{{Id: 3, Identifier: "admins", Label: "admins"}},
		"page":              "",
		"query":             "",
		"savedSuccessfully": false,
	})

	assert.Contains(t, out, `<tr data-id="3">`)
	assert.Contains(t, out, `<tr data-id="4">`)
	assert.Contains(t, out, `<a class="text-link" href="/admin/groups/4/settings">auditors</a>`)
	assert.Contains(t, out, `data-list-key="assignedGroupsIds" data-expected-key="expectedGroupIds"`)
	assert.Contains(t, out, `src="/static/pages/user-groups.js`)
	assertListScriptSendsTheLoadedList(t, "pages/user-groups.js", "loadedGroupIds", "memberOf()")
}

// TestRender_AdminUsersPaginator is the template hop of the paginator (#271): the partial reads a
// *pagination.Paginator, so what needs proving is that a Go template resolves its exported fields,
// and that addUrlParam turns them into page links.
//
// 73 users at 10 a page on page 4 is 8 pages, which exercises both ends of the bar at once:
// "1 2 3 [4] 5 6 ...". The lone "1" is decision 3's rule, the one place this change departs from
// the library, which would have put dots there and left page 1 reachable only by walking back.
func TestRender_AdminUsersPaginator(t *testing.T) {
	out := renderMenuPage(t, "/admin_users.html", map[string]interface{}{
		"pageResult": adminuserhandlers.PageResult{
			// Subject is left empty: the row only has to render.
			Users:    []api.UserResponse{{Id: 1, Username: "alice", Email: "alice@example.com"}},
			Total:    73,
			Query:    "",
			Page:     4,
			PageSize: 10,
		},
		"paginator": pagination.New(73, 10, 4, 5),
	})

	// Page 1 is a link, not dots. Reverting the rule renders "..." here instead.
	assert.Contains(t, out, `href="/admin/users?page=1"`)
	assert.Contains(t, out, `href="/admin/users?page=2"`)
	assert.Contains(t, out, `href="/admin/users?page=6"`)

	// One set of dots, at the trailing end, standing for pages 7 and 8, hidden from assistive
	// technology since it is no page.
	assert.Equal(t, 1, strings.Count(out, `<span class="pager-item" aria-hidden="true">…</span>`), "expected exactly one ellipsis in the bar")

	// Pages 3 and 5 are each a number link and an arrow target, so two occurrences each. That
	// count is what says Previous and Next resolved at all: a field the template cannot read
	// renders as nothing and would leave one.
	assert.Equal(t, 2, strings.Count(out, `href="/admin/users?page=3"`), "page 3 as a number and as the back arrow")
	assert.Equal(t, 2, strings.Count(out, `href="/admin/users?page=5"`), "page 5 as a number and as the forward arrow")

	// The current page is marked as such, and is its number's only link.
	assert.Contains(t, out, `<a class="pager-item" aria-current="page" href="/admin/users?page=4">4</a>`)
	assert.Equal(t, 1, strings.Count(out, `href="/admin/users?page=4"`))

	// The -1 sentinel must never reach addUrlParam: it means "ellipsis", not a page.
	assert.NotContains(t, out, "page=-1")
}

// The two admin user pages that read a timestamp and a full name off the bind. Neither was covered
// here before #350, and between them they carry every template edit the user family's move made:
// the created-at and last-updated cells, which read a *time.Time where they read a sql.NullTime's
// two fields; the full-name cell, which reads a value the handler assembles where it called a
// method on the model; and the delete page's memberships list, which now ranges over groups the
// handler loaded instead of a field the API never filled.
//
// A page that renders is the whole claim: RenderTemplate fails on a field the bind lacks,
// which is the bug this package exists for and the one a DTO swap is most likely to reach.
func TestRender_AdminUserDetails(t *testing.T) {
	createdAt := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updatedAt := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

	out := renderMenuPage(t, "/admin_users_details.html", map[string]interface{}{
		"user": &api.UserResponse{
			Id: 7, Subject: "3f2a1c4e-5b6d-4e8f-9a0b-1c2d3e4f5a6b", Username: "jdoe",
			Email: "jane@example.com", Enabled: true,
			CreatedAt: &createdAt, UpdatedAt: &updatedAt,
		},
		"userFullName":      "Jane Q Doe",
		"page":              "1",
		"query":             "",
		"savedSuccessfully": false,
		"userCreated":       false,
	})

	assert.Contains(t, out, "jane@example.com")
	assert.Contains(t, out, "Jane Q Doe")

	// Both cells render through DateTime, in pt-BR's catalog layout: this page's dates were
	// "02 Jan 2026 03:04:05 UTC" under every locale, month name and all, because the layout
	// lived in the template and Go's time.Format has no locale (#373, decision 8).
	assert.Contains(t, out, ">02/01/2026 03:04<", "the created-at cell renders from the *time.Time")
	assert.Contains(t, out, ">04/03/2026 05:06<", "and so does the last-updated cell")
	assert.NotContains(t, out, "Jan 2026", "an English month name is what the old layout produced")
}

// A user whose timestamps are absent renders an empty cell rather than the year 1: the guard in
// front of each Format call is what stops a nil pointer ending the page in a 500.
func TestRender_AdminUserDetailsWithNoTimestamps(t *testing.T) {
	out := renderMenuPage(t, "/admin_users_details.html", map[string]interface{}{
		"user":              &api.UserResponse{Id: 7, Email: "jane@example.com"},
		"userFullName":      "",
		"page":              "1",
		"query":             "",
		"savedSuccessfully": false,
		"userCreated":       false,
	})

	assert.NotContains(t, out, "0001", "an absent timestamp must render as nothing, not as the zero time")
}

// A refused disable, such as the last administrator's, marks Enabled, the page's one field, and
// gives it the focus, as every other refused field does, so the keyboard resumes there rather than
// at the top of the page (#617).
func TestRender_AdminUserDetailsRefusedFocusesEnabled(t *testing.T) {
	out := renderMenuPage(t, "/admin_users_details.html", map[string]interface{}{
		"user":              &api.UserResponse{Id: 7, Email: "jane@example.com", Enabled: true},
		"userFullName":      "",
		"page":              "1",
		"query":             "",
		"savedSuccessfully": false,
		"userCreated":       false,
		"error":             "The last administrator can't be disabled.",
	})

	start := strings.Index(out, `id="enabledDisabled"`)
	require.GreaterOrEqual(t, start, 0, "the Enabled checkbox renders")
	tag := out[strings.LastIndex(out[:start], "<input"):]
	tag = tag[:strings.Index(tag, ">")]
	assert.Contains(t, tag, `aria-invalid="true"`)
	assert.Contains(t, tag, " autofocus")
}

// The delete confirmation, which is the one page in this change whose output moves for a real
// user: the memberships row listed "none" for everybody before, and lists what deleting the user
// will discard now (#350, deferred decision 1).
func TestRender_AdminUserDelete(t *testing.T) {
	createdAt := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	out := renderMenuPage(t, "/admin_users_delete.html", map[string]interface{}{
		"user": &api.UserResponse{
			Id: 7, Subject: "3f2a1c4e-5b6d-4e8f-9a0b-1c2d3e4f5a6b", Username: "jdoe",
			Email: "jane@example.com", CreatedAt: &createdAt,
		},
		"userFullName": "Jane Q Doe",
		"groups": []api.GroupResponse{
			{Id: 2, GroupIdentifier: "admins"},
			{Id: 3, GroupIdentifier: "site-viewers"},
		},
		"page":  "1",
		"query": "",
	})

	assert.Contains(t, out, "Jane Q Doe")
	assert.Contains(t, out, ">02/01/2026 03:04<", "the created-at cell is localized (#373)")
	assert.NotContains(t, out, "Jan 2026", "an English month name is what the old layout produced")
	assert.Contains(t, out, "admins", "the memberships the deletion discards have to be on the page")
	assert.Contains(t, out, "site-viewers")
	assert.NotContains(t, out, ">Nenhum<", "with two groups listed, the none arm must not also render")
}

// The none arm, which is what every user saw before the fix and what a user in no groups sees now.
func TestRender_AdminUserDeleteWithNoGroups(t *testing.T) {
	out := renderMenuPage(t, "/admin_users_delete.html", map[string]interface{}{
		"user":         &api.UserResponse{Id: 7, Email: "jane@example.com"},
		"userFullName": "",
		"groups":       []api.GroupResponse{},
		"page":         "1",
		"query":        "",
	})

	assert.Contains(t, out, "jane@example.com")
	assert.Contains(t, out, ">Nenhum</span>", "a user in no groups still gets the row's none arm")
}
