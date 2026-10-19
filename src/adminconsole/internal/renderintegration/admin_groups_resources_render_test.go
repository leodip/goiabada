package renderintegration

import (
	"strings"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/core/api"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The group permissions page draws the grants it loaded as rows, which permission-list.js reads
// once, as it loads, and sends with every save, beside the group the route's body names (#428).
func TestRender_AdminGroupsPermissions_SendsTheLoadedList(t *testing.T) {
	out := renderMenuPage(t, "/admin_groups_permissions.html", map[string]interface{}{
		"group": struct {
			GroupId         int64
			GroupIdentifier string
		}{GroupId: 5, GroupIdentifier: "admins"},
		"granted": []struct {
			Id    int64
			Scope string
		}{{Id: 3, Scope: "some-resource:read"}, {Id: 4, Scope: "some-resource:write"}},
		"resources":         []render.Choice{},
		"savedSuccessfully": false,
	})

	assert.Contains(t, out, `<tr data-id="3">`)
	assert.Contains(t, out, `<tr data-id="4">`)
	assert.Contains(t, out, `data-save-url="/admin/groups/5/permissions" data-owner-key="groupId" data-owner-id="5"`)
	assert.Contains(t, out, `data-list-key="assignedPermissionsIds" data-expected-key="expectedPermissionIds"`)
	assert.Contains(t, out, `src="/static/pages/permission-list.js`)
	assertListScriptSendsTheLoadedList(t, "pages/permission-list.js", "loadedIds", "grantedIds()")
}

// Seam 4 for the group family (#350): the three group pages whose templates read the fields the
// apiclient used to rebuild into a record.Group. This is the only seam that catches a template
// naming a field the DTO does not carry, because it runs the real template FS, funcmap and layout.
//
// The list is the page that reads the most of the response: the identifier and description, the
// member count, and the two booleans that decide which token a membership reaches, drawn as tags.
func TestRender_AdminGroups(t *testing.T) {
	out := renderMenuPage(t, "/admin_groups.html", map[string]interface{}{
		"groups": []api.GroupResponse{
			{Id: 2, GroupIdentifier: "admins", Description: "Administradores",
				IncludeInIdToken: true, IncludeInAccessToken: false, MemberCount: 17},
			{Id: 3, GroupIdentifier: "site-viewers", MemberCount: 0},
		},
	})

	assert.Contains(t, out, "admins")
	assert.Contains(t, out, "Administradores")
	assert.Contains(t, out, "site-viewers")
	assert.Regexp(t, `data-label="Membros">17</td>`, out,
		"the member count column is what GetGroupById's second return used to carry")

	// The token cell, both arms: the first row's ID token tag and no access token tag, and the
	// second row's word for neither. A row that rendered neither arm would still leave the other
	// row's text, so the counts are what tell them apart.
	assert.Equal(t, 1, strings.Count(out, `<span class="tag">ID token</span>`))
	assert.Equal(t, 0, strings.Count(out, `<span class="tag">Token de acesso</span>`))
	assert.Equal(t, 1, strings.Count(out, `<span class="text-ink-muted">Nenhum</span>`))
}

// The delete confirmation, whose member count comes off the response now rather than from a second
// return value the apiclient answered beside the group.
func TestRender_AdminGroupDelete(t *testing.T) {
	out := renderMenuPage(t, "/admin_groups_delete.html", map[string]interface{}{
		"group":        &api.GroupResponse{Id: 2, GroupIdentifier: "admins", Description: "Administradores"},
		"countOfUsers": 17,
	})

	assert.Contains(t, out, "admins")
	assert.Contains(t, out, "Administradores")
	assert.Contains(t, out, "<dt>Membros</dt>")
	assert.Regexp(t, `<dd>17 <a`, out,
		"the count the administrator is about to orphan has to be on the page")
}

// The attributes page, both arms: a group with attributes and a group with none. The empty arm is
// the one a decode that answered an empty slice for a populated group would land on silently.
func TestRender_AdminGroupAttributes(t *testing.T) {
	t.Run("with attributes", func(t *testing.T) {
		out := renderMenuPage(t, "/admin_groups_attributes.html", map[string]interface{}{
			"groupId":         int64(2),
			"groupIdentifier": "admins",
			"description":     "Administradores",
			"attributes": []api.GroupAttributeResponse{
				{Id: 7, Key: "tier", Value: "gold", GroupId: 2, IncludeInIdToken: true},
				{Id: 8, Key: "region", Value: "br", GroupId: 2, IncludeInAccessToken: true},
			},
		})

		assert.Contains(t, out, "admins")
		assert.Contains(t, out, "tier")
		assert.Contains(t, out, "gold")
		assert.Contains(t, out, "region")
		assert.NotContains(t, out, "Nenhum atributo ainda.",
			"with two attributes listed, the empty arm must not also render")
	})

	t.Run("with none", func(t *testing.T) {
		out := renderMenuPage(t, "/admin_groups_attributes.html", map[string]interface{}{
			"groupId":         int64(2),
			"groupIdentifier": "admins",
			"description":     "Administradores",
			"attributes":      []api.GroupAttributeResponse{},
		})

		assert.Contains(t, out, "Nenhum atributo ainda.")
	})
}

// The two resource pages, which hold this change's last two families: admin_resources.html ranges
// over the resource DTOs the API client now hands back untouched, and admin_resources_permissions
// pushes each permission DTO into a JavaScript array by field. Both used to read a record.Resource
// and a record.Permission that the API client rebuilt column by column. This is the only seam that
// catches a template naming a field the DTO does not carry, which is the whole reason the package
// exists (#350).
func TestRender_AdminResourcesList(t *testing.T) {
	bind := map[string]interface{}{
		"resources": []api.ResourceResponse{
			{Id: 1, ResourceIdentifier: "authserver", Description: "Servidor de autenticação",
				IsSystemLevelResource: true},
			{Id: 2, ResourceIdentifier: "faturamento", Description: ""},
		},
	}

	out := renderMenuPage(t, "/admin_resources.html", bind)

	assert.Contains(t, out, "authserver")
	assert.Contains(t, out, "Servidor de autenticação")
	assert.Contains(t, out, "/admin/resources/2/settings",
		"the row's links are built from the DTO's Id")
}

func TestRender_AdminResourcePermissions(t *testing.T) {
	bind := map[string]interface{}{
		"resourceId":                   2,
		"resourceIdentifier":           "faturamento",
		"resourceDescription":          "Faturamento",
		"isSystemLevelResource":        false,
		"builtInPermissionIdentifiers": []string{},
		"savedSuccessfully":            false,
		"permissions": []api.PermissionResponse{
			{Id: 9, PermissionIdentifier: "ler", Description: "Ler faturas", ResourceId: 2,
				Resource: api.ResourceResponse{Id: 2, ResourceIdentifier: "faturamento"}},
		},
	}

	out := renderMenuPage(t, "/admin_resources_permissions.html", bind)

	// The page bootstraps its editor from a JavaScript array built out of the DTO's fields, so a
	// renamed or missing field arrives as an empty string rather than as a template error.
	assert.Contains(t, out, `"permissionIdentifier": "ler"`)
	assert.Contains(t, out, `"description": "Ler faturas"`)
	// html/template pads a number interpolated into a script with spaces, so the id is asserted in
	// the form the browser actually receives rather than the form the template reads.
	assert.Contains(t, out, `"id":  9 `)
}

// The resource permissions page keeps a copy of every entry it loaded and sends it with every
// save, so the auth server can refuse a save from an outdated page rather than undo another
// administrator's rename or new permission. The copy is taken entry by entry after every loaded
// entry is pushed, since the editor changes the loaded objects in place, and it is never edited,
// or the page would send its edited list as the loaded one and every save would pass (#428).
func TestRender_AdminResourcePermissions_SendsTheLoadedList(t *testing.T) {
	out := renderMenuPage(t, "/admin_resources_permissions.html", map[string]interface{}{
		"resourceId":                   2,
		"resourceIdentifier":           "faturamento",
		"resourceDescription":          "Faturamento",
		"isSystemLevelResource":        false,
		"builtInPermissionIdentifiers": []string{},
		"savedSuccessfully":            false,
		"permissions": []api.PermissionResponse{
			{Id: 9, PermissionIdentifier: "ler", Description: "Ler faturas", ResourceId: 2},
			{Id: 10, PermissionIdentifier: "escrever", Description: "Escrever faturas", ResourceId: 2},
		},
	})

	const copyTaken = `const loadedPermissions = availablePermissions.map(function(p) { return { "id": p.id, "permissionIdentifier": p.permissionIdentifier, "description": p.description }; });`
	lastLoaded := strings.Index(out, `"permissionIdentifier": "escrever"`)
	require.NotEqual(t, -1, lastLoaded, "the loaded entries are pushed into the editable list")
	require.Less(t, strings.Index(out, `"permissionIdentifier": "ler"`), lastLoaded)
	copyAt := strings.Index(out, copyTaken)
	require.NotEqual(t, -1, copyAt, "the page keeps a copy of each loaded entry")
	assert.Greater(t, copyAt, lastLoaded, "the copy is taken after every loaded entry is in the list")
	assert.Less(t, copyAt, strings.Index(out, "function btnSaveClick"), "the copy is taken at load, before anything can edit the list")

	assert.Contains(t, out, `"expectedPermissions": loadedPermissions`)
	assert.NotRegexp(t, `loadedPermissions\.(push|splice|pop|shift|unshift)\(`, out)
	assert.NotRegexp(t, `loadedPermissions\s*=[^=]`, strings.Replace(out, copyTaken, "", 1))
}
