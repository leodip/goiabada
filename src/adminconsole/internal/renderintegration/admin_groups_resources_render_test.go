package renderintegration

import (
	"strings"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/core/api"

	"github.com/stretchr/testify/assert"
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
	out := renderMenuPage(t, "/admin_resources_permissions.html", map[string]interface{}{
		"resourceId":            2,
		"resourceIdentifier":    "faturamento",
		"isSystemLevelResource": false,
		"savedSuccessfully":     false,
		"entries": []struct {
			Id          int64
			Identifier  string
			Description string
			BuiltIn     bool
		}{{Id: 9, Identifier: "ler", Description: "Ler faturas"}},
	})

	// The rows are drawn from the entries' fields, which the editor reads back out of the row, so a
	// renamed or missing field arrives as an empty attribute rather than as a template error.
	assert.Contains(t, out, `<tr data-id="9" data-identifier="ler" data-description="Ler faturas">`)
	assert.Contains(t, out, `type="button" data-entry-edit>Editar<span class="sr-only"> ler</span></button>`)
	assert.Contains(t, out, `type="button" data-entry-remove>Remover<span class="sr-only"> ler</span></button>`)
}

// The auth server's own resource draws its built-in permissions with no Edit or Remove, since no
// caller may rename or delete them, and asks before every save.
func TestRender_AdminResourcePermissions_BuiltInsHaveNoEditOrRemove(t *testing.T) {
	out := renderMenuPage(t, "/admin_resources_permissions.html", map[string]interface{}{
		"resourceId":            1,
		"resourceIdentifier":    "authserver",
		"isSystemLevelResource": true,
		"savedSuccessfully":     false,
		"entries": []struct {
			Id          int64
			Identifier  string
			Description string
			BuiltIn     bool
		}{{Id: 1, Identifier: "manage", Description: "Manage", BuiltIn: true}, {Id: 9, Identifier: "custom", Description: "Custom"}},
	})

	assert.Equal(t, 1, strings.Count(out, "data-entry-edit>"), "only the custom permission is editable")
	assert.Equal(t, 1, strings.Count(out, "data-entry-remove>"))
	assert.Contains(t, out, `<span class="tag">Embutida</span>`)
	assert.Contains(t, out, `data-confirm-always="`)
}

// The resource permissions page draws the entries it loaded as rows, which resource-permissions.js
// reads once, as it loads, and sends with every save, so the auth server can refuse a save from an
// outdated page rather than undo another administrator's rename or new permission (#428).
func TestRender_AdminResourcePermissions_SendsTheLoadedList(t *testing.T) {
	out := renderMenuPage(t, "/admin_resources_permissions.html", map[string]interface{}{
		"resourceId":            2,
		"resourceIdentifier":    "faturamento",
		"isSystemLevelResource": false,
		"savedSuccessfully":     false,
		"entries": []struct {
			Id          int64
			Identifier  string
			Description string
			BuiltIn     bool
		}{{Id: 9, Identifier: "ler", Description: "Ler faturas"}, {Id: 10, Identifier: "escrever", Description: "Escrever faturas"}},
	})

	assert.Contains(t, out, `data-list-key="permissions" data-expected-key="expectedPermissions"`)
	assert.Contains(t, out, `src="/static/pages/resource-permissions.js`)
	assertListScriptSendsTheLoadedList(t, "pages/resource-permissions.js", "loadedEntries", "entries()")
}
