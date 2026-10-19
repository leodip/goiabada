package renderintegration

import (
	"testing"

	"github.com/leodip/goiabada/core/api"

	"github.com/stretchr/testify/assert"
)

// Every icon-only edit and remove button of the resource permissions page is named for what it does and to
// which row, in the administrator's language: the page hands the icon builder the action and the
// thing from the catalog, joined to the row's value, and the builder writes that as the button's
// aria-label and title (#562, section 6). The builder's half is held by the lint in web; this is
// the template's half, rendered in both languages the console ships, since a key missing from a
// catalog would leave its raw name in the script, where the layout's raw-key check does not look.
func TestRender_IconButtonsAreNamedForTheirRow(t *testing.T) {
	permissionsResource := map[string]interface{}{
		"resourceId":                   2,
		"resourceIdentifier":           "faturamento",
		"resourceDescription":          "Faturamento",
		"isSystemLevelResource":        false,
		"builtInPermissionIdentifiers": []string{},
		"savedSuccessfully":            false,
		"permissions": []api.PermissionResponse{
			{Id: 9, PermissionIdentifier: "ler", Description: "Ler faturas", ResourceId: 2},
		},
	}

	cases := []struct {
		page string
		bind map[string]interface{}
		// calls are the icon-button calls the page's script makes, in English and in Portuguese.
		en, ptBR []string
	}{
		{"/admin_resources_permissions.html", permissionsResource,
			[]string{`createEditButton("Edit permission " + perm.permissionIdentifier, editPermission,`,
				`createTrashCanButton("Remove permission " + perm.permissionIdentifier, deletePermission,`},
			[]string{`createEditButton("Editar permissão " + perm.permissionIdentifier, editPermission,`,
				`createTrashCanButton("Remover permissão " + perm.permissionIdentifier, deletePermission,`}},
	}
	for _, tc := range cases {
		t.Run(tc.page, func(t *testing.T) {
			en := renderMenuPageIn(t, tc.page, tc.bind, "en", true)
			for _, call := range tc.en {
				assert.Contains(t, en, call)
			}
			ptBR := renderMenuPageIn(t, tc.page, tc.bind, "pt-BR", true)
			for _, call := range tc.ptBR {
				assert.Contains(t, ptBR, call)
			}
			assert.NotRegexp(t, `create(TrashCan|Edit)Button\("[^"]*adminconsole\.`, ptBR,
				"a label names a key the pt-BR catalog lacks")
		})
	}
}
