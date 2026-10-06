package renderintegration

import (
	"regexp"
	"strings"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminclienthandlers"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// allowanceSwitchRe matches the administrative scopes switch, whatever order its attributes come in.
var allowanceSwitchRe = regexp.MustCompile(`<input id="administrativeScopesAllowed"[^>]*>`)

// allowanceFormRe matches the allowance's own form element.
var allowanceFormRe = regexp.MustCompile(`<form id="formAdministrativeScopes"[^>]*>`)

// allowanceSaveRe matches the allowance's own Save button.
var allowanceSaveRe = regexp.MustCompile(`<button id="btnSaveAdministrativeScopes"[^>]*>`)

func renderClientSettings(t *testing.T, client adminclienthandlers.ClientSettings, extra map[string]interface{}) string {
	t.Helper()
	bind := map[string]interface{}{"client": client, "savedSuccessfully": false}
	for k, v := range extra {
		bind[k] = v
	}
	return renderMenuPage(t, "/admin_clients_settings.html", bind)
}

// The allowance is a switch of its own on the Settings tab, under Consent required, in its own form
// posting to its own route, with its own Save: the settings form's Save never carries it, so a
// settings save cannot switch it either way (#499 decision 5).
func TestRender_AdminClientSettings_TheAllowanceHasItsOwnForm(t *testing.T) {
	out := renderClientSettings(t, adminclienthandlers.ClientSettings{ClientId: 7, ClientIdentifier: "ops-tool"}, nil)

	form := allowanceFormRe.FindString(out)
	require.NotEmpty(t, form, "the allowance's form is rendered")
	assert.Contains(t, form, `method="post"`)
	assert.Contains(t, form, `action="/admin/clients/7/settings/administrative-scopes"`)

	toggle := allowanceSwitchRe.FindString(out)
	require.NotEmpty(t, toggle, "the switch is rendered")
	assert.Contains(t, toggle, `name="administrativeScopesAllowed"`)
	assert.Contains(t, toggle, `form="formAdministrativeScopes"`, "the switch belongs to its own form, not the settings form")

	save := allowanceSaveRe.FindString(out)
	require.NotEmpty(t, save, "the allowance has its own Save")
	assert.Contains(t, save, `form="formAdministrativeScopes"`)

	assert.Contains(t, out, "Pode solicitar escopos administrativos", "the label, in pt-BR")

	consentAt := strings.Index(out, `name="consentRequired"`)
	switchAt := strings.Index(out, `id="administrativeScopesAllowed"`)
	showLogoAt := strings.Index(out, `name="showLogo"`)
	require.NotEqual(t, -1, consentAt)
	require.NotEqual(t, -1, showLogoAt)
	assert.Greater(t, switchAt, consentAt, "the switch sits under Consent required")
	assert.Less(t, switchAt, showLogoAt, "and before the next setting")
}

// The switch shows the stored allowance: on for an allowed client, off for one that is not, and for
// the admin console's own client on and disabled, with its Save disabled and a sentence saying why
// (#499 decision 5).
func TestRender_AdminClientSettings_TheSwitchShowsTheAllowance(t *testing.T) {
	testCases := []struct {
		name         string
		client       adminclienthandlers.ClientSettings
		wantChecked  bool
		wantDisabled bool
	}{
		{
			name:        "an allowed client",
			client:      adminclienthandlers.ClientSettings{ClientId: 7, ClientIdentifier: "ops-tool", AdministrativeScopesAllowed: true},
			wantChecked: true,
		},
		{
			name:   "a client that is not allowed",
			client: adminclienthandlers.ClientSettings{ClientId: 7, ClientIdentifier: "portal"},
		},
		{
			name: "the admin console's client",
			client: adminclienthandlers.ClientSettings{ClientId: 1, ClientIdentifier: "admin-console-client",
				AdministrativeScopesAllowed: true, IsSystemLevelClient: true},
			wantChecked:  true,
			wantDisabled: true,
		},
	}

	const alwaysAllowed = "O cliente do console de administração sempre pode solicitar os escopos administrativos."

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			out := renderClientSettings(t, tc.client, nil)

			toggle := allowanceSwitchRe.FindString(out)
			require.NotEmpty(t, toggle, "the switch is rendered")
			assert.Equal(t, tc.wantChecked, strings.Contains(toggle, "checked"), "checked: %s", toggle)
			assert.Equal(t, tc.wantDisabled, strings.Contains(toggle, "disabled"), "disabled: %s", toggle)

			save := allowanceSaveRe.FindString(out)
			require.NotEmpty(t, save)
			assert.Equal(t, tc.wantDisabled, strings.Contains(save, "disabled"), "the Save: %s", save)

			assert.Equal(t, tc.wantDisabled, strings.Contains(out, alwaysAllowed))
		})
	}
}

// A refused switch and a saved one are each announced beside the allowance's Save, in their own
// slots, so neither reads as the outcome of the settings form.
func TestRender_AdminClientSettings_TheAllowanceAnswersBesideItsOwnSave(t *testing.T) {
	client := adminclienthandlers.ClientSettings{ClientId: 7, ClientIdentifier: "ops-tool"}

	refused := renderClientSettings(t, client, map[string]interface{}{
		"administrativeScopesError": "Only authserver:manage may switch this.",
	})
	assert.Contains(t, refused, "Only authserver:manage may switch this.")
	assert.NotContains(t, refused, "Configurações do cliente salvas com sucesso")

	saved := renderClientSettings(t, client, map[string]interface{}{"administrativeScopesSaved": true})
	assert.Contains(t, saved, "Autorização para escopos administrativos salva com sucesso")
	assert.NotContains(t, saved, "Configurações do cliente salvas com sucesso",
		"the settings form was not saved")

	settingsSaved := renderClientSettings(t, client, map[string]interface{}{"savedSuccessfully": true})
	assert.NotContains(t, settingsSaved, "Autorização para escopos administrativos salva com sucesso")
}
