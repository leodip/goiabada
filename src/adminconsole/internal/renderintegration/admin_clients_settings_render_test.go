package renderintegration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminclienthandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	web "github.com/leodip/goiabada/adminconsole/web"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// allowanceSwitchRe matches the administrative scopes switch, whatever order its attributes come in.
var allowanceSwitchRe = regexp.MustCompile(`<input id="administrativeScopesAllowed"[^>]*>`)

// buttonRe matches every button the page draws.
var buttonRe = regexp.MustCompile(`<button[^>]*>`)

func renderClientSettings(t *testing.T, client adminclienthandlers.ClientSettings, extra map[string]interface{}) string {
	t.Helper()
	// isAdmin as the renderer binds it for an administrator holding authserver:manage; a case
	// rendering for anyone else overrides it.
	bind := map[string]interface{}{"client": client, "storedClient": client, "savedSuccessfully": false, "isAdmin": true}
	for k, v := range extra {
		bind[k] = v
	}
	return renderMenuPage(t, "/admin_clients_settings.html", bind)
}

// The allowance is a field of the settings form, under Consent required, saved by the tab's one Save
// (#542). It had a Save of its own in the middle of the form, which saved it alone and reloaded the
// page, dropping every other change; nothing here may bring a second form or a second Save back.
func TestRender_AdminClientSettings_TheAllowanceIsSavedByTheTabsOneSave(t *testing.T) {
	out := renderClientSettings(t, adminclienthandlers.ClientSettings{ClientId: 7, ClientIdentifier: "ops-tool"}, nil)

	formStart := strings.Index(out, `<form id="formClientSettings"`)
	require.NotEqual(t, -1, formStart, "the settings form is rendered")
	formEnd := strings.Index(out[formStart:], "</form>") + formStart
	assert.NotContains(t, out, "formAdministrativeScopes", "no form of the allowance's own")
	assert.NotContains(t, out, "/settings/administrative-scopes", "and no route of its own")

	toggle := allowanceSwitchRe.FindString(out)
	require.NotEmpty(t, toggle, "the switch is rendered")
	assert.Contains(t, toggle, `name="administrativeScopesAllowed"`)
	assert.NotContains(t, toggle, `form=`, "the switch belongs to the settings form")
	switchAt := strings.Index(out, `id="administrativeScopesAllowed"`)
	assert.True(t, switchAt > formStart && switchAt < formEnd, "inside the settings form")

	var saves []string
	for _, button := range buttonRe.FindAllString(out, -1) {
		if !strings.Contains(button, `id="btnSave"`) && strings.Contains(button, "btn-primary") && !strings.Contains(button, "modal") {
			saves = append(saves, button)
		}
	}
	assert.Empty(t, saves, "no primary button but the one Save")
	assert.Equal(t, 1, strings.Count(out, `id="btnSave"`))

	assert.Contains(t, out, "Pode solicitar escopos administrativos", "the label, in pt-BR")

	consentAt := strings.Index(out, `name="consentRequired"`)
	showLogoAt := strings.Index(out, `name="showLogo"`)
	require.NotEqual(t, -1, consentAt)
	require.NotEqual(t, -1, showLogoAt)
	assert.Greater(t, switchAt, consentAt, "the switch sits under Consent required")
	assert.Less(t, switchAt, showLogoAt, "and before the next setting")
}

// The switch shows the allowance: on for an allowed client, off for one that is not, and for the
// admin console's own client on and disabled, with a sentence saying why (#499 decision 5).
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
			assert.Equal(t, tc.wantDisabled, strings.Contains(out, alwaysAllowed))
		})
	}
}

// A refused allowance is shown beside the switch, and the settings, written before it, as saved.
func TestRender_AdminClientSettings_ARefusedAllowanceIsShownBesideTheSwitch(t *testing.T) {
	client := adminclienthandlers.ClientSettings{ClientId: 7, ClientIdentifier: "ops-tool"}

	out := renderClientSettings(t, client, map[string]interface{}{
		"savedSuccessfully":         true,
		"administrativeScopesError": "Only authserver:manage may switch this.",
	})

	refusalAt := strings.Index(out, "Only authserver:manage may switch this.")
	require.NotEqual(t, -1, refusalAt)
	assert.Greater(t, refusalAt, strings.Index(out, `id="administrativeScopesAllowed"`), "under the switch")
	assert.Less(t, refusalAt, strings.Index(out, `name="showLogo"`), "and before the next setting")
	assert.Contains(t, out, "Configurações do cliente salvas com sucesso")
}

// The question asked before a save that switches the allowance on compares against the stored
// allowance, not the switch as a refused save drew it again: otherwise the second save of the same
// switch would ask nothing.
func TestRender_AdminClientSettings_TheSwitchingOnQuestionComparesWithTheStoredAllowance(t *testing.T) {
	typed := adminclienthandlers.ClientSettings{ClientId: 7, ClientIdentifier: "ops-tool", AdministrativeScopesAllowed: true}
	stored := adminclienthandlers.ClientSettings{ClientId: 7, ClientIdentifier: "ops-tool"}

	out := renderMenuPage(t, "/admin_clients_settings.html", map[string]interface{}{
		"client": typed, "storedClient": stored, "savedSuccessfully": false,
	})

	assert.Contains(t, out, `var originallyAllowedAdministrativeScopes = false;`)
}

// identifierInputRe matches the client identifier input, whatever order its attributes come in.
var identifierInputRe = regexp.MustCompile(`<input id="clientIdentifier"[^>]*>`)

// selfRegisteredIdentifierLine is the line beneath the identifier of a self-registered client, in pt-BR.
const selfRegisteredIdentifierLine = "Um cliente autorregistrado mantém o identificador com que se registrou."

// The identifier input is read-only for a client whose identifier the API refuses to change: the
// system-level client, and a self-registered one, which also says why beneath it. An ordinary
// client's identifier stays editable, with no line.
func TestRender_AdminClientSettings_TheIdentifierIsReadOnlyWhereItCannotChange(t *testing.T) {
	testCases := []struct {
		name         string
		client       adminclienthandlers.ClientSettings
		wantReadOnly bool
		wantLine     bool
	}{
		{
			name:   "an ordinary client",
			client: adminclienthandlers.ClientSettings{ClientId: 7, ClientIdentifier: "portal"},
		},
		{
			name: "a self-registered client",
			client: adminclienthandlers.ClientSettings{ClientId: 8,
				ClientIdentifier: "dcr_3f6c1d2e-8a4b-4c5d-9e0f-1a2b3c4d5e6f", CreatedViaDCR: true},
			wantReadOnly: true,
			wantLine:     true,
		},
		{
			name: "the admin console's client",
			client: adminclienthandlers.ClientSettings{ClientId: 1, ClientIdentifier: "admin-console-client",
				AdministrativeScopesAllowed: true, IsSystemLevelClient: true},
			wantReadOnly: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			out := renderClientSettings(t, tc.client, nil)

			input := identifierInputRe.FindString(out)
			require.NotEmpty(t, input, "the identifier input is rendered")
			assert.Contains(t, input, `value="`+tc.client.ClientIdentifier+`"`)
			assert.Equal(t, tc.wantReadOnly, strings.Contains(input, "readonly"), "readonly: %s", input)
			assert.Equal(t, tc.wantLine, strings.Contains(out, selfRegisteredIdentifierLine))
		})
	}
}

// settingsTabAPI is the auth server as the Settings tab reaches it: the client as stored, and a
// save it refuses with a 400 the administrator can act on.
type settingsTabAPI struct {
	stored  *api.ClientResponse
	refusal string
}

func (s *settingsTabAPI) GetClientById(_ context.Context, _ string, _ int64) (*api.ClientResponse, error) {
	return s.stored, nil
}

func (s *settingsTabAPI) UpdateClient(_ context.Context, _ string, _ int64,
	_ *api.UpdateClientSettingsRequest) (*api.ClientResponse, error) {
	return nil, &apiclient.APIError{Code: "VALIDATION_ERROR", Message: s.refusal, StatusCode: http.StatusBadRequest}
}

// UpdateClientAdministrativeScopes is never reached: the settings' write before it is refused.
func (s *settingsTabAPI) UpdateClientAdministrativeScopes(_ context.Context, _ string, _ int64,
	_ *api.UpdateClientAdministrativeScopesRequest) (*api.ClientResponse, error) {
	return nil, &apiclient.APIError{Code: "UNEXPECTED", Message: "the allowance was written after a refused save", StatusCode: http.StatusInternalServerError}
}

// postClientSettings drives the Settings tab's save through the real renderer, in pt-BR, and
// returns the page it answers with.
func postClientSettings(t *testing.T, apiClient *settingsTabAPI, form url.Values) string {
	t.Helper()
	req := handlertest.Request(http.MethodPost, "/admin/clients/7/settings",
		handlertest.WithAccessToken(), handlertest.WithRouteParam("clientId", "7"),
		handlertest.WithSettings(&api.PublicSettingsResponse{AppName: "Test", UITheme: "dark"}),
		handlertest.WithForm(form))
	req = req.WithContext(i18n.WithLocale(req.Context(), true, "pt-BR"))
	rec := httptest.NewRecorder()

	adminclienthandlers.HandleSettingsPost(render.New(web.TemplateFS()), nil, apiClient, "https://console.example").
		ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "the refused save is drawn again, not redirected: %s", rec.Body.String())
	return rec.Body.String()
}

// A refused save draws the tab again with the inputs as the administrator typed them, and
// everything that stands for the client as it is from the stored client: the page title, and the
// original identifier and enabled state the confirmation dialogs compare against. Drawn from the
// submission instead, a second save of the same rename or the same disable would ask nothing.
func TestRender_AdminClientSettings_ARefusedSaveKeepsTheStoredClient(t *testing.T) {
	const refusal = "The client identifier is already in use."
	apiClient := &settingsTabAPI{
		stored:  &api.ClientResponse{Id: 7, ClientIdentifier: "portal", DisplayName: "Portal", Enabled: true},
		refusal: refusal,
	}

	out := postClientSettings(t, apiClient, url.Values{
		"clientIdentifier": {"portal-renamed"},
		"displayName":      {"Renamed portal"},
	})

	assert.Contains(t, out, refusal)

	assert.Contains(t, out, `<span class="text-accent">portal</span>`, "the page title names the stored client")
	assert.NotContains(t, out, `<span class="text-accent">portal-renamed</span>`)
	assert.Contains(t, out, `var originalClientIdentifier = "portal";`)
	assert.Contains(t, out, `var originallyEnabled = true;`)

	input := identifierInputRe.FindString(out)
	require.NotEmpty(t, input)
	assert.Contains(t, input, `value="portal-renamed"`, "the input keeps what was typed")
	assert.Contains(t, out, `value="Renamed portal"`)
	enabled := regexp.MustCompile(`<input id="enabledDisabled"[^>]*>`).FindString(out)
	require.NotEmpty(t, enabled)
	assert.NotContains(t, enabled, "checked", "the switch keeps what was submitted: off")
}

// A self-registered client's identifier stays read-only, with its line, when a refused save draws
// the tab again.
func TestRender_AdminClientSettings_ARefusedSaveKeepsASelfRegisteredIdentifierReadOnly(t *testing.T) {
	const identifier = "dcr_3f6c1d2e-8a4b-4c5d-9e0f-1a2b3c4d5e6f"
	apiClient := &settingsTabAPI{
		stored:  &api.ClientResponse{Id: 7, ClientIdentifier: identifier, Enabled: true, CreatedViaDCR: true},
		refusal: "Invalid website URL.",
	}

	out := postClientSettings(t, apiClient, url.Values{
		"clientIdentifier": {identifier},
		"enabled":          {"on"},
		"websiteUrl":       {"not a url"},
	})

	input := identifierInputRe.FindString(out)
	require.NotEmpty(t, input)
	assert.Contains(t, input, "readonly")
	assert.Contains(t, out, selfRegisteredIdentifierLine)
}

// For an administrator without authserver:manage the switch is drawn disabled, with a sentence saying
// who can change it, since the auth server would refuse the change (#499 decision 4).
func TestRender_AdminClientSettings_WithoutManageTheSwitchIsDisabled(t *testing.T) {
	const manageOnly = "Somente um administrador com authserver:manage pode alterar isto."
	client := adminclienthandlers.ClientSettings{ClientId: 7, ClientIdentifier: "ops-tool", AdministrativeScopesAllowed: true}

	out := renderClientSettings(t, client, map[string]interface{}{"isAdmin": false})
	toggle := allowanceSwitchRe.FindString(out)
	require.NotEmpty(t, toggle)
	assert.Contains(t, toggle, "disabled")
	assert.Contains(t, toggle, "checked", "it still shows the allowance")
	assert.Contains(t, out, manageOnly)

	asManager := renderClientSettings(t, client, nil)
	assert.NotContains(t, allowanceSwitchRe.FindString(asManager), "disabled")
	assert.NotContains(t, asManager, manageOnly)
}
