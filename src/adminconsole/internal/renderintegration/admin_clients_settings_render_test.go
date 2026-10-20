package renderintegration

import (
	"context"
	"html"
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

// allowanceSwitchRe matches the administrative scopes checkbox, whatever order its attributes come in.
var allowanceSwitchRe = regexp.MustCompile(`<input [^>]*id="administrativeScopesAllowed"[^>]*>`)

// hasAttr says whether tag carries the boolean attribute name, such as checked, as an attribute of
// its own rather than inside another's name or value, such as data-stored-checked.
func hasAttr(tag, name string) bool {
	return regexp.MustCompile(`\s` + name + `(?:\s|>|$)`).MatchString(tag)
}

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
		if !strings.Contains(button, `id="btnSave"`) && strings.Contains(button, "button-primary") && !strings.Contains(button, "_btnModal") {
			saves = append(saves, button)
		}
	}
	assert.Empty(t, saves, "no primary button but the one Save")
	assert.Equal(t, 1, strings.Count(out, `id="btnSave"`))

	assert.Contains(t, out, "Pode solicitar escopos administrativos", "the label, in pt-BR")

	consentAt := strings.Index(out, `name="consentRequired"`)
	saveAt := strings.Index(out, `id="btnSave"`)
	require.NotEqual(t, -1, consentAt)
	assert.Greater(t, switchAt, consentAt, "the switch sits under Consent required")
	assert.Less(t, switchAt, saveAt, "and before the one Save")
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
			assert.Equal(t, tc.wantChecked, hasAttr(toggle, "checked"), "checked: %s", toggle)
			assert.Equal(t, tc.wantDisabled, hasAttr(toggle, "disabled"), "disabled: %s", toggle)
			assert.Equal(t, tc.wantDisabled, strings.Contains(out, alwaysAllowed))
		})
	}
}

// A refused allowance is said in a notice at the top of the form, which the checkbox it is about
// names and is marked invalid by, the checkbox focused, and the settings, written before it, as
// saved.
func TestRender_AdminClientSettings_ARefusedAllowanceIsShownBesideTheSwitch(t *testing.T) {
	client := adminclienthandlers.ClientSettings{ClientId: 7, ClientIdentifier: "ops-tool"}

	out := renderClientSettings(t, client, map[string]interface{}{
		"savedSuccessfully":         true,
		"administrativeScopesError": "Only authserver:manage may switch this.",
	})

	assert.Contains(t, out, `<div class="notice notice-danger" role="alert" id="administrative-scopes-error">`)
	refusalAt := strings.Index(out, "Only authserver:manage may switch this.")
	require.NotEqual(t, -1, refusalAt)
	assert.Less(t, refusalAt, strings.Index(out, `id="clientIdentifier"`), "at the top of the form")
	toggle := allowanceSwitchRe.FindString(out)
	assert.Contains(t, toggle, `aria-describedby="administrative-scopes-error administrativeScopesAllowedHint"`)
	assert.True(t, hasAttr(toggle, `aria-invalid="true"`) || strings.Contains(toggle, ` aria-invalid="true"`))
	assert.True(t, hasAttr(toggle, "autofocus"), "the refused checkbox takes the focus: %s", toggle)
	assert.Contains(t, out, "Configurações salvas.")
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

	toggle := allowanceSwitchRe.FindString(out)
	assert.True(t, hasAttr(toggle, "checked"), "the checkbox keeps what was submitted: on")
	assert.Contains(t, toggle, `data-confirm-when="checked" data-stored-checked="false"`,
		"the question compares with the allowance as stored")
}

// identifierInputRe matches the client identifier input, whatever order its attributes come in.
var identifierInputRe = regexp.MustCompile(`<input [^>]*id="clientIdentifier"[^>]*>`)

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
			assert.Equal(t, tc.wantReadOnly, hasAttr(input, "readonly"), "readonly: %s", input)
			assert.Equal(t, tc.wantLine, strings.Contains(out, selfRegisteredIdentifierLine))
		})
	}
}

// settingsTabAPI is the auth server as the Settings tab reaches it: the client as stored, and a
// save it refuses with a 400 the administrator can act on.
type settingsTabAPI struct {
	stored  *api.ClientResponse
	refusal string
	// code is the refusal's error_code; VALIDATION_ERROR when empty.
	code string
}

func (s *settingsTabAPI) GetClientById(_ context.Context, _ string, _ int64) (*api.ClientResponse, error) {
	return s.stored, nil
}

func (s *settingsTabAPI) UpdateClient(_ context.Context, _ string, _ int64,
	_ *api.UpdateClientSettingsRequest) (*api.ClientResponse, error) {
	code := s.code
	if code == "" {
		code = "VALIDATION_ERROR"
	}
	return nil, &apiclient.APIError{Code: code, Message: s.refusal, StatusCode: http.StatusBadRequest}
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

	adminclienthandlers.HandleSettingsPost(render.New(web.TemplateFS(), web.StaticFS()), nil, apiClient, "https://console.example").
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

	assert.Contains(t, out, `<title>Configurações – portal – Test</title>`, "the page title names the stored client")
	assert.Contains(t, out, `<h1 class="page-title" id="page-title">portal</h1>`, "and so does its heading")
	assert.NotContains(t, out, `>portal-renamed</h1>`)

	input := identifierInputRe.FindString(out)
	require.NotEmpty(t, input)
	assert.Contains(t, input, `value="portal-renamed"`, "the input keeps what was typed")
	assert.Contains(t, input, `data-stored-value="portal"`, "and the question compares with the stored identifier")
	assert.Contains(t, out, `value="Renamed portal"`)
	enabled := regexp.MustCompile(`<input [^>]*id="enabledDisabled"[^>]*>`).FindString(out)
	require.NotEmpty(t, enabled)
	assert.False(t, hasAttr(enabled, "checked"), "the checkbox keeps what was submitted: off")
	assert.Contains(t, enabled, `data-confirm-when="unchecked" data-stored-checked="true"`,
		"and the question compares with the stored enabled state")
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
	assert.True(t, hasAttr(input, "readonly"))
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
	assert.True(t, hasAttr(toggle, "disabled"))
	assert.True(t, hasAttr(toggle, "checked"), "it still shows the allowance")
	assert.Contains(t, out, manageOnly)

	asManager := renderClientSettings(t, client, nil)
	assert.False(t, hasAttr(allowanceSwitchRe.FindString(asManager), "disabled"))
	assert.NotContains(t, asManager, manageOnly)
}

// The Consent required hint keeps what the setting does and says when users are asked whatever it
// says: a client requesting offline_access or sending prompt=consent, and a client other than the
// admin console's requesting authserver:manage-account (#509 decision 5). An operator puzzled by an
// unexpected consent screen looks there first.
func TestRender_AdminClientSettings_TheConsentTooltipSaysWhenUsersAreAskedRegardless(t *testing.T) {
	out := renderClientSettings(t, adminclienthandlers.ClientSettings{ClientId: 7, ClientIdentifier: "portal"}, nil)

	consent := regexp.MustCompile(`<input [^>]*id="consentRequired"[^>]*>`).FindString(out)
	require.NotEmpty(t, consent, "the setting is rendered")
	assert.Contains(t, consent, `aria-describedby="consentRequiredHint"`, "the setting is described by its hint")
	m := regexp.MustCompile(`<span class="field-hint" id="consentRequiredHint">([^<]*)</span>`).FindStringSubmatch(out)
	require.NotNil(t, m, "the hint is rendered")

	//nolint:misspell // the pt-BR catalog's text: "Eles" is Portuguese, not a misspelling of "Eels"
	assert.Equal(t, "Depois de entrar, os usuários escolhem quais dos escopos solicitados o cliente recebe. Eles são "+
		"consultados de qualquer forma quando um cliente solicita offline_access ou envia prompt=consent, e quando "+
		"um cliente que não seja o do console de administração solicita authserver:manage-account.", html.UnescapeString(m[1]))
}

// The same sentence in English, which the render above cannot reach, since every page in this
// package renders in pt-BR.
func TestConsentRequiredTooltip_English(t *testing.T) {
	ctx := i18n.WithLocale(context.Background(), true, "en")

	assert.Equal(t, "After signing in, users choose which of the requested scopes the client gets. Users are asked "+
		"anyway when a client requests offline_access or sends prompt=consent, and when a client other than the admin "+
		"console's requests authserver:manage-account.",
		i18n.T(ctx, "adminconsole.admin_clients.settings.field.consent_required_tooltip"))
}

// A refusal the auth server answers by its key marks the field it is about, described by the
// notice and focused: the identifier for one in use, the website URL for one that is no URL (#617).
func TestRender_AdminClientSettings_ARefusalByKeyMarksItsField(t *testing.T) {
	for _, tc := range []struct {
		code, refusal, field string
	}{
		{"handler.client.identifier_in_use", "The client identifier is already in use.", "clientIdentifier"},
		{"handler.client.website_url_invalid", "Invalid website URL.", "websiteUrl"},
		{"handler.client.display_name_too_long", "The display name cannot exceed a maximum length of 100 characters.", "displayName"},
	} {
		t.Run(tc.code, func(t *testing.T) {
			apiClient := &settingsTabAPI{
				stored:  &api.ClientResponse{Id: 7, ClientIdentifier: "portal", Enabled: true, AuthorizationCodeEnabled: true},
				refusal: tc.refusal,
				code:    tc.code,
			}
			out := postClientSettings(t, apiClient, url.Values{"clientIdentifier": {"portal"}, "websiteUrl": {"not a url"}})

			invalid := regexp.MustCompile(`<(?:input|select) [^>]*id="([A-Za-z]+)"[^>]*aria-invalid="true"[^>]*>`).FindAllStringSubmatch(out, -1)
			require.Len(t, invalid, 1, "one field is marked invalid")
			assert.Equal(t, tc.field, invalid[0][1])
			assert.Contains(t, invalid[0][0], `aria-describedby="client-error `)
			assert.Contains(t, invalid[0][0], ` autofocus`)
		})
	}
}
