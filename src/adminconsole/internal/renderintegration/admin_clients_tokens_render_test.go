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
	"github.com/leodip/goiabada/adminconsole/internal/sessionkeys"
	web "github.com/leodip/goiabada/adminconsole/web"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/sessionstore/sessiontest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tokensTabAPI is the auth server as the client Tokens tab reaches it: the client as stored, and a
// save it refuses with a 400 the administrator can act on.
type tokensTabAPI struct {
	stored  *api.ClientResponse
	refusal string
	// code is the refusal's error_code, its catalog key, as the auth server answers a client's
	// refusal (#617).
	code  string
	saved bool
	// dpopRefusal is the message the DPoP requirement's write is refused with, when set.
	dpopRefusal string
}

func (s *tokensTabAPI) GetClientById(_ context.Context, _ string, _ int64) (*api.ClientResponse, error) {
	return s.stored, nil
}

// GetSettingsTokens answers the global token settings: the claims included in the ID token and
// left out of the access token, and an hour's token lifetime.
func (s *tokensTabAPI) GetSettingsTokens(_ context.Context, _ string) (*api.SettingsTokensResponse, error) {
	return &api.SettingsTokensResponse{TokenExpirationInSeconds: 3600, RefreshTokenOfflineIdleTimeoutInSeconds: 86400,
		RefreshTokenOfflineMaxLifetimeInSeconds: 2592000, IncludeOpenIDConnectClaimsInIdToken: true}, nil
}

func (s *tokensTabAPI) UpdateClientTokens(_ context.Context, _ string, _ int64,
	_ *api.UpdateClientTokensRequest) (*api.ClientResponse, error) {
	s.saved = true
	return nil, &apiclient.APIError{Code: s.code, Message: s.refusal, StatusCode: http.StatusBadRequest}
}

// UpdateClientDPoP refuses the requirement with dpopRefusal when one is set, and answers the stored
// client otherwise.
func (s *tokensTabAPI) UpdateClientDPoP(_ context.Context, _ string, _ int64,
	_ *api.UpdateClientDPoPRequest) (*api.ClientResponse, error) {
	if s.dpopRefusal != "" {
		return nil, &apiclient.APIError{Code: "VALIDATION_ERROR", Message: s.dpopRefusal, StatusCode: http.StatusBadRequest}
	}
	return s.stored, nil
}

// storedTokensClient is the client as stored: every duration a number, and the two OpenID Connect
// claims choices each a different one of the three values.
func storedTokensClient() *api.ClientResponse {
	return &api.ClientResponse{Id: 7, ClientIdentifier: "portal", Enabled: true,
		TokenExpirationInSeconds:                300,
		RefreshTokenOfflineIdleTimeoutInSeconds: 3600,
		RefreshTokenOfflineMaxLifetimeInSeconds: 86400,
		IncludeOpenIDConnectClaimsInAccessToken: "default",
		IncludeOpenIDConnectClaimsInIdToken:     "on",
	}
}

// newRenderSessionStore is the real session store over an in-memory backend, which is what a
// page's first draw reads its saved flash from.
func newRenderSessionStore(t *testing.T) sessionstore.Store {
	t.Helper()
	store, err := sessionstore.NewServerSideStore(
		sessiontest.NewMemoryBackend(),
		sessionkeys.JWT,
		false,
		sessionstore.BrowserSessionCookie,
		sessionstore.KeyPair{
			AuthenticationKey: []byte("12345678901234567890123456789012"),
			EncryptionKey:     []byte("abcdefghijklmnopqrstuvwxyz123456"),
		},
		nil,
	)
	require.NoError(t, err)
	return store
}

// serveClientTokens drives one of the Tokens tab's handlers through the real renderer, in pt-BR,
// and returns the page it answers with.
func serveClientTokens(t *testing.T, handler http.HandlerFunc, method string, form url.Values) string {
	t.Helper()
	opts := []handlertest.Option{handlertest.WithAccessToken(), handlertest.WithPathValue("clientId", "7"),
		handlertest.WithSettings(&api.PublicSettingsResponse{AppName: "Test", UITheme: "dark"})}
	if form != nil {
		opts = append(opts, handlertest.WithForm(form))
	}
	req := handlertest.Request(method, "/admin/clients/7/tokens", opts...)
	req = req.WithContext(i18n.WithLocale(req.Context(), true, "pt-BR"))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "the tab is drawn, not redirected: %s", rec.Body.String())
	return rec.Body.String()
}

// checkedChoice returns the value of the one radio of the named group the page draws checked, and
// fails when it draws none or more than one.
func checkedChoice(t *testing.T, out, name string) string {
	t.Helper()
	radios := regexp.MustCompile(`<input type="radio" name="`+name+`"[^>]*>`).FindAllString(out, -1)
	require.Len(t, radios, 3, "the three choices of %s", name)
	var checked []string
	for _, radio := range radios {
		if regexp.MustCompile(`\schecked(?:\s|>|$)`).MatchString(radio) {
			checked = append(checked, regexp.MustCompile(`value="([^"]*)"`).FindStringSubmatch(radio)[1])
		}
	}
	require.Len(t, checked, 1, "one choice of %s is checked: %v", name, checked)
	return checked[0]
}

// durationValue returns the value the page draws in the named duration input.
func durationValue(t *testing.T, out, id string) string {
	t.Helper()
	input := regexp.MustCompile(`<input [^>]*id="` + id + `"[^>]*>`).FindString(out)
	require.NotEmpty(t, input, "the %s input is rendered", id)
	value := regexp.MustCompile(`value="([^"]*)"`).FindStringSubmatch(input)
	require.NotNil(t, value, "the %s input has a value", id)
	return value[1]
}

// The first draw of the tab shows the client as stored: every duration and both choices.
func TestRender_AdminClientTokens_TheFirstDrawShowsTheStoredClient(t *testing.T) {
	apiClient := &tokensTabAPI{stored: storedTokensClient()}

	out := serveClientTokens(t,
		adminclienthandlers.HandleTokensGet(render.New(web.TemplateFS(), web.StaticFS()), newRenderSessionStore(t), apiClient),
		http.MethodGet, nil)

	assert.Contains(t, out, `<h1 class="page-title" id="page-title">portal</h1>`)
	assert.Equal(t, "300", durationValue(t, out, "tokenExpirationInSeconds"))
	assert.Equal(t, "3600", durationValue(t, out, "refreshTokenOfflineIdleTimeoutInSeconds"))
	assert.Equal(t, "86400", durationValue(t, out, "refreshTokenOfflineMaxLifetimeInSeconds"))
	assert.Equal(t, "default", checkedChoice(t, out, "includeOpenIDConnectClaimsInAccessToken"))
	assert.Equal(t, "on", checkedChoice(t, out, "includeOpenIDConnectClaimsInIdToken"))

	// Each "use the global setting" names what the global setting is now: the claims left out of the
	// access token and included in the ID token, and each duration's own, which the script says
	// beside a 0.
	assert.Contains(t, out, `value="default" checked><span>Usar a configuração global (não incluir)</span>`)
	assert.Equal(t, 1, strings.Count(out, `Usar a configuração global (incluir)`))
	assert.Contains(t, out, `data-duration-for="tokenExpirationInSeconds" data-duration-global="3600"`)
	assert.Contains(t, out, `data-duration-for="refreshTokenOfflineMaxLifetimeInSeconds" data-duration-global="2592000"`)
}

// A refused save draws the tab again with every input as the administrator submitted it: each
// duration as typed, a number or not, and both OpenID Connect claims choices as chosen. The choices
// used to be drawn from the stored client and a duration that was not a number replaced by the
// stored one, so the page showed values nobody had submitted beside the refusal (#562).
func TestRender_AdminClientTokens_ARefusedSaveKeepsWhatWasSubmitted(t *testing.T) {
	const apiRefusal = "Token lifetime must be between 0 and 160000000 seconds."
	testCases := []struct {
		name       string
		expiration string
		idle       string
		maxLife    string
		message    string
		field      string
		wantSaved  bool
	}{
		{name: "an expiration that is not a number", expiration: "5 minutes", idle: "7200", maxLife: "90000",
			message: "Informe a duração do token como um número inteiro de segundos.", field: "tokenExpirationInSeconds"},
		{name: "an idle timeout that is not a number", expiration: "600", idle: "two hours", maxLife: "90000",
			message: "Informe o tempo ocioso offline como um número inteiro de segundos.", field: "refreshTokenOfflineIdleTimeoutInSeconds"},
		{name: "a max lifetime that is not a number", expiration: "600", idle: "7200", maxLife: "a day",
			message: "Informe a duração máxima offline como um número inteiro de segundos.", field: "refreshTokenOfflineMaxLifetimeInSeconds"},
		{name: "numbers the auth server refuses", expiration: "160000001", idle: "7200", maxLife: "90000",
			message: apiRefusal, field: "tokenExpirationInSeconds", wantSaved: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			apiClient := &tokensTabAPI{stored: storedTokensClient(), refusal: apiRefusal,
				code: "handler.client_tokens.token_expiration_out_of_range"}

			out := serveClientTokens(t,
				adminclienthandlers.HandleTokensPost(render.New(web.TemplateFS(), web.StaticFS()), nil, apiClient, "https://console.example"),
				http.MethodPost, url.Values{
					"tokenExpirationInSeconds":                {tc.expiration},
					"refreshTokenOfflineIdleTimeoutInSeconds": {tc.idle},
					"refreshTokenOfflineMaxLifetimeInSeconds": {tc.maxLife},
					"includeOpenIDConnectClaimsInAccessToken": {"off"},
					"includeOpenIDConnectClaimsInIdToken":     {"default"},
				})

			assert.Equal(t, tc.wantSaved, apiClient.saved)
			assert.Contains(t, out, `<p>`+tc.message+`</p>`)
			assert.Contains(t, out, `<h1 class="page-title" id="page-title">portal</h1>`, "the page heading names the stored client")

			assert.Equal(t, tc.expiration, durationValue(t, out, "tokenExpirationInSeconds"))
			assert.Equal(t, tc.idle, durationValue(t, out, "refreshTokenOfflineIdleTimeoutInSeconds"))
			assert.Equal(t, tc.maxLife, durationValue(t, out, "refreshTokenOfflineMaxLifetimeInSeconds"))
			assert.Equal(t, "off", checkedChoice(t, out, "includeOpenIDConnectClaimsInAccessToken"))
			assert.Equal(t, "default", checkedChoice(t, out, "includeOpenIDConnectClaimsInIdToken"))

			// The duration a refusal names, the console's own or the auth server's by its key, is
			// marked invalid, described by the notice and focused.
			invalid := regexp.MustCompile(`<input [^>]*id="([A-Za-z]+)"[^>]*aria-invalid="true"[^>]*>`).FindAllStringSubmatch(out, -1)
			if tc.field == "" {
				assert.Empty(t, invalid)
				return
			}
			require.Len(t, invalid, 1)
			assert.Equal(t, tc.field, invalid[0][1])
			assert.Contains(t, invalid[0][0], `aria-describedby="tokens-error `)
			assert.Contains(t, invalid[0][0], ` autofocus`)
		})
	}
}

// dpopSwitchRe finds the DPoP requirement's checkbox.
var dpopSwitchRe = regexp.MustCompile(`<input [^>]*id="dpopBoundAccessTokens"[^>]*>`)

// The Tokens tab draws "Require DPoP for token requests" as a checkbox of the tab's own form, saved
// by its one Save, ticked as the client stores it, with the implicit-flow restriction said beside it
// (#42 decisions 12 and 13).
func TestRender_AdminClientTokens_TheDPoPRequirementIsASwitchOfTheTab(t *testing.T) {
	for _, stored := range []bool{true, false} {
		client := storedTokensClient()
		client.DPoPBoundAccessTokens = stored

		out := serveClientTokens(t,
			adminclienthandlers.HandleTokensGet(render.New(web.TemplateFS(), web.StaticFS()), newRenderSessionStore(t), &tokensTabAPI{stored: client}),
			http.MethodGet, nil)

		toggle := dpopSwitchRe.FindString(out)
		require.NotEmpty(t, toggle, "the switch is drawn")
		assert.Contains(t, toggle, `type="checkbox"`)
		assert.Contains(t, toggle, `name="dpopBoundAccessTokens"`)
		assert.Equal(t, stored, regexp.MustCompile(`\schecked(?:\s|>|$)`).MatchString(toggle), "stored %v", stored)
		assert.Contains(t, toggle, `aria-describedby="dpopBoundAccessTokensHint dpopBoundAccessTokensImplicit"`)

		assert.Contains(t, out, `<span class="choice-label">Exigir DPoP nas solicitações de token</span>`)
		assert.Contains(t, out, `<span class="field-hint" id="dpopBoundAccessTokensHint">Toda solicitação de token deste cliente precisa trazer uma prova DPoP`)
		assert.Contains(t, out, `<span class="field-hint" id="dpopBoundAccessTokensImplicit">Enquanto esta opção estiver ativa, o cliente não consegue tokens de acesso pelo fluxo implícito`)

		// Inside the tab's one form, before its Save.
		formStart := strings.Index(out, `<form class="panel" method="post"`)
		switchAt := strings.Index(out, `id="dpopBoundAccessTokens"`)
		saveAt := strings.Index(out, `id="btnSave"`)
		formEnd := strings.Index(out, `</form>`)
		require.True(t, formStart >= 0 && switchAt > formStart && saveAt > switchAt && formEnd > saveAt,
			"the switch is in the form, before Save")
		assert.Equal(t, 1, strings.Count(out, `<form `), "the tab has one form")
	}
}

// The admin console's own client is not offered the requirement (#42 decision 12): its tab draws
// neither the switch nor its words.
func TestRender_AdminClientTokens_TheAdminConsolesClientIsNotOfferedTheDPoPRequirement(t *testing.T) {
	client := storedTokensClient()
	client.ClientIdentifier = "admin-console-client"
	client.IsSystemLevelClient = true

	out := serveClientTokens(t,
		adminclienthandlers.HandleTokensGet(render.New(web.TemplateFS(), web.StaticFS()), newRenderSessionStore(t), &tokensTabAPI{stored: client}),
		http.MethodGet, nil)

	assert.Contains(t, out, `id="tokenExpirationInSeconds"`, "the rest of the tab is drawn")
	assert.NotContains(t, out, `dpopBoundAccessTokens`)
	assert.NotContains(t, out, `Exigir DPoP`)
}

// A refused requirement, which comes after the token settings were saved, is shown beside the
// switch: the notice says so, and the switch is marked invalid, described by the notice and
// focused, while the tab says the token settings were saved.
func TestRender_AdminClientTokens_ARefusedRequirementIsShownBesideTheSwitch(t *testing.T) {
	const refusal = "O cliente do console de administração não pode exigir DPoP nas solicitações de token."
	apiClient := &tokensTabAPI{stored: storedTokensClient(), dpopRefusal: refusal}

	out := serveClientTokens(t,
		adminclienthandlers.HandleTokensPost(render.New(web.TemplateFS(), web.StaticFS()), nil, &savingTokensTabAPI{apiClient}, "https://console.example"),
		http.MethodPost, url.Values{
			"tokenExpirationInSeconds":                {"300"},
			"refreshTokenOfflineIdleTimeoutInSeconds": {"3600"},
			"refreshTokenOfflineMaxLifetimeInSeconds": {"86400"},
			"includeOpenIDConnectClaimsInAccessToken": {"default"},
			"includeOpenIDConnectClaimsInIdToken":     {"on"},
			"dpopBoundAccessTokens":                   {"on"},
		})

	assert.Contains(t, out, `<div class="notice notice-danger" role="alert" id="dpop-error">`)
	assert.Contains(t, out, `<p>`+refusal+`</p>`)
	assert.Contains(t, out, `<p>Configurações de tokens salvas.</p>`, "the token settings were saved first")
	toggle := dpopSwitchRe.FindString(out)
	require.NotEmpty(t, toggle)
	assert.Contains(t, toggle, `aria-describedby="dpop-error dpopBoundAccessTokensHint dpopBoundAccessTokensImplicit"`)
	assert.Contains(t, toggle, ` aria-invalid="true"`)
	assert.Contains(t, toggle, ` autofocus`)
	assert.NotRegexp(t, `\schecked(?:\s|>|$)`, toggle, "the stored requirement, not the refused one")
}

// savingTokensTabAPI is tokensTabAPI with a token settings write that succeeds, answering the client
// as stored.
type savingTokensTabAPI struct{ *tokensTabAPI }

func (s *savingTokensTabAPI) UpdateClientTokens(_ context.Context, _ string, _ int64,
	_ *api.UpdateClientTokensRequest) (*api.ClientResponse, error) {
	s.saved = true
	return s.stored, nil
}
