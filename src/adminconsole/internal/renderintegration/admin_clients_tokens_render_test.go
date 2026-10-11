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
	saved   bool
}

func (s *tokensTabAPI) GetClientById(_ context.Context, _ string, _ int64) (*api.ClientResponse, error) {
	return s.stored, nil
}

func (s *tokensTabAPI) UpdateClientTokens(_ context.Context, _ string, _ int64,
	_ *api.UpdateClientTokensRequest) (*api.ClientResponse, error) {
	s.saved = true
	return nil, &apiclient.APIError{Code: "VALIDATION_ERROR", Message: s.refusal, StatusCode: http.StatusBadRequest}
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
	opts := []handlertest.Option{handlertest.WithAccessToken(), handlertest.WithRouteParam("clientId", "7"),
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
		if strings.Contains(radio, "checked") {
			checked = append(checked, regexp.MustCompile(`value="([^"]*)"`).FindStringSubmatch(radio)[1])
		}
	}
	require.Len(t, checked, 1, "one choice of %s is checked: %v", name, checked)
	return checked[0]
}

// durationValue returns the value the page draws in the named duration input.
func durationValue(t *testing.T, out, id string) string {
	t.Helper()
	input := regexp.MustCompile(`<input id="` + id + `"[^>]*>`).FindString(out)
	require.NotEmpty(t, input, "the %s input is rendered", id)
	value := regexp.MustCompile(`value="([^"]*)"`).FindStringSubmatch(input)
	require.NotNil(t, value, "the %s input has a value", id)
	return value[1]
}

// The first draw of the tab shows the client as stored: every duration and both choices.
func TestRender_AdminClientTokens_TheFirstDrawShowsTheStoredClient(t *testing.T) {
	apiClient := &tokensTabAPI{stored: storedTokensClient()}

	out := serveClientTokens(t,
		adminclienthandlers.HandleTokensGet(render.New(web.TemplateFS()), newRenderSessionStore(t), apiClient),
		http.MethodGet, nil)

	assert.Contains(t, out, `<span class="text-accent">portal</span>`)
	assert.Equal(t, "300", durationValue(t, out, "tokenExpirationInSeconds"))
	assert.Equal(t, "3600", durationValue(t, out, "refreshTokenOfflineIdleTimeoutInSeconds"))
	assert.Equal(t, "86400", durationValue(t, out, "refreshTokenOfflineMaxLifetimeInSeconds"))
	assert.Equal(t, "default", checkedChoice(t, out, "includeOpenIDConnectClaimsInAccessToken"))
	assert.Equal(t, "on", checkedChoice(t, out, "includeOpenIDConnectClaimsInIdToken"))
}

// A refused save draws the tab again with every input as the administrator submitted it: each
// duration as typed, a number or not, and both OpenID Connect claims choices as chosen. The choices
// used to be drawn from the stored client and a duration that was not a number replaced by the
// stored one, so the page showed values nobody had submitted beside the refusal (#562).
func TestRender_AdminClientTokens_ARefusedSaveKeepsWhatWasSubmitted(t *testing.T) {
	const apiRefusal = "Token expiration in seconds must be at least 30."
	testCases := []struct {
		name       string
		expiration string
		idle       string
		maxLife    string
		message    string
		wantSaved  bool
	}{
		{name: "an expiration that is not a number", expiration: "5 minutes", idle: "7200", maxLife: "90000",
			message: "Invalid value for token expiration in seconds."},
		{name: "an idle timeout that is not a number", expiration: "600", idle: "two hours", maxLife: "90000",
			message: "Invalid value for refresh token offline - idle timeout in seconds."},
		{name: "a max lifetime that is not a number", expiration: "600", idle: "7200", maxLife: "a day",
			message: "Invalid value for refresh token offline - max lifetime in seconds."},
		{name: "numbers the auth server refuses", expiration: "10", idle: "7200", maxLife: "90000",
			message: apiRefusal, wantSaved: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			apiClient := &tokensTabAPI{stored: storedTokensClient(), refusal: apiRefusal}

			out := serveClientTokens(t,
				adminclienthandlers.HandleTokensPost(render.New(web.TemplateFS()), nil, apiClient, "https://console.example"),
				http.MethodPost, url.Values{
					"tokenExpirationInSeconds":                {tc.expiration},
					"refreshTokenOfflineIdleTimeoutInSeconds": {tc.idle},
					"refreshTokenOfflineMaxLifetimeInSeconds": {tc.maxLife},
					"includeOpenIDConnectClaimsInAccessToken": {"off"},
					"includeOpenIDConnectClaimsInIdToken":     {"default"},
				})

			assert.Equal(t, tc.wantSaved, apiClient.saved)
			assert.Contains(t, out, `<p>`+tc.message+`</p>`)
			assert.Contains(t, out, `<span class="text-accent">portal</span>`, "the page title names the stored client")

			assert.Equal(t, tc.expiration, durationValue(t, out, "tokenExpirationInSeconds"))
			assert.Equal(t, tc.idle, durationValue(t, out, "refreshTokenOfflineIdleTimeoutInSeconds"))
			assert.Equal(t, tc.maxLife, durationValue(t, out, "refreshTokenOfflineMaxLifetimeInSeconds"))
			assert.Equal(t, "off", checkedChoice(t, out, "includeOpenIDConnectClaimsInAccessToken"))
			assert.Equal(t, "default", checkedChoice(t, out, "includeOpenIDConnectClaimsInIdToken"))
		})
	}
}
