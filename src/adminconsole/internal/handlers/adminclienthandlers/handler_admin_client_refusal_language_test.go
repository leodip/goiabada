package adminclienthandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
)

// refusingClientApiClient answers the reads the client pages make before they refuse a form, and
// panics on every write: each refusal below happens before the console calls the API to change
// anything.
type refusingClientApiClient struct{}

func (*refusingClientApiClient) GetClientPermissions(_ context.Context, _ string, clientId int64) (*api.ClientResponse, []api.PermissionResponse, error) {
	return &api.ClientResponse{Id: clientId, ClientIdentifier: "billing-app"}, nil, nil
}

func (*refusingClientApiClient) GetClientById(_ context.Context, _ string, clientId int64) (*api.ClientResponse, error) {
	return &api.ClientResponse{Id: clientId, ClientIdentifier: "billing-app"}, nil
}

func (*refusingClientApiClient) DeleteClient(context.Context, string, int64) error {
	panic("unexpected call to DeleteClient")
}

func (*refusingClientApiClient) CreateClient(context.Context, string, *api.CreateClientRequest) (*api.ClientResponse, error) {
	panic("unexpected call to CreateClient")
}

// GetSettingsTokens answers the global token settings, which the refused tokens tab names.
func (*refusingClientApiClient) GetSettingsTokens(context.Context, string) (*api.SettingsTokensResponse, error) {
	return &api.SettingsTokensResponse{TokenExpirationInSeconds: 300}, nil
}

func (*refusingClientApiClient) UpdateClientTokens(context.Context, string, int64, *api.UpdateClientTokensRequest) (*api.ClientResponse, error) {
	panic("unexpected call to UpdateClientTokens")
}

// The client pages' refusals are the console's own sentences, and they come from the catalog in the
// language the page is rendered in: English with no language on the request, word for word what
// they said before, and Portuguese under pt-BR (#559 decision 4).
func TestAdminClientPages_RefuseInThePagesLanguage(t *testing.T) {
	routed := handlertest.WithRouteParam("clientId", "3")
	validTokens := url.Values{
		"tokenExpirationInSeconds":                {"300"},
		"refreshTokenOfflineIdleTimeoutInSeconds": {"3600"},
		"refreshTokenOfflineMaxLifetimeInSeconds": {"86400"},
	}
	tokensWith := func(field, value string) url.Values {
		form := url.Values{}
		for k, v := range validTokens {
			form[k] = v
		}
		form.Set(field, value)
		return form
	}

	testCases := []struct {
		name       string
		template   string
		handler    func(httpHelper *handlersmocks.HttpHelper) http.HandlerFunc
		target     string
		form       url.Values
		english    string
		portuguese string
	}{
		{
			name:     "a new client with no identifier",
			template: "/admin_clients_new.html",
			handler: func(h *handlersmocks.HttpHelper) http.HandlerFunc {
				return HandleNewPost(h, &refusingClientApiClient{}, consoleBaseURL)
			},
			target:     "/admin/clients/new",
			form:       url.Values{"clientIdentifier": {"  "}},
			english:    "Client identifier is required.",
			portuguese: "O identificador do cliente é obrigatório.",
		},
		{
			name:     "a delete with no identifier",
			template: "/admin_clients_delete.html",
			handler: func(h *handlersmocks.HttpHelper) http.HandlerFunc {
				return HandleDeletePost(h, &refusingClientApiClient{}, consoleBaseURL)
			},
			target:     "/admin/clients/3/delete",
			form:       url.Values{"clientIdentifier": {""}},
			english:    "Client identifier is required.",
			portuguese: "O identificador do cliente é obrigatório.",
		},
		{
			name:     "a delete naming another client",
			template: "/admin_clients_delete.html",
			handler: func(h *handlersmocks.HttpHelper) http.HandlerFunc {
				return HandleDeletePost(h, &refusingClientApiClient{}, consoleBaseURL)
			},
			target:     "/admin/clients/3/delete",
			form:       url.Values{"clientIdentifier": {"shipping-app"}},
			english:    "That isn't this client's identifier. Type it as shown above.",
			portuguese: "Esse não é o identificador deste cliente. Digite-o como aparece acima.",
		},
		{
			name:     "a token expiration that is not a number",
			template: "/admin_clients_tokens.html",
			handler: func(h *handlersmocks.HttpHelper) http.HandlerFunc {
				return HandleTokensPost(h, nil, &refusingClientApiClient{}, consoleBaseURL)
			},
			target:     "/admin/clients/3/tokens",
			form:       tokensWith("tokenExpirationInSeconds", "soon"),
			english:    "Enter the token lifetime as a whole number of seconds.",
			portuguese: "Informe a duração do token como um número inteiro de segundos.",
		},
		{
			name:     "an offline idle timeout that is not a number",
			template: "/admin_clients_tokens.html",
			handler: func(h *handlersmocks.HttpHelper) http.HandlerFunc {
				return HandleTokensPost(h, nil, &refusingClientApiClient{}, consoleBaseURL)
			},
			target:     "/admin/clients/3/tokens",
			form:       tokensWith("refreshTokenOfflineIdleTimeoutInSeconds", "soon"),
			english:    "Enter the offline idle timeout as a whole number of seconds.",
			portuguese: "Informe o tempo ocioso offline como um número inteiro de segundos.",
		},
		{
			name:     "an offline max lifetime that is not a number",
			template: "/admin_clients_tokens.html",
			handler: func(h *handlersmocks.HttpHelper) http.HandlerFunc {
				return HandleTokensPost(h, nil, &refusingClientApiClient{}, consoleBaseURL)
			},
			target:     "/admin/clients/3/tokens",
			form:       tokensWith("refreshTokenOfflineMaxLifetimeInSeconds", "soon"),
			english:    "Enter the offline maximum lifetime as a whole number of seconds.",
			portuguese: "Informe a duração máxima offline como um número inteiro de segundos.",
		},
	}

	for _, testCase := range testCases {
		for _, language := range []struct{ name, tag, want string }{
			{"with no language", "", testCase.english},
			{"in pt-BR", "pt-BR", testCase.portuguese},
		} {
			t.Run(testCase.name+" "+language.name, func(t *testing.T) {
				httpHelper := handlersmocks.NewHttpHelper(t)
				handlertest.RefuseInternalServerError(t, httpHelper)
				handlertest.ExpectRender(httpHelper, mock.Anything, testCase.template).Once()

				req := handlertest.Request(http.MethodPost, testCase.target,
					handlertest.WithAccessToken(), routed, handlertest.WithLocale(language.tag),
					handlertest.WithForm(testCase.form))
				testCase.handler(httpHelper).ServeHTTP(httptest.NewRecorder(), req)

				assert.Equal(t, language.want, handlertest.Bind(t, httpHelper)["error"])
			})
		}
	}
}
