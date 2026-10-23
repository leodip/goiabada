package adminresourcehandlers

import (
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

// The resource delete page's three refusals are the console's own sentences, and they come from the
// catalog in the language the page is rendered in: English with no language on the request, word
// for word what they said before, and Portuguese under pt-BR (#559 decision 4).
func TestAdminResourceDeletePost_RefusesInThePagesLanguage(t *testing.T) {
	ordinary := api.ResourceResponse{ResourceIdentifier: "billing"}
	systemLevel := api.ResourceResponse{ResourceIdentifier: "billing", IsSystemLevelResource: true}

	testCases := []struct {
		name       string
		resource   api.ResourceResponse
		identifier string
		english    string
		portuguese string
	}{
		{
			name:       "a system-level resource",
			resource:   systemLevel,
			identifier: "billing",
			english:    "This is the auth server's own resource, so it can't be deleted.",
			portuguese: "Este é o recurso do próprio servidor de autenticação, então não pode ser excluído.",
		},
		{
			name:       "no identifier typed",
			resource:   ordinary,
			identifier: "",
			english:    "Type the resource identifier to confirm.",
			portuguese: "Digite o identificador do recurso para confirmar.",
		},
		{
			name:       "another resource's identifier typed",
			resource:   ordinary,
			identifier: "shipping",
			english:    "That isn't this resource's identifier. Type it as shown above.",
			portuguese: "Este não é o identificador deste recurso. Digite-o como aparece acima.",
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
				handlertest.ExpectRender(httpHelper, mock.Anything, "/admin_resources_delete.html").Once()

				handler := HandleDeletePost(httpHelper, &systemLevelApiClient{resource: testCase.resource}, consoleBaseURL)
				req := handlertest.Request(http.MethodPost, "/admin/resources/7/delete",
					handlertest.WithAccessToken(), handlertest.WithPathValue("resourceId", "7"),
					handlertest.WithLocale(language.tag),
					handlertest.WithForm(url.Values{"resourceIdentifier": {testCase.identifier}}))
				handler.ServeHTTP(httptest.NewRecorder(), req)

				assert.Equal(t, language.want, handlertest.Bind(t, httpHelper)["error"])
			})
		}
	}
}
