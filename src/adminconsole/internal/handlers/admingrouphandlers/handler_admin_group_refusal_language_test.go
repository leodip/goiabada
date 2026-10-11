package admingrouphandlers

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

// refusingGroupDeleteApiClient answers the group the delete page reads, and panics on the delete:
// both refusals below happen before the console asks the API to delete anything.
type refusingGroupDeleteApiClient struct{}

func (*refusingGroupDeleteApiClient) GetGroupById(_ context.Context, _ string, groupId int64) (*api.GroupResponse, error) {
	return &api.GroupResponse{Id: groupId, GroupIdentifier: "staff"}, nil
}

func (*refusingGroupDeleteApiClient) DeleteGroup(context.Context, string, int64) error {
	panic("unexpected call to DeleteGroup")
}

// The group delete page's two refusals are the console's own sentences, and they come from the
// catalog in the language the page is rendered in: English with no language on the request, word
// for word what they said before, and Portuguese under pt-BR (#559 decision 4).
func TestAdminGroupDeletePost_RefusesInThePagesLanguage(t *testing.T) {
	testCases := []struct {
		name       string
		identifier string
		english    string
		portuguese string
	}{
		{
			name:       "no identifier typed",
			identifier: "",
			english:    "Group identifier is required.",
			portuguese: "O identificador do grupo é obrigatório.",
		},
		{
			name:       "another group's identifier typed",
			identifier: "contractors",
			english:    "Group identifier does not match the group being deleted.",
			portuguese: "O identificador do grupo não corresponde ao grupo que está sendo excluído.",
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
				handlertest.ExpectRender(httpHelper, mock.Anything, "/admin_groups_delete.html").Once()

				handler := HandleDeletePost(httpHelper, &refusingGroupDeleteApiClient{}, consoleBaseURL)
				req := handlertest.Request(http.MethodPost, "/admin/groups/4/delete",
					handlertest.WithAccessToken(), handlertest.WithRouteParam("groupId", "4"),
					handlertest.WithLocale(language.tag),
					handlertest.WithForm(url.Values{"groupIdentifier": {testCase.identifier}}))
				handler.ServeHTTP(httptest.NewRecorder(), req)

				assert.Equal(t, language.want, handlertest.Bind(t, httpHelper)["error"])
			})
		}
	}
}
