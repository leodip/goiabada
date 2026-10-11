package adminuserhandlers

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

// refusingUserApiClient answers the reads the user pages make before they refuse a form, and panics
// on every write: each refusal below happens before the console asks the API to change anything.
type refusingUserApiClient struct{}

func (*refusingUserApiClient) GetUserById(_ context.Context, _ string, userId int64) (*api.UserResponse, error) {
	return &api.UserResponse{Id: userId}, nil
}

func (*refusingUserApiClient) GetUserAttributeById(_ context.Context, _ string, attributeId int64) (*api.UserAttributeResponse, error) {
	return &api.UserAttributeResponse{Id: attributeId, Key: "department", UserId: 5}, nil
}

func (*refusingUserApiClient) CreateUserAdmin(context.Context, string, *api.CreateUserAdminRequest) (*api.UserResponse, error) {
	panic("unexpected call to CreateUserAdmin")
}

func (*refusingUserApiClient) CreateUserAttribute(context.Context, string, *api.CreateUserAttributeRequest) (*api.UserAttributeResponse, error) {
	panic("unexpected call to CreateUserAttribute")
}

func (*refusingUserApiClient) UpdateUserAttribute(context.Context, string, int64, *api.UpdateUserAttributeRequest) (*api.UserAttributeResponse, error) {
	panic("unexpected call to UpdateUserAttribute")
}

// The user pages' refusals are the console's own sentences, and they come from the catalog in the
// language the page is rendered in: English with no language on the request, word for word what
// they said before, and Portuguese under pt-BR (#559 decision 4).
func TestAdminUserPages_RefuseInThePagesLanguage(t *testing.T) {
	testCases := []struct {
		name       string
		template   string
		handler    func(httpHelper *handlersmocks.HttpHelper) http.HandlerFunc
		target     string
		options    []handlertest.Option
		form       url.Values
		english    string
		portuguese string
	}{
		{
			name:     "a new user with no email",
			template: "/admin_users_new.html",
			handler: func(h *handlersmocks.HttpHelper) http.HandlerFunc {
				return HandleNewPost(h, nil, &refusingUserApiClient{}, consoleBaseURL)
			},
			target:     "/admin/users/new",
			options:    []handlertest.Option{handlertest.WithSettings(&api.PublicSettingsResponse{})},
			form:       url.Values{"email": {"  "}},
			english:    "The email address cannot be empty.",
			portuguese: "O endereço de e-mail não pode ficar vazio.",
		},
		{
			name:     "a new attribute with no key",
			template: "/admin_users_attributes_add.html",
			handler: func(h *handlersmocks.HttpHelper) http.HandlerFunc {
				return HandleAttributesAddPost(h, &refusingUserApiClient{}, consoleBaseURL)
			},
			target:     "/admin/users/5/attributes/add",
			options:    []handlertest.Option{handlertest.WithRouteParam("userId", "5")},
			form:       url.Values{"attributeKey": {" "}, "attributeValue": {"sales"}},
			english:    "Attribute key is required",
			portuguese: "A chave do atributo é obrigatória",
		},
		{
			name:     "an attribute edited to no key",
			template: "/admin_users_attributes_edit.html",
			handler: func(h *handlersmocks.HttpHelper) http.HandlerFunc {
				return HandleAttributesEditPost(h, &refusingUserApiClient{}, consoleBaseURL)
			},
			target: "/admin/users/5/attributes/edit/9",
			options: []handlertest.Option{handlertest.WithRouteParam("userId", "5"),
				handlertest.WithRouteParam("attributeId", "9")},
			form:       url.Values{"attributeKey": {""}, "attributeValue": {"sales"}},
			english:    "Attribute key is required",
			portuguese: "A chave do atributo é obrigatória",
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

				options := append([]handlertest.Option{handlertest.WithAccessToken(),
					handlertest.WithLocale(language.tag), handlertest.WithForm(testCase.form)},
					testCase.options...)
				req := handlertest.Request(http.MethodPost, testCase.target, options...)
				testCase.handler(httpHelper).ServeHTTP(httptest.NewRecorder(), req)

				assert.Equal(t, language.want, handlertest.Bind(t, httpHelper)["error"])
			})
		}
	}
}
