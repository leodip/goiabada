package renderintegration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminclienthandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	web "github.com/leodip/goiabada/adminconsole/web"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// deletePageAPI is the auth server as the client delete page reaches it: the client as stored, with
// the permissions the page warns about, and a delete it records.
type deletePageAPI struct {
	stored  *api.ClientResponse
	perms   []api.PermissionResponse
	deleted bool
}

func (d *deletePageAPI) GetClientPermissions(_ context.Context, _ string, _ int64) (*api.ClientResponse, []api.PermissionResponse, error) {
	return d.stored, d.perms, nil
}

func (d *deletePageAPI) DeleteClient(_ context.Context, _ string, _ int64) error {
	d.deleted = true
	return nil
}

// serveClientDelete drives one of the delete page's handlers through the real renderer, in pt-BR,
// and returns the status and the page it answers with.
func serveClientDelete(t *testing.T, handler http.HandlerFunc, method string, form url.Values) (int, string) {
	t.Helper()
	opts := []handlertest.Option{handlertest.WithAccessToken(), handlertest.WithRouteParam("clientId", "7"),
		handlertest.WithSettings(&api.PublicSettingsResponse{AppName: "Test", UITheme: "dark"})}
	if form != nil {
		opts = append(opts, handlertest.WithForm(form))
	}
	req := handlertest.Request(method, "/admin/clients/7/delete", opts...)
	req = req.WithContext(i18n.WithLocale(req.Context(), true, "pt-BR"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// A wrong or empty identifier draws the delete page again with its message, never the 500 page, and
// draws it from the same view as the page's first draw: the client as stored and the permissions
// the page warns about. The refusal used to bind the API's client alone, which has no Permissions
// for the template to read, so the render failed and the administrator saw "Server error" (#562).
func TestRender_AdminClientDelete_ARefusalDrawsTheDeletePageAgain(t *testing.T) {
	testCases := []struct {
		name       string
		identifier string
		message    string
	}{
		{name: "an empty identifier", identifier: "", message: "O identificador do cliente é obrigatório."},
		{name: "a wrong identifier", identifier: "portal-typo",
			message: "O identificador do cliente não corresponde ao cliente que está sendo excluído."},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			apiClient := &deletePageAPI{
				stored: &api.ClientResponse{Id: 7, ClientIdentifier: "portal", Description: "The customer portal",
					Enabled: true, AuthorizationCodeEnabled: true},
				perms: []api.PermissionResponse{{Id: 3, PermissionIdentifier: "read",
					Resource: api.ResourceResponse{Id: 2, ResourceIdentifier: "orders"}}},
			}
			renderer := render.New(web.TemplateFS(), web.StaticFS())

			status, out := serveClientDelete(t,
				adminclienthandlers.HandleDeletePost(renderer, apiClient, "https://console.example"),
				http.MethodPost, url.Values{"clientIdentifier": {tc.identifier}})

			require.Equal(t, http.StatusOK, status, "the refusal is drawn on the delete page: %s", out)
			assert.False(t, apiClient.deleted, "a refused delete deletes nothing")

			assert.Contains(t, out, `<p>`+tc.message+`</p>`)
			assert.Contains(t, out, `<span class="text-accent">portal</span>`, "the page title names the client")
			assert.Contains(t, out, `<td class="font-mono">portal</td>`)
			assert.Contains(t, out, `The customer portal`)
			assert.Contains(t, out, `<li>orders:read</li>`, "the permissions the page warns about")
			assert.Contains(t, out, `id="btnDelete"`, "and the button to try again")

			// Beyond the message, the refusal is the first draw itself.
			firstStatus, firstDraw := serveClientDelete(t, adminclienthandlers.HandleDeleteGet(renderer, apiClient),
				http.MethodGet, nil)
			require.Equal(t, http.StatusOK, firstStatus)
			messageBlock := "\n            <div class=\"mb-4 text-right text-error\">\n                <p>" + tc.message +
				"</p>\n            </div>\n            "
			require.Contains(t, out, messageBlock)
			assert.Equal(t, firstDraw, strings.Replace(out, messageBlock, "", 1))
		})
	}
}
