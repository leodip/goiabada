package renderintegration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminresourcehandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	web "github.com/leodip/goiabada/adminconsole/web"
	"github.com/leodip/goiabada/core/api"
)

// resourceToDelete answers the resource delete page's two reads, and panics on the delete itself,
// which a refused form never reaches.
type resourceToDelete struct{}

func (resourceToDelete) GetResourceById(_ context.Context, _ string, resourceId int64) (*api.ResourceResponse, error) {
	return &api.ResourceResponse{Id: resourceId, ResourceIdentifier: "billing", Description: "Billing"}, nil
}

func (resourceToDelete) GetPermissionsByResource(context.Context, string, int64) ([]api.PermissionResponse, error) {
	return nil, nil
}

func (resourceToDelete) DeleteResource(context.Context, string, int64) error {
	panic("unexpected call to DeleteResource")
}

// A form the console refuses itself is redrawn with its refusal in the page's language. The real
// resource delete handler runs here through the real renderer, so the sentence is what an
// administrator reading the console in Portuguese sees on the page, not only what the handler
// bound (#559 decision 4).
func TestRender_AdminResourceDelete_TheConsolesRefusalIsInThePagesLanguage(t *testing.T) {
	req := handlertest.Request(http.MethodPost, "/admin/resources/7/delete",
		handlertest.WithAccessToken(), handlertest.WithRouteParam("resourceId", "7"),
		handlertest.WithSettings(&api.PublicSettingsResponse{AppName: "Test", UITheme: "dark"}),
		handlertest.WithLocale("pt-BR"),
		handlertest.WithForm(url.Values{"resourceIdentifier": {"shipping"}}))

	w := httptest.NewRecorder()
	adminresourcehandlers.HandleDeletePost(render.New(web.TemplateFS(), web.StaticFS()), resourceToDelete{}, "https://console.example.test").
		ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, "the refused form is redrawn, not answered with an error page")
	out := w.Body.String()
	assert.Contains(t, out, `lang="pt-BR"`)
	assert.Contains(t, out, "Este não é o identificador deste recurso. Digite-o como aparece acima.")
	assert.NotContains(t, out, "That isn't this resource's identifier. Type it as shown above.")
}
