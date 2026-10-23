package adminclienthandlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
)

// A hand-made delete of the admin console's own client is answered with the delete page again and
// its refusal, as the resource page answers one for the auth server's own resource, rather than the
// 500 page (#632 decision 5). It is refused first, before the identifier is read, and DeleteClient
// is never reached, which refusingClientApiClient proves by panicking if it is.
func TestAdminClientDeletePost_RefusesTheConsolesOwnClient(t *testing.T) {
	// Refused first: with no identifier typed, the refusal is still that this client cannot go.
	for _, typed := range []string{"billing-app", ""} {
		t.Run("clientIdentifier="+typed, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_clients_delete.html").Once()

			handler := HandleDeletePost(httpHelper, &refusingClientApiClient{isSystemLevel: true}, consoleBaseURL)
			req := handlertest.Request(http.MethodPost, "/admin/clients/3/delete",
				handlertest.WithAccessToken(), handlertest.WithPathValue("clientId", "3"),
				handlertest.WithForm(url.Values{"clientIdentifier": {typed}}))
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)

			assert.Equal(t, http.StatusOK, recorder.Code)
			bind := handlertest.Bind(t, httpHelper)
			view, ok := bind["client"].(clientDeleteView)
			require.True(t, ok, "the page is drawn from the view its first draw binds")
			assert.True(t, view.IsSystemLevelClient, "the page draws the caution it always draws for this client")
			assert.Equal(t, "billing-app", view.ClientIdentifier)
			assert.Equal(t, "This is the admin console's own client, so it can't be deleted.", bind["error"])
		})
	}
}
