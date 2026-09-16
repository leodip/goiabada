package adminresourcehandlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
	mocks_handler_helpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
)

// Decision 10 at the console's seam. These five pages disable rename and delete on a system-level
// resource, and the auth server refuses both for the same reason, at handler_api_resources.go. The
// console used to decide it for itself, by calling models.Resource.IsSystemLevelResource(), which
// compares the identifier against constants.AuthServerResourceIdentifier; it reads a bool off the
// response now, which the server sets by asking that same method.
//
// The distinction the rows below turn on is what makes a local copy of the rule unsafe. A resource
// the server calls system level but whose identifier is not the auth server's own is exactly the
// case the two implementations answer differently: the console would offer a rename the API then
// refuses. Both rows are here, so a return to the local rule fails the first and a hard-coded true
// fails the second.
type systemLevelApiClient struct {
	apiclient.ApiClient
	resource api.ResourceResponse
}

func (c *systemLevelApiClient) GetResourceById(accessToken string, resourceId int64) (*api.ResourceResponse, error) {
	resource := c.resource
	resource.Id = resourceId
	return &resource, nil
}

func (c *systemLevelApiClient) GetPermissionsByResource(accessToken string, resourceId int64) ([]api.PermissionResponse, error) {
	return nil, nil
}

// bindOfSystemLevelPage runs one resource GET and hands back what it rendered with.
func bindOfSystemLevelPage(t *testing.T, page string, resource api.ResourceResponse) map[string]interface{} {
	t.Helper()

	httpHelper := mocks_handler_helpers.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, mock.Anything, mock.Anything).Once()

	apiClient := &systemLevelApiClient{resource: resource}

	var handler http.HandlerFunc
	switch page {
	case "settings":
		handler = HandleAdminResourceSettingsGet(httpHelper, testStore(), apiClient)
	case "permissions":
		handler = HandleAdminResourcePermissionsGet(httpHelper, testStore(), apiClient)
	default:
		t.Fatalf("no such page: %s", page)
	}

	req := handlertest.Request(http.MethodGet, "/admin/resources/7/"+page,
		handlertest.WithAccessToken(), handlertest.WithRouteParam("resourceId", "7"))
	handler.ServeHTTP(httptest.NewRecorder(), req)

	return handlertest.Bind(t, httpHelper)
}

func TestAdminResourcePages_TheSystemLevelFlagIsTheServersAnswer(t *testing.T) {
	// Not "authserver": a console recomputing the rule from the identifier answers false here,
	// which is the disagreement decision 10 exists to prevent.
	systemLevel := api.ResourceResponse{
		ResourceIdentifier:    "some-other-resource",
		Description:           "Flagged by the server",
		IsSystemLevelResource: true,
	}
	ordinary := api.ResourceResponse{
		ResourceIdentifier: "billing",
		Description:        "Not flagged",
	}

	for _, page := range []string{"settings", "permissions"} {
		t.Run(page+" carries a flagged resource through", func(t *testing.T) {
			bind := bindOfSystemLevelPage(t, page, systemLevel)
			assert.Equal(t, true, bind["isSystemLevelResource"],
				"the page must mirror what the API said, not what the identifier looks like")
			assert.Equal(t, "some-other-resource", bind["resourceIdentifier"])
		})

		t.Run(page+" leaves an ordinary resource unflagged", func(t *testing.T) {
			bind := bindOfSystemLevelPage(t, page, ordinary)
			assert.Equal(t, false, bind["isSystemLevelResource"],
				"a hard-coded true would disable rename and delete on every resource")
		})
	}
}

// The delete POST refuses before it calls the API, and it refuses on the same flag. This is the one
// of the nine call sites that decides rather than displays, so it gets a row of its own: the page
// re-renders with the refusal and DeleteResource is never reached, which the embedded stub proves
// by panicking if it is.
func TestAdminResourceDeletePost_RefusesOnTheServersFlag(t *testing.T) {
	httpHelper := mocks_handler_helpers.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, mock.Anything, mock.Anything).Once()

	apiClient := &systemLevelApiClient{resource: api.ResourceResponse{
		ResourceIdentifier:    "some-other-resource",
		IsSystemLevelResource: true,
	}}

	handler := HandleAdminResourceDeletePost(httpHelper, apiClient)
	req := handlertest.Request(http.MethodPost, "/admin/resources/7/delete",
		handlertest.WithAccessToken(), handlertest.WithRouteParam("resourceId", "7"))
	handler.ServeHTTP(httptest.NewRecorder(), req)

	bind := handlertest.Bind(t, httpHelper)
	require.Equal(t, true, bind["isSystemLevelResource"])
	assert.Equal(t, "System-level resources cannot be deleted.", bind["error"],
		"the refusal is the server's flag acted on, and it happens before DeleteResource is called")
}
