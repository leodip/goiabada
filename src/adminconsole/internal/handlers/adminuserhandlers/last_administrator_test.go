package adminuserhandlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/core/api"
)

// The auth server refuses a change that would leave no enabled user holding authserver:manage with
// 409 LAST_ADMINISTRATOR, and the console shows its sentence on every page that can meet it: on the
// user's details page (disabling), its delete page, its permissions page and its groups page (#402
// decision 12). A 409 handed to HandleAPIError was the 500 page, which blamed the server for a
// refusal the administrator can resolve by granting manage to someone else first.

// lastAdministratorSentence is decision 12's description, written out here rather than read from
// the auth server.
const lastAdministratorSentence = "This change would leave no enabled user holding authserver:manage. Grant it to another user first."

func lastAdministratorRefusal() error {
	return &apiclient.APIError{Code: "LAST_ADMINISTRATOR", Message: lastAdministratorSentence, StatusCode: http.StatusConflict}
}

// lastAdministratorUserApiClient answers the reads a re-rendered page makes and refuses every
// write as the last administrator's.
type lastAdministratorUserApiClient struct {
	user   *api.UserResponse
	groups []api.GroupResponse
}

func (c *lastAdministratorUserApiClient) GetUserById(context.Context, string, int64) (*api.UserResponse, error) {
	return c.user, nil
}

func (c *lastAdministratorUserApiClient) GetUserGroups(context.Context, string, int64) (*api.UserResponse, []api.GroupResponse, error) {
	return c.user, c.groups, nil
}

func (*lastAdministratorUserApiClient) UpdateUserEnabled(context.Context, string, int64, bool) (*api.UserResponse, error) {
	return nil, lastAdministratorRefusal()
}

func (*lastAdministratorUserApiClient) DeleteUser(context.Context, string, int64) error {
	return lastAdministratorRefusal()
}

func (*lastAdministratorUserApiClient) UpdateUserPermissions(context.Context, string, int64, *api.UpdateUserPermissionsRequest) error {
	return lastAdministratorRefusal()
}

// The rest of the ports lastAdministratorUserApiClient is passed to, which no test here reaches.

func (*lastAdministratorUserApiClient) GetAllResources(context.Context, string) ([]api.ResourceResponse, error) {
	panic("unexpected call to GetAllResources")
}

func (*lastAdministratorUserApiClient) GetUserPermissions(context.Context, string, int64) (*api.UserResponse, []api.PermissionResponse, error) {
	panic("unexpected call to GetUserPermissions")
}

// Disabling the last administrator renders the details page again, with the user as stored and the
// sentence where the page shows an error, and no saved notice.
func TestHandleDetailsPost_TheLastAdministratorRefusalIsShownOnThePage(t *testing.T) {
	user := &api.UserResponse{Id: 7, Email: "admin@example.com", GivenName: "Ada", FamilyName: "Admin", Enabled: true}
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_users_details.html").Once()

	req := handlertest.Request(http.MethodPost, "/admin/users/7/details",
		handlertest.WithAccessToken(),
		handlertest.WithRouteParam("userId", "7"),
		handlertest.WithForm(url.Values{}),
	)

	HandleDetailsPost(httpHelper, nil, &lastAdministratorUserApiClient{user: user}, "https://console.example.com").
		ServeHTTP(httptest.NewRecorder(), req)

	bind := handlertest.Bind(t, httpHelper)
	assert.Equal(t, lastAdministratorSentence, bind["error"])
	assert.Equal(t, user, bind["user"], "the page shows the user as stored, still enabled")
	assert.Equal(t, "Ada Admin", bind["userFullName"])
	assert.NotEqual(t, true, bind["savedSuccessfully"], "nothing was saved")
}

// Deleting the last administrator renders the confirmation page again, with what it showed before
// and the sentence where the page shows an error.
func TestHandleDeletePost_TheLastAdministratorRefusalIsShownOnThePage(t *testing.T) {
	user := &api.UserResponse{Id: 7, Email: "admin@example.com", GivenName: "Ada", FamilyName: "Admin", Enabled: true}
	groups := []api.GroupResponse{{Id: 2, GroupIdentifier: "admins"}}
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_users_delete.html").Once()

	req := handlertest.Request(http.MethodPost, "/admin/users/7/delete",
		handlertest.WithAccessToken(),
		handlertest.WithRouteParam("userId", "7"),
		handlertest.WithForm(url.Values{}),
	)
	rec := httptest.NewRecorder()

	HandleDeletePost(httpHelper, &lastAdministratorUserApiClient{user: user, groups: groups}, "https://console.example.com").
		ServeHTTP(rec, req)

	assert.Empty(t, rec.Header().Get("Location"), "no redirect to the list: the user was not deleted")
	bind := handlertest.Bind(t, httpHelper)
	assert.Equal(t, lastAdministratorSentence, bind["error"])
	assert.Equal(t, user, bind["user"])
	assert.Equal(t, "Ada Admin", bind["userFullName"])
	assert.Equal(t, groups, bind["groups"])
}

// Revoking manage from the last administrator on the permissions page answers the page's AJAX call
// with the status and the sentence, which the page shows.
func TestHandlePermissionsPost_TheLastAdministratorRefusalReachesTheBrowser(t *testing.T) {
	req := handlertest.Request(http.MethodPost, "/admin/users/7/permissions",
		handlertest.WithAccessToken(),
		handlertest.WithRouteParam("userId", "7"),
		handlertest.WithBody(bytes.NewBufferString(`{"assignedPermissionsIds":[],"expectedPermissionIds":[1]}`)),
	)
	rec := httptest.NewRecorder()

	HandlePermissionsPost(render.New(nil), nil, &lastAdministratorUserApiClient{}).ServeHTTP(rec, req)

	assertLastAdministratorJSON(t, rec)
}

// Removing the last administrator from the group that gives them manage, on the groups page.
func TestHandleGroupsPost_TheLastAdministratorRefusalReachesTheBrowser(t *testing.T) {
	req := handlertest.Request(http.MethodPost, "/admin/users/7/groups",
		handlertest.WithAccessToken(),
		handlertest.WithRouteParam("userId", "7"),
		handlertest.WithBody(bytes.NewBufferString(`{"assignedGroupsIds":[],"expectedGroupIds":[2]}`)),
	)
	rec := httptest.NewRecorder()

	HandleGroupsPost(render.New(nil), nil, &userGroupsSaveApiClient{err: lastAdministratorRefusal()}).ServeHTTP(rec, req)

	assertLastAdministratorJSON(t, rec)
}

func assertLastAdministratorJSON(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	assert.Equal(t, http.StatusConflict, rec.Code)
	var response map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
	assert.Equal(t, "LAST_ADMINISTRATOR", response["error"])
	assert.Equal(t, lastAdministratorSentence, response["error_description"])
}
