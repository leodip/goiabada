package admingrouphandlers

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
// 409 LAST_ADMINISTRATOR, and the console shows its sentence on every group page that can meet it:
// deleting the group that gives the last administrator manage, removing them from it, and revoking
// manage from it (#402 decision 12).

// lastAdministratorSentence is decision 12's description, written out here rather than read from
// the auth server.
const lastAdministratorSentence = "This change would leave no enabled user holding authserver:manage. Grant it to another user first."

func lastAdministratorRefusal() error {
	return &apiclient.APIError{Code: "LAST_ADMINISTRATOR", Message: lastAdministratorSentence, StatusCode: http.StatusConflict}
}

// lastAdministratorGroupApiClient answers the group read and refuses every write as the last
// administrator's.
type lastAdministratorGroupApiClient struct {
	group *api.GroupResponse
}

func (c *lastAdministratorGroupApiClient) GetGroupById(context.Context, string, int64) (*api.GroupResponse, error) {
	return c.group, nil
}

func (*lastAdministratorGroupApiClient) DeleteGroup(context.Context, string, int64) error {
	return lastAdministratorRefusal()
}

func (*lastAdministratorGroupApiClient) RemoveUserFromGroup(context.Context, string, int64, int64) error {
	return lastAdministratorRefusal()
}

// Deleting the group renders the confirmation page again, with the group and its member count as
// before and the sentence where the page shows an error, rather than the 500 page.
func TestHandleDeletePost_TheLastAdministratorRefusalIsShownOnThePage(t *testing.T) {
	group := &api.GroupResponse{Id: 4, GroupIdentifier: "admins", MemberCount: 1}
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_groups_delete.html").Once()

	req := handlertest.Request(http.MethodPost, "/admin/groups/4/delete",
		handlertest.WithAccessToken(),
		handlertest.WithRouteParam("groupId", "4"),
		handlertest.WithForm(url.Values{"groupIdentifier": {"admins"}}),
	)
	rec := httptest.NewRecorder()

	HandleDeletePost(httpHelper, &lastAdministratorGroupApiClient{group: group}, "https://console.example.com").ServeHTTP(rec, req)

	assert.Empty(t, rec.Header().Get("Location"), "no redirect to the list: the group was not deleted")
	bind := handlertest.Bind(t, httpHelper)
	assert.Equal(t, lastAdministratorSentence, bind["error"])
	assert.Equal(t, group, bind["group"])
	assert.Equal(t, 1, bind["countOfUsers"])
}

// Removing the last administrator from the group on its members page answers the page's AJAX call
// with the status and the sentence, which the page shows.
func TestHandleMembersRemoveUserPost_TheLastAdministratorRefusalReachesTheBrowser(t *testing.T) {
	req := handlertest.Request(http.MethodPost, "/admin/groups/4/members/7/remove",
		handlertest.WithAccessToken(),
		handlertest.WithRouteParam("groupId", "4"),
		handlertest.WithRouteParam("userId", "7"),
	)
	rec := httptest.NewRecorder()

	HandleMembersRemoveUserPost(render.New(nil), &lastAdministratorGroupApiClient{}).ServeHTTP(rec, req)

	assertLastAdministratorJSON(t, rec)
}

// Revoking manage from the group on its permissions page.
func TestHandlePermissionsPost_TheLastAdministratorRefusalReachesTheBrowser(t *testing.T) {
	req := handlertest.Request(http.MethodPost, "/admin/groups/4/permissions",
		handlertest.WithAccessToken(),
		handlertest.WithBody(bytes.NewBufferString(`{"groupId":4,"assignedPermissionsIds":[],"expectedPermissionIds":[1]}`)),
	)
	rec := httptest.NewRecorder()

	HandlePermissionsPost(render.New(nil), nil, &groupPermissionsSaveApiClient{err: lastAdministratorRefusal()}).ServeHTTP(rec, req)

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
