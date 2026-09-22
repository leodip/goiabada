package admingrouphandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	mocks_handlerhelpers "github.com/leodip/goiabada/adminconsole/internal/handlerhelpers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/sessionstore"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
)

// Seam 3 for the group family (#350).
//
// These handlers used to bind a models.Group the apiclient rebuilt from the response field by
// field. They bind the response itself now, and the fields they read off it are the pages' own
// columns, so a field that stopped arriving renders an empty cell rather than failing. Each case
// below reads one bind the template cannot do without.
//
// groupBindApiClient answers the reads each page performs and embeds the interface, so any other
// method a handler reached for would panic rather than answer a helpful zero value.
type groupBindApiClient struct {
	apiclient.ApiClient
	group      *api.GroupResponse
	attributes []api.GroupAttributeResponse
}

func (c *groupBindApiClient) GetGroupById(_ context.Context, accessToken string, groupId int64) (*api.GroupResponse, error) {
	return c.group, nil
}

func (c *groupBindApiClient) GetGroupAttributesByGroupId(_ context.Context, accessToken string,
	groupId int64) ([]api.GroupAttributeResponse, error) {

	return c.attributes, nil
}

func renderGroupPage(t *testing.T, client *groupBindApiClient, target, page string,
	handler func(*mocks_handlerhelpers.HttpHelper) http.HandlerFunc) map[string]interface{} {

	t.Helper()

	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", page).Maybe()

	req := handlertest.Request(http.MethodGet, target,
		handlertest.WithAccessToken(),
		handlertest.WithRouteParam("groupId", "4"),
	)

	handler(httpHelper).ServeHTTP(httptest.NewRecorder(), req)

	return handlertest.Bind(t, httpHelper)
}

// The attributes page names the group in its heading and lists the attributes below it. Both come
// off responses now, and the group's three scalars are three separate keys on the bind rather than
// one object, so a field lost between the two is lost silently.
func TestHandleAdminGroupAttributesGet_BindsTheGroupAndItsAttributes(t *testing.T) {
	client := &groupBindApiClient{
		group: &api.GroupResponse{Id: 4, GroupIdentifier: "admins", Description: "Administrators"},
		attributes: []api.GroupAttributeResponse{
			{Id: 7, Key: "tier", Value: "gold", GroupId: 4, IncludeInIdToken: true},
			{Id: 8, Key: "region", Value: "br", GroupId: 4},
		},
	}

	bind := renderGroupPage(t, client, "/admin/groups/4/attributes", "/admin_groups_attributes.html",
		func(h *mocks_handlerhelpers.HttpHelper) http.HandlerFunc {
			return HandleAdminGroupAttributesGet(h, client)
		})

	assert.Equal(t, int64(4), bind["groupId"])
	assert.Equal(t, "admins", bind["groupIdentifier"])
	assert.Equal(t, "Administrators", bind["description"])

	attributes, ok := bind["attributes"].([]api.GroupAttributeResponse)
	require.True(t, ok, "the bind carries no attributes at all")
	require.Len(t, attributes, 2)
	assert.Equal(t, "tier", attributes[0].Key)
	assert.Equal(t, "gold", attributes[0].Value)
	assert.Equal(t, "region", attributes[1].Key)
}

// The member count reaches this page off the response's own field, where it used to arrive as a
// second return value beside the group. The page is a confirmation screen for a destructive
// action, so a count that silently became zero tells the administrator the group is empty.
func TestHandleAdminGroupDeleteGet_BindsTheMemberCountOffTheResponse(t *testing.T) {
	client := &groupBindApiClient{
		group: &api.GroupResponse{Id: 4, GroupIdentifier: "admins", Description: "Administrators",
			MemberCount: 17},
	}

	bind := renderGroupPage(t, client, "/admin/groups/4/delete", "/admin_groups_delete.html",
		func(h *mocks_handlerhelpers.HttpHelper) http.HandlerFunc {
			return HandleAdminGroupDeleteGet(h, client)
		})

	assert.Equal(t, 17, bind["countOfUsers"],
		"the count comes off the group the API answered, not from a second return that no longer exists")

	group, ok := bind["group"].(*api.GroupResponse)
	require.True(t, ok, "the bind carries no group at all")
	assert.Equal(t, "admins", group.GroupIdentifier)
	assert.Equal(t, "Administrators", group.Description)
}

// The settings page's two checkboxes. They are booleans, so a bind that lost one renders it
// unchecked, which is a valid-looking page asserting the opposite of the truth.
func TestHandleAdminGroupSettingsGet_BindsBothTokenFlags(t *testing.T) {
	client := &groupBindApiClient{
		group: &api.GroupResponse{Id: 4, GroupIdentifier: "admins", Description: "Administrators",
			IncludeInIdToken: true, IncludeInAccessToken: false},
	}

	httpSession := mocks_sessionstore.NewStore(t)
	httpSession.On("Get", mock.Anything, constants.AdminConsoleSessionName).
		Return(&sessionstore.Session{Values: map[string]any{}}, nil)

	bind := renderGroupPage(t, client, "/admin/groups/4/settings", "/admin_groups_settings.html",
		func(h *mocks_handlerhelpers.HttpHelper) http.HandlerFunc {
			return HandleAdminGroupSettingsGet(h, httpSession, client)
		})

	assert.Equal(t, int64(4), bind["groupId"])
	assert.Equal(t, "admins", bind["groupIdentifier"])
	assert.Equal(t, "Administrators", bind["description"])
	assert.Equal(t, true, bind["includeInIdToken"])
	assert.Equal(t, false, bind["includeInAccessToken"])
}
