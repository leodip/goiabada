package adminuserhandlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
	mocks_handler_helpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
)

// deleteUserApiClient answers the two reads the confirmation page performs, and records the
// groups call so a handler that stopped making it is caught by more than an empty bind.
type deleteUserApiClient struct {
	apiclient.ApiClient
	user       *api.UserResponse
	groups     []api.GroupResponse
	askedGroup []int64
}

func (c *deleteUserApiClient) GetUserById(accessToken string, userId int64) (*api.UserResponse, error) {
	return c.user, nil
}

func (c *deleteUserApiClient) GetUserGroups(accessToken string,
	userId int64) (*api.UserResponse, []api.GroupResponse, error) {

	c.askedGroup = append(c.askedGroup, userId)
	return c.user, c.groups, nil
}

func renderUserDelete(t *testing.T, client *deleteUserApiClient) map[string]interface{} {
	t.Helper()

	httpHelper := mocks_handler_helpers.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_users_delete.html").Maybe()

	req := handlertest.Request(http.MethodGet, "/admin/users/7/delete",
		handlertest.WithAccessToken(),
		handlertest.WithRouteParam("userId", "7"),
	)

	HandleAdminUserDeleteGet(httpHelper, client).ServeHTTP(httptest.NewRecorder(), req)

	return handlertest.Bind(t, httpHelper)
}

// The memberships row on this page read .user.Groups, which GET /api/v1/admin/users/{id} has never
// populated, so a confirmation screen for a destructive action told every administrator the user
// belonged to no groups. The handler loads them now, from the endpoint that serves them (#350).
func TestHandleAdminUserDeleteGet_BindsTheMembershipsTheDeletionWillDiscard(t *testing.T) {
	client := &deleteUserApiClient{
		user: &api.UserResponse{Id: 7, Email: "someone@example.com"},
		groups: []api.GroupResponse{
			{Id: 2, GroupIdentifier: "admins"},
			{Id: 3, GroupIdentifier: "site-viewers"},
		},
	}

	bind := renderUserDelete(t, client)

	assert.Equal(t, []int64{7}, client.askedGroup,
		"the page has to ask for the memberships; nothing else on this response carries them")

	groups, ok := bind["groups"].([]api.GroupResponse)
	require.True(t, ok, "the bind carries no groups at all")
	require.Len(t, groups, 2)
	assert.Equal(t, "admins", groups[0].GroupIdentifier)
	assert.Equal(t, "site-viewers", groups[1].GroupIdentifier)
}

// A user in no groups still renders, and the row's "none" arm is what it renders. This is the case
// that was indistinguishable from the defect above before the fix.
func TestHandleAdminUserDeleteGet_AUserInNoGroupsBindsNone(t *testing.T) {
	bind := renderUserDelete(t, &deleteUserApiClient{user: &api.UserResponse{Id: 7}})

	groups, ok := bind["groups"].([]api.GroupResponse)
	require.True(t, ok, "the bind carries no groups key")
	assert.Empty(t, groups)
}

// The full name is assembled beside the user rather than read off it: the response is a DTO with
// no methods, and a template cannot reach a package function. A bind that stopped carrying it
// leaves the page's "full name" row silently empty rather than failing (#350 decision 10).
func TestHandleAdminUserDeleteGet_BindsTheAssembledFullName(t *testing.T) {
	testCases := []struct {
		name  string
		user  *api.UserResponse
		wants string
	}{
		{"all three parts", &api.UserResponse{Id: 7, GivenName: "Jane", MiddleName: "Q", FamilyName: "Doe"}, "Jane Q Doe"},
		{"no middle name", &api.UserResponse{Id: 7, GivenName: "Jane", FamilyName: "Doe"}, "Jane Doe"},
		{"family name only", &api.UserResponse{Id: 7, FamilyName: "Doe"}, "Doe"},
		{"no name at all", &api.UserResponse{Id: 7}, ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			bind := renderUserDelete(t, &deleteUserApiClient{user: tc.user})
			assert.Equal(t, tc.wants, bind["userFullName"])
		})
	}
}
