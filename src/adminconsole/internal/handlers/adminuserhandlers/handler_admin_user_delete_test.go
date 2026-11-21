package adminuserhandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
)

// deleteUserAPIClient answers the two reads the confirmation page performs, and records the
// groups call so a handler that stopped making it is caught by more than an empty bind.
type deleteUserAPIClient struct {
	user       *api.UserResponse
	groups     []api.GroupResponse
	askedGroup []int64
}

func (c *deleteUserAPIClient) GetUserByID(_ context.Context, accessToken string, userID int64) (*api.UserResponse, error) {
	return c.user, nil
}

func (c *deleteUserAPIClient) GetUserGroups(_ context.Context, accessToken string,
	userID int64) (*api.UserResponse, []api.GroupResponse, error) {

	c.askedGroup = append(c.askedGroup, userID)
	return c.user, c.groups, nil
}

// The rest of the ports deleteUserAPIClient is passed to, which no test here reaches.

func (*deleteUserAPIClient) DeleteUser(context.Context, string, int64) error {
	panic("unexpected call to DeleteUser")
}

func renderUserDelete(t *testing.T, client *deleteUserAPIClient) map[string]interface{} {
	t.Helper()

	httpHelper := handlersmocks.NewHTTPHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_users_delete.html").Maybe()

	req := handlertest.Request(http.MethodGet, "/admin/users/7/delete",
		handlertest.WithAccessToken(),
		handlertest.WithPathValue("userId", "7"),
	)

	HandleDeleteGet(httpHelper, client).ServeHTTP(httptest.NewRecorder(), req)

	return handlertest.Bind(t, httpHelper)
}

// The memberships row on this page read .user.Groups, which GET /api/v1/admin/users/{id} has never
// populated, so a confirmation screen for a destructive action told every administrator the user
// belonged to no groups. The handler loads them now, from the endpoint that serves them (#350).
func TestHandleDeleteGet_BindsTheMembershipsTheDeletionWillDiscard(t *testing.T) {
	client := &deleteUserAPIClient{
		user: &api.UserResponse{ID: 7, Email: "someone@example.com"},
		groups: []api.GroupResponse{
			{ID: 2, GroupIdentifier: "admins"},
			{ID: 3, GroupIdentifier: "site-viewers"},
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
func TestHandleDeleteGet_AUserInNoGroupsBindsNone(t *testing.T) {
	bind := renderUserDelete(t, &deleteUserAPIClient{user: &api.UserResponse{ID: 7}})

	groups, ok := bind["groups"].([]api.GroupResponse)
	require.True(t, ok, "the bind carries no groups key")
	assert.Empty(t, groups)
}

// The full name is assembled beside the user rather than read off it: the response is a DTO with
// no methods, and a template cannot reach a package function. A bind that stopped carrying it
// leaves the page's "full name" row silently empty rather than failing (#350 decision 10).
func TestHandleDeleteGet_BindsTheAssembledFullName(t *testing.T) {
	testCases := []struct {
		name  string
		user  *api.UserResponse
		wants string
	}{
		{"all three parts", &api.UserResponse{ID: 7, GivenName: "Jane", MiddleName: "Q", FamilyName: "Doe"}, "Jane Q Doe"},
		{"no middle name", &api.UserResponse{ID: 7, GivenName: "Jane", FamilyName: "Doe"}, "Jane Doe"},
		{"family name only", &api.UserResponse{ID: 7, FamilyName: "Doe"}, "Doe"},
		{"no name at all", &api.UserResponse{ID: 7}, ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			bind := renderUserDelete(t, &deleteUserAPIClient{user: tc.user})
			assert.Equal(t, tc.wants, bind["userFullName"])
		})
	}
}

// The deletion asks for the user's email typed, as the client, group and resource deletions ask for
// the identifier: a blank field and another address are each refused on the page, with nothing
// deleted, which deleteUserAPIClient's DeleteUser would panic on (#617).
func TestHandleDeletePost_RefusesAnEmailThatIsNotTheUsers(t *testing.T) {
	for _, typed := range []string{"", "  ", "someone-else@example.com"} {
		t.Run(typed, func(t *testing.T) {
			client := &deleteUserAPIClient{user: &api.UserResponse{ID: 7, Email: "someone@example.com"}}
			httpHelper := handlersmocks.NewHTTPHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_users_delete.html").Once()

			req := handlertest.Request(http.MethodPost, "/admin/users/7/delete",
				handlertest.WithAccessToken(),
				handlertest.WithPathValue("userId", "7"),
				handlertest.WithForm(url.Values{"email": {typed}}),
			)
			rec := httptest.NewRecorder()

			HandleDeletePost(httpHelper, client, "https://console.example.com").ServeHTTP(rec, req)

			assert.Empty(t, rec.Header().Get("Location"), "no redirect to the list: the user was not deleted")
			bind := handlertest.Bind(t, httpHelper)
			assert.NotEmpty(t, bind["error"])
			assert.Equal(t, client.user, bind["user"])
		})
	}
}
