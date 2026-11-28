package adminuserhandlers

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
)

// namedUserAPIClient answers the details GET with the user it holds.
type namedUserAPIClient struct {
	flashStubAPIClient
	user *api.UserResponse
}

func (c namedUserAPIClient) GetUserByID(context.Context, string, int64) (*api.UserResponse, error) {
	return c.user, nil
}

// The details page binds the full name core/personname writes: a name in kanji family name first,
// with no space, and a Latin name as before (#662 decisions 1 and 2).
func TestHandleDetailsGet_BindsTheFullName(t *testing.T) {
	for _, tc := range []struct {
		name  string
		user  *api.UserResponse
		wants string
	}{
		{"a name in kanji", &api.UserResponse{ID: 7, GivenName: "太郎", FamilyName: "山田"}, "山田太郎"},
		{"a Latin name", &api.UserResponse{ID: 7, GivenName: "Jane", MiddleName: "Q", FamilyName: "Doe"}, "Jane Q Doe"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHTTPHelper(t)
			handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_users_details.html").Once()

			HandleDetailsGet(httpHelper, newFlashTestStore(), namedUserAPIClient{user: tc.user}).
				ServeHTTP(httptest.NewRecorder(), detailsRequest())

			assert.Equal(t, tc.wants, handlertest.Bind(t, httpHelper)["userFullName"])
		})
	}
}
