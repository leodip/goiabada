package adminuserhandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
)

// userLegalDocumentsApiClient answers the two reads the user's Legal documents tab performs, and
// records which user's acceptances were read.
type userLegalDocumentsApiClient struct {
	user        *api.UserResponse
	acceptances []api.LegalDocumentAcceptanceResponse

	readFor []int64
}

func (c *userLegalDocumentsApiClient) GetUserById(_ context.Context, _ string, _ int64) (*api.UserResponse, error) {
	return c.user, nil
}

func (c *userLegalDocumentsApiClient) GetUserLegalDocumentAcceptances(_ context.Context, accessToken string,
	userId int64) ([]api.LegalDocumentAcceptanceResponse, error) {
	if accessToken != handlertest.AccessToken {
		panic("the tab must forward the signed-in administrator's token")
	}
	c.readFor = append(c.readFor, userId)
	return c.acceptances, nil
}

// The tab binds the user's acceptances as the API answers them, with the list's page and search.
func TestHandleLegalDocumentsGet_BindsTheUsersAcceptances(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_users_legal_documents.html").Maybe()

	acceptances := []api.LegalDocumentAcceptanceResponse{
		{Id: 4, LegalDocumentId: 8, ShortName: "house", Version: 1, Title: "House rules", Retired: true},
		{Id: 3, LegalDocumentId: 7, ShortName: "terms", Version: 2, Title: "Terms of use"},
	}
	apiClient := &userLegalDocumentsApiClient{user: &api.UserResponse{Id: 7, Email: "someone@example.com"}, acceptances: acceptances}

	req := handlertest.Request(http.MethodGet, "/admin/users/7/legal-documents?page=2&query=some",
		handlertest.WithAccessToken(), handlertest.WithPathValue("userId", "7"))
	HandleLegalDocumentsGet(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), req)

	bind := handlertest.Bind(t, httpHelper)
	assert.Equal(t, []int64{7}, apiClient.readFor)
	got, ok := bind["acceptances"].([]api.LegalDocumentAcceptanceResponse)
	require.True(t, ok, "the bind carries no acceptances")
	assert.Equal(t, acceptances, got)
	assert.Equal(t, int64(7), bind["user"].(*api.UserResponse).Id)
	assert.Equal(t, "2", bind["page"])
	assert.Equal(t, "some", bind["query"])
}

func TestHandleLegalDocumentsGet_NotFound(t *testing.T) {
	for _, tc := range []struct {
		name   string
		userId string
		user   *api.UserResponse
	}{
		{name: "an address that is not an id", userId: "abc"},
		{name: "a user that does not exist", userId: "7"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			httpHelper.On("NotFound", mock.Anything, mock.Anything).Return().Once()
			apiClient := &userLegalDocumentsApiClient{user: tc.user}

			req := handlertest.Request(http.MethodGet, "/admin/users/"+tc.userId+"/legal-documents",
				handlertest.WithAccessToken(), handlertest.WithPathValue("userId", tc.userId))
			HandleLegalDocumentsGet(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), req)

			assert.Empty(t, apiClient.readFor, "no acceptances are read for a user that is not there")
		})
	}
}
