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

// userLegalDocumentsAPIClient answers the two reads the user's Legal documents tab performs, and
// records which user's acceptances were read.
type userLegalDocumentsAPIClient struct {
	user        *api.UserResponse
	acceptances []api.LegalDocumentAcceptanceResponse

	readFor []int64
}

func (c *userLegalDocumentsAPIClient) GetUserByID(_ context.Context, _ string, _ int64) (*api.UserResponse, error) {
	return c.user, nil
}

func (c *userLegalDocumentsAPIClient) GetUserLegalDocumentAcceptances(_ context.Context, accessToken string,
	userID int64) ([]api.LegalDocumentAcceptanceResponse, error) {
	if accessToken != handlertest.AccessToken {
		panic("the tab must forward the signed-in administrator's token")
	}
	c.readFor = append(c.readFor, userID)
	return c.acceptances, nil
}

// The tab binds the user's acceptances as the API answers them, with the list's page and search.
func TestHandleLegalDocumentsGet_BindsTheUsersAcceptances(t *testing.T) {
	httpHelper := handlersmocks.NewHTTPHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_users_legal_documents.html").Maybe()

	acceptances := []api.LegalDocumentAcceptanceResponse{
		{ID: 4, LegalDocumentID: 8, ShortName: "house", Version: 1, Title: "House rules", Retired: true},
		{ID: 3, LegalDocumentID: 7, ShortName: "terms", Version: 2, Title: "Terms of use"},
	}
	apiClient := &userLegalDocumentsAPIClient{user: &api.UserResponse{ID: 7, Email: "someone@example.com"}, acceptances: acceptances}

	req := handlertest.Request(http.MethodGet, "/admin/users/7/legal-documents?page=2&query=some",
		handlertest.WithAccessToken(), handlertest.WithPathValue("userId", "7"))
	HandleLegalDocumentsGet(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), req)

	bind := handlertest.Bind(t, httpHelper)
	assert.Equal(t, []int64{7}, apiClient.readFor)
	got, ok := bind["acceptances"].([]api.LegalDocumentAcceptanceResponse)
	require.True(t, ok, "the bind carries no acceptances")
	assert.Equal(t, acceptances, got)
	assert.Equal(t, int64(7), bind["user"].(*api.UserResponse).ID)
	assert.Equal(t, "2", bind["page"])
	assert.Equal(t, "some", bind["query"])
}

func TestHandleLegalDocumentsGet_NotFound(t *testing.T) {
	for _, tc := range []struct {
		name   string
		userID string
		user   *api.UserResponse
	}{
		{name: "an address that is not an id", userID: "abc"},
		{name: "a user that does not exist", userID: "7"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHTTPHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			httpHelper.On("NotFound", mock.Anything, mock.Anything).Return().Once()
			apiClient := &userLegalDocumentsAPIClient{user: tc.user}

			req := handlertest.Request(http.MethodGet, "/admin/users/"+tc.userID+"/legal-documents",
				handlertest.WithAccessToken(), handlertest.WithPathValue("userId", tc.userID))
			HandleLegalDocumentsGet(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), req)

			assert.Empty(t, apiClient.readFor, "no acceptances are read for a user that is not there")
		})
	}
}
