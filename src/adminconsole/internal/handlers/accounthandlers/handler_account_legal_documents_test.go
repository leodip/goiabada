package accounthandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
)

// accountLegalDocumentsApiClient answers the one read My Account's Legal documents page performs,
// with the signed-in user's token.
type accountLegalDocumentsApiClient struct {
	acceptances []api.LegalDocumentAcceptanceResponse
	tokens      []string
}

func (c *accountLegalDocumentsApiClient) GetAccountLegalDocumentAcceptances(_ context.Context,
	accessToken string) ([]api.LegalDocumentAcceptanceResponse, error) {
	c.tokens = append(c.tokens, accessToken)
	return c.acceptances, nil
}

// The page binds the user's acceptances as the API answers them, read with the user's own token.
func TestHandleLegalDocumentsGet_BindsTheUsersAcceptances(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/account_legal_documents.html").Maybe()

	url := "https://auth.example/legal/terms/versions/2"
	acceptances := []api.LegalDocumentAcceptanceResponse{
		{Id: 3, LegalDocumentId: 7, ShortName: "terms", Version: 2, Title: "Terms of use", URL: &url},
	}
	apiClient := &accountLegalDocumentsApiClient{acceptances: acceptances}

	req := handlertest.Request(http.MethodGet, "/account/legal-documents", handlertest.WithAccessToken())
	HandleLegalDocumentsGet(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), req)

	bind := handlertest.Bind(t, httpHelper)
	assert.Equal(t, []string{handlertest.AccessToken}, apiClient.tokens)
	got, ok := bind["acceptances"].([]api.LegalDocumentAcceptanceResponse)
	require.True(t, ok, "the bind carries no acceptances")
	assert.Equal(t, acceptances, got)
}
