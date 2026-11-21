package adminclienthandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	handlersmocks "github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
)

// A client's Legal documents tab (#622): the documents that apply to the client, read only, out of
// one read of the client's.

type fakeClientLegalDocumentsAPI struct {
	answer  *api.GetClientLegalDocumentsResponse
	err     error
	readIDs []int64
}

func (f *fakeClientLegalDocumentsAPI) GetClientLegalDocuments(_ context.Context, _ string, clientID int64) (*api.GetClientLegalDocumentsResponse, error) {
	f.readIDs = append(f.readIDs, clientID)
	return f.answer, f.err
}

func TestHandleLegalDocumentsGet_ListsTheDocumentsThatApplyToTheClient(t *testing.T) {
	httpHelper := handlersmocks.NewHTTPHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_clients_legal_documents.html").Once()
	docs := []api.LegalDocumentResponse{
		{ID: 7, ShortName: "privacy", AppliesTo: "all_apps", ClientIDs: []int64{}},
		{ID: 8, ShortName: "shop-terms", AppliesTo: "selected_apps", ClientIDs: []int64{3}},
	}
	fake := &fakeClientLegalDocumentsAPI{answer: &api.GetClientLegalDocumentsResponse{
		Client: api.ClientResponse{ID: 3, ClientIdentifier: "shop"}, LegalDocuments: docs}}

	HandleLegalDocumentsGet(httpHelper, fake).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodGet, "/admin/clients/3/legal-documents", handlertest.WithAccessToken(),
			handlertest.WithPathValue("clientId", "3")))

	bind := handlertest.Bind(t, httpHelper)
	assert.Equal(t, []int64{3}, fake.readIDs)
	assert.Equal(t, &api.ClientResponse{ID: 3, ClientIdentifier: "shop"}, bind["client"])
	assert.Equal(t, docs, bind["legalDocuments"])
}

func TestHandleLegalDocumentsGet_AnUnknownClientIsNotFound(t *testing.T) {
	httpHelper := handlersmocks.NewHTTPHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	httpHelper.On("NotFound", mock.Anything, mock.Anything).Once()
	fake := &fakeClientLegalDocumentsAPI{err: &apiclient.APIError{Code: "NOT_FOUND", Message: "Client not found", StatusCode: http.StatusNotFound}}

	HandleLegalDocumentsGet(httpHelper, fake).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodGet, "/admin/clients/3/legal-documents", handlertest.WithAccessToken(),
			handlertest.WithPathValue("clientId", "3")))

	assert.Equal(t, []int64{3}, fake.readIDs)
}

func TestHandleLegalDocumentsGet_AnAddressThatIsNotAnIDIsNotFound(t *testing.T) {
	httpHelper := handlersmocks.NewHTTPHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	httpHelper.On("NotFound", mock.Anything, mock.Anything).Once()
	fake := &fakeClientLegalDocumentsAPI{}

	HandleLegalDocumentsGet(httpHelper, fake).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodGet, "/admin/clients/x/legal-documents", handlertest.WithAccessToken(),
			handlertest.WithPathValue("clientId", "x")))

	assert.Empty(t, fake.readIDs)
}
