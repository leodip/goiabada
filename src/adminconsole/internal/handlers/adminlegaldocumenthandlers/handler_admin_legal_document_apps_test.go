package adminlegaldocumenthandlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/i18n"
)

// A legal document's Applies to tab (#622): all apps or the apps ticked, the admin console's own
// client never offered, the list as the page drew it sent with every save, and a document left
// with no apps said to apply to nobody.

// threeClients are the apps the instance holds, out of order, with the admin console's own.
func threeClients() []api.ClientResponse {
	return []api.ClientResponse{
		{Id: 4, ClientIdentifier: "shop", Description: "The shop"},
		{Id: 1, ClientIdentifier: builtin.AdminConsoleClientIdentifier, IsSystemLevelClient: true},
		{Id: 6, ClientIdentifier: "blog"},
	}
}

func appsRequest(method string, form url.Values) *http.Request {
	opts := []handlertest.Option{handlertest.WithAccessToken(), handlertest.WithPathValue("legalDocumentId", "7")}
	if form != nil {
		opts = append(opts, handlertest.WithForm(form))
	}
	return handlertest.Request(method, "/admin/legal-documents/7/apps", opts...)
}

func TestHandleAppsGet_OffersEveryAppButTheAdminConsoleAndMarksTheSelected(t *testing.T) {
	httpHelper := pageHelper(t, "/admin_legal_documents_apps.html")
	detail := publishedTerms()
	detail.LegalDocument.AppliesTo = "selected_apps"
	detail.LegalDocument.ClientIds = []int64{4}
	fake := &fakeLegalDocumentsAPI{detail: detail, clients: threeClients()}

	HandleAppsGet(httpHelper, newSessionStore(t), fake).ServeHTTP(httptest.NewRecorder(), appsRequest(http.MethodGet, nil))

	bind := handlertest.Bind(t, httpHelper)
	assert.Equal(t, []int64{7}, fake.readIds)
	assert.Equal(t, false, bind["allApps"])
	assert.Equal(t, []appChoice{
		{Id: 6, Identifier: "blog"},
		{Id: 4, Identifier: "shop", Description: "The shop", Selected: true},
	}, bind["apps"], "every app but the admin console's own, by identifier")
	assert.Equal(t, []int64{4}, bind["expectedClientIds"], "the list as drawn goes back with the save")
	assert.Equal(t, false, bind["noApps"])
}

func TestHandleAppsGet_ADocumentForAllApps(t *testing.T) {
	httpHelper := pageHelper(t, "/admin_legal_documents_apps.html")
	detail := publishedTerms()
	detail.LegalDocument.AppliesTo = "all_apps"
	detail.LegalDocument.ClientIds = []int64{}
	fake := &fakeLegalDocumentsAPI{detail: detail, clients: threeClients()}

	HandleAppsGet(httpHelper, newSessionStore(t), fake).ServeHTTP(httptest.NewRecorder(), appsRequest(http.MethodGet, nil))

	bind := handlertest.Bind(t, httpHelper)
	assert.Equal(t, true, bind["allApps"])
	assert.Equal(t, []int64{}, bind["expectedClientIds"])
	assert.Equal(t, false, bind["noApps"], "all apps is not a document with no apps")
	for _, app := range bind["apps"].([]appChoice) {
		assert.False(t, app.Selected, "nothing is ticked for all apps")
	}
}

// Selected apps with none listed applies to nobody, which the tab says.
func TestHandleAppsGet_SelectedAppsWithNoneListedIsFlagged(t *testing.T) {
	httpHelper := pageHelper(t, "/admin_legal_documents_apps.html")
	detail := publishedTerms()
	detail.LegalDocument.AppliesTo = "selected_apps"
	detail.LegalDocument.ClientIds = []int64{}
	fake := &fakeLegalDocumentsAPI{detail: detail, clients: threeClients()}

	HandleAppsGet(httpHelper, newSessionStore(t), fake).ServeHTTP(httptest.NewRecorder(), appsRequest(http.MethodGet, nil))

	assert.Equal(t, true, handlertest.Bind(t, httpHelper)["noApps"])
}

func TestHandleAppsPost_SavesTheAppsTickedAndSaysSo(t *testing.T) {
	store := newSessionStore(t)
	detail := publishedTerms()
	detail.LegalDocument.AppliesTo = "selected_apps"
	detail.LegalDocument.ClientIds = []int64{4}
	fake := &fakeLegalDocumentsAPI{detail: detail, clients: threeClients()}
	rec := httptest.NewRecorder()

	HandleAppsPost(render.New(nil, nil), store, fake, consoleBaseURL).ServeHTTP(rec, appsRequest(http.MethodPost, url.Values{
		"appliesTo": {"selected_apps"}, "clientId": {"6", "4"}, "expectedClientId": {"4"},
	}))

	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
	assert.Equal(t, consoleBaseURL+"/admin/legal-documents/7/apps", rec.Header().Get("Location"))
	assert.Equal(t, int64(7), fake.appsSavedId)
	require.NotNil(t, fake.appsSaved)
	assert.Equal(t, api.UpdateLegalDocumentAppsRequest{AppliesTo: "selected_apps", ClientIds: []int64{6, 4},
		ExpectedClientIds: []int64{4}}, *fake.appsSaved)

	httpHelper := pageHelper(t, "/admin_legal_documents_apps.html")
	HandleAppsGet(httpHelper, store, fake).ServeHTTP(httptest.NewRecorder(), withCookies(appsRequest(http.MethodGet, nil), rec))
	assert.Equal(t, true, handlertest.Bind(t, httpHelper)["appsSaved"])
}

// All apps sends no app, whatever boxes were left ticked, and the empty list loaded is sent as [],
// never left out.
func TestHandleAppsPost_AllAppsSendsNoAppAndAnEmptyLoadedListAsEmpty(t *testing.T) {
	fake := &fakeLegalDocumentsAPI{detail: publishedTerms(), clients: threeClients()}
	rec := httptest.NewRecorder()

	HandleAppsPost(render.New(nil, nil), newSessionStore(t), fake, consoleBaseURL).ServeHTTP(rec, appsRequest(http.MethodPost, url.Values{
		"appliesTo": {"all_apps"}, "clientId": {"6"},
	}))

	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
	require.NotNil(t, fake.appsSaved)
	assert.Equal(t, "all_apps", fake.appsSaved.AppliesTo)
	assert.Equal(t, []int64{}, fake.appsSaved.ClientIds)
	assert.Equal(t, []int64{}, fake.appsSaved.ExpectedClientIds)
}

// A refused save is drawn again with what was chosen, and the API's sentence.
func TestHandleAppsPost_ARefusalKeepsWhatWasChosen(t *testing.T) {
	for name, err := range map[string]error{
		"a refusal":        refusal(i18n.ErrCodeLegalDocumentAdminConsoleClient, "the API's sentence"),
		"an outdated page": &apiclient.APIError{Code: "CONCURRENT_UPDATE", Message: "the API's sentence", StatusCode: http.StatusConflict},
	} {
		t.Run(name, func(t *testing.T) {
			httpHelper := pageHelper(t, "/admin_legal_documents_apps.html")
			detail := publishedTerms()
			detail.LegalDocument.AppliesTo = "all_apps"
			detail.LegalDocument.ClientIds = []int64{}
			fake := &fakeLegalDocumentsAPI{detail: detail, clients: threeClients(), writeErr: err}

			HandleAppsPost(httpHelper, newSessionStore(t), fake, consoleBaseURL).ServeHTTP(httptest.NewRecorder(),
				appsRequest(http.MethodPost, url.Values{"appliesTo": {"selected_apps"}, "clientId": {"6"}, "expectedClientId": {}}))

			bind := handlertest.Bind(t, httpHelper)
			assert.Equal(t, "the API's sentence", bind["error"])
			assert.Equal(t, false, bind["allApps"], "the choice made is kept")
			assert.Equal(t, []appChoice{
				{Id: 6, Identifier: "blog", Selected: true},
				{Id: 4, Identifier: "shop", Description: "The shop"},
			}, bind["apps"], "and so are the boxes ticked")
			assert.Equal(t, []int64{}, bind["expectedClientIds"], "the list as stored, to retry against")
		})
	}
}
