package apihandlers

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// A legal document's Applies to (#622), one rule per test, through the handlers with the generated
// database mock: the apps a document lists are saved whole as a list save is, never the admin
// console's own client, and a client's documents are the ones not retired that apply to all apps or
// list it.

func links(documentId int64, clientIds ...int64) []record.LegalDocumentClient {
	out := []record.LegalDocumentClient{}
	for i, clientId := range clientIds {
		out = append(out, record.LegalDocumentClient{Id: int64(900 + i), LegalDocumentId: documentId, ClientId: clientId})
	}
	return out
}

func appClient(id int64) *record.Client {
	return &record.Client{Id: id, ClientIdentifier: "app-" + string(rune('a'+id))}
}

// expectClients answers each id with an app of its own.
func expectClients(database *datamocks.Database, ids ...int64) {
	for _, id := range ids {
		database.On("GetClientById", mock.Anything, mock.Anything, id).Return(appClient(id), nil).Maybe()
	}
}

// --- PUT /legal-documents/{id}/apps -------------------------------------------------------------

func TestLegalDocumentApps_SelectedAppsAreSavedWholeAndAudited(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	datamocks.ExpectRunInTransaction(database, legalTx)
	database.On("AcquireLegalDocumentRow", mock.Anything, legalTx, int64(5)).Return(nil).Once()
	doc := draftDocument(5)
	doc.AppliesToAllApps = true
	database.On("GetLegalDocumentById", mock.Anything, mock.Anything, int64(5)).Return(doc, nil)
	expectClients(database, 1, 2)
	database.On("GetLegalDocumentClientsByLegalDocumentId", mock.Anything, legalTx, int64(5)).Return(links(5, 1), nil).Once()
	var created []int64
	database.On("CreateLegalDocumentClient", mock.Anything, legalTx, mock.Anything).
		Run(func(args mock.Arguments) {
			link := args.Get(2).(*record.LegalDocumentClient)
			assert.Equal(t, int64(5), link.LegalDocumentId)
			created = append(created, link.ClientId)
		}).Return(nil)
	database.On("UpdateLegalDocumentAppliesToAllApps", mock.Anything, legalTx, int64(5), false).Return(nil).Once()
	database.On("GetLegalDocumentVersionsByLegalDocumentId", mock.Anything, mock.Anything, int64(5)).Return(publishedVersions(5, 1), nil)
	database.On("GetLegalDocumentClientsByLegalDocumentId", mock.Anything, mock.Anything, int64(5)).Return(links(5, 1, 2), nil)
	auditLogger.On("Log", mock.Anything, audit.EventUpdatedLegalDocumentApps, map[string]interface{}{
		"legal_document_id":  int64(5),
		"short_name":         "terms",
		"applies_to":         "selected_apps",
		"added_client_ids":   []int64{2},
		"removed_client_ids": []int64{},
		"logged_in_user":     legalCaller,
	}).Once()

	status, body := serveLegal(HandleLegalDocumentAppsPut(database, auditLogger), legalRequest(t, http.MethodPut, map[string]any{
		"appliesTo": "selected_apps", "clientIds": []int64{1, 2, 2}, "expectedClientIds": []int64{1},
	}, "id", "5"))

	require.Equal(t, http.StatusOK, status, "%v", body)
	assert.Equal(t, []int64{2}, created, "the app not yet listed is added once, the one listed kept")
	database.AssertNotCalled(t, "DeleteLegalDocumentClient", mock.Anything, mock.Anything, mock.Anything)
	document := body["legalDocument"].(map[string]any)
	assert.Equal(t, "selected_apps", document["appliesTo"])
	assert.Equal(t, []any{float64(1), float64(2)}, document["clientIds"], "the apps as read back")
}

func TestLegalDocumentApps_AllAppsClearsTheList(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	datamocks.ExpectRunInTransaction(database, legalTx)
	database.On("AcquireLegalDocumentRow", mock.Anything, legalTx, int64(5)).Return(nil).Once()
	doc := draftDocument(5)
	doc.AppliesToAllApps = false
	database.On("GetLegalDocumentById", mock.Anything, mock.Anything, int64(5)).Return(doc, nil)
	stored := links(5, 1, 2)
	database.On("GetLegalDocumentClientsByLegalDocumentId", mock.Anything, legalTx, int64(5)).Return(stored, nil).Once()
	var deleted []int64
	database.On("DeleteLegalDocumentClient", mock.Anything, legalTx, mock.Anything).
		Run(func(args mock.Arguments) { deleted = append(deleted, args.Get(2).(int64)) }).Return(nil)
	database.On("UpdateLegalDocumentAppliesToAllApps", mock.Anything, legalTx, int64(5), true).Return(nil).Once()
	database.On("GetLegalDocumentVersionsByLegalDocumentId", mock.Anything, mock.Anything, int64(5)).Return(nil, nil)
	database.On("GetLegalDocumentClientsByLegalDocumentId", mock.Anything, mock.Anything, int64(5)).Return(nil, nil)
	auditLogger.On("Log", mock.Anything, audit.EventUpdatedLegalDocumentApps, map[string]interface{}{
		"legal_document_id":  int64(5),
		"short_name":         "terms",
		"applies_to":         "all_apps",
		"added_client_ids":   []int64{},
		"removed_client_ids": []int64{1, 2},
		"logged_in_user":     legalCaller,
	}).Once()

	status, body := serveLegal(HandleLegalDocumentAppsPut(database, auditLogger), legalRequest(t, http.MethodPut, map[string]any{
		"appliesTo": "all_apps", "clientIds": []int64{}, "expectedClientIds": []int64{2, 1},
	}, "id", "5"))

	require.Equal(t, http.StatusOK, status, "%v", body)
	assert.ElementsMatch(t, []int64{stored[0].Id, stored[1].Id}, deleted, "every listed app is removed")
	database.AssertNotCalled(t, "CreateLegalDocumentClient", mock.Anything, mock.Anything, mock.Anything)
	document := body["legalDocument"].(map[string]any)
	assert.Equal(t, "all_apps", document["appliesTo"])
	assert.Equal(t, []any{}, document["clientIds"])
}

// Selected apps with an empty list is saved as it is: the document applies to nobody, and never
// becomes all apps.
func TestLegalDocumentApps_SelectedAppsWithNoAppIsKeptAsSelected(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	datamocks.ExpectRunInTransaction(database, legalTx)
	database.On("AcquireLegalDocumentRow", mock.Anything, legalTx, int64(5)).Return(nil).Once()
	doc := draftDocument(5)
	doc.AppliesToAllApps = false
	database.On("GetLegalDocumentById", mock.Anything, mock.Anything, int64(5)).Return(doc, nil)
	database.On("GetLegalDocumentClientsByLegalDocumentId", mock.Anything, legalTx, int64(5)).Return(links(5, 3), nil).Once()
	database.On("DeleteLegalDocumentClient", mock.Anything, legalTx, int64(900)).Return(nil).Once()
	database.On("GetLegalDocumentVersionsByLegalDocumentId", mock.Anything, mock.Anything, int64(5)).Return(nil, nil)
	database.On("GetLegalDocumentClientsByLegalDocumentId", mock.Anything, mock.Anything, int64(5)).Return(nil, nil)
	auditLogger.On("Log", mock.Anything, audit.EventUpdatedLegalDocumentApps, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["applies_to"] == "selected_apps"
	})).Once()

	status, body := serveLegal(HandleLegalDocumentAppsPut(database, auditLogger), legalRequest(t, http.MethodPut, map[string]any{
		"appliesTo": "selected_apps", "clientIds": []int64{}, "expectedClientIds": []int64{3},
	}, "id", "5"))

	require.Equal(t, http.StatusOK, status, "%v", body)
	database.AssertNotCalled(t, "UpdateLegalDocumentAppliesToAllApps", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	document := body["legalDocument"].(map[string]any)
	assert.Equal(t, "selected_apps", document["appliesTo"], "no app left is still selected apps")
	assert.Equal(t, []any{}, document["clientIds"])
}

func TestLegalDocumentApps_Refusals(t *testing.T) {
	adminConsole := &record.Client{Id: 9, ClientIdentifier: builtin.AdminConsoleClientIdentifier}
	cases := []struct {
		name    string
		body    map[string]any
		retired bool
		status  int
		code    string
	}{
		{"an unknown applies to", map[string]any{"appliesTo": "some_apps", "clientIds": []int64{}, "expectedClientIds": []int64{}},
			false, http.StatusBadRequest, "handler.legal_document.applies_to_invalid"},
		{"no applies to", map[string]any{"clientIds": []int64{1}, "expectedClientIds": []int64{}},
			false, http.StatusBadRequest, "handler.legal_document.applies_to_invalid"},
		{"apps with all apps", map[string]any{"appliesTo": "all_apps", "clientIds": []int64{1}, "expectedClientIds": []int64{}},
			false, http.StatusBadRequest, "handler.legal_document.apps_with_all_apps"},
		{"the admin console's own client", map[string]any{"appliesTo": "selected_apps", "clientIds": []int64{1, 9}, "expectedClientIds": []int64{}},
			false, http.StatusBadRequest, "handler.legal_document.admin_console_client"},
		{"an app that does not exist", map[string]any{"appliesTo": "selected_apps", "clientIds": []int64{1, 404}, "expectedClientIds": []int64{}},
			false, http.StatusNotFound, "NOT_FOUND"},
		{"no expected list", map[string]any{"appliesTo": "selected_apps", "clientIds": []int64{1}},
			false, http.StatusBadRequest, "VALIDATION_ERROR"},
		{"a retired document", map[string]any{"appliesTo": "selected_apps", "clientIds": []int64{1}, "expectedClientIds": []int64{}},
			true, http.StatusBadRequest, "handler.legal_document.retired"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			doc := draftDocument(5)
			if c.retired {
				doc.RetiredAt = sql.NullTime{Time: time.Now(), Valid: true}
			}
			database.On("GetLegalDocumentById", mock.Anything, mock.Anything, int64(5)).Return(doc, nil).Maybe()
			expectClients(database, 1)
			database.On("GetClientById", mock.Anything, mock.Anything, int64(9)).Return(adminConsole, nil).Maybe()
			database.On("GetClientById", mock.Anything, mock.Anything, int64(404)).Return(nil, nil).Maybe()

			status, body := serveLegal(HandleLegalDocumentAppsPut(database, handlersmocks.NewAuditLogger(t)),
				legalRequest(t, http.MethodPut, c.body, "id", "5"))

			assert.Equal(t, c.status, status)
			assert.Equal(t, c.code, errorCode(body))
			database.AssertNotCalled(t, "RunInTransaction", mock.Anything, mock.Anything)
			database.AssertNotCalled(t, "CreateLegalDocumentClient", mock.Anything, mock.Anything, mock.Anything)
			database.AssertNotCalled(t, "UpdateLegalDocumentAppliesToAllApps", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

func TestLegalDocumentApps_AnUnknownDocumentIs404(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetLegalDocumentById", mock.Anything, mock.Anything, int64(5)).Return(nil, nil).Once()

	status, body := serveLegal(HandleLegalDocumentAppsPut(database, handlersmocks.NewAuditLogger(t)), legalRequest(t, http.MethodPut,
		map[string]any{"appliesTo": "all_apps", "clientIds": []int64{}, "expectedClientIds": []int64{}}, "id", "5"))

	assert.Equal(t, http.StatusNotFound, status)
	assert.Equal(t, "NOT_FOUND", errorCode(body))
}

func TestLegalDocumentApps_AnUnreadableBodyIsABadRequest(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetLegalDocumentById", mock.Anything, mock.Anything, int64(5)).Return(draftDocument(5), nil).Once()
	req := legalRequest(t, http.MethodPut, nil, "id", "5")

	status, body := serveLegal(HandleLegalDocumentAppsPut(database, handlersmocks.NewAuditLogger(t)), req)

	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "INVALID_REQUEST_BODY", errorCode(body))
}

// A list read before another save changed it is refused, with nothing written.
func TestLegalDocumentApps_AnOutdatedListIsAConflict(t *testing.T) {
	database := datamocks.NewDatabase(t)
	datamocks.ExpectRunInTransaction(database, legalTx)
	database.On("AcquireLegalDocumentRow", mock.Anything, legalTx, int64(5)).Return(nil).Once()
	database.On("GetLegalDocumentById", mock.Anything, mock.Anything, int64(5)).Return(draftDocument(5), nil)
	expectClients(database, 1)
	database.On("GetLegalDocumentClientsByLegalDocumentId", mock.Anything, legalTx, int64(5)).Return(links(5, 2), nil).Once()

	status, body := serveLegal(HandleLegalDocumentAppsPut(database, handlersmocks.NewAuditLogger(t)), legalRequest(t, http.MethodPut,
		map[string]any{"appliesTo": "selected_apps", "clientIds": []int64{1}, "expectedClientIds": []int64{}}, "id", "5"))

	assert.Equal(t, http.StatusConflict, status)
	assert.Equal(t, "CONCURRENT_UPDATE", errorCode(body))
	database.AssertNotCalled(t, "CreateLegalDocumentClient", mock.Anything, mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "DeleteLegalDocumentClient", mock.Anything, mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "UpdateLegalDocumentAppliesToAllApps", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// Two saves adding the same app meet the pair's unique key: the loser is the same 409.
func TestLegalDocumentApps_AnAppAddedMeanwhileIsAConflict(t *testing.T) {
	database := datamocks.NewDatabase(t)
	datamocks.ExpectRunInTransaction(database, legalTx)
	database.On("AcquireLegalDocumentRow", mock.Anything, legalTx, int64(5)).Return(nil).Once()
	database.On("GetLegalDocumentById", mock.Anything, mock.Anything, int64(5)).Return(draftDocument(5), nil)
	expectClients(database, 1)
	database.On("GetLegalDocumentClientsByLegalDocumentId", mock.Anything, legalTx, int64(5)).Return(nil, nil).Once()
	database.On("CreateLegalDocumentClient", mock.Anything, legalTx, mock.Anything).
		Return(errs.Errorf("insert: %w", data.ErrUniqueViolation)).Once()

	status, body := serveLegal(HandleLegalDocumentAppsPut(database, handlersmocks.NewAuditLogger(t)), legalRequest(t, http.MethodPut,
		map[string]any{"appliesTo": "selected_apps", "clientIds": []int64{1}, "expectedClientIds": []int64{}}, "id", "5"))

	assert.Equal(t, http.StatusConflict, status)
	assert.Equal(t, "CONCURRENT_UPDATE", errorCode(body))
}

// A document retired after the request read it is refused by the read inside the transaction.
func TestLegalDocumentApps_ADocumentRetiredMeanwhileIsRefused(t *testing.T) {
	database := datamocks.NewDatabase(t)
	datamocks.ExpectRunInTransaction(database, legalTx)
	database.On("AcquireLegalDocumentRow", mock.Anything, legalTx, int64(5)).Return(nil).Once()
	database.On("GetLegalDocumentById", mock.Anything, (*sql.Tx)(nil), int64(5)).Return(draftDocument(5), nil).Once()
	retired := draftDocument(5)
	retired.RetiredAt = sql.NullTime{Time: time.Now(), Valid: true}
	database.On("GetLegalDocumentById", mock.Anything, legalTx, int64(5)).Return(retired, nil).Once()
	expectClients(database, 1)
	database.On("GetLegalDocumentClientsByLegalDocumentId", mock.Anything, legalTx, int64(5)).Return(nil, nil).Maybe()

	status, body := serveLegal(HandleLegalDocumentAppsPut(database, handlersmocks.NewAuditLogger(t)), legalRequest(t, http.MethodPut,
		map[string]any{"appliesTo": "selected_apps", "clientIds": []int64{1}, "expectedClientIds": []int64{}}, "id", "5"))

	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "handler.legal_document.retired", errorCode(body))
	database.AssertNotCalled(t, "CreateLegalDocumentClient", mock.Anything, mock.Anything, mock.Anything)
}

// --- GET /clients/{id}/legal-documents ----------------------------------------------------------

func clientDocumentsRequest(t *testing.T, id string) *http.Request {
	t.Helper()
	return legalRequest(t, http.MethodGet, nil, "id", id)
}

func TestClientLegalDocuments_TheDocumentsThatApplyToTheClient(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetClientById", mock.Anything, mock.Anything, int64(4)).Return(appClient(4), nil).Once()

	allApps := draftDocument(1)
	allApps.ShortName, allApps.AppliesToAllApps = "privacy", true
	listing := draftDocument(2)
	listing.ShortName = "app-terms"
	notListing := draftDocument(3)
	notListing.ShortName = "other-terms"
	retiredAll := draftDocument(6)
	retiredAll.ShortName, retiredAll.AppliesToAllApps = "old-privacy", true
	retiredAll.RetiredAt = sql.NullTime{Time: time.Now(), Valid: true}
	retiredListing := draftDocument(7)
	retiredListing.ShortName = "old-terms"
	retiredListing.RetiredAt = sql.NullTime{Time: time.Now(), Valid: true}
	nobody := draftDocument(8)
	nobody.ShortName = "nobody"
	database.On("GetAllLegalDocuments", mock.Anything, mock.Anything).
		Return([]record.LegalDocument{*allApps, *listing, *notListing, *retiredAll, *retiredListing, *nobody}, nil).Once()
	database.On("GetLegalDocumentClientsByClientId", mock.Anything, mock.Anything, int64(4)).
		Return([]record.LegalDocumentClient{{Id: 70, LegalDocumentId: 2, ClientId: 4}, {Id: 71, LegalDocumentId: 7, ClientId: 4}}, nil).Once()
	database.On("GetLegalDocumentVersionsByLegalDocumentId", mock.Anything, mock.Anything, int64(1)).Return(publishedVersions(1, 2), nil)
	database.On("GetLegalDocumentVersionsByLegalDocumentId", mock.Anything, mock.Anything, int64(2)).Return(nil, nil)
	database.On("GetLegalDocumentClientsByLegalDocumentId", mock.Anything, mock.Anything, int64(1)).Return(nil, nil)
	database.On("GetLegalDocumentClientsByLegalDocumentId", mock.Anything, mock.Anything, int64(2)).Return(links(2, 4, 11), nil)

	status, body := serveLegal(HandleClientLegalDocumentsGet(database), clientDocumentsRequest(t, "4"))

	require.Equal(t, http.StatusOK, status, "%v", body)
	assert.InDelta(t, 4, body["client"].(map[string]any)["id"], 0)
	list := body["legalDocuments"].([]any)
	require.Len(t, list, 2, "the all-apps document and the one listing the client, neither retired: %v", list)
	first, second := list[0].(map[string]any), list[1].(map[string]any)
	assert.Equal(t, "privacy", first["shortName"])
	assert.Equal(t, "all_apps", first["appliesTo"])
	assert.InDelta(t, 2, first["currentVersion"], 0)
	assert.Equal(t, "app-terms", second["shortName"])
	assert.Equal(t, "selected_apps", second["appliesTo"])
	assert.Equal(t, []any{float64(4), float64(11)}, second["clientIds"])
	assert.InDelta(t, 0, second["currentVersion"], 0, "a document not yet published is listed with its state")
}

func TestClientLegalDocuments_NoneIsAnEmptyList(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetClientById", mock.Anything, mock.Anything, int64(4)).Return(appClient(4), nil).Once()
	database.On("GetAllLegalDocuments", mock.Anything, mock.Anything).Return(nil, nil).Once()
	database.On("GetLegalDocumentClientsByClientId", mock.Anything, mock.Anything, int64(4)).Return(nil, nil).Maybe()

	rr := httptest.NewRecorder()
	HandleClientLegalDocumentsGet(database).ServeHTTP(rr, clientDocumentsRequest(t, "4"))

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `"legalDocuments":[]`)
}

func TestClientLegalDocuments_AnUnknownClientIs404(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetClientById", mock.Anything, mock.Anything, int64(4)).Return(nil, nil).Once()

	status, body := serveLegal(HandleClientLegalDocumentsGet(database), clientDocumentsRequest(t, "4"))

	assert.Equal(t, http.StatusNotFound, status)
	assert.Equal(t, "NOT_FOUND", errorCode(body))
}

func TestClientLegalDocuments_AnInvalidIdIsABadRequest(t *testing.T) {
	database := datamocks.NewDatabase(t)

	status, body := serveLegal(HandleClientLegalDocumentsGet(database), clientDocumentsRequest(t, "abc"))

	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "VALIDATION_ERROR", errorCode(body))
}
