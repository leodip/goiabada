package integration

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A legal document's Applies to over HTTP (#622): all apps, the default, or selected apps saved
// whole as a list save is; the admin console's own client never chosen; a document left with no
// apps still selected apps; and a client's documents read with the clients-read scopes.

// appForLegalDocuments creates a client of the test's own, deleted when the test ends.
func appForLegalDocuments(t *testing.T) *record.Client {
	t.Helper()
	client := createTestClient(t, "legal-app-"+strings.ToLower(fake.LetterN(10)))
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })
	return client
}

// setApps sends a document's Applies to and answers the status and body.
func setApps(t *testing.T, accessToken string, id int64, appliesTo string, clientIds, expected []int64) (int, map[string]any) {
	t.Helper()
	status, body, _ := legalCall(t, accessToken, http.MethodPut, legalPath(id, "/apps"), map[string]any{
		"appliesTo": appliesTo, "clientIds": clientIds, "expectedClientIds": expected,
	})
	return status, body
}

// appliesTo reads a document's Applies to and its client ids over the API.
func appliesTo(t *testing.T, accessToken string, id int64) (string, []any) {
	t.Helper()
	status, body, _ := legalCall(t, accessToken, http.MethodGet, legalPath(id, ""), nil)
	require.Equal(t, http.StatusOK, status, "%v", body)
	doc := body["legalDocument"].(map[string]any)
	return doc["appliesTo"].(string), doc["clientIds"].([]any)
}

func ids(values ...int64) []any {
	out := []any{}
	for _, v := range values {
		out = append(out, float64(v))
	}
	return out
}

func TestAPILegalDocumentApps_AllAppsByDefaultThenSelectedAppsAndBack(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	id := createLegalDocumentOverAPI(t, accessToken, "must_accept", legalShortName("apps"), "Terms", "Text")
	first, second := appForLegalDocuments(t), appForLegalDocuments(t)

	all, clients := appliesTo(t, accessToken, id)
	assert.Equal(t, "all_apps", all, "a new document applies to all apps")
	assert.Equal(t, []any{}, clients)

	status, body := setApps(t, accessToken, id, "selected_apps", []int64{first.Id, second.Id}, []int64{})
	require.Equal(t, http.StatusOK, status, "%v", body)
	assert.Equal(t, "selected_apps", body["legalDocument"].(map[string]any)["appliesTo"])
	all, clients = appliesTo(t, accessToken, id)
	assert.Equal(t, "selected_apps", all)
	assert.ElementsMatch(t, ids(first.Id, second.Id), clients)

	// The list shows it too, which is where a document with no apps is flagged.
	status, list, _ := legalCall(t, accessToken, http.MethodGet, legalDocumentsPath, nil)
	require.Equal(t, http.StatusOK, status)
	var listed map[string]any
	for _, d := range list["legalDocuments"].([]any) {
		if int64(d.(map[string]any)["id"].(float64)) == id {
			listed = d.(map[string]any)
		}
	}
	require.NotNil(t, listed, "the document is listed")
	assert.Equal(t, "selected_apps", listed["appliesTo"])
	assert.ElementsMatch(t, ids(first.Id, second.Id), listed["clientIds"])

	status, body = setApps(t, accessToken, id, "selected_apps", []int64{second.Id}, []int64{second.Id, first.Id})
	require.Equal(t, http.StatusOK, status, "%v", body)
	_, clients = appliesTo(t, accessToken, id)
	assert.Equal(t, ids(second.Id), clients, "the app left out is removed")

	// A save from a page read before the last one is refused, with nothing written.
	status, body = setApps(t, accessToken, id, "selected_apps", []int64{first.Id}, []int64{first.Id, second.Id})
	assert.Equal(t, http.StatusConflict, status)
	assert.Equal(t, "CONCURRENT_UPDATE", body["error_code"])
	_, clients = appliesTo(t, accessToken, id)
	assert.Equal(t, ids(second.Id), clients, "the refused save wrote nothing")

	status, body = setApps(t, accessToken, id, "all_apps", []int64{}, []int64{second.Id})
	require.Equal(t, http.StatusOK, status, "%v", body)
	all, clients = appliesTo(t, accessToken, id)
	assert.Equal(t, "all_apps", all)
	assert.Equal(t, []any{}, clients, "all apps lists none")
}

func TestAPILegalDocumentApps_Refusals(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	id := createLegalDocumentOverAPI(t, accessToken, "must_accept", legalShortName("apps-refused"), "Terms", "Text")
	app := appForLegalDocuments(t)
	adminConsole, err := database.GetClientByClientIdentifier(context.Background(), nil, builtin.AdminConsoleClientIdentifier)
	require.NoError(t, err)
	require.NotNil(t, adminConsole)

	cases := []struct {
		name      string
		appliesTo string
		clientIds []int64
		status    int
		code      string
	}{
		{"the admin console's own client", "selected_apps", []int64{app.Id, adminConsole.Id}, http.StatusBadRequest, "handler.legal_document.admin_console_client"},
		{"an app that does not exist", "selected_apps", []int64{app.Id + 1_000_000}, http.StatusNotFound, "NOT_FOUND"},
		{"apps with all apps", "all_apps", []int64{app.Id}, http.StatusBadRequest, "handler.legal_document.apps_with_all_apps"},
		{"an unknown applies to", "every_app", []int64{}, http.StatusBadRequest, "handler.legal_document.applies_to_invalid"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			status, body := setApps(t, accessToken, id, c.appliesTo, c.clientIds, []int64{})
			assert.Equal(t, c.status, status)
			assert.Equal(t, c.code, body["error_code"])
			all, clients := appliesTo(t, accessToken, id)
			assert.Equal(t, "all_apps", all, "nothing was written")
			assert.Equal(t, []any{}, clients)
		})
	}

	status, body, _ := legalCall(t, accessToken, http.MethodPut, legalPath(id, "/apps"), map[string]any{
		"appliesTo": "selected_apps", "clientIds": []int64{app.Id},
	})
	assert.Equal(t, http.StatusBadRequest, status, "the list as loaded is required")
	assert.Equal(t, "VALIDATION_ERROR", body["error_code"])

	status, body = setApps(t, accessToken, id+1_000_000, "all_apps", []int64{}, []int64{})
	assert.Equal(t, http.StatusNotFound, status)
	assert.Equal(t, "NOT_FOUND", body["error_code"])
}

// Deleting an app leaves its documents on their other apps; a document whose only app is deleted
// is flagged by applying to nobody, never to all apps.
func TestAPILegalDocumentApps_DeletingAnAppLeavesTheDocumentOnItsOtherApps(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	both := createLegalDocumentOverAPI(t, accessToken, "must_accept", legalShortName("apps-both"), "Terms", "Text")
	only := createLegalDocumentOverAPI(t, accessToken, "for_information", legalShortName("apps-only"), "Privacy", "Text")
	deleted, kept := appForLegalDocuments(t), appForLegalDocuments(t)
	status, body := setApps(t, accessToken, both, "selected_apps", []int64{deleted.Id, kept.Id}, []int64{})
	require.Equal(t, http.StatusOK, status, "%v", body)
	status, body = setApps(t, accessToken, only, "selected_apps", []int64{deleted.Id}, []int64{})
	require.Equal(t, http.StatusOK, status, "%v", body)

	status, body, _ = legalCall(t, accessToken, http.MethodDelete, fmt.Sprintf("/api/v1/admin/clients/%d", deleted.Id), nil)
	require.Equal(t, http.StatusOK, status, "%v", body)

	all, clients := appliesTo(t, accessToken, both)
	assert.Equal(t, "selected_apps", all)
	assert.Equal(t, ids(kept.Id), clients, "the document keeps its other app")
	all, clients = appliesTo(t, accessToken, only)
	assert.Equal(t, "selected_apps", all, "a document left with no apps is still selected apps")
	assert.Equal(t, []any{}, clients, "and lists none, so it applies to nobody")
}

func clientLegalDocumentsPath(clientId int64) string {
	return fmt.Sprintf("/api/v1/admin/clients/%d/legal-documents", clientId)
}

// clientDocumentIds reads a client's documents and answers their ids, failing on anything but 200.
func clientDocumentIds(t *testing.T, accessToken string, clientId int64) map[int64]map[string]any {
	t.Helper()
	status, body, _ := legalCall(t, accessToken, http.MethodGet, clientLegalDocumentsPath(clientId), nil)
	require.Equal(t, http.StatusOK, status, "%v", body)
	assert.InDelta(t, clientId, body["client"].(map[string]any)["id"], 0)
	out := map[int64]map[string]any{}
	for _, d := range body["legalDocuments"].([]any) {
		doc := d.(map[string]any)
		out[int64(doc["id"].(float64))] = doc
	}
	return out
}

func TestAPIClientLegalDocuments_TheDocumentsThatApplyToTheClient(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	app, other := appForLegalDocuments(t), appForLegalDocuments(t)

	// Every document here but the all-apps one is selected apps; the all-apps one is never
	// published, so it asks nothing of other tests' sign-ins.
	allApps := createLegalDocumentOverAPI(t, accessToken, "for_information", legalShortName("client-all"), "Privacy", "Text")
	listing := createLegalDocumentOverAPI(t, accessToken, "must_accept", legalShortName("client-listing"), "Terms", "Text")
	notListing := createLegalDocumentOverAPI(t, accessToken, "must_accept", legalShortName("client-other"), "Terms", "Text")
	retired := createLegalDocumentOverAPI(t, accessToken, "must_accept", legalShortName("client-retired"), "Terms", "Text")
	for doc, clientId := range map[int64]int64{listing: app.Id, notListing: other.Id, retired: app.Id} {
		status, body := setApps(t, accessToken, doc, "selected_apps", []int64{clientId}, []int64{})
		require.Equal(t, http.StatusOK, status, "%v", body)
	}
	status, body, _ := legalCall(t, accessToken, http.MethodPost, legalPath(retired, "/publish"), nil)
	require.Equal(t, http.StatusOK, status, "%v", body)
	status, body, _ = legalCall(t, accessToken, http.MethodPost, legalPath(retired, "/retire"), nil)
	require.Equal(t, http.StatusOK, status, "%v", body)

	docs := clientDocumentIds(t, accessToken, app.Id)
	require.Contains(t, docs, allApps, "a document for all apps applies to the client")
	require.Contains(t, docs, listing, "a document listing the client applies to it")
	assert.NotContains(t, docs, notListing, "a document listing another app does not")
	assert.NotContains(t, docs, retired, "a retired document applies to no app")
	assert.Equal(t, "all_apps", docs[allApps]["appliesTo"])
	assert.Equal(t, "selected_apps", docs[listing]["appliesTo"])
	assert.Equal(t, ids(app.Id), docs[listing]["clientIds"])

	otherDocs := clientDocumentIds(t, accessToken, other.Id)
	assert.Contains(t, otherDocs, notListing)
	assert.Contains(t, otherDocs, allApps)
	assert.NotContains(t, otherDocs, listing)

	status, body, _ = legalCall(t, accessToken, http.MethodGet, clientLegalDocumentsPath(app.Id+1_000_000), nil)
	assert.Equal(t, http.StatusNotFound, status)
	assert.Equal(t, "NOT_FOUND", body["error_code"])
}

// Choosing a document's apps is a settings change; reading a client's documents is a clients read
// (#622 decision 6).
func TestAPILegalDocumentApps_TheScopesOfEachRoute(t *testing.T) {
	manageToken, _ := createAdminClientWithToken(t)
	id := createLegalDocumentOverAPI(t, manageToken, "must_accept", legalShortName("apps-scopes"), "Terms", "Text")
	app := appForLegalDocuments(t)

	for _, c := range []struct {
		permission string
		write      bool
		read       int
	}{
		{builtin.AdminReadPermissionIdentifier, false, http.StatusOK},
		{builtin.ManageUsersPermissionIdentifier, false, http.StatusForbidden},
		{builtin.ManageClientsPermissionIdentifier, false, http.StatusOK},
		{builtin.ManageSettingsPermissionIdentifier, true, http.StatusForbidden},
	} {
		t.Run(c.permission, func(t *testing.T) {
			token, client := createClientWithGranularScope(t, c.permission)
			t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })

			status, body := setApps(t, token, id, "all_apps", []int64{}, []int64{})
			if c.write {
				assert.Equal(t, http.StatusOK, status, "%v", body)
			} else {
				assert.Equal(t, http.StatusForbidden, status)
				assert.Equal(t, "INSUFFICIENT_SCOPE", body["error_code"])
			}

			status, body, _ = legalCall(t, token, http.MethodGet, clientLegalDocumentsPath(app.Id), nil)
			assert.Equal(t, c.read, status, "%v", body)
		})
	}
}

func TestAPILegalDocumentApps_ChangesAreAudited(t *testing.T) {
	requireDatabaseAuditLogs(t)
	accessToken, caller := createAdminClientWithToken(t)
	shortName := legalShortName("apps-audit")
	id := createLegalDocumentOverAPI(t, accessToken, "must_accept", shortName, "Terms", "Text")
	first, second := appForLegalDocuments(t), appForLegalDocuments(t)

	_, _, requestId := legalCall(t, accessToken, http.MethodPut, legalPath(id, "/apps"), map[string]any{
		"appliesTo": "selected_apps", "clientIds": []int64{first.Id, second.Id}, "expectedClientIds": []int64{},
	})
	assert.Equal(t, []map[string]any{{
		"legal_document_id": float64(id), "short_name": shortName, "applies_to": "selected_apps",
		"added_client_ids": ids(first.Id, second.Id), "removed_client_ids": []any{}, "logged_in_user": caller.ClientIdentifier,
	}}, auditRows(t, accessToken, "updated_legal_document_apps", requestId))

	_, _, requestId = legalCall(t, accessToken, http.MethodPut, legalPath(id, "/apps"), map[string]any{
		"appliesTo": "all_apps", "clientIds": []int64{}, "expectedClientIds": []int64{first.Id, second.Id},
	})
	rows := auditRows(t, accessToken, "updated_legal_document_apps", requestId)
	require.Len(t, rows, 1)
	assert.Equal(t, "all_apps", rows[0]["applies_to"])
	assert.Equal(t, []any{}, rows[0]["added_client_ids"])
	assert.ElementsMatch(t, ids(first.Id, second.Id), rows[0]["removed_client_ids"])

	// A refused change writes nothing.
	_, _, requestId = legalCall(t, accessToken, http.MethodPut, legalPath(id, "/apps"), map[string]any{
		"appliesTo": "selected_apps", "clientIds": []int64{first.Id}, "expectedClientIds": []int64{first.Id},
	})
	assert.Empty(t, auditRows(t, accessToken, "updated_legal_document_apps", requestId))
}
