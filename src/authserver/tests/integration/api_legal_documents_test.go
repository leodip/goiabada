package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The admin API's legal documents over HTTP (#622 decisions 1, 2, 4, 5 and 6): a document is
// drafted and published as numbered versions that never change, retired and restored, deleted only
// when never published, and reached with the settings domain's scopes.
//
// Legal documents are instance-wide, so every document a test publishes is retired when the test
// ends: a published must-accept document would otherwise be asked of every sign-in once the
// acceptance step reads them.

const legalDocumentsPath = "/api/v1/admin/legal-documents"

// legalShortName is a short name no other test uses.
func legalShortName(prefix string) string {
	return prefix + "-" + strings.ToLower(fake.LetterN(10))
}

// retireWhenDone retires the document when the test ends, whatever it left it as.
func retireWhenDone(t *testing.T, id int64) {
	t.Cleanup(func() {
		doc, err := database.GetLegalDocumentById(context.Background(), nil, id)
		if err != nil || doc == nil || doc.RetiredAt.Valid {
			return
		}
		versions, err := database.GetLegalDocumentVersionsByLegalDocumentId(context.Background(), nil, id)
		if err != nil {
			return
		}
		if len(versions) == 0 {
			_ = database.DeleteLegalDocument(context.Background(), nil, id)
			return
		}
		doc.RetiredAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}
		_ = database.UpdateLegalDocument(context.Background(), nil, doc)
	})
}

// legalCall sends one admin API request and decodes its JSON answer.
func legalCall(t *testing.T, accessToken, method, path string, body any) (int, map[string]any, string) {
	t.Helper()
	resp, requestId := sendAdmin(t, accessToken, method, path, body)
	defer func() { _ = resp.Body.Close() }()
	var answer map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&answer)
	return resp.StatusCode, answer, requestId
}

// createLegalDocumentOverAPI creates a document and returns its id.
func createLegalDocumentOverAPI(t *testing.T, accessToken, kind, shortName, title, markdown string) int64 {
	t.Helper()
	status, body, _ := legalCall(t, accessToken, http.MethodPost, legalDocumentsPath, map[string]any{
		"kind": kind, "shortName": shortName, "title": title, "markdown": markdown,
	})
	require.Equal(t, http.StatusCreated, status, "create: %v", body)
	id := int64(body["legalDocument"].(map[string]any)["id"].(float64))
	retireWhenDone(t, id)
	return id
}

func legalPath(id int64, rest string) string {
	return fmt.Sprintf("%s/%d%s", legalDocumentsPath, id, rest)
}

func TestAPILegalDocuments_DraftPublishAndVersions(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	draftName := legalShortName("terms-draft")
	id := createLegalDocumentOverAPI(t, accessToken, "must_accept", draftName, "Terms of use", "# Terms\n\nFirst text.")

	// Read back: a draft, no version yet, named by the draft's title.
	status, body, _ := legalCall(t, accessToken, http.MethodGet, legalPath(id, ""), nil)
	require.Equal(t, http.StatusOK, status)
	doc := body["legalDocument"].(map[string]any)
	assert.Equal(t, draftName, doc["shortName"])
	assert.Equal(t, "must_accept", doc["kind"])
	assert.Equal(t, "Terms of use", doc["title"])
	assert.InDelta(t, 0, doc["currentVersion"], 0)
	assert.Nil(t, doc["publishedAt"])
	assert.Equal(t, true, doc["hasDraft"])
	assert.Equal(t, map[string]any{"title": "Terms of use", "markdown": "# Terms\n\nFirst text."}, body["draft"])
	assert.Equal(t, []any{}, body["versions"])

	// The short name changes freely until the first publish.
	shortName := legalShortName("terms")
	status, body, _ = legalCall(t, accessToken, http.MethodPut, legalPath(id, "/draft"), map[string]any{
		"shortName": shortName, "title": "Terms of use", "markdown": "# Terms\n\nFirst text, fixed.",
	})
	require.Equal(t, http.StatusOK, status, "%v", body)
	assert.Equal(t, shortName, body["legalDocument"].(map[string]any)["shortName"])

	// Publish freezes the draft as version 1 and clears it.
	status, body, _ = legalCall(t, accessToken, http.MethodPost, legalPath(id, "/publish"), nil)
	require.Equal(t, http.StatusOK, status, "%v", body)
	doc = body["legalDocument"].(map[string]any)
	assert.InDelta(t, 1, doc["currentVersion"], 0)
	assert.NotNil(t, doc["publishedAt"])
	assert.Equal(t, false, doc["hasDraft"])
	assert.Nil(t, body["draft"])
	require.Len(t, body["versions"], 1)

	// A second publish with no draft is refused.
	status, body, _ = legalCall(t, accessToken, http.MethodPost, legalPath(id, "/publish"), nil)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "handler.legal_document.no_draft", body["error_code"])

	// From now on the short name is fixed; the same one, or none, is fine.
	status, body, _ = legalCall(t, accessToken, http.MethodPut, legalPath(id, "/draft"), map[string]any{
		"shortName": legalShortName("renamed"), "title": "Terms of use", "markdown": "x",
	})
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "handler.legal_document.short_name_fixed", body["error_code"])
	status, body, _ = legalCall(t, accessToken, http.MethodPut, legalPath(id, "/draft"), map[string]any{
		"title": "Terms of use, revised", "markdown": "Second text.",
	})
	require.Equal(t, http.StatusOK, status, "%v", body)
	assert.Equal(t, shortName, body["legalDocument"].(map[string]any)["shortName"])
	assert.InDelta(t, 1, body["legalDocument"].(map[string]any)["currentVersion"], 0, "a draft is not a version")

	status, body, _ = legalCall(t, accessToken, http.MethodPost, legalPath(id, "/publish"), nil)
	require.Equal(t, http.StatusOK, status, "%v", body)
	assert.InDelta(t, 2, body["legalDocument"].(map[string]any)["currentVersion"], 0)
	assert.Equal(t, "Terms of use, revised", body["legalDocument"].(map[string]any)["title"])

	// Every published version reads back as it was published.
	status, body, _ = legalCall(t, accessToken, http.MethodGet, legalPath(id, "/versions/1"), nil)
	require.Equal(t, http.StatusOK, status)
	version := body["version"].(map[string]any)
	assert.InDelta(t, 1, version["version"], 0)
	assert.Equal(t, "Terms of use", version["title"])
	assert.Equal(t, "# Terms\n\nFirst text, fixed.", version["markdown"])
	assert.InDelta(t, 2, body["legalDocument"].(map[string]any)["currentVersion"], 0)
	status, body, _ = legalCall(t, accessToken, http.MethodGet, legalPath(id, "/versions/2"), nil)
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, "Second text.", body["version"].(map[string]any)["markdown"])
	status, _, _ = legalCall(t, accessToken, http.MethodGet, legalPath(id, "/versions/3"), nil)
	assert.Equal(t, http.StatusNotFound, status)

	stored, err := database.GetLegalDocumentVersionsByLegalDocumentId(context.Background(), nil, id)
	require.NoError(t, err)
	require.Len(t, stored, 2)
	assert.Equal(t, "# Terms\n\nFirst text, fixed.", stored[0].Markdown, "version 1 is never rewritten")

	// The list names it by its current version.
	status, body, _ = legalCall(t, accessToken, http.MethodGet, legalDocumentsPath, nil)
	require.Equal(t, http.StatusOK, status)
	var listed map[string]any
	for _, entry := range body["legalDocuments"].([]any) {
		if entry.(map[string]any)["id"] == float64(id) {
			listed = entry.(map[string]any)
		}
	}
	require.NotNil(t, listed, "the document is listed")
	assert.Equal(t, "Terms of use, revised", listed["title"])
	assert.InDelta(t, 2, listed["currentVersion"], 0)
}

func TestAPILegalDocuments_RetireRestoreAndDelete(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	published := createLegalDocumentOverAPI(t, accessToken, "for_information", legalShortName("privacy"), "Privacy notice", "We keep little.")
	status, body, _ := legalCall(t, accessToken, http.MethodPost, legalPath(published, "/publish"), nil)
	require.Equal(t, http.StatusOK, status, "%v", body)

	status, body, _ = legalCall(t, accessToken, http.MethodDelete, legalPath(published, ""), nil)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "handler.legal_document.published_not_deleted", body["error_code"])

	status, body, _ = legalCall(t, accessToken, http.MethodPost, legalPath(published, "/retire"), nil)
	require.Equal(t, http.StatusOK, status, "%v", body)
	assert.Equal(t, true, body["legalDocument"].(map[string]any)["retired"])
	assert.NotNil(t, body["legalDocument"].(map[string]any)["retiredAt"])

	// A retired document is read only, and its versions stay readable.
	status, body, _ = legalCall(t, accessToken, http.MethodPut, legalPath(published, "/draft"), map[string]any{"title": "x", "markdown": "y"})
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "handler.legal_document.retired", body["error_code"])
	status, body, _ = legalCall(t, accessToken, http.MethodPost, legalPath(published, "/retire"), nil)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "handler.legal_document.already_retired", body["error_code"])
	status, body, _ = legalCall(t, accessToken, http.MethodGet, legalPath(published, "/versions/1"), nil)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "We keep little.", body["version"].(map[string]any)["markdown"])

	status, body, _ = legalCall(t, accessToken, http.MethodPost, legalPath(published, "/restore"), nil)
	require.Equal(t, http.StatusOK, status, "%v", body)
	assert.Equal(t, false, body["legalDocument"].(map[string]any)["retired"])
	assert.InDelta(t, 1, body["legalDocument"].(map[string]any)["currentVersion"], 0, "restored with its current version")
	status, body, _ = legalCall(t, accessToken, http.MethodPost, legalPath(published, "/restore"), nil)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "handler.legal_document.not_retired", body["error_code"])

	// A never-published document cannot be retired, and is deleted instead.
	draft := createLegalDocumentOverAPI(t, accessToken, "must_accept", legalShortName("draft"), "Draft terms", "Not yet.")
	status, body, _ = legalCall(t, accessToken, http.MethodPost, legalPath(draft, "/retire"), nil)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "handler.legal_document.not_published", body["error_code"])
	status, body, _ = legalCall(t, accessToken, http.MethodDelete, legalPath(draft, ""), nil)
	require.Equal(t, http.StatusOK, status, "%v", body)
	status, _, _ = legalCall(t, accessToken, http.MethodGet, legalPath(draft, ""), nil)
	assert.Equal(t, http.StatusNotFound, status)
}

func TestAPILegalDocuments_ShortNamesAreUniqueAndWellFormed(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	taken := legalShortName("taken")
	createLegalDocumentOverAPI(t, accessToken, "must_accept", taken, "Terms", "Text")

	status, body, _ := legalCall(t, accessToken, http.MethodPost, legalDocumentsPath, map[string]any{
		"kind": "for_information", "shortName": taken, "title": "Privacy", "markdown": "Text",
	})
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "handler.legal_document.short_name_in_use", body["error_code"])

	other := createLegalDocumentOverAPI(t, accessToken, "for_information", legalShortName("other"), "Privacy", "Text")
	status, body, _ = legalCall(t, accessToken, http.MethodPut, legalPath(other, "/draft"), map[string]any{
		"shortName": taken, "title": "Privacy", "markdown": "Text",
	})
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "handler.legal_document.short_name_in_use", body["error_code"])

	for shortName, code := range map[string]string{
		"Terms":                 "handler.legal_document.short_name_invalid",
		"terms of use":          "handler.legal_document.short_name_invalid",
		"-terms":                "handler.legal_document.short_name_invalid",
		strings.Repeat("a", 65): "handler.legal_document.short_name_too_long",
		"":                      "handler.legal_document.short_name_required",
	} {
		status, body, _ = legalCall(t, accessToken, http.MethodPost, legalDocumentsPath, map[string]any{
			"kind": "must_accept", "shortName": shortName, "title": "Terms", "markdown": "Text",
		})
		assert.Equalf(t, http.StatusBadRequest, status, "short name %q", shortName)
		assert.Equalf(t, code, body["error_code"], "short name %q", shortName)
	}

	status, body, _ = legalCall(t, accessToken, http.MethodPost, legalDocumentsPath, map[string]any{
		"kind": "optional", "shortName": legalShortName("kind"), "title": "Terms", "markdown": "Text",
	})
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "handler.legal_document.kind_invalid", body["error_code"])
}

func TestAPILegalDocuments_PreviewRendersAsThePublishedPageWill(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	status, body, _ := legalCall(t, accessToken, http.MethodPost, legalDocumentsPath+"/preview", map[string]any{
		"markdown": "## Your data\n\n| Data | Kept |\n|---|---|\n| Email | 2 years |\n\n<script>alert(1)</script>\n\n" +
			"[bad](javascript:alert(1)) ![pixel](https://tracker.example/p.gif)\n",
	})

	require.Equal(t, http.StatusOK, status, "%v", body)
	assert.Equal(t, "<h2>Your data</h2>\n"+
		"<table>\n<thead>\n<tr>\n<th>Data</th>\n<th>Kept</th>\n</tr>\n</thead>\n<tbody>\n<tr>\n<td>Email</td>\n<td>2 years</td>\n</tr>\n</tbody>\n</table>\n"+
		"<!-- raw HTML omitted -->\n"+
		"<p><a href=\"\">bad</a> <a href=\"https://tracker.example/p.gif\">pixel</a></p>\n", body["html"])
}

func TestAPILegalDocuments_NotFoundAndBadIds(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	for _, c := range []struct{ method, path string }{
		{http.MethodGet, legalPath(999999999, "")},
		{http.MethodDelete, legalPath(999999999, "")},
		{http.MethodPost, legalPath(999999999, "/publish")},
		{http.MethodPost, legalPath(999999999, "/retire")},
		{http.MethodPost, legalPath(999999999, "/restore")},
		{http.MethodGet, legalPath(999999999, "/versions/1")},
	} {
		status, body, _ := legalCall(t, accessToken, c.method, c.path, nil)
		assert.Equalf(t, http.StatusNotFound, status, "%s %s", c.method, c.path)
		assert.Equalf(t, "NOT_FOUND", body["error_code"], "%s %s", c.method, c.path)
	}
	status, _, _ := legalCall(t, accessToken, http.MethodPut, legalPath(999999999, "/draft"), map[string]any{"title": "x"})
	assert.Equal(t, http.StatusNotFound, status)

	status, body, _ := legalCall(t, accessToken, http.MethodGet, legalDocumentsPath+"/abc", nil)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "VALIDATION_ERROR", body["error_code"])
	status, body, _ = legalCall(t, accessToken, http.MethodGet, legalPath(1, "/versions/0"), nil)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "VALIDATION_ERROR", body["error_code"])
}

// Decision 6: the settings domain. Reading accepts admin-read beside manage-settings and manage;
// every change, the preview included, needs manage-settings or manage.
func TestAPILegalDocuments_TheSettingsDomainsScopes(t *testing.T) {
	manageToken, _ := createAdminClientWithToken(t)
	id := createLegalDocumentOverAPI(t, manageToken, "for_information", legalShortName("scopes"), "Privacy", "Text")

	reads := []struct{ method, path string }{
		{http.MethodGet, legalDocumentsPath},
		{http.MethodGet, legalPath(id, "")},
	}
	writes := []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, legalDocumentsPath, map[string]any{"kind": "must_accept", "shortName": legalShortName("w"), "title": "T", "markdown": "M"}},
		{http.MethodPost, legalDocumentsPath + "/preview", map[string]any{"markdown": "M"}},
		{http.MethodPut, legalPath(id, "/draft"), map[string]any{"title": "Privacy", "markdown": "Text"}},
		{http.MethodPost, legalPath(id, "/retire"), nil},
		{http.MethodPost, legalPath(id, "/restore"), nil},
		{http.MethodPost, legalPath(id, "/publish"), nil},
		{http.MethodDelete, legalPath(id, ""), nil},
	}

	for _, c := range []struct {
		permission string
		read       int
		write      bool
	}{
		{builtin.AdminReadPermissionIdentifier, http.StatusOK, false},
		{builtin.ManageUsersPermissionIdentifier, http.StatusForbidden, false},
		{builtin.ManageClientsPermissionIdentifier, http.StatusForbidden, false},
		{builtin.ManageSettingsPermissionIdentifier, http.StatusOK, true},
	} {
		t.Run(c.permission, func(t *testing.T) {
			token, client := createClientWithGranularScope(t, c.permission)
			t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })

			for _, r := range reads {
				status, _, _ := legalCall(t, token, r.method, r.path, nil)
				assert.Equalf(t, c.read, status, "%s %s", r.method, r.path)
			}
			for _, w := range writes {
				status, body, _ := legalCall(t, token, w.method, w.path, w.body)
				if c.write {
					assert.NotEqualf(t, http.StatusForbidden, status, "%s %s reaches its handler: %v", w.method, w.path, body)
				} else {
					assert.Equalf(t, http.StatusForbidden, status, "%s %s", w.method, w.path)
					assert.Equalf(t, "INSUFFICIENT_SCOPE", body["error_code"], "%s %s", w.method, w.path)
				}
			}
		})
	}
}

func TestAPILegalDocuments_ChangesAreAudited(t *testing.T) {
	requireDatabaseAuditLogs(t)
	accessToken, caller := createAdminClientWithToken(t)
	who := caller.ClientIdentifier

	shortName := legalShortName("audit")
	resp, requestId := sendAdmin(t, accessToken, http.MethodPost, legalDocumentsPath, map[string]any{
		"kind": "must_accept", "shortName": shortName, "title": "Terms", "markdown": "Text",
	})
	var created map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
	_ = resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	id := int64(created["legalDocument"].(map[string]any)["id"].(float64))
	retireWhenDone(t, id)
	assert.Equal(t, []map[string]any{{"legal_document_id": float64(id), "short_name": shortName, "kind": "must_accept", "logged_in_user": who}},
		auditRows(t, accessToken, "created_legal_document", requestId))

	plain := []map[string]any{{"legal_document_id": float64(id), "short_name": shortName, "logged_in_user": who}}
	_, _, requestId = legalCall(t, accessToken, http.MethodPut, legalPath(id, "/draft"), map[string]any{"title": "Terms", "markdown": "Text 2"})
	assert.Equal(t, plain, auditRows(t, accessToken, "updated_legal_document_draft", requestId))

	_, _, requestId = legalCall(t, accessToken, http.MethodPost, legalPath(id, "/publish"), nil)
	assert.Equal(t, []map[string]any{{"legal_document_id": float64(id), "short_name": shortName, "version": float64(1), "logged_in_user": who}},
		auditRows(t, accessToken, "published_legal_document", requestId))
	assert.Empty(t, auditRows(t, accessToken, "updated_legal_document_draft", requestId), "publishing writes no draft event")

	_, _, requestId = legalCall(t, accessToken, http.MethodPost, legalPath(id, "/retire"), nil)
	assert.Equal(t, plain, auditRows(t, accessToken, "retired_legal_document", requestId))
	_, _, requestId = legalCall(t, accessToken, http.MethodPost, legalPath(id, "/restore"), nil)
	assert.Equal(t, plain, auditRows(t, accessToken, "restored_legal_document", requestId))

	// A refused change writes nothing.
	status, _, requestId := legalCall(t, accessToken, http.MethodDelete, legalPath(id, ""), nil)
	require.Equal(t, http.StatusBadRequest, status)
	assert.Empty(t, auditRows(t, accessToken, "deleted_legal_document", requestId))

	draftName := legalShortName("audit-draft")
	draft := createLegalDocumentOverAPI(t, accessToken, "for_information", draftName, "Privacy", "Text")
	_, _, requestId = legalCall(t, accessToken, http.MethodDelete, legalPath(draft, ""), nil)
	assert.Equal(t, []map[string]any{{"legal_document_id": float64(draft), "short_name": draftName, "logged_in_user": who}},
		auditRows(t, accessToken, "deleted_legal_document", requestId))
}
