package apiclient

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The legal document pages bind what these methods decode (#622). The bodies are literal JSON text,
// as in groups_test.go, so a renamed json tag in core/api fails here rather than leaving a page
// blank.
//
// serves lives in users_test.go.
const legalDocumentDetailBody = `{
	"legalDocument": {
		"id": 7,
		"createdAt": "2026-10-01T09:00:00Z",
		"updatedAt": null,
		"shortName": "terms-of-use",
		"kind": "must_accept",
		"title": "Terms of use",
		"currentVersion": 2,
		"publishedAt": "2026-10-20T12:30:00Z",
		"hasDraft": true,
		"retired": false,
		"retiredAt": null
	},
	"draft": {"title": "Terms of use (2027)", "markdown": "# Terms\n\nBe kind."},
	"versions": [
		{"version": 1, "title": "Terms", "publishedAt": "2026-10-02T08:00:00Z"},
		{"version": 2, "title": "Terms of use", "publishedAt": "2026-10-20T12:30:00Z"}
	]
}`

// The editor reads the document, its draft and its versions out of one answer: a decode that
// dropped the draft would open the editor on the published text and lose the administrator's work.
func TestAuthServerClient_GetLegalDocumentByIdDecodesTheDocumentItsDraftAndItsVersions(t *testing.T) {
	client, recorded := serves(t, legalDocumentDetailBody)

	detail, err := client.GetLegalDocumentById(context.Background(), "an-access-token", 7)
	require.NoError(t, err)

	gotPath, gotAuthorization := recorded()
	assert.Equal(t, "/api/v1/admin/legal-documents/7", gotPath)
	assert.Equal(t, "Bearer an-access-token", gotAuthorization)

	doc := detail.LegalDocument
	assert.Equal(t, int64(7), doc.Id)
	assert.Equal(t, "terms-of-use", doc.ShortName)
	assert.Equal(t, "must_accept", doc.Kind)
	assert.Equal(t, "Terms of use", doc.Title)
	assert.Equal(t, 2, doc.CurrentVersion)
	require.NotNil(t, doc.PublishedAt)
	assert.Equal(t, time.Date(2026, 10, 20, 12, 30, 0, 0, time.UTC), doc.PublishedAt.UTC())
	assert.True(t, doc.HasDraft)
	assert.False(t, doc.Retired)
	assert.Nil(t, doc.RetiredAt)

	require.NotNil(t, detail.Draft)
	assert.Equal(t, "Terms of use (2027)", detail.Draft.Title)
	assert.Equal(t, "# Terms\n\nBe kind.", detail.Draft.Markdown)

	require.Len(t, detail.Versions, 2)
	assert.Equal(t, 1, detail.Versions[0].Version)
	assert.Equal(t, "Terms", detail.Versions[0].Title)
	assert.Equal(t, 2, detail.Versions[1].Version)
	require.NotNil(t, detail.Versions[1].PublishedAt)
	assert.Equal(t, time.Date(2026, 10, 20, 12, 30, 0, 0, time.UTC), detail.Versions[1].PublishedAt.UTC())
}

// A document with no draft answers draft null, which must reach the editor as nil, the sign that it
// opens on the current version's text.
func TestAuthServerClient_GetLegalDocumentByIdDecodesANullDraftAsNil(t *testing.T) {
	client, _ := serves(t, `{"legalDocument":{"id":7,"shortName":"privacy","kind":"for_information",`+
		`"currentVersion":1,"hasDraft":false,"retired":true,"retiredAt":"2026-10-30T10:00:00Z"},"draft":null,`+
		`"versions":[{"version":1,"title":"Privacy notice","publishedAt":"2026-10-02T08:00:00Z"}]}`)

	detail, err := client.GetLegalDocumentById(context.Background(), "an-access-token", 7)
	require.NoError(t, err)

	assert.Nil(t, detail.Draft)
	assert.Equal(t, "for_information", detail.LegalDocument.Kind)
	assert.True(t, detail.LegalDocument.Retired)
	require.NotNil(t, detail.LegalDocument.RetiredAt)
	assert.Equal(t, time.Date(2026, 10, 30, 10, 0, 0, 0, time.UTC), detail.LegalDocument.RetiredAt.UTC())
}

// The list's rows, each with its own status: a decode reading one row's fields into another is
// invisible with a single row.
func TestAuthServerClient_GetAllLegalDocumentsDecodesEachRow(t *testing.T) {
	client, recorded := serves(t, `{"legalDocuments":[`+
		`{"id":7,"shortName":"terms-of-use","kind":"must_accept","title":"Terms of use","currentVersion":2,"hasDraft":true},`+
		`{"id":8,"shortName":"privacy","kind":"for_information","title":"Privacy notice","currentVersion":0,"hasDraft":true,"retired":false}]}`)

	docs, err := client.GetAllLegalDocuments(context.Background(), "an-access-token")
	require.NoError(t, err)

	gotPath, _ := recorded()
	assert.Equal(t, "/api/v1/admin/legal-documents", gotPath)
	require.Len(t, docs, 2)
	assert.Equal(t, "terms-of-use", docs[0].ShortName)
	assert.Equal(t, 2, docs[0].CurrentVersion)
	assert.Equal(t, int64(8), docs[1].Id)
	assert.Equal(t, "privacy", docs[1].ShortName)
	assert.Equal(t, "for_information", docs[1].Kind)
	assert.Equal(t, "Privacy notice", docs[1].Title)
	assert.Equal(t, 0, docs[1].CurrentVersion)
}

// One published version with its text, which the console's version page shows.
func TestAuthServerClient_GetLegalDocumentVersionDecodesTheVersionsText(t *testing.T) {
	client, recorded := serves(t, `{"legalDocument":{"id":7,"shortName":"terms-of-use","kind":"must_accept",`+
		`"title":"Terms of use","currentVersion":2},`+
		`"version":{"version":1,"title":"Terms","markdown":"Old *terms*.","publishedAt":"2026-10-02T08:00:00Z"}}`)

	got, err := client.GetLegalDocumentVersion(context.Background(), "an-access-token", 7, 1)
	require.NoError(t, err)

	gotPath, _ := recorded()
	assert.Equal(t, "/api/v1/admin/legal-documents/7/versions/1", gotPath)
	assert.Equal(t, "terms-of-use", got.LegalDocument.ShortName)
	assert.Equal(t, 1, got.Version.Version)
	assert.Equal(t, "Terms", got.Version.Title)
	assert.Equal(t, "Old *terms*.", got.Version.Markdown)
	require.NotNil(t, got.Version.PublishedAt)
	assert.Equal(t, time.Date(2026, 10, 2, 8, 0, 0, 0, time.UTC), got.Version.PublishedAt.UTC())
}

// The preview answers the auth server's rendering, which the editor shows as it is.
func TestAuthServerClient_PreviewLegalDocumentAnswersTheRenderedHTML(t *testing.T) {
	client, recorded := serves(t, `{"html":"<h1>Terms</h1>\n"}`)

	html, err := client.PreviewLegalDocument(context.Background(), "an-access-token", "# Terms")
	require.NoError(t, err)

	gotPath, _ := recorded()
	assert.Equal(t, "/api/v1/admin/legal-documents/preview", gotPath)
	assert.Equal(t, "<h1>Terms</h1>\n", html)
}

// A create answers 201 with the new document, whose id the console redirects to.
func TestAuthServerClient_CreateLegalDocumentDecodesTheNewDocument(t *testing.T) {
	client, _ := servesStatus(t, http.StatusCreated, `{"legalDocument":{"id":9,"shortName":"cookies",`+
		`"kind":"for_information","title":"Cookies","currentVersion":0,"hasDraft":true},`+
		`"draft":{"title":"Cookies","markdown":""},"versions":[]}`)

	detail, err := client.CreateLegalDocument(context.Background(), "an-access-token", charCreateLegalDocument)
	require.NoError(t, err)

	assert.Equal(t, int64(9), detail.LegalDocument.Id)
	assert.Equal(t, "cookies", detail.LegalDocument.ShortName)
	require.NotNil(t, detail.Draft)
	assert.Equal(t, "Cookies", detail.Draft.Title)
}
