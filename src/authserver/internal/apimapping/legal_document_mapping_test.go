package apimapping

import (
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A legal document on the wire (#622): what the admin console reads to draw the list, the editor
// and the versions, written out byte for byte.

var (
	legalCreated   = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	legalUpdated   = time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	legalPublished = time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	legalRepublish = time.Date(2026, 10, 4, 9, 0, 0, 0, time.UTC)
	legalRetired   = time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)
)

func publishedTerms() (*record.LegalDocument, []record.LegalDocumentVersion) {
	doc := &record.LegalDocument{
		Id:            7,
		CreatedAt:     sql.NullTime{Time: legalCreated, Valid: true},
		UpdatedAt:     sql.NullTime{Time: legalUpdated, Valid: true},
		ShortName:     "terms",
		Kind:          record.LegalDocumentKindMustAccept,
		DraftTitle:    sql.NullString{String: "Terms (draft)", Valid: true},
		DraftMarkdown: sql.NullString{String: "Next text", Valid: true},
		// Applies to all apps, the default a document is created with.
		AppliesToAllApps: true,
	}
	versions := []record.LegalDocumentVersion{
		{Id: 11, PublishedAt: legalPublished, LegalDocumentId: 7, VersionNumber: 1, Title: "Terms", Markdown: "First text"},
		{Id: 12, PublishedAt: legalRepublish, LegalDocumentId: 7, VersionNumber: 2, Title: "Terms of use", Markdown: "Second text"},
	}
	return doc, versions
}

func wire(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return string(b)
}

func TestLegalDocumentDetail_APublishedDocumentWithADraft(t *testing.T) {
	doc, versions := publishedTerms()
	assert.Equal(t, `{"legalDocument":{"id":7,"createdAt":"2026-10-01T09:00:00Z","updatedAt":"2026-10-02T09:00:00Z",`+
		`"shortName":"terms","kind":"must_accept","title":"Terms of use","currentVersion":2,`+
		`"publishedAt":"2026-10-04T09:00:00Z","hasDraft":true,"retired":false,"retiredAt":null,"appliesTo":"all_apps","clientIds":[]},`+
		`"draft":{"title":"Terms (draft)","markdown":"Next text"},`+
		`"versions":[{"version":1,"title":"Terms","publishedAt":"2026-10-03T09:00:00Z"},`+
		`{"version":2,"title":"Terms of use","publishedAt":"2026-10-04T09:00:00Z"}]}`,
		wire(t, ToLegalDocumentDetailResponse(doc, versions, nil)))
}

func TestLegalDocumentDetail_ANeverPublishedDocumentIsNamedByItsDraft(t *testing.T) {
	doc, _ := publishedTerms()
	assert.Equal(t, `{"legalDocument":{"id":7,"createdAt":"2026-10-01T09:00:00Z","updatedAt":"2026-10-02T09:00:00Z",`+
		`"shortName":"terms","kind":"must_accept","title":"Terms (draft)","currentVersion":0,`+
		`"publishedAt":null,"hasDraft":true,"retired":false,"retiredAt":null,"appliesTo":"all_apps","clientIds":[]},`+
		`"draft":{"title":"Terms (draft)","markdown":"Next text"},"versions":[]}`,
		wire(t, ToLegalDocumentDetailResponse(doc, nil, nil)))
}

func TestLegalDocumentDetail_ARetiredDocumentWithNoDraft(t *testing.T) {
	doc, versions := publishedTerms()
	doc.Kind = record.LegalDocumentKindForInformation
	doc.DraftTitle = sql.NullString{}
	doc.DraftMarkdown = sql.NullString{}
	doc.RetiredAt = sql.NullTime{Time: legalRetired, Valid: true}
	got := ToLegalDocumentDetailResponse(doc, versions[:1], nil)
	assert.Equal(t, `{"id":7,"createdAt":"2026-10-01T09:00:00Z","updatedAt":"2026-10-02T09:00:00Z",`+
		`"shortName":"terms","kind":"for_information","title":"Terms","currentVersion":1,`+
		`"publishedAt":"2026-10-03T09:00:00Z","hasDraft":false,"retired":true,"retiredAt":"2026-10-05T09:00:00Z","appliesTo":"all_apps","clientIds":[]}`,
		wire(t, got.LegalDocument))
	assert.Nil(t, got.Draft, "no draft is null on the wire")
}

func TestLegalDocumentVersion_CarriesItsText(t *testing.T) {
	_, versions := publishedTerms()
	assert.Equal(t, `{"version":1,"title":"Terms","markdown":"First text","publishedAt":"2026-10-03T09:00:00Z"}`,
		wire(t, ToLegalDocumentVersionResponse(&versions[0])))
}

func TestLegalDocumentList_TakesEachDocumentsCurrentVersion(t *testing.T) {
	doc, versions := publishedTerms()
	got := ToLegalDocumentResponse(doc, &versions[1], nil)
	assert.Equal(t, "Terms of use", got.Title)
	assert.Equal(t, 2, got.CurrentVersion)
	unpublished := ToLegalDocumentResponse(doc, nil, nil)
	assert.Equal(t, "Terms (draft)", unpublished.Title)
	assert.Equal(t, 0, unpublished.CurrentVersion)
	assert.Nil(t, unpublished.PublishedAt)
}

// A document set to selected apps carries the client ids it lists, in the order read; one listing
// none carries [] and is still selected apps, which applies to nobody, never all apps.
func TestLegalDocument_SelectedAppsCarryTheirClientIds(t *testing.T) {
	doc, versions := publishedTerms()
	doc.AppliesToAllApps = false
	links := []record.LegalDocumentClient{
		{Id: 31, LegalDocumentId: 7, ClientId: 5},
		{Id: 32, LegalDocumentId: 7, ClientId: 3},
	}
	got := ToLegalDocumentResponse(doc, &versions[1], links)
	assert.Equal(t, "selected_apps", got.AppliesTo)
	assert.Equal(t, []int64{5, 3}, got.ClientIds)

	none := ToLegalDocumentDetailResponse(doc, versions, nil)
	assert.Contains(t, wire(t, none.LegalDocument), `"appliesTo":"selected_apps","clientIds":[]`)
}

// A user's acceptance on the wire: the version's public page for a document in effect, and no
// address for a retired one, whose pages all answer not found.
func TestLegalDocumentAcceptance_LinksTheVersionsPublicPageUnlessRetired(t *testing.T) {
	doc, versions := publishedTerms()
	acceptedAt := time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC)
	acceptance := &record.LegalDocumentAcceptance{Id: 31, AcceptedAt: acceptedAt, UserId: 42, LegalDocumentVersionId: 11}

	assert.Equal(t, `{"id":31,"acceptedAt":"2026-10-06T09:00:00Z","legalDocumentId":7,"shortName":"terms",`+
		`"version":1,"title":"Terms","publishedAt":"2026-10-03T09:00:00Z","retired":false,`+
		`"url":"https://auth.example/legal/terms/versions/1"}`,
		wire(t, ToLegalDocumentAcceptanceResponse(acceptance, doc, &versions[0], "https://auth.example")))

	doc.RetiredAt = sql.NullTime{Time: legalRetired, Valid: true}
	assert.Equal(t, `{"id":31,"acceptedAt":"2026-10-06T09:00:00Z","legalDocumentId":7,"shortName":"terms",`+
		`"version":1,"title":"Terms","publishedAt":"2026-10-03T09:00:00Z","retired":true,"url":null}`,
		wire(t, ToLegalDocumentAcceptanceResponse(acceptance, doc, &versions[0], "https://auth.example")))
}
