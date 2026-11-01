package handlers

import (
	"database/sql"
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// A legal document's public pages (#622 decision 5): the current version at /legal/{shortName},
// each version at /legal/{shortName}/versions/{version}, and the not-found page for anything not
// published or retired.

// privacyNotice is a published document for information, at version 2.
func privacyNotice() (*record.LegalDocument, []record.LegalDocumentVersion) {
	return &record.LegalDocument{Id: 9, ShortName: "privacy", Kind: record.LegalDocumentKindForInformation},
		[]record.LegalDocumentVersion{
			{LegalDocumentId: 9, VersionNumber: 1, Title: "Privacy notice", Markdown: "We keep your **email**.",
				PublishedAt: time.Date(2026, 3, 4, 23, 30, 0, 0, time.UTC)},
			{LegalDocumentId: 9, VersionNumber: 2, Title: "Privacy notice, revised", Markdown: "We keep your *address*.",
				PublishedAt: time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)},
		}
}

// legalDocumentRequest is a GET of the page, its path values bound as the router binds them.
func legalDocumentRequest(shortName, version string) *http.Request {
	path := "/legal/" + shortName
	if version != "" {
		path += "/versions/" + version
	}
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.SetPathValue("shortName", shortName)
	if version != "" {
		req.SetPathValue("version", version)
	}
	return req
}

// servedBind serves the page over the document and versions given and answers what it rendered.
func servedBind(t *testing.T, doc *record.LegalDocument, versions []record.LegalDocumentVersion, version string) map[string]interface{} {
	t.Helper()
	database := datamocks.NewDatabase(t)
	database.EXPECT().GetLegalDocumentByShortName(mock.Anything, (*sql.Tx)(nil), doc.ShortName).Return(doc, nil)
	database.EXPECT().GetLegalDocumentVersionsByLegalDocumentId(mock.Anything, (*sql.Tx)(nil), doc.Id).Return(versions, nil)
	pageRenderer := handlersmocks.NewPageRenderer(t)
	var bind map[string]interface{}
	pageRenderer.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/no_menu_layout.html", "/legal_document.html", mock.Anything).
		Run(func(args mock.Arguments) { bind = args.Get(4).(map[string]interface{}) }).Return(nil).Once()

	HandleLegalDocumentGet(pageRenderer, database).ServeHTTP(httptest.NewRecorder(), legalDocumentRequest(doc.ShortName, version))
	require.NotNil(t, bind)
	return bind
}

func TestHandleLegalDocumentGet_TheCurrentVersion(t *testing.T) {
	doc, versions := privacyNotice()
	bind := servedBind(t, doc, versions, "")

	assert.Equal(t, "Privacy notice, revised", bind["documentTitle"])
	assert.Equal(t, template.HTML("<p>We keep your <em>address</em>.</p>\n"), bind["documentHTML"])
	assert.Equal(t, 2, bind["versionNumber"])
	assert.Equal(t, "2026-10-01", bind["publishedAt"])
	assert.Equal(t, true, bind["isCurrent"])
	assert.Equal(t, []legalDocumentVersionLink{{Number: 1}, {Number: 2}}, bind["versions"])
	assert.Equal(t, "privacy", bind["shortName"])
	assert.Equal(t, true, bind["layoutWide"])
}

func TestHandleLegalDocumentGet_AnEarlierVersion(t *testing.T) {
	doc, versions := privacyNotice()
	bind := servedBind(t, doc, versions, "1")

	assert.Equal(t, "Privacy notice", bind["documentTitle"])
	assert.Equal(t, template.HTML("<p>We keep your <strong>email</strong>.</p>\n"), bind["documentHTML"])
	assert.Equal(t, 1, bind["versionNumber"])
	assert.Equal(t, "2026-03-04", bind["publishedAt"], "the publish date in UTC")
	assert.Equal(t, false, bind["isCurrent"])
	assert.Equal(t, 2, bind["currentVersionNumber"])
}

func TestHandleLegalDocumentGet_TheCurrentVersionByNumberIsCurrent(t *testing.T) {
	doc, versions := privacyNotice()
	bind := servedBind(t, doc, versions, "2")
	assert.Equal(t, "Privacy notice, revised", bind["documentTitle"])
	assert.Equal(t, true, bind["isCurrent"])
}

func TestHandleLegalDocumentGet_WhatIsNotPublishedIsNotFound(t *testing.T) {
	retired, retiredVersions := privacyNotice()
	retired.RetiredAt = sql.NullTime{Time: time.Now(), Valid: true}
	doc, versions := privacyNotice()

	for _, tc := range []struct {
		name     string
		doc      *record.LegalDocument
		versions []record.LegalDocumentVersion
		version  string
	}{
		{"an unknown short name", nil, nil, ""},
		{"a retired document", retired, retiredVersions, ""},
		{"a retired document's version", retired, retiredVersions, "1"},
		{"a document never published", &record.LegalDocument{Id: 9, ShortName: "privacy"}, []record.LegalDocumentVersion{}, ""},
		{"a version not published yet", doc, versions, "3"},
		{"version 0", doc, versions, "0"},
		{"a version with a leading zero", doc, versions, "01"},
		{"a version with a sign", doc, versions, "+1"},
		{"a version that is not a number", doc, versions, "one"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			database.EXPECT().GetLegalDocumentByShortName(mock.Anything, (*sql.Tx)(nil), "privacy").Return(tc.doc, nil)
			if tc.doc != nil && !tc.doc.IsRetired() {
				database.EXPECT().GetLegalDocumentVersionsByLegalDocumentId(mock.Anything, (*sql.Tx)(nil), int64(9)).Return(tc.versions, nil)
			}
			pageRenderer := handlersmocks.NewPageRenderer(t)
			pageRenderer.On("NotFound", mock.Anything, mock.Anything).Return().Once()

			HandleLegalDocumentGet(pageRenderer, database).ServeHTTP(httptest.NewRecorder(), legalDocumentRequest("privacy", tc.version))
		})
	}
}

func TestHandleLegalDocumentGet_AFailedReadIsTheErrorPage(t *testing.T) {
	failure := errors.New("database down")
	doc, _ := privacyNotice()
	for name, setUp := range map[string]func(*datamocks.Database){
		"the document": func(database *datamocks.Database) {
			database.EXPECT().GetLegalDocumentByShortName(mock.Anything, (*sql.Tx)(nil), "privacy").Return(nil, failure)
		},
		"its versions": func(database *datamocks.Database) {
			database.EXPECT().GetLegalDocumentByShortName(mock.Anything, (*sql.Tx)(nil), "privacy").Return(doc, nil)
			database.EXPECT().GetLegalDocumentVersionsByLegalDocumentId(mock.Anything, (*sql.Tx)(nil), int64(9)).Return(nil, failure)
		},
	} {
		t.Run(name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			setUp(database)
			pageRenderer := handlersmocks.NewPageRenderer(t)
			pageRenderer.On("InternalServerError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
				return errors.Is(err, failure)
			})).Return().Once()

			HandleLegalDocumentGet(pageRenderer, database).ServeHTTP(httptest.NewRecorder(), legalDocumentRequest("privacy", ""))
		})
	}
}
