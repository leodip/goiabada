package apihandlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The admin API's legal documents (#622 decisions 1, 2, 4 and 5), one rule per test, through the
// handlers with the generated database mock: what each refusal answers and writes, and what each
// write stores and audits.

const legalCaller = "admin-console-client"

// legalRequest is an admin API request from legalCaller, with a JSON body when body is not nil and
// the path values the route would set.
func legalRequest(t *testing.T, method string, body any, pathValues ...string) *http.Request {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(b)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, "/api/v1/admin/legal-documents", reader)
	req = req.WithContext(reqctx.WithValidatedToken(req.Context(), oauth.JwtToken{Claims: map[string]any{"sub": legalCaller}}))
	for i := 0; i+1 < len(pathValues); i += 2 {
		req.SetPathValue(pathValues[i], pathValues[i+1])
	}
	return req
}

func serveLegal(handler http.HandlerFunc, req *http.Request) (int, map[string]any) {
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	return rr.Code, body
}

// errorCode is a refusal's error_code.
func errorCode(body map[string]any) any { return body["error_code"] }

func draftDocument(id int64) *record.LegalDocument {
	return &record.LegalDocument{
		Id:            id,
		ShortName:     "terms",
		Kind:          record.LegalDocumentKindMustAccept,
		DraftTitle:    sql.NullString{String: "Terms of use", Valid: true},
		DraftMarkdown: sql.NullString{String: "# Terms", Valid: true},
	}
}

func publishedVersions(id int64, n int) []record.LegalDocumentVersion {
	var versions []record.LegalDocumentVersion
	for i := 1; i <= n; i++ {
		versions = append(versions, record.LegalDocumentVersion{
			Id: int64(100 + i), LegalDocumentId: id, VersionNumber: i, Title: "Terms", Markdown: "Text",
			PublishedAt: time.Date(2026, 10, i, 9, 0, 0, 0, time.UTC),
		})
	}
	return versions
}

var legalTx = &sql.Tx{}

// noApps lets a handler read the apps a document lists, answering none, as a document applying to
// all apps does.
func noApps(database *datamocks.Database) {
	database.On("GetLegalDocumentClientsByLegalDocumentId", mock.Anything, mock.Anything, mock.Anything).Return(nil, nil).Maybe()
}

// --- create -------------------------------------------------------------------------------------

func validCreate() map[string]any {
	return map[string]any{"kind": "must_accept", "shortName": "terms", "title": "Terms of use", "markdown": "# Terms"}
}

func TestLegalDocumentCreate_Refusals(t *testing.T) {
	cases := []struct {
		name  string
		edit  func(body map[string]any)
		code  string
		taken bool
	}{
		{"an unknown kind", func(b map[string]any) { b["kind"] = "optional" }, "handler.legal_document.kind_invalid", false},
		{"no kind", func(b map[string]any) { delete(b, "kind") }, "handler.legal_document.kind_invalid", false},
		{"no short name", func(b map[string]any) { b["shortName"] = "  " }, "handler.legal_document.short_name_required", false},
		{"an uppercase letter", func(b map[string]any) { b["shortName"] = "Terms" }, "handler.legal_document.short_name_invalid", false},
		{"an underscore", func(b map[string]any) { b["shortName"] = "terms_of_use" }, "handler.legal_document.short_name_invalid", false},
		{"a leading hyphen", func(b map[string]any) { b["shortName"] = "-terms" }, "handler.legal_document.short_name_invalid", false},
		{"a trailing hyphen", func(b map[string]any) { b["shortName"] = "terms-" }, "handler.legal_document.short_name_invalid", false},
		{"a slash", func(b map[string]any) { b["shortName"] = "terms/v2" }, "handler.legal_document.short_name_invalid", false},
		{"a non-ASCII letter", func(b map[string]any) { b["shortName"] = "términos" }, "handler.legal_document.short_name_invalid", false},
		{"65 characters", func(b map[string]any) { b["shortName"] = strings.Repeat("a", 65) }, "handler.legal_document.short_name_too_long", false},
		{"no title", func(b map[string]any) { b["title"] = " \t" }, "handler.legal_document.title_required", false},
		{"a 201-character title", func(b map[string]any) { b["title"] = strings.Repeat("é", 201) }, "handler.legal_document.title_too_long", false},
		{"a title of 101 emoji", func(b map[string]any) { b["title"] = strings.Repeat("😀", 101) }, "handler.legal_document.title_too_long", false},
		{"100,001 characters of text", func(b map[string]any) { b["markdown"] = strings.Repeat("ü", 100_001) }, "handler.legal_document.markdown_too_long", false},
		{"a short name another document holds", func(b map[string]any) {}, "handler.legal_document.short_name_in_use", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			noApps(database)
			if c.taken {
				database.On("GetLegalDocumentByShortName", mock.Anything, mock.Anything, "terms").
					Return(&record.LegalDocument{Id: 3, ShortName: "terms"}, nil).Once()
			} else {
				database.On("GetLegalDocumentByShortName", mock.Anything, mock.Anything, mock.Anything).Return(nil, nil).Maybe()
			}
			body := validCreate()
			c.edit(body)

			status, answer := serveLegal(HandleLegalDocumentCreatePost(database, handlersmocks.NewAuditLogger(t)),
				legalRequest(t, http.MethodPost, body))

			assert.Equal(t, http.StatusBadRequest, status)
			assert.Equal(t, c.code, errorCode(answer))
			database.AssertNotCalled(t, "CreateLegalDocument", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

func TestLegalDocumentCreate_AtTheBoundsIsAccepted(t *testing.T) {
	database := datamocks.NewDatabase(t)
	noApps(database)
	auditLogger := handlersmocks.NewAuditLogger(t)
	shortName := strings.Repeat("a", 63) + "1"
	database.On("GetLegalDocumentByShortName", mock.Anything, mock.Anything, shortName).Return(nil, nil).Once()
	database.On("CreateLegalDocument", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	auditLogger.On("Log", mock.Anything, audit.EventCreatedLegalDocument, mock.Anything).Once()

	status, _ := serveLegal(HandleLegalDocumentCreatePost(database, auditLogger), legalRequest(t, http.MethodPost, map[string]any{
		"kind": "for_information", "shortName": shortName,
		"title": strings.Repeat("😀", 100), "markdown": strings.Repeat("ü", 100_000),
	}))

	assert.Equal(t, http.StatusCreated, status)
}

func TestLegalDocumentCreate_StoresADraftAndAuditsIt(t *testing.T) {
	database := datamocks.NewDatabase(t)
	noApps(database)
	auditLogger := handlersmocks.NewAuditLogger(t)
	database.On("GetLegalDocumentByShortName", mock.Anything, mock.Anything, "privacy-notice").Return(nil, nil).Once()
	var stored *record.LegalDocument
	database.On("CreateLegalDocument", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			stored = args.Get(2).(*record.LegalDocument)
			stored.Id = 42
		}).Return(nil).Once()
	auditLogger.On("Log", mock.Anything, audit.EventCreatedLegalDocument, map[string]interface{}{
		"legal_document_id": int64(42), "short_name": "privacy-notice", "kind": "for_information", "logged_in_user": legalCaller,
	}).Once()

	status, body := serveLegal(HandleLegalDocumentCreatePost(database, auditLogger), legalRequest(t, http.MethodPost, map[string]any{
		"kind": "for_information", "shortName": " privacy-notice ", "title": "  Privacy notice ", "markdown": "  We keep little.\n",
	}))

	require.Equal(t, http.StatusCreated, status)
	require.NotNil(t, stored)
	assert.Equal(t, "privacy-notice", stored.ShortName)
	assert.Equal(t, "for_information", stored.Kind)
	assert.Equal(t, sql.NullString{String: "Privacy notice", Valid: true}, stored.DraftTitle, "the title is trimmed")
	assert.Equal(t, sql.NullString{String: "  We keep little.\n", Valid: true}, stored.DraftMarkdown, "the Markdown is kept as written")
	assert.False(t, stored.RetiredAt.Valid)
	assert.True(t, stored.AppliesToAllApps, "a new document applies to all apps")
	document := body["legalDocument"].(map[string]any)
	assert.Equal(t, "all_apps", document["appliesTo"])
	assert.Equal(t, []any{}, document["clientIds"])
	assert.InDelta(t, 42, document["id"], 0)
	assert.InDelta(t, 0, document["currentVersion"], 0, "a new document is unpublished")
	assert.Equal(t, map[string]any{"title": "Privacy notice", "markdown": "  We keep little.\n"}, body["draft"])
	assert.Equal(t, []any{}, body["versions"])
}

func TestLegalDocumentCreate_AShortNameTakenMeanwhileIsRefused(t *testing.T) {
	database := datamocks.NewDatabase(t)
	noApps(database)
	database.On("GetLegalDocumentByShortName", mock.Anything, mock.Anything, "terms").Return(nil, nil).Once()
	database.On("CreateLegalDocument", mock.Anything, mock.Anything, mock.Anything).
		Return(errs.Errorf("insert: %w", data.ErrUniqueViolation)).Once()

	status, body := serveLegal(HandleLegalDocumentCreatePost(database, handlersmocks.NewAuditLogger(t)),
		legalRequest(t, http.MethodPost, validCreate()))

	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "handler.legal_document.short_name_in_use", errorCode(body))
}

// --- draft --------------------------------------------------------------------------------------

// underItsRow expects the one transaction a lifecycle write runs in, which takes document 5's row
// and reads the document again under it, answering doc.
func underItsRow(database *datamocks.Database, doc *record.LegalDocument) {
	datamocks.ExpectRunInTransaction(database, legalTx)
	database.On("AcquireLegalDocumentRow", mock.Anything, legalTx, int64(5)).Return(nil).Once()
	database.On("GetLegalDocumentById", mock.Anything, legalTx, int64(5)).Return(doc, nil).Once()
}

func TestLegalDocumentDraft_TheShortNameChangesUntilTheFirstPublish(t *testing.T) {
	database := datamocks.NewDatabase(t)
	noApps(database)
	auditLogger := handlersmocks.NewAuditLogger(t)
	underItsRow(database, draftDocument(5))
	database.On("GetLegalDocumentVersionsByLegalDocumentId", mock.Anything, legalTx, int64(5)).Return(nil, nil)
	database.On("GetLegalDocumentByShortName", mock.Anything, legalTx, "terms-of-use").Return(nil, nil).Once()
	var saved *record.LegalDocument
	database.On("UpdateLegalDocument", mock.Anything, legalTx, mock.Anything).
		Run(func(args mock.Arguments) { saved = args.Get(2).(*record.LegalDocument) }).Return(nil).Once()
	auditLogger.On("Log", mock.Anything, audit.EventUpdatedLegalDocumentDraft, map[string]interface{}{
		"legal_document_id": int64(5), "short_name": "terms-of-use", "logged_in_user": legalCaller,
	}).Once()

	status, _ := serveLegal(HandleLegalDocumentDraftPut(database, auditLogger), legalRequest(t, http.MethodPut,
		map[string]any{"shortName": "terms-of-use", "title": "Terms", "markdown": "New text"}, "id", "5"))

	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, "terms-of-use", saved.ShortName)
	assert.Equal(t, sql.NullString{String: "Terms", Valid: true}, saved.DraftTitle)
	assert.Equal(t, sql.NullString{String: "New text", Valid: true}, saved.DraftMarkdown)
	assert.Equal(t, record.LegalDocumentKindMustAccept, saved.Kind)
}

func TestLegalDocumentDraft_TheShortNameIsFixedOncePublished(t *testing.T) {
	database := datamocks.NewDatabase(t)
	noApps(database)
	underItsRow(database, draftDocument(5))
	database.On("GetLegalDocumentVersionsByLegalDocumentId", mock.Anything, legalTx, int64(5)).Return(publishedVersions(5, 1), nil)

	status, body := serveLegal(HandleLegalDocumentDraftPut(database, handlersmocks.NewAuditLogger(t)), legalRequest(t, http.MethodPut,
		map[string]any{"shortName": "terms-of-use", "title": "Terms", "markdown": "New text"}, "id", "5"))

	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "handler.legal_document.short_name_fixed", errorCode(body))
	database.AssertNotCalled(t, "UpdateLegalDocument", mock.Anything, mock.Anything, mock.Anything)
}

func TestLegalDocumentDraft_APublishedDocumentKeepsItsShortNameAndTakesANewDraft(t *testing.T) {
	for name, shortName := range map[string]string{"its own short name": "terms", "no short name": ""} {
		t.Run(name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			noApps(database)
			auditLogger := handlersmocks.NewAuditLogger(t)
			doc := draftDocument(5)
			doc.DraftTitle, doc.DraftMarkdown = sql.NullString{}, sql.NullString{}
			underItsRow(database, doc)
			database.On("GetLegalDocumentVersionsByLegalDocumentId", mock.Anything, legalTx, int64(5)).Return(publishedVersions(5, 2), nil)
			var saved *record.LegalDocument
			database.On("UpdateLegalDocument", mock.Anything, legalTx, mock.Anything).
				Run(func(args mock.Arguments) { saved = args.Get(2).(*record.LegalDocument) }).Return(nil).Once()
			auditLogger.On("Log", mock.Anything, audit.EventUpdatedLegalDocumentDraft, mock.Anything).Once()

			status, body := serveLegal(HandleLegalDocumentDraftPut(database, auditLogger), legalRequest(t, http.MethodPut,
				map[string]any{"shortName": shortName, "title": "Terms v3", "markdown": "Third text"}, "id", "5"))

			require.Equal(t, http.StatusOK, status)
			assert.Equal(t, "terms", saved.ShortName)
			assert.True(t, saved.HasDraft())
			assert.Equal(t, map[string]any{"title": "Terms v3", "markdown": "Third text"}, body["draft"])
			database.AssertNotCalled(t, "GetLegalDocumentByShortName", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

func TestLegalDocumentDraft_ARetiredDocumentIsReadOnly(t *testing.T) {
	database := datamocks.NewDatabase(t)
	noApps(database)
	doc := draftDocument(5)
	doc.RetiredAt = sql.NullTime{Time: time.Now(), Valid: true}
	underItsRow(database, doc)

	status, body := serveLegal(HandleLegalDocumentDraftPut(database, handlersmocks.NewAuditLogger(t)), legalRequest(t, http.MethodPut,
		map[string]any{"title": "Terms", "markdown": "x"}, "id", "5"))

	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "handler.legal_document.retired", errorCode(body))
	database.AssertNotCalled(t, "UpdateLegalDocument", mock.Anything, mock.Anything, mock.Anything)
}

func TestLegalDocumentDraft_AnUnknownDocumentIs404(t *testing.T) {
	database := datamocks.NewDatabase(t)
	noApps(database)
	underItsRow(database, nil)

	status, body := serveLegal(HandleLegalDocumentDraftPut(database, handlersmocks.NewAuditLogger(t)), legalRequest(t, http.MethodPut,
		map[string]any{"title": "Terms", "markdown": "x"}, "id", "5"))

	assert.Equal(t, http.StatusNotFound, status)
	assert.Equal(t, "NOT_FOUND", errorCode(body))
}

// --- publish ------------------------------------------------------------------------------------

func TestLegalDocumentPublish_FreezesTheDraftAsTheNextVersion(t *testing.T) {
	database := datamocks.NewDatabase(t)
	noApps(database)
	auditLogger := handlersmocks.NewAuditLogger(t)
	doc := draftDocument(5)
	underItsRow(database, doc)
	database.On("GetLegalDocumentVersionsByLegalDocumentId", mock.Anything, legalTx, int64(5)).Return(publishedVersions(5, 2), nil).Once()
	var published *record.LegalDocumentVersion
	database.On("CreateLegalDocumentVersion", mock.Anything, legalTx, mock.Anything).
		Run(func(args mock.Arguments) { published = args.Get(2).(*record.LegalDocumentVersion) }).Return(nil).Once()
	var cleared *record.LegalDocument
	database.On("UpdateLegalDocument", mock.Anything, legalTx, mock.Anything).
		Run(func(args mock.Arguments) { cleared = args.Get(2).(*record.LegalDocument) }).Return(nil).Once()
	auditLogger.On("Log", mock.Anything, audit.EventPublishedLegalDocument, map[string]interface{}{
		"legal_document_id": int64(5), "short_name": "terms", "version": 3, "logged_in_user": legalCaller,
	}).Once()

	before := time.Now().UTC()
	status, body := serveLegal(HandleLegalDocumentPublishPost(database, auditLogger), legalRequest(t, http.MethodPost, nil, "id", "5"))

	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, published)
	assert.Equal(t, int64(5), published.LegalDocumentId)
	assert.Equal(t, 3, published.VersionNumber, "after versions 1 and 2 comes 3")
	assert.Equal(t, "Terms of use", published.Title)
	assert.Equal(t, "# Terms", published.Markdown)
	assert.False(t, published.PublishedAt.Before(before.Truncate(time.Second)), "published now")
	assert.False(t, cleared.HasDraft(), "the draft is consumed")
	assert.Nil(t, body["draft"])
	document := body["legalDocument"].(map[string]any)
	assert.InDelta(t, 3, document["currentVersion"], 0)
	assert.Equal(t, "Terms of use", document["title"])
	assert.Len(t, body["versions"], 3)
}

func TestLegalDocumentPublish_TheFirstVersionIsOne(t *testing.T) {
	database := datamocks.NewDatabase(t)
	noApps(database)
	auditLogger := handlersmocks.NewAuditLogger(t)
	underItsRow(database, draftDocument(5))
	database.On("GetLegalDocumentVersionsByLegalDocumentId", mock.Anything, legalTx, int64(5)).Return(nil, nil).Once()
	var published *record.LegalDocumentVersion
	database.On("CreateLegalDocumentVersion", mock.Anything, legalTx, mock.Anything).
		Run(func(args mock.Arguments) { published = args.Get(2).(*record.LegalDocumentVersion) }).Return(nil).Once()
	database.On("UpdateLegalDocument", mock.Anything, legalTx, mock.Anything).Return(nil).Once()
	auditLogger.On("Log", mock.Anything, audit.EventPublishedLegalDocument, mock.Anything).Once()

	status, _ := serveLegal(HandleLegalDocumentPublishPost(database, auditLogger), legalRequest(t, http.MethodPost, nil, "id", "5"))

	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, 1, published.VersionNumber)
}

func TestLegalDocumentPublish_Refusals(t *testing.T) {
	cases := []struct {
		name string
		doc  func() *record.LegalDocument
		code string
	}{
		{"no draft", func() *record.LegalDocument {
			d := draftDocument(5)
			d.DraftTitle, d.DraftMarkdown = sql.NullString{}, sql.NullString{}
			return d
		}, "handler.legal_document.no_draft"},
		{"a draft with no text", func() *record.LegalDocument {
			d := draftDocument(5)
			d.DraftMarkdown = sql.NullString{String: " \n\t", Valid: true}
			return d
		}, "handler.legal_document.draft_empty"},
		{"a retired document", func() *record.LegalDocument {
			d := draftDocument(5)
			d.RetiredAt = sql.NullTime{Time: time.Now(), Valid: true}
			return d
		}, "handler.legal_document.retired"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			noApps(database)
			underItsRow(database, c.doc())
			database.On("GetLegalDocumentVersionsByLegalDocumentId", mock.Anything, legalTx, int64(5)).Return(publishedVersions(5, 1), nil).Maybe()

			status, body := serveLegal(HandleLegalDocumentPublishPost(database, handlersmocks.NewAuditLogger(t)),
				legalRequest(t, http.MethodPost, nil, "id", "5"))

			assert.Equal(t, http.StatusBadRequest, status)
			assert.Equal(t, c.code, errorCode(body))
			database.AssertNotCalled(t, "CreateLegalDocumentVersion", mock.Anything, mock.Anything, mock.Anything)
			database.AssertNotCalled(t, "UpdateLegalDocument", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

func TestLegalDocumentPublish_AnUnknownDocumentIs404(t *testing.T) {
	database := datamocks.NewDatabase(t)
	noApps(database)
	underItsRow(database, nil)

	status, body := serveLegal(HandleLegalDocumentPublishPost(database, handlersmocks.NewAuditLogger(t)),
		legalRequest(t, http.MethodPost, nil, "id", "5"))

	assert.Equal(t, http.StatusNotFound, status)
	assert.Equal(t, "NOT_FOUND", errorCode(body))
}

// Two publishes racing for one number: the engine refuses the second version row, and the loser is
// answered 409 with nothing published and nothing audited.
func TestLegalDocumentPublish_LosingARaceIsAConflict(t *testing.T) {
	database := datamocks.NewDatabase(t)
	noApps(database)
	underItsRow(database, draftDocument(5))
	database.On("GetLegalDocumentVersionsByLegalDocumentId", mock.Anything, legalTx, int64(5)).Return(publishedVersions(5, 1), nil).Once()
	database.On("CreateLegalDocumentVersion", mock.Anything, legalTx, mock.Anything).
		Return(errs.Errorf("insert: %w", data.ErrUniqueViolation)).Once()

	status, body := serveLegal(HandleLegalDocumentPublishPost(database, handlersmocks.NewAuditLogger(t)),
		legalRequest(t, http.MethodPost, nil, "id", "5"))

	assert.Equal(t, http.StatusConflict, status)
	assert.Equal(t, "CONCURRENT_UPDATE", errorCode(body))
	database.AssertNotCalled(t, "UpdateLegalDocument", mock.Anything, mock.Anything, mock.Anything)
}

// --- retire, restore, delete --------------------------------------------------------------------

func TestLegalDocumentRetire_OnlyAPublishedDocument(t *testing.T) {
	database := datamocks.NewDatabase(t)
	noApps(database)
	underItsRow(database, draftDocument(5))
	database.On("GetLegalDocumentVersionsByLegalDocumentId", mock.Anything, legalTx, int64(5)).Return(nil, nil).Once()

	status, body := serveLegal(HandleLegalDocumentRetirePost(database, handlersmocks.NewAuditLogger(t)),
		legalRequest(t, http.MethodPost, nil, "id", "5"))

	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "handler.legal_document.not_published", errorCode(body))
	database.AssertNotCalled(t, "UpdateLegalDocument", mock.Anything, mock.Anything, mock.Anything)
}

func TestLegalDocumentRetire_SetsRetiredAndAuditsIt(t *testing.T) {
	database := datamocks.NewDatabase(t)
	noApps(database)
	auditLogger := handlersmocks.NewAuditLogger(t)
	underItsRow(database, draftDocument(5))
	database.On("GetLegalDocumentVersionsByLegalDocumentId", mock.Anything, legalTx, int64(5)).Return(publishedVersions(5, 1), nil).Once()
	var saved *record.LegalDocument
	database.On("UpdateLegalDocument", mock.Anything, legalTx, mock.Anything).
		Run(func(args mock.Arguments) { saved = args.Get(2).(*record.LegalDocument) }).Return(nil).Once()
	auditLogger.On("Log", mock.Anything, audit.EventRetiredLegalDocument, map[string]interface{}{
		"legal_document_id": int64(5), "short_name": "terms", "logged_in_user": legalCaller,
	}).Once()

	status, body := serveLegal(HandleLegalDocumentRetirePost(database, auditLogger), legalRequest(t, http.MethodPost, nil, "id", "5"))

	require.Equal(t, http.StatusOK, status)
	assert.True(t, saved.IsRetired())
	assert.True(t, saved.HasDraft(), "retiring keeps the draft")
	assert.Equal(t, true, body["legalDocument"].(map[string]any)["retired"])
}

func TestLegalDocumentRetire_AnAlreadyRetiredDocumentIsRefused(t *testing.T) {
	database := datamocks.NewDatabase(t)
	noApps(database)
	doc := draftDocument(5)
	doc.RetiredAt = sql.NullTime{Time: time.Now(), Valid: true}
	underItsRow(database, doc)

	status, body := serveLegal(HandleLegalDocumentRetirePost(database, handlersmocks.NewAuditLogger(t)),
		legalRequest(t, http.MethodPost, nil, "id", "5"))

	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "handler.legal_document.already_retired", errorCode(body))
}

func TestLegalDocumentRestore(t *testing.T) {
	t.Run("a document that is not retired is refused", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		noApps(database)
		underItsRow(database, draftDocument(5))

		status, body := serveLegal(HandleLegalDocumentRestorePost(database, handlersmocks.NewAuditLogger(t)),
			legalRequest(t, http.MethodPost, nil, "id", "5"))

		assert.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, "handler.legal_document.not_retired", errorCode(body))
		database.AssertNotCalled(t, "UpdateLegalDocument", mock.Anything, mock.Anything, mock.Anything)
	})
	t.Run("a retired document is restored and audited", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		noApps(database)
		auditLogger := handlersmocks.NewAuditLogger(t)
		doc := draftDocument(5)
		doc.RetiredAt = sql.NullTime{Time: time.Now(), Valid: true}
		underItsRow(database, doc)
		database.On("GetLegalDocumentVersionsByLegalDocumentId", mock.Anything, legalTx, int64(5)).Return(publishedVersions(5, 1), nil).Once()
		var saved *record.LegalDocument
		database.On("UpdateLegalDocument", mock.Anything, legalTx, mock.Anything).
			Run(func(args mock.Arguments) { saved = args.Get(2).(*record.LegalDocument) }).Return(nil).Once()
		auditLogger.On("Log", mock.Anything, audit.EventRestoredLegalDocument, map[string]interface{}{
			"legal_document_id": int64(5), "short_name": "terms", "logged_in_user": legalCaller,
		}).Once()

		status, _ := serveLegal(HandleLegalDocumentRestorePost(database, auditLogger), legalRequest(t, http.MethodPost, nil, "id", "5"))

		require.Equal(t, http.StatusOK, status)
		assert.False(t, saved.IsRetired())
	})
}

func TestLegalDocumentDelete_APublishedDocumentIsKept(t *testing.T) {
	database := datamocks.NewDatabase(t)
	noApps(database)
	underItsRow(database, draftDocument(5))
	database.On("GetLegalDocumentVersionsByLegalDocumentId", mock.Anything, legalTx, int64(5)).Return(publishedVersions(5, 1), nil).Once()

	status, body := serveLegal(HandleLegalDocumentDelete(database, handlersmocks.NewAuditLogger(t)),
		legalRequest(t, http.MethodDelete, nil, "id", "5"))

	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "handler.legal_document.published_not_deleted", errorCode(body))
	database.AssertNotCalled(t, "DeleteLegalDocument", mock.Anything, mock.Anything, mock.Anything)
}

func TestLegalDocumentDelete_ANeverPublishedDocumentIsDeleted(t *testing.T) {
	database := datamocks.NewDatabase(t)
	noApps(database)
	auditLogger := handlersmocks.NewAuditLogger(t)
	underItsRow(database, draftDocument(5))
	database.On("GetLegalDocumentVersionsByLegalDocumentId", mock.Anything, legalTx, int64(5)).Return(nil, nil).Once()
	database.On("DeleteLegalDocument", mock.Anything, legalTx, int64(5)).Return(nil).Once()
	auditLogger.On("Log", mock.Anything, audit.EventDeletedLegalDocument, map[string]interface{}{
		"legal_document_id": int64(5), "short_name": "terms", "logged_in_user": legalCaller,
	}).Once()

	status, body := serveLegal(HandleLegalDocumentDelete(database, auditLogger), legalRequest(t, http.MethodDelete, nil, "id", "5"))

	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, true, body["success"])
}

// --- reads --------------------------------------------------------------------------------------

func TestLegalDocumentVersionGet(t *testing.T) {
	t.Run("a version reads with its text", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		noApps(database)
		database.On("GetLegalDocumentById", mock.Anything, mock.Anything, int64(5)).Return(draftDocument(5), nil).Once()
		database.On("GetLegalDocumentVersionsByLegalDocumentId", mock.Anything, mock.Anything, int64(5)).Return(publishedVersions(5, 2), nil).Once()
		version := publishedVersions(5, 2)[0]
		database.On("GetLegalDocumentVersion", mock.Anything, mock.Anything, int64(5), 1).Return(&version, nil).Once()

		status, body := serveLegal(HandleLegalDocumentVersionGet(database), legalRequest(t, http.MethodGet, nil, "id", "5", "version", "1"))

		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, map[string]any{"version": float64(1), "title": "Terms", "markdown": "Text",
			"publishedAt": "2026-10-01T09:00:00Z"}, body["version"])
		assert.InDelta(t, 2, body["legalDocument"].(map[string]any)["currentVersion"], 0)
	})
	t.Run("a number never published is 404", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		noApps(database)
		database.On("GetLegalDocumentById", mock.Anything, mock.Anything, int64(5)).Return(draftDocument(5), nil).Once()
		database.On("GetLegalDocumentVersion", mock.Anything, mock.Anything, int64(5), 3).Return(nil, nil).Once()

		status, body := serveLegal(HandleLegalDocumentVersionGet(database), legalRequest(t, http.MethodGet, nil, "id", "5", "version", "3"))

		assert.Equal(t, http.StatusNotFound, status)
		assert.Equal(t, "NOT_FOUND", errorCode(body))
	})
	for _, bad := range []string{"0", "-1", "x", "1.5"} {
		t.Run("version "+bad+" is a bad request", func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			noApps(database)

			status, body := serveLegal(HandleLegalDocumentVersionGet(database), legalRequest(t, http.MethodGet, nil, "id", "5", "version", bad))

			assert.Equal(t, http.StatusBadRequest, status)
			assert.Equal(t, "VALIDATION_ERROR", errorCode(body))
		})
	}
}

func TestLegalDocumentGet_AnInvalidIdIsABadRequest(t *testing.T) {
	database := datamocks.NewDatabase(t)
	noApps(database)

	status, body := serveLegal(HandleLegalDocumentGet(database), legalRequest(t, http.MethodGet, nil, "id", "abc"))

	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "VALIDATION_ERROR", errorCode(body))
}

func TestLegalDocumentsGet_ListsEachWithItsCurrentVersion(t *testing.T) {
	database := datamocks.NewDatabase(t)
	noApps(database)
	unpublished := draftDocument(6)
	unpublished.ShortName = "privacy"
	unpublished.DraftTitle = sql.NullString{String: "Privacy notice", Valid: true}
	database.On("GetAllLegalDocuments", mock.Anything, mock.Anything).Return([]record.LegalDocument{*draftDocument(5), *unpublished}, nil).Once()
	database.On("GetLegalDocumentVersionsByLegalDocumentId", mock.Anything, mock.Anything, int64(5)).Return(publishedVersions(5, 2), nil).Once()
	database.On("GetLegalDocumentVersionsByLegalDocumentId", mock.Anything, mock.Anything, int64(6)).Return(nil, nil).Once()

	status, body := serveLegal(HandleLegalDocumentsGet(database), legalRequest(t, http.MethodGet, nil))

	require.Equal(t, http.StatusOK, status)
	list := body["legalDocuments"].([]any)
	require.Len(t, list, 2)
	first, second := list[0].(map[string]any), list[1].(map[string]any)
	assert.Equal(t, "Terms", first["title"], "a published document is named by its current version")
	assert.InDelta(t, 2, first["currentVersion"], 0)
	assert.Equal(t, "Privacy notice", second["title"], "a never-published one by its draft")
	assert.InDelta(t, 0, second["currentVersion"], 0)
}

func TestLegalDocumentsGet_NoDocumentsIsAnEmptyList(t *testing.T) {
	database := datamocks.NewDatabase(t)
	noApps(database)
	database.On("GetAllLegalDocuments", mock.Anything, mock.Anything).Return(nil, nil).Once()

	rr := httptest.NewRecorder()
	HandleLegalDocumentsGet(database).ServeHTTP(rr, legalRequest(t, http.MethodGet, nil))

	require.Equal(t, http.StatusOK, rr.Code)
	assert.JSONEq(t, `{"legalDocuments":[]}`, rr.Body.String())
}

// --- preview ------------------------------------------------------------------------------------

func TestLegalDocumentPreview_RendersAsThePublishedPageWould(t *testing.T) {
	status, body := serveLegal(HandleLegalDocumentPreviewPost(), legalRequest(t, http.MethodPost,
		map[string]any{"markdown": "# Terms\n\n<script>alert(1)</script>\n\n![logo](https://cdn.example/logo.png)\n"}))

	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, "<h2>Terms</h2>\n<!-- raw HTML omitted -->\n<p><a href=\"https://cdn.example/logo.png\">logo</a></p>\n", body["html"])
}

func TestLegalDocumentPreview_TheTextIsBounded(t *testing.T) {
	status, body := serveLegal(HandleLegalDocumentPreviewPost(), legalRequest(t, http.MethodPost,
		map[string]any{"markdown": strings.Repeat("a", 100_001)}))

	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "handler.legal_document.markdown_too_long", errorCode(body))
}

func TestLegalDocumentPreview_AnUnreadableBodyIsABadRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/legal-documents/preview", strings.NewReader("{"))

	status, body := serveLegal(HandleLegalDocumentPreviewPost(), req)

	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "INVALID_REQUEST_BODY", errorCode(body))
}
