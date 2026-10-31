package adminlegaldocumenthandlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	handlersmocks "github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/sessionkeys"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/sessionstore/sessiontest"
)

// consoleBaseURL is the admin console base URL every handler in these tests is built with. It is
// not the configuration's default, so a handler building a redirect from anything but the value it
// was given cannot pass a test that reads the redirect (#441).
const consoleBaseURL = "https://console.example.test"

// fakeLegalDocumentsAPI is the admin API the legal document pages call (#622): it answers the
// document and version it holds, records each write it is asked for, and answers every write with
// writeErr when one is set.
type fakeLegalDocumentsAPI struct {
	docs    []api.LegalDocumentResponse
	detail  *api.LegalDocumentDetailResponse
	version *api.GetLegalDocumentVersionResponse
	html    string

	writeErr error

	readIds       []int64
	versionsAsked []int
	created       *api.CreateLegalDocumentRequest
	saved         *api.SaveLegalDocumentDraftRequest
	savedId       int64
	previewed     *string
	published     []int64
	retired       []int64
	restored      []int64
	deleted       []int64
}

func (f *fakeLegalDocumentsAPI) GetAllLegalDocuments(context.Context, string) ([]api.LegalDocumentResponse, error) {
	return f.docs, nil
}

func (f *fakeLegalDocumentsAPI) CreateLegalDocument(_ context.Context, _ string,
	request *api.CreateLegalDocumentRequest) (*api.LegalDocumentDetailResponse, error) {
	f.created = request
	if f.writeErr != nil {
		return nil, f.writeErr
	}
	return &api.LegalDocumentDetailResponse{LegalDocument: api.LegalDocumentResponse{Id: 9, ShortName: request.ShortName}}, nil
}

func (f *fakeLegalDocumentsAPI) PreviewLegalDocument(_ context.Context, _ string, markdown string) (string, error) {
	f.previewed = &markdown
	if f.writeErr != nil {
		return "", f.writeErr
	}
	return f.html, nil
}

func (f *fakeLegalDocumentsAPI) GetLegalDocumentById(_ context.Context, _ string, id int64) (*api.LegalDocumentDetailResponse, error) {
	f.readIds = append(f.readIds, id)
	if f.detail == nil {
		return nil, &apiclient.APIError{Code: "NOT_FOUND", Message: "Legal document not found", StatusCode: http.StatusNotFound}
	}
	return f.detail, nil
}

func (f *fakeLegalDocumentsAPI) SaveLegalDocumentDraft(_ context.Context, _ string, id int64,
	request *api.SaveLegalDocumentDraftRequest) (*api.LegalDocumentDetailResponse, error) {
	f.savedId, f.saved = id, request
	if f.writeErr != nil {
		return nil, f.writeErr
	}
	return f.detail, nil
}

func (f *fakeLegalDocumentsAPI) PublishLegalDocument(_ context.Context, _ string, id int64) (*api.LegalDocumentDetailResponse, error) {
	f.published = append(f.published, id)
	if f.writeErr != nil {
		return nil, f.writeErr
	}
	published := *f.detail
	published.LegalDocument.CurrentVersion++
	return &published, nil
}

func (f *fakeLegalDocumentsAPI) RetireLegalDocument(_ context.Context, _ string, id int64) (*api.LegalDocumentDetailResponse, error) {
	f.retired = append(f.retired, id)
	if f.writeErr != nil {
		return nil, f.writeErr
	}
	return f.detail, nil
}

func (f *fakeLegalDocumentsAPI) RestoreLegalDocument(_ context.Context, _ string, id int64) (*api.LegalDocumentDetailResponse, error) {
	f.restored = append(f.restored, id)
	if f.writeErr != nil {
		return nil, f.writeErr
	}
	return f.detail, nil
}

func (f *fakeLegalDocumentsAPI) DeleteLegalDocument(_ context.Context, _ string, id int64) error {
	f.deleted = append(f.deleted, id)
	return f.writeErr
}

func (f *fakeLegalDocumentsAPI) GetLegalDocumentVersion(_ context.Context, _ string, _ int64,
	version int) (*api.GetLegalDocumentVersionResponse, error) {
	f.versionsAsked = append(f.versionsAsked, version)
	if f.version == nil {
		return nil, &apiclient.APIError{Code: "NOT_FOUND", Message: "Legal document version not found", StatusCode: http.StatusNotFound}
	}
	return f.version, nil
}

// refusal is an admin API refusal of a value, as the API answers it: 400, the catalog key, and its
// sentence.
func refusal(code, message string) error {
	return &apiclient.APIError{Code: code, Message: message, StatusCode: http.StatusBadRequest}
}

// publishedTerms is a must-accept document at version 2 with no draft.
func publishedTerms() *api.LegalDocumentDetailResponse {
	return &api.LegalDocumentDetailResponse{
		LegalDocument: api.LegalDocumentResponse{Id: 7, ShortName: "terms-of-use", Kind: "must_accept",
			Title: "Terms of use", CurrentVersion: 2},
		Versions: []api.LegalDocumentVersionSummaryResponse{{Version: 1, Title: "Terms"}, {Version: 2, Title: "Terms of use"}},
	}
}

// draftPrivacy is a for-information document that was never published, holding its draft.
func draftPrivacy() *api.LegalDocumentDetailResponse {
	return &api.LegalDocumentDetailResponse{
		LegalDocument: api.LegalDocumentResponse{Id: 7, ShortName: "privacy", Kind: "for_information",
			Title: "Privacy notice", HasDraft: true},
		Draft:    &api.LegalDocumentDraftResponse{Title: "Privacy notice", Markdown: "We keep your email."},
		Versions: []api.LegalDocumentVersionSummaryResponse{},
	}
}

func newSessionStore(t *testing.T) sessionstore.Store {
	t.Helper()
	store, err := sessionstore.NewServerSideStore(sessiontest.NewMemoryBackend(), sessionkeys.JWT, false,
		sessionstore.BrowserSessionCookie, sessionstore.KeyPair{
			AuthenticationKey: []byte("12345678901234567890123456789012"),
			EncryptionKey:     []byte("abcdefghijklmnopqrstuvwxyz123456"),
		}, nil)
	require.NoError(t, err)
	return store
}

// pageHelper is the HttpHelper mock admitting one page and refusing a 500.
func pageHelper(t *testing.T, template string) *handlersmocks.HttpHelper {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", template).Once()
	return httpHelper
}

// withCookies carries the cookies a response set onto the next request, as a browser following its
// redirect does.
func withCookies(req *http.Request, from *httptest.ResponseRecorder) *http.Request {
	for _, cookie := range from.Result().Cookies() {
		req.AddCookie(cookie)
	}
	return req
}

func TestHandleListGet_ListsTheDocuments(t *testing.T) {
	httpHelper := pageHelper(t, "/admin_legal_documents.html")
	fake := &fakeLegalDocumentsAPI{docs: []api.LegalDocumentResponse{{Id: 7, ShortName: "terms-of-use"}, {Id: 8, ShortName: "privacy"}}}

	HandleListGet(httpHelper, fake).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodGet, "/admin/legal-documents", handlertest.WithAccessToken()))

	assert.Equal(t, fake.docs, handlertest.Bind(t, httpHelper)["legalDocuments"])
}

// A new document is created with the kind chosen and its title and short name trimmed, holding an
// empty draft, and the console opens that draft, where its text is written.
func TestHandleNewPost_CreatesTheDocumentAndOpensItsDraft(t *testing.T) {
	fake := &fakeLegalDocumentsAPI{}
	rec := httptest.NewRecorder()

	HandleNewPost(render.New(nil, nil), fake, consoleBaseURL).ServeHTTP(rec,
		handlertest.Request(http.MethodPost, "/admin/legal-documents/new", handlertest.WithAccessToken(),
			handlertest.WithForm(url.Values{"kind": {"must_accept"}, "title": {"  Terms of use  "}, "shortName": {" terms-of-use "}})))

	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
	assert.Equal(t, consoleBaseURL+"/admin/legal-documents/9/draft", rec.Header().Get("Location"))
	require.NotNil(t, fake.created)
	assert.Equal(t, api.CreateLegalDocumentRequest{Kind: "must_accept", ShortName: "terms-of-use", Title: "Terms of use"}, *fake.created)
}

// A refused document is drawn again with what was typed, the kind chosen included, and the field the
// refusal is about named, so it is marked and focused.
func TestHandleNewPost_ARefusalKeepsWhatWasTypedAndNamesItsField(t *testing.T) {
	for _, tc := range []struct {
		code, field string
	}{
		{i18n.ErrCodeLegalDocumentKindInvalid, "kind"},
		{i18n.ErrCodeLegalDocumentShortNameInUse, "shortName"},
		{i18n.ErrCodeLegalDocumentShortNameInvalid, "shortName"},
		{i18n.ErrCodeLegalDocumentShortNameRequired, "shortName"},
		{i18n.ErrCodeLegalDocumentShortNameTooLong, "shortName"},
		{i18n.ErrCodeLegalDocumentTitleRequired, "title"},
		{i18n.ErrCodeLegalDocumentTitleTooLong, "title"},
	} {
		t.Run(tc.code, func(t *testing.T) {
			httpHelper := pageHelper(t, "/admin_legal_documents_new.html")
			fake := &fakeLegalDocumentsAPI{writeErr: refusal(tc.code, "the API's sentence")}

			HandleNewPost(httpHelper, fake, consoleBaseURL).ServeHTTP(httptest.NewRecorder(),
				handlertest.Request(http.MethodPost, "/admin/legal-documents/new", handlertest.WithAccessToken(),
					handlertest.WithForm(url.Values{"kind": {"for_information"}, "title": {"Privacy"}, "shortName": {"Privacy!"}})))

			bind := handlertest.Bind(t, httpHelper)
			assert.Equal(t, "the API's sentence", bind["error"])
			assert.Equal(t, tc.field, bind["errorField"])
			assert.Equal(t, "for_information", bind["kind"])
			assert.Equal(t, "Privacy", bind["title"])
			assert.Equal(t, "Privacy!", bind["shortName"])
		})
	}
}

// The editor opens on the draft when the document holds one, and reads no version for it.
func TestHandleDraftGet_OpensOnTheDraft(t *testing.T) {
	httpHelper := pageHelper(t, "/admin_legal_documents_draft.html")
	detail := publishedTerms()
	detail.LegalDocument.HasDraft = true
	detail.Draft = &api.LegalDocumentDraftResponse{Title: "Terms of use (2027)", Markdown: "New *terms*."}
	fake := &fakeLegalDocumentsAPI{detail: detail}

	HandleDraftGet(httpHelper, newSessionStore(t), fake).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodGet, "/admin/legal-documents/7/draft", handlertest.WithAccessToken(),
			handlertest.WithPathValue("legalDocumentId", "7")))

	bind := handlertest.Bind(t, httpHelper)
	assert.Equal(t, []int64{7}, fake.readIds)
	assert.Empty(t, fake.versionsAsked)
	assert.Equal(t, "Terms of use (2027)", bind["title"])
	assert.Equal(t, "New *terms*.", bind["markdown"])
	assert.Equal(t, "terms-of-use", bind["shortName"])
	assert.Equal(t, true, bind["hasDraft"])
	assert.Equal(t, true, bind["shortNameFixed"], "a published document's short name is fixed")
	assert.Equal(t, 3, bind["nextVersion"])
}

// With no draft, the editor opens on the current version's text, which saving starts a draft from.
func TestHandleDraftGet_WithNoDraftOpensOnTheCurrentVersionsText(t *testing.T) {
	httpHelper := pageHelper(t, "/admin_legal_documents_draft.html")
	fake := &fakeLegalDocumentsAPI{detail: publishedTerms(), version: &api.GetLegalDocumentVersionResponse{
		Version: api.LegalDocumentVersionResponse{Version: 2, Title: "Terms of use", Markdown: "Current *terms*."}}}

	HandleDraftGet(httpHelper, newSessionStore(t), fake).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodGet, "/admin/legal-documents/7/draft", handlertest.WithAccessToken(),
			handlertest.WithPathValue("legalDocumentId", "7")))

	bind := handlertest.Bind(t, httpHelper)
	assert.Equal(t, []int{2}, fake.versionsAsked)
	assert.Equal(t, "Terms of use", bind["title"])
	assert.Equal(t, "Current *terms*.", bind["markdown"])
	assert.Equal(t, false, bind["hasDraft"])
}

// A never-published document's short name can still change: the save sends it, the text as the
// browser posted it with its line breaks as newlines, and the editor then says the draft was saved.
func TestHandleDraftPost_SavesTheDraftAndSaysSo(t *testing.T) {
	store := newSessionStore(t)
	fake := &fakeLegalDocumentsAPI{detail: draftPrivacy()}
	rec := httptest.NewRecorder()

	HandleDraftPost(render.New(nil, nil), store, fake, consoleBaseURL).ServeHTTP(rec,
		handlertest.Request(http.MethodPost, "/admin/legal-documents/7/draft", handlertest.WithAccessToken(),
			handlertest.WithPathValue("legalDocumentId", "7"),
			handlertest.WithForm(url.Values{"shortName": {" privacy-notice "}, "title": {" Privacy notice "},
				"markdown": {"# Privacy\r\n\r\nWe keep your email.\r\n"}})))

	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
	assert.Equal(t, consoleBaseURL+"/admin/legal-documents/7/draft", rec.Header().Get("Location"))
	assert.Equal(t, int64(7), fake.savedId)
	require.NotNil(t, fake.saved)
	assert.Equal(t, api.SaveLegalDocumentDraftRequest{ShortName: "privacy-notice", Title: "Privacy notice",
		Markdown: "# Privacy\n\nWe keep your email.\n"}, *fake.saved)

	httpHelper := pageHelper(t, "/admin_legal_documents_draft.html")
	HandleDraftGet(httpHelper, store, fake).ServeHTTP(httptest.NewRecorder(), withCookies(
		handlertest.Request(http.MethodGet, "/admin/legal-documents/7/draft", handlertest.WithAccessToken(),
			handlertest.WithPathValue("legalDocumentId", "7")), rec))
	assert.Equal(t, true, handlertest.Bind(t, httpHelper)["draftSaved"])
}

// Once published, the short name is fixed, so the save never sends one, whatever the form held.
func TestHandleDraftPost_APublishedDocumentsShortNameIsNotSent(t *testing.T) {
	fake := &fakeLegalDocumentsAPI{detail: publishedTerms()}
	rec := httptest.NewRecorder()

	HandleDraftPost(render.New(nil, nil), newSessionStore(t), fake, consoleBaseURL).ServeHTTP(rec,
		handlertest.Request(http.MethodPost, "/admin/legal-documents/7/draft", handlertest.WithAccessToken(),
			handlertest.WithPathValue("legalDocumentId", "7"),
			handlertest.WithForm(url.Values{"shortName": {"another-name"}, "title": {"Terms"}, "markdown": {"Be kind."}})))

	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
	require.NotNil(t, fake.saved)
	assert.Empty(t, fake.saved.ShortName)
}

// A refused save is drawn with the text as typed, so nothing written is lost, and the field named.
func TestHandleDraftPost_ARefusalKeepsTheTextAsTyped(t *testing.T) {
	httpHelper := pageHelper(t, "/admin_legal_documents_draft.html")
	fake := &fakeLegalDocumentsAPI{detail: draftPrivacy(),
		writeErr: refusal(i18n.ErrCodeLegalDocumentMarkdownTooLong, "The text is too long.")}

	HandleDraftPost(httpHelper, newSessionStore(t), fake, consoleBaseURL).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodPost, "/admin/legal-documents/7/draft", handlertest.WithAccessToken(),
			handlertest.WithPathValue("legalDocumentId", "7"),
			handlertest.WithForm(url.Values{"shortName": {"privacy"}, "title": {"Privacy"}, "markdown": {"Very long text"}})))

	bind := handlertest.Bind(t, httpHelper)
	assert.Equal(t, "The text is too long.", bind["error"])
	assert.Equal(t, "markdown", bind["errorField"])
	assert.Equal(t, "Very long text", bind["markdown"])
	assert.Equal(t, "Privacy", bind["title"])
	assert.Equal(t, "privacy", bind["shortName"])
}

// Publishing publishes the saved draft and opens the versions list, which names the new version.
func TestHandlePublishPost_PublishesAndOpensTheVersions(t *testing.T) {
	store := newSessionStore(t)
	fake := &fakeLegalDocumentsAPI{detail: publishedTerms()}
	rec := httptest.NewRecorder()

	HandlePublishPost(render.New(nil, nil), store, fake, consoleBaseURL).ServeHTTP(rec,
		handlertest.Request(http.MethodPost, "/admin/legal-documents/7/publish", handlertest.WithAccessToken(),
			handlertest.WithPathValue("legalDocumentId", "7")))

	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
	assert.Equal(t, consoleBaseURL+"/admin/legal-documents/7/versions", rec.Header().Get("Location"))
	assert.Equal(t, []int64{7}, fake.published)

	httpHelper := pageHelper(t, "/admin_legal_documents_versions.html")
	HandleVersionsGet(httpHelper, store, fake).ServeHTTP(httptest.NewRecorder(), withCookies(
		handlertest.Request(http.MethodGet, "/admin/legal-documents/7/versions", handlertest.WithAccessToken(),
			handlertest.WithPathValue("legalDocumentId", "7")), rec))
	bind := handlertest.Bind(t, httpHelper)
	assert.Equal(t, "3", bind["publishedVersion"], "the version the publish made, which the page names")
	assert.Equal(t, publishedTerms().Versions, bind["versions"])
}

// A publish the API refuses, a draft with no text for one, is said on the editor, at the text.
func TestHandlePublishPost_ARefusalIsShownOnTheDraft(t *testing.T) {
	httpHelper := pageHelper(t, "/admin_legal_documents_draft.html")
	fake := &fakeLegalDocumentsAPI{detail: draftPrivacy(),
		writeErr: refusal(i18n.ErrCodeLegalDocumentDraftEmpty, "The draft has no text to publish.")}

	HandlePublishPost(httpHelper, newSessionStore(t), fake, consoleBaseURL).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodPost, "/admin/legal-documents/7/publish", handlertest.WithAccessToken(),
			handlertest.WithPathValue("legalDocumentId", "7")))

	bind := handlertest.Bind(t, httpHelper)
	assert.Equal(t, "The draft has no text to publish.", bind["error"])
	assert.Equal(t, "markdown", bind["errorField"])
	assert.Equal(t, "We keep your email.", bind["markdown"], "the editor still shows the draft")
}

// The preview forwards the Markdown as typed and answers the auth server's rendering of it.
func TestHandlePreviewPost_AnswersTheAuthServersRendering(t *testing.T) {
	fake := &fakeLegalDocumentsAPI{html: "<h1>Privacy</h1>\n"}
	rec := httptest.NewRecorder()

	HandlePreviewPost(render.New(nil, nil), fake).ServeHTTP(rec,
		handlertest.Request(http.MethodPost, "/admin/legal-documents/preview", handlertest.WithAccessToken(),
			handlertest.WithBody(strings.NewReader(`{"markdown":"# Privacy"}`))))

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotNil(t, fake.previewed)
	assert.Equal(t, "# Privacy", *fake.previewed)
	var answer struct {
		Html string `json:"html"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &answer))
	assert.Equal(t, "<h1>Privacy</h1>\n", answer.Html)
}

// A refused preview is answered as JSON, which the editor's script shows beside the text.
func TestHandlePreviewPost_ARefusalIsAnsweredAsJSON(t *testing.T) {
	fake := &fakeLegalDocumentsAPI{writeErr: refusal(i18n.ErrCodeLegalDocumentMarkdownTooLong, "The text is too long.")}
	rec := httptest.NewRecorder()

	HandlePreviewPost(render.New(nil, nil), fake).ServeHTTP(rec,
		handlertest.Request(http.MethodPost, "/admin/legal-documents/preview", handlertest.WithAccessToken(),
			handlertest.WithBody(strings.NewReader(`{"markdown":"x"}`))))

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "The text is too long.")
}

// Retiring and restoring act on the document the path names and open its versions, saying what
// was done.
func TestHandleRetireAndRestorePost_ActOnTheDocumentAndSaySo(t *testing.T) {
	for _, tc := range []struct {
		name   string
		build  func(sessionstore.Store, *fakeLegalDocumentsAPI) http.HandlerFunc
		called func(*fakeLegalDocumentsAPI) []int64
		flash  string
	}{
		{"retire", func(s sessionstore.Store, f *fakeLegalDocumentsAPI) http.HandlerFunc {
			return HandleRetirePost(render.New(nil, nil), s, f, consoleBaseURL)
		}, func(f *fakeLegalDocumentsAPI) []int64 { return f.retired }, "retired"},
		{"restore", func(s sessionstore.Store, f *fakeLegalDocumentsAPI) http.HandlerFunc {
			return HandleRestorePost(render.New(nil, nil), s, f, consoleBaseURL)
		}, func(f *fakeLegalDocumentsAPI) []int64 { return f.restored }, "restored"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newSessionStore(t)
			fake := &fakeLegalDocumentsAPI{detail: publishedTerms()}
			rec := httptest.NewRecorder()

			tc.build(store, fake).ServeHTTP(rec, handlertest.Request(http.MethodPost, "/admin/legal-documents/7/"+tc.name,
				handlertest.WithAccessToken(), handlertest.WithPathValue("legalDocumentId", "7")))

			require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
			assert.Equal(t, consoleBaseURL+"/admin/legal-documents/7/versions", rec.Header().Get("Location"))
			assert.Equal(t, []int64{7}, tc.called(fake))

			httpHelper := pageHelper(t, "/admin_legal_documents_versions.html")
			HandleVersionsGet(httpHelper, store, fake).ServeHTTP(httptest.NewRecorder(), withCookies(
				handlertest.Request(http.MethodGet, "/admin/legal-documents/7/versions", handlertest.WithAccessToken(),
					handlertest.WithPathValue("legalDocumentId", "7")), rec))
			assert.Equal(t, true, handlertest.Bind(t, httpHelper)[tc.flash])
		})
	}
}

// A retirement the API refuses, of a document never published, is said on the versions page.
func TestHandleRetirePost_ARefusalIsShownOnTheVersions(t *testing.T) {
	httpHelper := pageHelper(t, "/admin_legal_documents_versions.html")
	fake := &fakeLegalDocumentsAPI{detail: draftPrivacy(),
		writeErr: refusal(i18n.ErrCodeLegalDocumentNotPublished, "Only a published document can be retired.")}

	HandleRetirePost(httpHelper, newSessionStore(t), fake, consoleBaseURL).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodPost, "/admin/legal-documents/7/retire", handlertest.WithAccessToken(),
			handlertest.WithPathValue("legalDocumentId", "7")))

	assert.Equal(t, "Only a published document can be retired.", handlertest.Bind(t, httpHelper)["error"])
}

// One version's page reads the version the path names.
func TestHandleVersionGet_ReadsTheVersionThePathNames(t *testing.T) {
	httpHelper := pageHelper(t, "/admin_legal_documents_version.html")
	version := &api.GetLegalDocumentVersionResponse{LegalDocument: publishedTerms().LegalDocument,
		Version: api.LegalDocumentVersionResponse{Version: 1, Title: "Terms", Markdown: "Old terms."}}
	fake := &fakeLegalDocumentsAPI{version: version}

	HandleVersionGet(httpHelper, fake).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodGet, "/admin/legal-documents/7/versions/1", handlertest.WithAccessToken(),
			handlertest.WithPathValue("legalDocumentId", "7"), handlertest.WithPathValue("version", "1")))

	bind := handlertest.Bind(t, httpHelper)
	assert.Equal(t, []int{1}, fake.versionsAsked)
	assert.Equal(t, version.Version, bind["version"])
	assert.Equal(t, version.LegalDocument, bind["doc"])
}

// An address naming no document or no version, and one the API finds nothing at, is not found.
func TestHandlers_AnAddressNamingNothingIsNotFound(t *testing.T) {
	for _, tc := range []struct {
		name   string
		build  func(HttpHelper) http.HandlerFunc
		values [][2]string
	}{
		{"draft, an id that is not a number", func(h HttpHelper) http.HandlerFunc {
			return HandleDraftGet(h, newSessionStore(t), &fakeLegalDocumentsAPI{})
		}, [][2]string{{"legalDocumentId", "seven"}}},
		{"versions, an id that is not a number", func(h HttpHelper) http.HandlerFunc {
			return HandleVersionsGet(h, newSessionStore(t), &fakeLegalDocumentsAPI{})
		}, [][2]string{{"legalDocumentId", "x"}}},
		{"version, a number that is not one", func(h HttpHelper) http.HandlerFunc {
			return HandleVersionGet(h, &fakeLegalDocumentsAPI{})
		}, [][2]string{{"legalDocumentId", "7"}, {"version", "first"}}},
		{"delete, no id", func(h HttpHelper) http.HandlerFunc {
			return HandleDeleteGet(h, &fakeLegalDocumentsAPI{})
		}, [][2]string{{"legalDocumentId", ""}}},
		{"draft, a document the API does not find", func(h HttpHelper) http.HandlerFunc {
			return HandleDraftGet(h, newSessionStore(t), &fakeLegalDocumentsAPI{})
		}, [][2]string{{"legalDocumentId", "70"}}},
		{"version, a version the API does not find", func(h HttpHelper) http.HandlerFunc {
			return HandleVersionGet(h, &fakeLegalDocumentsAPI{})
		}, [][2]string{{"legalDocumentId", "7"}, {"version", "9"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			httpHelper.On("NotFound", mock.Anything, mock.Anything).Once()
			opts := []handlertest.Option{handlertest.WithAccessToken()}
			for _, value := range tc.values {
				opts = append(opts, handlertest.WithPathValue(value[0], value[1]))
			}
			tc.build(httpHelper).ServeHTTP(httptest.NewRecorder(), handlertest.Request(http.MethodGet, "/admin/legal-documents/x", opts...))
		})
	}
}

// The delete page needs the short name typed, and deletes only the document whose short name it is.
func TestHandleDeletePost_NeedsTheShortNameTyped(t *testing.T) {
	for _, tc := range []struct {
		typed, want string
	}{
		{"", "Type the short name to confirm."},
		{"privacy-notice", "That isn't this document's short name. Type it as shown above."},
	} {
		t.Run(tc.typed, func(t *testing.T) {
			httpHelper := pageHelper(t, "/admin_legal_documents_delete.html")
			fake := &fakeLegalDocumentsAPI{detail: draftPrivacy()}

			HandleDeletePost(httpHelper, fake, consoleBaseURL).ServeHTTP(httptest.NewRecorder(),
				handlertest.Request(http.MethodPost, "/admin/legal-documents/7/delete", handlertest.WithAccessToken(),
					handlertest.WithPathValue("legalDocumentId", "7"), handlertest.WithForm(url.Values{"shortName": {tc.typed}})))

			assert.Equal(t, tc.want, handlertest.Bind(t, httpHelper)["error"])
			assert.Empty(t, fake.deleted)
		})
	}

	t.Run("the document's short name", func(t *testing.T) {
		fake := &fakeLegalDocumentsAPI{detail: draftPrivacy()}
		rec := httptest.NewRecorder()

		HandleDeletePost(render.New(nil, nil), fake, consoleBaseURL).ServeHTTP(rec,
			handlertest.Request(http.MethodPost, "/admin/legal-documents/7/delete", handlertest.WithAccessToken(),
				handlertest.WithPathValue("legalDocumentId", "7"), handlertest.WithForm(url.Values{"shortName": {"privacy"}})))

		require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
		assert.Equal(t, consoleBaseURL+"/admin/legal-documents", rec.Header().Get("Location"))
		assert.Equal(t, []int64{7}, fake.deleted)
	})
}

// A published document is retired, never deleted: its delete page says so and offers no deletion.
func TestHandleDeleteGet_APublishedDocumentIsNotOfferedForDeletion(t *testing.T) {
	for _, tc := range []struct {
		name      string
		detail    *api.LegalDocumentDetailResponse
		published bool
	}{
		{"never published", draftPrivacy(), false},
		{"published", publishedTerms(), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := pageHelper(t, "/admin_legal_documents_delete.html")

			HandleDeleteGet(httpHelper, &fakeLegalDocumentsAPI{detail: tc.detail}).ServeHTTP(httptest.NewRecorder(),
				handlertest.Request(http.MethodGet, "/admin/legal-documents/7/delete", handlertest.WithAccessToken(),
					handlertest.WithPathValue("legalDocumentId", "7")))

			assert.Equal(t, tc.published, handlertest.Bind(t, httpHelper)["published"])
		})
	}
}
