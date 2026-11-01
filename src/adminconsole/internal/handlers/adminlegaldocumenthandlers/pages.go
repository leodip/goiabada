package adminlegaldocumenthandlers

import (
	"context"
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/sessionstore"
)

// The two tabs of one document's pages, which every page of a document draws with its header: the
// draft, edited beside its preview, and the published versions.

// legalDocumentReader reads one document with its draft and versions.
type legalDocumentReader interface {
	GetLegalDocumentById(ctx context.Context, accessToken string, legalDocumentId int64) (*api.LegalDocumentDetailResponse, error)
}

// legalDocumentTextReader is legalDocumentReader with the text of one version, which the editor
// opens on when the document holds no draft.
type legalDocumentTextReader interface {
	legalDocumentReader
	GetLegalDocumentVersion(ctx context.Context, accessToken string, legalDocumentId int64, version int) (*api.GetLegalDocumentVersionResponse, error)
}

// accessToken answers the bearer the request carries, answering the request when it carries none,
// which is a wiring defect: every one of these routes is mounted under RequiresScope.
func accessToken(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request) (string, bool) {
	jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
	if !ok {
		httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
		return "", false
	}
	return jwtInfo.TokenResponse.AccessToken, true
}

// loadLegalDocument reads the document the path names, answering the request when it cannot: not
// found for an address naming no document, and what the API's failure classifies as.
func loadLegalDocument(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request, apiClient legalDocumentReader,
	token string) (*api.LegalDocumentDetailResponse, bool) {
	id, ok := legalDocumentId(r)
	if !ok {
		httpHelper.NotFound(w, r)
		return nil, false
	}
	detail, err := apiClient.GetLegalDocumentById(r.Context(), token, id)
	if err != nil {
		render.HandleAPIError(httpHelper, w, r, err)
		return nil, false
	}
	return detail, true
}

// draftText is the text the editor opens on: the draft when there is one, and otherwise the
// current version's, which saving starts a draft from.
func draftText(ctx context.Context, apiClient legalDocumentTextReader, token string,
	detail *api.LegalDocumentDetailResponse) (title, markdown string, err error) {
	if detail.Draft != nil {
		return detail.Draft.Title, detail.Draft.Markdown, nil
	}
	if detail.LegalDocument.CurrentVersion == 0 {
		return detail.LegalDocument.Title, "", nil
	}
	current, err := apiClient.GetLegalDocumentVersion(ctx, token, detail.LegalDocument.Id, detail.LegalDocument.CurrentVersion)
	if err != nil {
		return "", "", err
	}
	return current.Version.Title, current.Version.Markdown, nil
}

// draftForm is the editor's fields as they are drawn: as stored, or as typed when a save or a
// publish was refused.
type draftForm struct {
	shortName, title, markdown string
}

// renderDraft draws the editor of the document with form in its fields and extra beside them, the
// flash or the refusal.
func renderDraft(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request, detail *api.LegalDocumentDetailResponse,
	form draftForm, extra map[string]interface{}) {
	doc := detail.LegalDocument
	bind := map[string]interface{}{
		"doc":            doc,
		"shortName":      form.shortName,
		"title":          form.title,
		"markdown":       form.markdown,
		"hasDraft":       detail.Draft != nil,
		"shortNameFixed": doc.CurrentVersion > 0,
		"nextVersion":    doc.CurrentVersion + 1,
		"mustAccept":     doc.Kind == kindMustAccept,
	}
	for k, v := range extra {
		bind[k] = v
	}
	if err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_legal_documents_draft.html", bind); err != nil {
		httpHelper.InternalServerError(w, r, err)
	}
}

// renderStoredDraft draws the editor with the document's text as stored, beside extra.
func renderStoredDraft(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request, apiClient legalDocumentTextReader,
	token string, detail *api.LegalDocumentDetailResponse, extra map[string]interface{}) {
	title, markdown, err := draftText(r.Context(), apiClient, token, detail)
	if err != nil {
		render.HandleAPIError(httpHelper, w, r, err)
		return
	}
	renderDraft(httpHelper, w, r, detail, draftForm{shortName: detail.LegalDocument.ShortName, title: title, markdown: markdown}, extra)
}

// renderVersions draws the versions tab of the document beside extra.
func renderVersions(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request, detail *api.LegalDocumentDetailResponse,
	extra map[string]interface{}) {
	bind := map[string]interface{}{
		"doc":        detail.LegalDocument,
		"versions":   detail.Versions,
		"mustAccept": detail.LegalDocument.Kind == kindMustAccept,
	}
	for k, v := range extra {
		bind[k] = v
	}
	if err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_legal_documents_versions.html", bind); err != nil {
		httpHelper.InternalServerError(w, r, err)
	}
}

// takeFlashes reads, and clears, the flashes named, answering the request when the session cannot
// be read or saved.
func takeFlashes(httpHelper HttpHelper, httpSession sessionstore.Store, w http.ResponseWriter, r *http.Request,
	keys ...string) (map[string]string, bool) {
	sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
	if err != nil {
		httpHelper.InternalServerError(w, r, err)
		return nil, false
	}
	taken := map[string]string{}
	for _, key := range keys {
		if value, ok := sess.TakeFlash(key); ok {
			taken[key] = value
		}
	}
	if len(taken) > 0 {
		if err := httpSession.Save(r, w, sess); err != nil {
			httpHelper.InternalServerError(w, r, err)
			return nil, false
		}
	}
	return taken, true
}

// setFlash leaves a flash for the page a write redirects to, answering the request when the
// session cannot be saved.
func setFlash(httpHelper HttpHelper, httpSession sessionstore.Store, w http.ResponseWriter, r *http.Request,
	key, value string) bool {
	sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
	if err != nil {
		httpHelper.InternalServerError(w, r, err)
		return false
	}
	sess.SetFlash(key, value)
	if err := httpSession.Save(r, w, sess); err != nil {
		httpHelper.InternalServerError(w, r, err)
		return false
	}
	return true
}
