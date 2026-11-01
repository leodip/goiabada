package adminlegaldocumenthandlers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/sessionstore"
)

func HandleDraftGet(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient legalDocumentTextReader,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		token, ok := accessToken(httpHelper, w, r)
		if !ok {
			return
		}
		detail, ok := loadLegalDocument(httpHelper, w, r, apiClient, token)
		if !ok {
			return
		}
		flashes, ok := takeFlashes(httpHelper, httpSession, w, r, flashDraftSaved)
		if !ok {
			return
		}

		_, draftSaved := flashes[flashDraftSaved]
		renderStoredDraft(httpHelper, w, r, apiClient, token, detail, map[string]interface{}{"draftSaved": draftSaved})
	}
}

// legalDocumentDraftAPI is what the editor's save needs: the document, which a refusal is drawn
// with, and the write.
type legalDocumentDraftAPI interface {
	legalDocumentReader
	SaveLegalDocumentDraft(ctx context.Context, accessToken string, legalDocumentId int64, request *api.SaveLegalDocumentDraftRequest) (*api.LegalDocumentDetailResponse, error)
}

// HandleDraftPost saves the editor's fields as the document's one draft, which replaces the draft
// it held or starts one. The short name goes with it only until the document is first published:
// from then on it is fixed, so links to its public page keep working.
func HandleDraftPost(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient legalDocumentDraftAPI,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		token, ok := accessToken(httpHelper, w, r)
		if !ok {
			return
		}
		detail, ok := loadLegalDocument(httpHelper, w, r, apiClient, token)
		if !ok {
			return
		}
		doc := detail.LegalDocument

		form := draftForm{
			shortName: strings.TrimSpace(r.PostFormValue("shortName")),
			title:     strings.TrimSpace(r.PostFormValue("title")),
			markdown:  postedMarkdown(r),
		}
		request := &api.SaveLegalDocumentDraftRequest{ShortName: form.shortName, Title: form.title, Markdown: form.markdown}
		if doc.CurrentVersion > 0 {
			request.ShortName = ""
			form.shortName = doc.ShortName
		}

		_, err := apiClient.SaveLegalDocumentDraft(r.Context(), token, doc.Id, request)
		if err != nil {
			render.HandleAPIErrorWithCallback(httpHelper, w, r, err, func(message string) {
				renderDraft(httpHelper, w, r, detail, form, map[string]interface{}{
					"error":      message,
					"errorField": render.ErrorField(err, legalDocumentErrorFields),
				})
			})
			return
		}

		if !setFlash(httpHelper, httpSession, w, r, flashDraftSaved, "true") {
			return
		}
		http.Redirect(w, r, fmt.Sprintf("%v/admin/legal-documents/%v/draft", baseURL, doc.Id), http.StatusFound)
	}
}

// legalDocumentPublishAPI is what Publish needs: the document and its text, which a refusal is
// drawn with, and the write.
type legalDocumentPublishAPI interface {
	legalDocumentTextReader
	PublishLegalDocument(ctx context.Context, accessToken string, legalDocumentId int64) (*api.LegalDocumentDetailResponse, error)
}

// HandlePublishPost publishes the document's saved draft as its next version and opens the
// versions, which name the one published. A refusal is said on the editor.
func HandlePublishPost(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient legalDocumentPublishAPI,
	settingsCache publicSettingsCache,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		token, ok := accessToken(httpHelper, w, r)
		if !ok {
			return
		}
		detail, ok := loadLegalDocument(httpHelper, w, r, apiClient, token)
		if !ok {
			return
		}

		published, err := apiClient.PublishLegalDocument(r.Context(), token, detail.LegalDocument.Id)
		if err != nil {
			render.HandleAPIErrorWithCallback(httpHelper, w, r, err, func(message string) {
				renderStoredDraft(httpHelper, w, r, apiClient, token, detail, map[string]interface{}{
					"error":      message,
					"errorField": render.ErrorField(err, legalDocumentErrorFields),
				})
			})
			return
		}
		settingsCache.Invalidate()

		if !setFlash(httpHelper, httpSession, w, r, flashPublished, strconv.Itoa(published.LegalDocument.CurrentVersion)) {
			return
		}
		http.Redirect(w, r, fmt.Sprintf("%v/admin/legal-documents/%v/versions", baseURL, detail.LegalDocument.Id), http.StatusFound)
	}
}
