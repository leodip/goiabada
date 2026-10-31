package adminlegaldocumenthandlers

import (
	"context"
	"fmt"
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"
)

// legalDocumentDeleteAPI is what the delete page needs: the document it confirms, and the delete.
type legalDocumentDeleteAPI interface {
	legalDocumentReader
	DeleteLegalDocument(ctx context.Context, accessToken string, legalDocumentId int64) error
}

// renderDelete draws the delete confirmation of the document beside extra. A published document is
// never deleted, so the record of what users accepted is kept: its page says to retire it instead
// and offers no deletion.
func renderDelete(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request, doc api.LegalDocumentResponse,
	extra map[string]interface{}) {
	bind := map[string]interface{}{
		"doc":        doc,
		"published":  doc.CurrentVersion > 0,
		"mustAccept": doc.Kind == kindMustAccept,
	}
	for k, v := range extra {
		bind[k] = v
	}
	if err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_legal_documents_delete.html", bind); err != nil {
		httpHelper.InternalServerError(w, r, err)
	}
}

func HandleDeleteGet(
	httpHelper HttpHelper,
	apiClient legalDocumentReader,
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

		renderDelete(httpHelper, w, r, detail.LegalDocument, nil)
	}
}

// HandleDeletePost deletes a document never published, once its short name is typed. The API
// refuses a published one, whatever the page offered.
func HandleDeletePost(
	httpHelper HttpHelper,
	apiClient legalDocumentDeleteAPI,
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

		renderError := func(message string) {
			renderDelete(httpHelper, w, r, doc, map[string]interface{}{"error": message})
		}

		typed := r.PostFormValue("shortName")
		if typed == "" {
			renderError(i18n.T(r.Context(), "adminconsole.refusal.legal_document_delete.short_name_required"))
			return
		}
		if typed != doc.ShortName {
			renderError(i18n.T(r.Context(), "adminconsole.refusal.legal_document_delete.short_name_mismatch"))
			return
		}

		if err := apiClient.DeleteLegalDocument(r.Context(), token, doc.Id); err != nil {
			render.HandleAPIErrorWithCallback(httpHelper, w, r, err, renderError)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("%v/admin/legal-documents", baseURL), http.StatusFound)
	}
}
