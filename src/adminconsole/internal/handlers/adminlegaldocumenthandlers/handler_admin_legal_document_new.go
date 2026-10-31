package adminlegaldocumenthandlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
)

func HandleNewGet(
	httpHelper HttpHelper,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// No kind is chosen for the administrator: which one a document is cannot change later.
		bind := map[string]interface{}{
			"kind":      "",
			"title":     "",
			"shortName": "",
		}

		err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_legal_documents_new.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

// legalDocumentNewAPI is what the new document page needs: the one write it makes.
type legalDocumentNewAPI interface {
	CreateLegalDocument(ctx context.Context, accessToken string, request *api.CreateLegalDocumentRequest) (*api.LegalDocumentDetailResponse, error)
}

// HandleNewPost creates the document holding an empty draft, and opens that draft, where its text
// is written beside the preview.
func HandleNewPost(
	httpHelper HttpHelper,
	apiClient legalDocumentNewAPI,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		kind := r.PostFormValue("kind")
		title := strings.TrimSpace(r.PostFormValue("title"))
		shortName := strings.TrimSpace(r.PostFormValue("shortName"))

		// A refused document is drawn with every input as submitted, the kind chosen included.
		renderError := func(message, errorField string) {
			bind := map[string]interface{}{
				"error":      message,
				"errorField": errorField,
				"kind":       kind,
				"title":      title,
				"shortName":  shortName,
			}
			if err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_legal_documents_new.html", bind); err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		created, err := apiClient.CreateLegalDocument(r.Context(), jwtInfo.TokenResponse.AccessToken, &api.CreateLegalDocumentRequest{
			Kind:      kind,
			ShortName: shortName,
			Title:     title,
		})
		if err != nil {
			render.HandleAPIErrorWithCallback(httpHelper, w, r, err, func(message string) {
				renderError(message, render.ErrorField(err, legalDocumentErrorFields))
			})
			return
		}

		http.Redirect(w, r, fmt.Sprintf("%v/admin/legal-documents/%v/draft", baseURL, created.LegalDocument.Id), http.StatusFound)
	}
}
