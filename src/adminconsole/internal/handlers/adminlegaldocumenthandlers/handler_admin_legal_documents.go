package adminlegaldocumenthandlers

import (
	"context"
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
)

// legalDocumentsListAPI is what the list needs: the one read it renders.
type legalDocumentsListAPI interface {
	GetAllLegalDocuments(ctx context.Context, accessToken string) ([]api.LegalDocumentResponse, error)
}

func HandleListGet(
	httpHelper HttpHelper,
	apiClient legalDocumentsListAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		docs, err := apiClient.GetAllLegalDocuments(r.Context(), jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		bind := map[string]interface{}{
			"legalDocuments": docs,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_legal_documents.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}
