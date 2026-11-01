package accounthandlers

import (
	"context"
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
)

// accountLegalDocumentsAPI is what the Legal documents page needs: the versions the user accepted.
type accountLegalDocumentsAPI interface {
	GetAccountLegalDocumentAcceptances(ctx context.Context, accessToken string) ([]api.LegalDocumentAcceptanceResponse, error)
}

// HandleLegalDocumentsGet draws the legal documents the user accepted, the latest first, each
// linked to its version's public page, or marked no longer in effect when its document is retired
// (#622 decision 10). It only reads: acceptances are never edited or removed by hand.
func HandleLegalDocumentsGet(
	httpHelper HttpHelper,
	apiClient accountLegalDocumentsAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		acceptances, err := apiClient.GetAccountLegalDocumentAcceptances(r.Context(), jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		bind := map[string]interface{}{
			"acceptances": acceptances,
		}

		if err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_legal_documents.html", bind); err != nil {
			httpHelper.InternalServerError(w, r, err)
		}
	}
}
