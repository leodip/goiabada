package adminclienthandlers

import (
	"context"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
)

// A client's Legal documents tab lists, read only, the legal documents that apply to it (#622):
// every document not retired that applies to all apps or lists the client. A document's apps are
// chosen on the document's own Applies to tab, in the Legal documents section.

// clientLegalDocumentsAPI is what the tab needs: the client and the documents that apply to it, in
// one read.
type clientLegalDocumentsAPI interface {
	GetClientLegalDocuments(ctx context.Context, accessToken string, clientId int64) (*api.GetClientLegalDocumentsResponse, error)
}

func HandleLegalDocumentsGet(
	httpHelper HttpHelper,
	apiClient clientLegalDocumentsAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		id, err := strconv.ParseInt(r.PathValue("clientId"), 10, 64)
		if err != nil {
			httpHelper.NotFound(w, r)
			return
		}
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		answer, err := apiClient.GetClientLegalDocuments(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		bind := map[string]interface{}{
			"client":         &answer.Client,
			"legalDocuments": answer.LegalDocuments,
		}
		if err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_legal_documents.html", bind); err != nil {
			httpHelper.InternalServerError(w, r, err)
		}
	}
}
