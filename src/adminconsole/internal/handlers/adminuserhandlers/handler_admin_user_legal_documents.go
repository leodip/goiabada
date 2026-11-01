package adminuserhandlers

import (
	"context"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
)

// userLegalDocumentsAPI is what the user's Legal documents tab needs: the user, and the versions
// they accepted.
type userLegalDocumentsAPI interface {
	GetUserById(ctx context.Context, accessToken string, userId int64) (*api.UserResponse, error)
	GetUserLegalDocumentAcceptances(ctx context.Context, accessToken string, userId int64) ([]api.LegalDocumentAcceptanceResponse, error)
}

// HandleLegalDocumentsGet draws the legal documents the user accepted, the latest first, each
// opening the accepted version's text in the console, a retired document's included (#622 decision
// 10). The tab only reads: acceptances are never edited or removed by hand.
func HandleLegalDocumentsGet(
	httpHelper HttpHelper,
	apiClient userLegalDocumentsAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		id, err := strconv.ParseInt(r.PathValue("userId"), 10, 64)
		if err != nil {
			httpHelper.NotFound(w, r)
			return
		}

		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		user, err := apiClient.GetUserById(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if user == nil {
			httpHelper.NotFound(w, r)
			return
		}

		acceptances, err := apiClient.GetUserLegalDocumentAcceptances(r.Context(), jwtInfo.TokenResponse.AccessToken, user.Id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		bind := map[string]interface{}{
			"user":        user,
			"acceptances": acceptances,
			"page":        r.URL.Query().Get("page"),
			"query":       r.URL.Query().Get("query"),
		}

		if err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_legal_documents.html", bind); err != nil {
			httpHelper.InternalServerError(w, r, err)
		}
	}
}
