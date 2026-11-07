package adminuserhandlers

import (
	"context"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
)

// userExportAPI is what the user header's Download data button needs: the user's export.
type userExportAPI interface {
	GetUserExport(ctx context.Context, accessToken string, userId int64) (*apiclient.UserExport, error)
}

// HandleExportPost answers the Download data form with the user's export, their data as one JSON
// document the browser saves (#781 decision 7), passed through by render's export pass-through. It
// is a form's POST rather than a link because the origin check covers unsafe methods only, and the
// session cookie rides another site's link: a forged download would put the person's data on the
// administrator's disk and audit an export in the administrator's name.
//
// A failed call goes through the API error classifier, before anything is written.
func HandleExportPost(
	httpHelper HttpHelper,
	apiClient userExportAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		render.LiftExportWriteDeadline(w, r)

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

		export, err := apiClient.GetUserExport(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
		render.ServeExport(w, r, export)
	}
}
