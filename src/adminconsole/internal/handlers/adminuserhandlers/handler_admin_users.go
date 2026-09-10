package adminuserhandlers

import (
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/adminconsole/internal/pagination"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
)

func HandleAdminUsersGet(
	httpHelper handlers.HttpHelper,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		page := r.URL.Query().Get("page")
		query := r.URL.Query().Get("query")

		pageInt := pagination.ParsePage(page)

		const pageSize = 10

		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errs.New("no JWT info found in context"))
			return
		}

		users, total, err := apiClient.SearchUsersPaginated(jwtInfo.TokenResponse.AccessToken, query, pageInt, pageSize)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		// The total is only known once the search has answered, so a page past the
		// end can only be caught here. Ask again at the last page, so the rows and
		// the bar agree instead of an empty list rendering under a bar that
		// highlights a full one (#305). Once, not in a loop: a total that moves
		// again between these two calls is a list somebody else is editing, and the
		// page after it is as good an answer as any.
		if clamped := pagination.ClampPage(total, pageSize, pageInt); clamped != pageInt {
			pageInt = clamped
			users, total, err = apiClient.SearchUsersPaginated(jwtInfo.TokenResponse.AccessToken, query, pageInt, pageSize)
			if err != nil {
				handlers.HandleAPIError(httpHelper, w, r, err)
				return
			}
		}

		pageResult := PageResult{
			Users:    users,
			Total:    total,
			Query:    query,
			Page:     pageInt,
			PageSize: pageSize,
		}

		p := pagination.New(total, pageSize, pageInt, 5)

		bind := map[string]interface{}{
			"pageResult": pageResult,
			"paginator":  p,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}
