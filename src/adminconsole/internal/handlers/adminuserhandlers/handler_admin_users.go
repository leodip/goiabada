package adminuserhandlers

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/unknwon/paginater"
)

func HandleAdminUsersGet(
	httpHelper handlers.HttpHelper,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		page := r.URL.Query().Get("page")
		query := r.URL.Query().Get("query")

		pageInt, err := strconv.Atoi(page)
		if err != nil {
			pageInt = 1
		}
		if pageInt < 1 {
			pageInt = 1
		}

		const pageSize = 10

		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, fmt.Errorf("no JWT info found in context"))
			return
		}

		users, total, err := apiClient.SearchUsersPaginated(jwtInfo.TokenResponse.AccessToken, query, pageInt, pageSize)
		if err != nil {
			httpHelper.InternalServerError(w, r, fmt.Errorf("API request failed: %w", err))
			return
		}

		pageResult := PageResult{
			Users:    users,
			Total:    total,
			Query:    query,
			Page:     pageInt,
			PageSize: pageSize,
		}

		p := paginater.New(total, pageSize, pageInt, 5)

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
