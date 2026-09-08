package admingrouphandlers

import (
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/adminconsole/internal/pagination"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5"
)

func HandleAdminGroupMembersGet(
	httpHelper handlers.HttpHelper,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "groupId")
		if len(idStr) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("groupId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
			return
		}

		// Get group details
		group, _, err := apiClient.GetGroupById(jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if group == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("group not found")))
			return
		}

		pageInt := pagination.ParsePage(r.URL.Query().Get("page"))

		const pageSize = 10
		users, total, err := apiClient.GetGroupMembers(jwtInfo.TokenResponse.AccessToken, group.Id, pageInt, pageSize)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		// A page past the last one is only visible once the total has come back.
		// Ask again at the last page rather than render an empty list under a bar
		// that highlights a full one (#305).
		if clamped := pagination.ClampPage(total, pageSize, pageInt); clamped != pageInt {
			pageInt = clamped
			users, total, err = apiClient.GetGroupMembers(jwtInfo.TokenResponse.AccessToken, group.Id, pageInt, pageSize)
			if err != nil {
				handlers.HandleAPIError(httpHelper, w, r, err)
				return
			}
		}

		pageResult := PageResult{
			Page:     pageInt,
			PageSize: pageSize,
			Total:    total,
			Users:    users,
		}

		p := pagination.New(total, pageSize, pageInt, 5)

		bind := map[string]interface{}{
			"groupId":         group.Id,
			"groupIdentifier": group.GroupIdentifier,
			"pageResult":      pageResult,
			"paginator":       p,
			"description":     group.Description,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_members.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}
