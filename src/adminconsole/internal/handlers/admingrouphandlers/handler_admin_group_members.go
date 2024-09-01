package admingrouphandlers

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/unknwon/paginater"
)

func HandleAdminGroupMembersGet(
	httpHelper handlers.HttpHelper,
	database data.Database,
) http.HandlerFunc {

	type PageResult struct {
		Page     int
		PageSize int
		Total    int
		Users    []models.User
	}

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
		group, err := database.GetGroupById(nil, id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if group == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("group not found")))
			return
		}

		page := r.URL.Query().Get("page")
		if len(page) == 0 {
			page = "1"
		}
		pageInt, err := strconv.Atoi(page)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if pageInt < 1 {
			httpHelper.InternalServerError(w, r, errors.WithStack(fmt.Errorf("invalid page %d", pageInt)))
			return
		}

		const pageSize = 10
		users, total, err := database.GetGroupMembersPaginated(nil, group.Id, pageInt, pageSize)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		pageResult := PageResult{
			Page:     pageInt,
			PageSize: pageSize,
			Total:    total,
			Users:    users,
		}

		p := paginater.New(total, pageSize, pageInt, 5)

		bind := map[string]interface{}{
			"groupId":         group.Id,
			"groupIdentifier": group.GroupIdentifier,
			"pageResult":      pageResult,
			"paginator":       p,
			"description":     group.Description,
			"csrfField":       csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_members.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}
