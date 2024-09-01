package admingrouphandlers

import (
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/data"
)

func HandleAdminGroupsGet(
	httpHelper handlers.HttpHelper,
	database data.Database,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		groups, err := database.GetAllGroups(nil)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"groups": groups,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}
