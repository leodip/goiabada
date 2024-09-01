package adminclienthandlers

import (
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/data"
)

func HandleAdminClientsGet(
	httpHelper handlers.HttpHelper,
	database data.Database,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		clients, err := database.GetAllClients(nil)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"clients": clients,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}
