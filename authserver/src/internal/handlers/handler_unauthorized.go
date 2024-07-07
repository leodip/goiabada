package handlers

import (
	"net/http"

	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/internal/data"
)

func HandleUnauthorizedGet(httpHelper HttpHelper,
	httpSession sessions.Store,
	authHelper AuthHelper,
	database data.Database) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		bind := map[string]interface{}{
			"_httpStatus": http.StatusUnauthorized,
		}

		err := httpHelper.RenderTemplate(w, r, "/layouts/no_menu_layout.html", "/unauthorized.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}
