package handlers

import (
	"net/http"
)

func HandleNotFoundGet(
	httpHelper HttpHelper,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		bind := map[string]interface{}{
			"_httpStatus": http.StatusNotFound,
		}

		err := httpHelper.RenderTemplate(w, r, "/layouts/no_menu_layout.html", "/not_found.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}
