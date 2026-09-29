package handlers

import (
	"net/http"
)

func HandleUnauthorizedGet(
	pageRenderer PageRenderer,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		bind := map[string]interface{}{
			"_httpStatus": http.StatusUnauthorized,
		}

		err := pageRenderer.RenderTemplate(w, r, "/layouts/no_menu_layout.html", "/unauthorized.html", bind)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
	}
}
