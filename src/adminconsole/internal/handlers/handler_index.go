package handlers

import (
	"net/http"

	"github.com/leodip/goiabada/core/config"
)

func HandleIndexGet(
	httpHelper HttpHelper,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bind := map[string]interface{}{}

		bind["AuthServerBaseUrl"] = config.GetAuthServer().BaseURL

		err := httpHelper.RenderTemplate(w, r, "/layouts/no_menu_layout.html", "/index.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}
