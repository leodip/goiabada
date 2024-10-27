package handlers

import (
	"net/http"

	"github.com/leodip/goiabada/core/config"
)

func HandleIndexGet(
	httpHelper HttpHelper,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// redirect to admin console
		http.Redirect(w, r, config.GetAdminConsole().BaseURL, http.StatusFound)
	}
}
