package handlers

import "net/http"

func HandleIndexGet(
	adminConsoleBaseURL string,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// redirect to admin console
		http.Redirect(w, r, adminConsoleBaseURL, http.StatusFound)
	}
}
