package handlers

import (
	"net/http"
)

// HandleNotFoundGet is the router's fallback for a URL no route matches. It is the same 404 page,
// rendered the same way, that HttpHelper.NotFound answers a stale or malformed id with, so it is
// that method rather than a second copy of it (#279).
func HandleNotFoundGet(
	httpHelper HttpHelper,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		httpHelper.NotFound(w, r)
	}
}
