package handlers

import "net/http"

func HandleHealthCheckGet(
	httpHelper HttpHelper,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("healthy"))
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}
