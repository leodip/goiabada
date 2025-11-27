package handlers

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/core/data"
)

func HandleProfilePictureGet(
	httpHelper HttpHelper,
	database data.Database,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		subject := chi.URLParam(r, "subject")
		if len(subject) == 0 {
			http.NotFound(w, r)
			return
		}

		user, err := database.GetUserBySubject(nil, subject)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		if user == nil {
			http.NotFound(w, r)
			return
		}

		profilePicture, err := database.GetUserProfilePictureByUserId(nil, user.Id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		if profilePicture == nil {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", profilePicture.ContentType)
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.Header().Set("Content-Length", strconv.Itoa(len(profilePicture.Picture)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(profilePicture.Picture)
	}
}
