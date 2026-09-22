package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/models"
)

// profilePictureDatabase is what the profile picture page needs: the caller's user row and the
// picture attached to it.
type profilePictureDatabase interface {
	GetUserBySubject(ctx context.Context, tx *sql.Tx, subject string) (*models.User, error)
	GetUserProfilePictureByUserId(ctx context.Context, tx *sql.Tx, userId int64) (*models.UserProfilePicture, error)
}

func HandleProfilePictureGet(
	httpHelper HttpHelper,
	database profilePictureDatabase,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		subject := chi.URLParam(r, "subject")
		if len(subject) == 0 {
			http.NotFound(w, r)
			return
		}

		user, err := database.GetUserBySubject(r.Context(), nil, subject)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		if user == nil {
			http.NotFound(w, r)
			return
		}

		profilePicture, err := database.GetUserProfilePictureByUserId(r.Context(), nil, user.Id)
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
