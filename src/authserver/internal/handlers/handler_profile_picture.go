package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/authserver/internal/record"
)

// profilePictureDatabase is what the profile picture page needs: the caller's user row and the
// picture attached to it.
type profilePictureDatabase interface {
	GetUserBySubject(ctx context.Context, tx *sql.Tx, subject string) (*record.User, error)
	GetUserProfilePictureByUserID(ctx context.Context, tx *sql.Tx, userID int64) (*record.UserProfilePicture, error)
}

// HandleProfilePictureGet answers a user's profile picture, to anyone, and no cache may store it. A
// user that does not exist, or one with no picture, is not found, and that answer is no-store as
// well (ResourceNotFound).
func HandleProfilePictureGet(
	pageRenderer PageRenderer,
	database profilePictureDatabase,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		subject := r.PathValue("subject")
		if len(subject) == 0 {
			ResourceNotFound(w, r)
			return
		}

		user, err := database.GetUserBySubject(r.Context(), nil, subject)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}

		if user == nil {
			ResourceNotFound(w, r)
			return
		}

		profilePicture, err := database.GetUserProfilePictureByUserID(r.Context(), nil, user.ID)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}

		if profilePicture == nil {
			ResourceNotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", profilePicture.ContentType)
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.Header().Set("Content-Length", strconv.Itoa(len(profilePicture.Picture)))
		w.WriteHeader(http.StatusOK)
		//nolint:gosec // G705: image bytes under the image content type the upload validated, and nosniff is set at the root
		_, _ = w.Write(profilePicture.Picture)
	}
}
