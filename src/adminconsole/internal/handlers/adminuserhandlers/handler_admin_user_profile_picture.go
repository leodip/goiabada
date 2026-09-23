package adminuserhandlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/constants"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/core/errs"
)

// userProfilePictureAPI is what the user profile picture page needs: the upload, and the delete.
type userProfilePictureAPI interface {
	DeleteUserProfilePicture(ctx context.Context, accessToken string, userId int64) error
	UploadUserProfilePicture(ctx context.Context, accessToken string, userId int64, pictureData []byte, filename string) (*apiclient.ProfilePictureUploadResponse, error)
}

// The error surface here answers through the console's shared JSON writers rather than the
// hand-rolled {"success": false, "error": <message>} these handlers wrote until #279, which put an
// internal message on the wire at 500 with nothing in the log, answered 401 for the middleware
// invariant the other 100 sites answer 500 for, and rendered the HTML 500 page into a fetch() that
// was about to call response.json(). The success bodies are unchanged.
// HandleAdminUserProfilePicturePost handles uploading a profile picture for a user (admin)
func HandleAdminUserProfilePicturePost(
	httpHelper handlers.HttpHelper,
	apiClient userProfilePictureAPI,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get JWT info to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauthclient.JwtInfo)
		if !ok {
			httpHelper.JsonError(w, r, errs.New("no JWT info found in context"))
			return
		}

		// Get user ID from URL
		userIdStr := chi.URLParam(r, "userId")
		userId, err := strconv.ParseInt(userIdStr, 10, 64)
		if err != nil {
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}

		// Parse multipart form (max 10MB)
		if err := r.ParseMultipartForm(10 << 20); err != nil {
			handlers.JsonBadRequestBody(httpHelper, w, r)
			return
		}

		// Get file from form
		file, header, err := r.FormFile("picture")
		if err != nil {
			handlers.JsonBadRequestBody(httpHelper, w, r)
			return
		}
		defer func() { _ = file.Close() }()

		// Read file data
		pictureData, err := io.ReadAll(file)
		if err != nil {
			httpHelper.JsonError(w, r, errs.Wrap(err, "failed to read picture data"))
			return
		}

		// Call API client to upload
		response, err := apiClient.UploadUserProfilePicture(r.Context(), jwtInfo.TokenResponse.AccessToken, userId, pictureData, header.Filename)
		if err != nil {
			handlers.HandleAPIErrorJson(httpHelper, w, r, err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success":    true,
			"pictureUrl": response.PictureUrl,
		})
	}
}

// HandleAdminUserProfilePictureDelete handles deleting a user's profile picture (admin)
func HandleAdminUserProfilePictureDelete(
	httpHelper handlers.HttpHelper,
	apiClient userProfilePictureAPI,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get JWT info to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauthclient.JwtInfo)
		if !ok {
			httpHelper.JsonError(w, r, errs.New("no JWT info found in context"))
			return
		}

		// Get user ID from URL
		userIdStr := chi.URLParam(r, "userId")
		userId, err := strconv.ParseInt(userIdStr, 10, 64)
		if err != nil {
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}

		// Call API client to delete
		err = apiClient.DeleteUserProfilePicture(r.Context(), jwtInfo.TokenResponse.AccessToken, userId)
		if err != nil {
			handlers.HandleAPIErrorJson(httpHelper, w, r, err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
		})
	}
}
