package adminuserhandlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
)

// userPictureAPI is what the user picture endpoint needs: the user, and the picture it serves.
type userPictureAPI interface {
	GetUserById(ctx context.Context, accessToken string, userId int64) (*api.UserResponse, error)
	GetUserProfilePicture(ctx context.Context, accessToken string, userId int64) (*api.ProfilePictureInfoResponse, error)
}

func HandleAdminUserPictureGet(
	httpHelper HttpHelper,
	apiClient userPictureAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "userId")
		if len(idStr) == 0 {
			httpHelper.NotFound(w, r)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.NotFound(w, r)
			return
		}

		// Get JWT info from context to extract access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		user, err := apiClient.GetUserById(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if user == nil {
			httpHelper.NotFound(w, r)
			return
		}

		// Get profile picture info
		var profilePictureUrl string
		// A user with no picture is a 200 from the API with HasPicture false, so an error here is a
		// real failure and is answered as one rather than drawn as an empty picture (#425).
		pictureInfo, err := apiClient.GetUserProfilePicture(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if pictureInfo != nil && pictureInfo.HasPicture {
			// Add cache-busting parameter to prevent browser caching
			profilePictureUrl = fmt.Sprintf("%s?t=%d", pictureInfo.PictureUrl, time.Now().UnixNano())
		}

		bind := map[string]interface{}{
			"user":              user,
			"page":              r.URL.Query().Get("page"),
			"query":             r.URL.Query().Get("query"),
			"profilePictureUrl": profilePictureUrl,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_picture.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

// userProfilePictureAPI is what the user profile picture page needs: the upload, and the delete.
type userProfilePictureAPI interface {
	DeleteUserProfilePicture(ctx context.Context, accessToken string, userId int64) error
	UploadUserProfilePicture(ctx context.Context, accessToken string, userId int64, pictureData []byte, filename string) (*api.ProfilePictureUploadResponse, error)
}

// The error surface here answers through the console's shared JSON writers rather than the
// hand-rolled {"success": false, "error": <message>} these handlers wrote until #279, which put an
// internal message on the wire at 500 with nothing in the log, answered 401 for the middleware
// invariant the other 100 sites answer 500 for, and rendered the HTML 500 page into a fetch() that
// was about to call response.json(). The success bodies are unchanged.
// HandleAdminUserProfilePicturePost handles uploading a profile picture for a user (admin)
func HandleAdminUserProfilePicturePost(
	httpHelper HttpHelper,
	apiClient userProfilePictureAPI,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get JWT info to extract access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.JSONError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		// Get user ID from URL
		userIdStr := chi.URLParam(r, "userId")
		userId, err := strconv.ParseInt(userIdStr, 10, 64)
		if err != nil {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		// The body is bounded before it gets here, by uploadBodyLimit in the server's
		// request-body table (#426). The argument is not a limit: it is how much of the form is
		// held in memory before the rest spills to temporary files.
		//nolint:gosec // G120: bounded by uploadBodyLimit, as above; G120 flags every multipart parse
		if parseFormErr := r.ParseMultipartForm(10 << 20); parseFormErr != nil {
			render.JSONBadRequestBody(httpHelper, w, r)
			return
		}

		// Get file from form
		file, header, err := r.FormFile("picture")
		if err != nil {
			render.JSONBadRequestBody(httpHelper, w, r)
			return
		}
		defer func() { _ = file.Close() }()

		// Read file data
		pictureData, err := io.ReadAll(file)
		if err != nil {
			httpHelper.JSONError(w, r, errs.Wrap(err, "failed to read picture data"))
			return
		}

		// Call API client to upload
		response, err := apiClient.UploadUserProfilePicture(r.Context(), jwtInfo.TokenResponse.AccessToken, userId, pictureData, header.Filename)
		if err != nil {
			render.HandleAPIErrorJSON(httpHelper, w, r, err)
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
	httpHelper HttpHelper,
	apiClient userProfilePictureAPI,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get JWT info to extract access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.JSONError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		// Get user ID from URL
		userIdStr := chi.URLParam(r, "userId")
		userId, err := strconv.ParseInt(userIdStr, 10, 64)
		if err != nil {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		// Call API client to delete
		err = apiClient.DeleteUserProfilePicture(r.Context(), jwtInfo.TokenResponse.AccessToken, userId)
		if err != nil {
			render.HandleAPIErrorJSON(httpHelper, w, r, err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
		})
	}
}
