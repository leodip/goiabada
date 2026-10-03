package accounthandlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/leodip/goiabada/adminconsole/internal/handlerhelpers"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
)

// accountPictureAPI is what the account picture endpoint needs: the one read it serves.
type accountPictureAPI interface {
	GetAccountProfilePicture(ctx context.Context, accessToken string) (*api.ProfilePictureInfoResponse, error)
}

func HandleAccountPictureGet(
	httpHelper HttpHelper,
	apiClient accountPictureAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get JWT info to extract access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		// Get profile picture info
		var profilePictureUrl string
		// A user with no picture is a 200 from the API with HasPicture false, so an error here is a
		// real failure and is answered as one rather than drawn as an empty picture (#425).
		pictureInfo, err := apiClient.GetAccountProfilePicture(r.Context(), jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			handlerhelpers.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if pictureInfo != nil && pictureInfo.HasPicture {
			// Add cache-busting parameter to prevent browser caching
			profilePictureUrl = fmt.Sprintf("%s?t=%d", pictureInfo.PictureUrl, time.Now().UnixNano())
		}

		bind := map[string]interface{}{
			"profilePictureUrl": profilePictureUrl,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_picture.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

// The two handlers below answer errors through the console's shared JSON writers rather than
// hand-rolling {"success": false, "error": <message>}, which is what they did until #279. Three
// things were wrong with the hand-rolled shape and all three are fixed by using the writers the
// rest of the console's AJAX paths use.
//
// The generic branch wrote err.Error() straight onto the wire at 500 and logged nothing, so an
// internal message reached the browser and no operator ever saw the failure. JsonError logs it
// once with a stack and answers the request id sentence instead.
//
// The multipart branches answered a client's mistake correctly at 400 but with their own wording,
// and the JWT branch answered 401 where the other 100 sites that guard the same middleware
// invariant answer 500. That invariant is the JWT middleware's to hold, so this joins them.
//
// A failure reading the uploaded bytes was answered with InternalServerError, which renders the
// HTML 500 page into a fetch() that is about to call response.json(). It is a real server fault,
// so it stays a 500, but it has to be a JSON one.

// accountProfilePictureAPI is what the account profile picture page needs: the upload, and the
// delete.
type accountProfilePictureAPI interface {
	DeleteAccountProfilePicture(ctx context.Context, accessToken string) error
	UploadAccountProfilePicture(ctx context.Context, accessToken string, pictureData []byte, filename string) (*api.ProfilePictureUploadResponse, error)
}

// HandleAccountProfilePicturePost handles uploading a profile picture for the current user
func HandleAccountProfilePicturePost(
	httpHelper HttpHelper,
	apiClient accountProfilePictureAPI,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get JWT info to extract access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.JsonError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		// The body is bounded before it gets here, by uploadBodyLimit in the server's
		// request-body table (#426). The argument is not a limit: it is how much of the form is
		// held in memory before the rest spills to temporary files.
		//nolint:gosec // G120: bounded by uploadBodyLimit, as above; G120 flags every multipart parse
		if err := r.ParseMultipartForm(10 << 20); err != nil {
			handlerhelpers.JsonBadRequestBody(httpHelper, w, r)
			return
		}

		// Get file from form
		file, header, err := r.FormFile("picture")
		if err != nil {
			handlerhelpers.JsonBadRequestBody(httpHelper, w, r)
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
		response, err := apiClient.UploadAccountProfilePicture(r.Context(), jwtInfo.TokenResponse.AccessToken, pictureData, header.Filename)
		if err != nil {
			handlerhelpers.HandleAPIErrorJson(httpHelper, w, r, err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success":    true,
			"pictureUrl": response.PictureUrl,
		})
	}
}

// HandleAccountProfilePictureDelete handles deleting the current user's profile picture
func HandleAccountProfilePictureDelete(
	httpHelper HttpHelper,
	apiClient accountProfilePictureAPI,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get JWT info to extract access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.JsonError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		// Call API client to delete
		err := apiClient.DeleteAccountProfilePicture(r.Context(), jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			handlerhelpers.HandleAPIErrorJson(httpHelper, w, r, err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
		})
	}
}
