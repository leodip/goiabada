package accounthandlers

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
)

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

// HandleAccountProfilePicturePost handles uploading a profile picture for the current user
func HandleAccountProfilePicturePost(
	httpHelper handlers.HttpHelper,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get JWT info to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.JsonError(w, r, errs.New("no JWT info found in context"))
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
		response, err := apiClient.UploadAccountProfilePicture(jwtInfo.TokenResponse.AccessToken, pictureData, header.Filename)
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

// HandleAccountProfilePictureDelete handles deleting the current user's profile picture
func HandleAccountProfilePictureDelete(
	httpHelper handlers.HttpHelper,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get JWT info to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.JsonError(w, r, errs.New("no JWT info found in context"))
			return
		}

		// Call API client to delete
		err := apiClient.DeleteAccountProfilePicture(jwtInfo.TokenResponse.AccessToken)
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
