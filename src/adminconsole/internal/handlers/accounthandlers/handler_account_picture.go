package accounthandlers

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/constants"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/core/errs"
)

// accountPictureAPI is what the account picture endpoint needs: the one read it serves.
type accountPictureAPI interface {
	GetAccountProfilePicture(ctx context.Context, accessToken string) (*apiclient.ProfilePictureInfo, error)
}

func HandleAccountPictureGet(
	httpHelper handlers.HttpHelper,
	apiClient accountPictureAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get JWT info to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauthclient.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errs.New("no JWT info found in context"))
			return
		}

		// Get profile picture info
		var profilePictureUrl string
		// A user with no picture is a 200 from the API with HasPicture false, so an error here is a
		// real failure and is answered as one rather than drawn as an empty picture (#425).
		pictureInfo, err := apiClient.GetAccountProfilePicture(r.Context(), jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
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
