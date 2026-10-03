package adminuserhandlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/handlerhelpers"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	coreconstants "github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/sessionstore"
)

// userConsentsAPI is what the user consents page needs: the user, its consents, and the revoke of
// one.
type userConsentsAPI interface {
	DeleteUserConsent(ctx context.Context, accessToken string, consentId int64) error
	GetUserById(ctx context.Context, accessToken string, userId int64) (*api.UserResponse, error)
	GetUserConsents(ctx context.Context, accessToken string, userId int64) ([]api.UserConsentResponse, error)
}

func HandleAdminUserConsentsGet(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient userConsentsAPI,
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
			handlerhelpers.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if user == nil {
			httpHelper.NotFound(w, r)
			return
		}

		userConsents, err := apiClient.GetUserConsents(r.Context(), jwtInfo.TokenResponse.AccessToken, user.Id)
		if err != nil {
			handlerhelpers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		consentInfoArr := handlerhelpers.ConsentInfos(userConsents)

		sess, err := httpSession.Get(r, coreconstants.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		_, savedSuccessfully := sess.TakeFlash("savedSuccessfully")
		if savedSuccessfully {
			err = httpSession.Save(r, w, sess)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		bind := map[string]interface{}{
			"user":              user,
			"consents":          consentInfoArr,
			"page":              r.URL.Query().Get("page"),
			"query":             r.URL.Query().Get("query"),
			"savedSuccessfully": savedSuccessfully,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_consents.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminUserConsentsPost(
	httpHelper HttpHelper,
	apiClient userConsentsAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "userId")
		if len(idStr) == 0 {
			handlerhelpers.JsonNotFound(httpHelper, w, r)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			handlerhelpers.JsonNotFound(httpHelper, w, r)
			return
		}

		// Get JWT info from context to extract access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.JsonError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		user, err := apiClient.GetUserById(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handlerhelpers.HandleAPIErrorJson(httpHelper, w, r, err)
			return
		}
		if user == nil {
			handlerhelpers.JsonNotFound(httpHelper, w, r)
			return
		}

		var data map[string]interface{}
		decoder := json.NewDecoder(r.Body)
		if decodeErr := decoder.Decode(&data); decodeErr != nil {
			handlerhelpers.JsonBadRequestBody(httpHelper, w, r)
			return
		}

		consentId, ok := data["consentId"].(float64)
		if !ok || consentId == 0 {
			handlerhelpers.JsonBadRequestBody(httpHelper, w, r)
			return
		}

		userConsents, err := apiClient.GetUserConsents(r.Context(), jwtInfo.TokenResponse.AccessToken, user.Id)
		if err != nil {
			handlerhelpers.HandleAPIErrorJson(httpHelper, w, r, err)
			return
		}

		found := false
		for _, c := range userConsents {
			if c.Id == int64(consentId) {
				found = true
				break
			}
		}

		// A consent no longer this user's is a stale page: it was revoked after the page loaded,
		// so the id names nothing here and is answered as one, with nothing logged (#440).
		if !found {
			handlerhelpers.JsonNotFound(httpHelper, w, r)
			return
		} else {

			err := apiClient.DeleteUserConsent(r.Context(), jwtInfo.TokenResponse.AccessToken, int64(consentId))
			if err != nil {
				handlerhelpers.HandleAPIErrorJson(httpHelper, w, r, err)
				return
			}

			result := struct {
				Success bool
			}{
				Success: true,
			}
			httpHelper.EncodeJson(w, r, result)
		}
	}
}
