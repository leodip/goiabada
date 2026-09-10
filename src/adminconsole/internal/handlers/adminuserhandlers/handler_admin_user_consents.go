package adminuserhandlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/sessionstore"
)

func HandleAdminUserConsentsGet(
	httpHelper handlers.HttpHelper,
	httpSession sessionstore.Store,
	apiClient apiclient.ApiClient,
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
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errs.New("no JWT info found in context"))
			return
		}

		user, err := apiClient.GetUserById(jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if user == nil {
			httpHelper.NotFound(w, r)
			return
		}

		userConsents, err := apiClient.GetUserConsents(jwtInfo.TokenResponse.AccessToken, user.Id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		consentInfoArr := []ConsentInfo{}
		for _, c := range userConsents {
			ci := ConsentInfo{
				ConsentId:         c.Id,
				Client:            c.Client.ClientIdentifier,
				ClientDescription: c.Client.Description,
				GrantedAt:         c.GrantedAt.Time.Format(time.RFC1123),
				Scope:             c.Scope,
			}
			consentInfoArr = append(consentInfoArr, ci)
		}

		sess, err := httpSession.Get(r, constants.AdminConsoleSessionName)
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
	httpHelper handlers.HttpHelper,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "userId")
		if len(idStr) == 0 {
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}

		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.JsonError(w, r, errs.New("no JWT info found in context"))
			return
		}

		user, err := apiClient.GetUserById(jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handlers.HandleAPIErrorJson(httpHelper, w, r, err)
			return
		}
		if user == nil {
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}

		var data map[string]interface{}
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&data); err != nil {
			handlers.JsonBadRequestBody(httpHelper, w, r)
			return
		}

		consentId, ok := data["consentId"].(float64)
		if !ok || consentId == 0 {
			handlers.JsonBadRequestBody(httpHelper, w, r)
			return
		}

		userConsents, err := apiClient.GetUserConsents(jwtInfo.TokenResponse.AccessToken, user.Id)
		if err != nil {
			handlers.HandleAPIErrorJson(httpHelper, w, r, err)
			return
		}

		found := false
		for _, c := range userConsents {
			if c.Id == int64(consentId) {
				found = true
				break
			}
		}

		if !found {
			httpHelper.JsonError(w, r, errs.Errorf("unable to revoke consent with id %v because it doesn't belong to user id %v", consentId, user.Id))
			return
		} else {

			err := apiClient.DeleteUserConsent(jwtInfo.TokenResponse.AccessToken, int64(consentId))
			if err != nil {
				handlers.HandleAPIErrorJson(httpHelper, w, r, err)
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
