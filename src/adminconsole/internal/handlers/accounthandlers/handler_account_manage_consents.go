package accounthandlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
)

func HandleAccountManageConsentsGet(
	httpHelper handlers.HttpHelper,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get JWT info to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errs.New("no JWT info found in context"))
			return
		}

		userConsents, err := apiClient.GetAccountConsents(jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		consentInfoArr := []ConsentInfo{}
		for _, c := range userConsents {
			ci := ConsentInfo{
				ConsentId:         c.Id,
				Client:            c.ClientIdentifier,
				ClientDescription: c.ClientDescription,
				Scope:             c.Scope,
			}
			// grantedAt is nullable on the wire, where the column it comes from is not: a
			// consent row always records when it was granted, so an absent value is a
			// response this console cannot date rather than an ungranted consent (#350).
			if c.GrantedAt != nil {
				ci.GrantedAt = c.GrantedAt.Format(time.RFC1123)
			}
			consentInfoArr = append(consentInfoArr, ci)
		}

		bind := map[string]interface{}{
			"consents": consentInfoArr,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_manage_consents.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAccountManageConsentsRevokePost(
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

		// Call API to revoke
		if err := apiClient.RevokeAccountConsent(jwtInfo.TokenResponse.AccessToken, int64(consentId)); err != nil {
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
