package accounthandlers

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
)

// accountConsentsAPI is what the manage-consents page needs: the list, and the revoke.
type accountConsentsAPI interface {
	GetAccountConsents(ctx context.Context, accessToken string) ([]api.UserConsentResponse, error)
	RevokeAccountConsent(ctx context.Context, accessToken string, consentId int64) error
}

func HandleManageConsentsGet(
	httpHelper HttpHelper,
	apiClient accountConsentsAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get JWT info to extract access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		userConsents, err := apiClient.GetAccountConsents(r.Context(), jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		consentInfoArr := render.ConsentInfos(userConsents)

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

func HandleManageConsentsRevokePost(
	httpHelper HttpHelper,
	apiClient accountConsentsAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get JWT info to extract access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.JSONError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		var data map[string]interface{}
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&data); err != nil {
			render.JSONBadRequestBody(httpHelper, w, r)
			return
		}

		consentId, ok := data["consentId"].(float64)
		if !ok || consentId == 0 {
			render.JSONBadRequestBody(httpHelper, w, r)
			return
		}

		// Call API to revoke
		if err := apiClient.RevokeAccountConsent(r.Context(), jwtInfo.TokenResponse.AccessToken, int64(consentId)); err != nil {
			render.HandleAPIErrorJSON(httpHelper, w, r, err)
			return
		}

		result := struct {
			Success bool
		}{
			Success: true,
		}
		httpHelper.EncodeJSON(w, r, result)
	}
}
