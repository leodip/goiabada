package adminsettingshandlers

import (
	"encoding/json"
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/constants"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
)

func HandleAdminSettingsKeysGet(
	httpHelper handlers.HttpHelper,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errs.New("no JWT info found in context"))
			return
		}

		apiKeys, err := apiClient.GetSettingsKeys(jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		keys := make([]SettingsKey, 0, len(apiKeys))
		for _, k := range apiKeys {
			// API already returns state/type/algorithm and public key encodings
			keys = append(keys, SettingsKey{
				Id: k.Id,
				// The instant, formatted by the page in the viewer's locale (#373).
				CreatedAt:        k.CreatedAt,
				State:            k.State,
				KeyIdentifier:    k.KeyIdentifier,
				Type:             k.Type,
				Algorithm:        k.Algorithm,
				PublicKeyASN1DER: k.PublicKeyASN1DER,
				PublicKeyPEM:     k.PublicKeyPEM,
				PublicKeyJWK:     k.PublicKeyJWK,
			})
		}

		// Rendered in the order the API returned. GET /api/v1/admin/settings/keys orders its
		// response next, current, then all previous, and the loop that used to re-impose that
		// order here was a structurally identical copy of the one that produces it, so it only
		// ever reordered a list already in that order. Restoring it would make the page's order
		// the console's claim rather than the API's, and would go stale the moment the API's
		// changed (#385).
		bind := map[string]interface{}{
			"keys": keys,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_keys.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminSettingsKeysRotatePost(
	httpHelper handlers.HttpHelper,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.JsonError(w, r, errs.New("no JWT info found in context"))
			return
		}

		if err := apiClient.RotateSettingsKeys(jwtInfo.TokenResponse.AccessToken); err != nil {
			// Not JsonError directly: the API answers 409 when another rotation won the race,
			// and JsonError's generic branch would show the administrator "An unexpected
			// server error has occurred" with a request id, for something neither unexpected
			// nor a server error. HandleAPIErrorJson forwards the API's description instead,
			// so the modal reads "Another key rotation is in progress" (#251).
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

func HandleAdminSettingsKeysRevokePost(
	httpHelper handlers.HttpHelper,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		var data map[string]interface{}
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&data); err != nil {
			handlers.JsonBadRequestBody(httpHelper, w, r)
			return
		}

		id, ok := data["id"].(float64)
		if !ok {
			handlers.JsonBadRequestBody(httpHelper, w, r)
			return
		}

		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.JsonError(w, r, errs.New("no JWT info found in context"))
			return
		}

		// Let the API enforce state=previous and handle auditing
		if err := apiClient.DeleteSettingsKey(jwtInfo.TokenResponse.AccessToken, int64(id)); err != nil {
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
