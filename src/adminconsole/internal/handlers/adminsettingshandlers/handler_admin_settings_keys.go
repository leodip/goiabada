package adminsettingshandlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/pkg/errors"
)

func HandleAdminSettingsKeysGet(
	httpHelper handlers.HttpHelper,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
			return
		}

		apiKeys, err := apiClient.GetSettingsKeys(jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		keys := make([]SettingsKey, 0, len(apiKeys))
		for _, k := range apiKeys {
			createdAt := ""
			if k.CreatedAt != nil {
				createdAt = k.CreatedAt.Format("02 Jan 2006 15:04:05 MST")
			}
			// API already returns state/type/algorithm and public key encodings
			keys = append(keys, SettingsKey{
				Id:               k.Id,
				CreatedAt:        createdAt,
				State:            k.State,
				KeyIdentifier:    k.KeyIdentifier,
				Type:             k.Type,
				Algorithm:        k.Algorithm,
				PublicKeyASN1DER: k.PublicKeyASN1DER,
				PublicKeyPEM:     k.PublicKeyPEM,
				PublicKeyJWK:     k.PublicKeyJWK,
			})
		}

		orderedKeys := make([]SettingsKey, 0, len(keys))
		for _, ki := range keys {
			if ki.State == enums.KeyStateNext.String() {
				orderedKeys = append(orderedKeys, ki)
				break
			}
		}
		for _, ki := range keys {
			if ki.State == enums.KeyStateCurrent.String() {
				orderedKeys = append(orderedKeys, ki)
				break
			}
		}
		for _, ki := range keys {
			if ki.State == enums.KeyStatePrevious.String() {
				orderedKeys = append(orderedKeys, ki)
			}
		}

		bind := map[string]interface{}{
			"keys":      orderedKeys,
			"csrfField": csrf.TemplateField(r),
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
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
			return
		}

		if err := apiClient.RotateSettingsKeys(jwtInfo.TokenResponse.AccessToken); err != nil {
			httpHelper.JsonError(w, r, err)
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
			httpHelper.JsonError(w, r, err)
			return
		}

		id, ok := data["id"].(float64)
		if !ok {
			httpHelper.JsonError(w, r, errors.WithStack(fmt.Errorf("unable to cast id to float64")))
			return
		}

		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
			return
		}

		// Let the API enforce state=previous and handle auditing
		if err := apiClient.DeleteSettingsKey(jwtInfo.TokenResponse.AccessToken, int64(id)); err != nil {
			httpHelper.JsonError(w, r, err)
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
