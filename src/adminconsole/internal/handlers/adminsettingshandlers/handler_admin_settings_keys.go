package adminsettingshandlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/sessionstore"
)

// settingsKeysAPI is what the keys page needs: the key list, the rotation, and the delete of one.
type settingsKeysAPI interface {
	DeleteSettingsKey(ctx context.Context, accessToken string, id int64) error
	GetSettingsKeys(ctx context.Context, accessToken string) ([]api.SettingsSigningKeyResponse, error)
	RotateSettingsKeys(ctx context.Context, accessToken string) error
}

// renderKeys draws the keys page from the keys the auth server answers, in the order it answers
// them, with bind's other values beside them. GET /api/v1/admin/settings/keys orders its response
// next, current, then all previous, and the loop that used to re-impose that order here was a
// structurally identical copy of the one that produces it, so it only ever reordered a list already
// in that order. Restoring it would make the page's order the console's claim rather than the API's,
// and would go stale the moment the API's changed (#385).
func renderKeys(httpHelper HttpHelper, apiClient settingsKeysAPI, w http.ResponseWriter, r *http.Request,
	accessToken string, bind map[string]interface{}) {

	apiKeys, err := apiClient.GetSettingsKeys(r.Context(), accessToken)
	if err != nil {
		render.HandleAPIError(httpHelper, w, r, err)
		return
	}

	keys := make([]SettingsKey, 0, len(apiKeys))
	hasPreviousKey := false
	for _, k := range apiKeys {
		hasPreviousKey = hasPreviousKey || k.State == "previous"
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
	bind["keys"] = keys
	// A rotation deletes the previous key, so the confirmation says so when there is one.
	bind["hasPreviousKey"] = hasPreviousKey

	err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_keys.html", bind)
	if err != nil {
		httpHelper.InternalServerError(w, r, err)
	}
}

func HandleKeysGet(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient settingsKeysAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get JWT info from context to extract access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		_, keysRotated := sess.TakeFlash("keysRotated")
		if keysRotated {
			err = httpSession.Save(r, w, sess)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		renderKeys(httpHelper, apiClient, w, r, jwtInfo.TokenResponse.AccessToken, map[string]interface{}{
			"keysRotated": keysRotated,
		})
	}
}

// HandleKeysRotatePost rotates the keys and answers with the page again: through a redirect that
// says it rotated, or drawn at once with the API's sentence when it refused. A refusal is a 409:
// another rotation winning the race, "Another key rotation is in progress", which rotated nothing
// (#251), or a commit whose outcome is unknown, which may have rotated, and whose sentence asks the
// administrator to check the keys the page draws beside it (#371).
func HandleKeysRotatePost(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient settingsKeysAPI,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get JWT info from context to extract access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		if err := apiClient.RotateSettingsKeys(r.Context(), jwtInfo.TokenResponse.AccessToken); err != nil {
			render.HandleAPIErrorWithCallback(httpHelper, w, r, err, func(message string) {
				renderKeys(httpHelper, apiClient, w, r, jwtInfo.TokenResponse.AccessToken, map[string]interface{}{
					"error": message,
				})
			})
			return
		}

		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		sess.SetFlash("keysRotated", "true")
		err = httpSession.Save(r, w, sess)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("%v/admin/settings/keys", baseURL), http.StatusFound)
	}
}

func HandleKeysRevokePost(
	httpHelper HttpHelper,
	apiClient settingsKeysAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		var data map[string]interface{}
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&data); err != nil {
			render.JSONBadRequestBody(httpHelper, w, r)
			return
		}

		id, ok := data["id"].(float64)
		if !ok {
			render.JSONBadRequestBody(httpHelper, w, r)
			return
		}

		// Get JWT info from context to extract access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.JSONError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		// Let the API enforce state=previous and handle auditing
		if err := apiClient.DeleteSettingsKey(r.Context(), jwtInfo.TokenResponse.AccessToken, int64(id)); err != nil {
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
