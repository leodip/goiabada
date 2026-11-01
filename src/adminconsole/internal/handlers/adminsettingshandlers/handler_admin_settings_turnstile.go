package adminsettingshandlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/sessionstore"
)

// settingsTurnstileAPI is what the Turnstile settings page needs: the settings and the write.
type settingsTurnstileAPI interface {
	GetSettingsTurnstile(ctx context.Context, accessToken string) (*api.SettingsTurnstileResponse, error)
	UpdateSettingsTurnstile(ctx context.Context, accessToken string, request *api.UpdateSettingsTurnstileRequest) (*api.SettingsTurnstileResponse, error)
}

// HandleTurnstileGet draws the Cloudflare Turnstile challenge's settings: the switch, the site key,
// and whether a secret key is saved. The secret key never comes back from the API, so its box is
// empty on every load (#642 decision 11).
func HandleTurnstileGet(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient settingsTurnstileAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		apiResp, err := apiClient.GetSettingsTurnstile(r.Context(), jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		settingsInfo := SettingsTurnstile{
			TurnstileEnabled:      apiResp.TurnstileEnabled,
			TurnstileSiteKey:      apiResp.TurnstileSiteKey,
			HasTurnstileSecretKey: apiResp.HasTurnstileSecretKey,
			SavedTurnstileEnabled: apiResp.TurnstileEnabled,
		}

		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
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
			"settings":          settingsInfo,
			"savedSuccessfully": savedSuccessfully,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_turnstile.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

// HandleTurnstilePost saves the challenge's settings. The auth server decides every refusal, and a
// refused save is redrawn as it was submitted, with the refusal at the field its code names.
func HandleTurnstilePost(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient settingsTurnstileAPI,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		// The secret key is a credential, so it is read from the body alone, with r.PostFormValue: a
		// query string would leave it in the browser's history and every proxy's access log (#202).
		// The other fields are configuration, and are read from the body the same way, as nothing
		// here is ever submitted through the query.
		//
		// An empty box keeps the stored secret key and the ticked checkbox removes it.
		// hasTurnstileSecretKey and savedTurnstileEnabled are hidden fields carrying the state the
		// page was loaded with, which only a refused save's redraw reads: the auth server decides
		// what the save does to the secret key from the row it holds, not from them.
		settingsInfo := SettingsTurnstile{
			TurnstileEnabled:        r.PostFormValue("turnstileEnabled") == "on",
			TurnstileSiteKey:        r.PostFormValue("turnstileSiteKey"),
			TurnstileSecretKey:      r.PostFormValue("turnstileSecretKey"),
			ClearTurnstileSecretKey: r.PostFormValue("clearTurnstileSecretKey") == "on",
			HasTurnstileSecretKey:   r.PostFormValue("hasTurnstileSecretKey") == "true",
			SavedTurnstileEnabled:   r.PostFormValue("savedTurnstileEnabled") == "true",
		}

		updateReq := &api.UpdateSettingsTurnstileRequest{
			TurnstileEnabled:        settingsInfo.TurnstileEnabled,
			TurnstileSiteKey:        strings.TrimSpace(settingsInfo.TurnstileSiteKey),
			TurnstileSecretKey:      settingsInfo.TurnstileSecretKey,
			ClearTurnstileSecretKey: settingsInfo.ClearTurnstileSecretKey,
		}

		_, err := apiClient.UpdateSettingsTurnstile(r.Context(), jwtInfo.TokenResponse.AccessToken, updateReq)
		if err != nil {
			render.HandleAPIErrorWithCallback(httpHelper, w, r, err, func(message string) {
				bind := map[string]interface{}{
					"settings":   settingsInfo,
					"error":      message,
					"errorField": render.ErrorField(err, turnstileErrorFields),
				}
				renderErr := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_turnstile.html", bind)
				if renderErr != nil {
					httpHelper.InternalServerError(w, r, renderErr)
				}
			})
			return
		}

		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		sess.SetFlash("savedSuccessfully", "true")
		err = httpSession.Save(r, w, sess)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("%v/admin/settings/turnstile", baseURL), http.StatusFound)
	}
}
