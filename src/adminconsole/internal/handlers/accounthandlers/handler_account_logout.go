package accounthandlers

import (
	"net/http"
	"net/url"

	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/stringutil"
)

func HandleAccountLogoutGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	authHelper handlers.AuthHelper,
	database data.Database,
	tokenParser handlers.TokenParser,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

		var jwtInfo oauth.JwtInfo
		if r.Context().Value(constants.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		}

		session, err := httpSession.Get(r, constants.SessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		// Clear the local session
		session.Options.MaxAge = -1
		err = session.Save(r, w)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		if jwtInfo.IdToken != nil {
			// Valid ID token present, proceed with OIDC-compliant logout

			client, err := database.GetClientByClientIdentifier(nil, constants.AdminConsoleClientIdentifier)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			clientSecret, err := encryption.DecryptText(client.ClientSecretEncrypted, settings.AESEncryptionKey)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			encryptedIdToken, err := encryption.AesGcmEncryption(jwtInfo.IdToken.TokenBase64, clientSecret)
			if err != nil {
				http.Error(w, "Failed to encrypt ID token", http.StatusInternalServerError)
				return
			}

			logoutURL, err := url.Parse(config.GetAuthServer().BaseURL + "/auth/logout")
			if err != nil {
				http.Error(w, "Failed to parse OIDC provider URL", http.StatusInternalServerError)
				return
			}

			query := logoutURL.Query()
			query.Set("id_token_hint", encryptedIdToken)
			query.Set("post_logout_redirect_uri", config.Get().BaseURL)
			query.Set("client_id", client.ClientIdentifier)
			query.Set("state", stringutil.GenerateSecurityRandomString(32))

			logoutURL.RawQuery = query.Encode()

			// Redirect to the OIDC provider's logout endpoint
			http.Redirect(w, r, logoutURL.String(), http.StatusFound)
		} else {
			// No valid ID token present, redirect to the home page
			http.Redirect(w, r, config.Get().BaseURL, http.StatusFound)
		}
	}
}
