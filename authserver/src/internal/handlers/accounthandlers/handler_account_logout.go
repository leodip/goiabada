package accounthandlers

import (
	"encoding/base64"
	"net/http"

	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/pkg/errors"
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

		getFromUrlQueryOrFormPost := func(key string) string {
			value := r.URL.Query().Get(key)
			if len(value) == 0 {
				value = r.FormValue(key)
			}
			return value
		}

		idTokenHint := getFromUrlQueryOrFormPost("id_token_hint")

		if len(idTokenHint) == 0 {

			// if no id_token_hint is provided, render the logout consent page

			bind := map[string]interface{}{
				"csrfField": csrf.TemplateField(r),
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/auth_layout.html", "/logout_consent.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
			return
		}

		renderErrorUi := func(message string) {
			bind := map[string]interface{}{
				"title": "Logout error",
				"error": message,
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/no_menu_layout.html", "/auth_error.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		postLogoutRedirectURI := getFromUrlQueryOrFormPost("post_logout_redirect_uri")

		if len(postLogoutRedirectURI) == 0 {
			renderErrorUi("The post_logout_redirect_uri parameter is required. This parameter must match one of the redirect URIs that was registered for this client.")
			return
		}

		clientId := getFromUrlQueryOrFormPost("client_id")
		if len(clientId) > 0 {
			// if a client id is provided, that means id_token_hint is encrypted with the client secret
			// we need to decrypt it

			client, err := database.GetClientByClientIdentifier(nil, clientId)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			if client == nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			decodedTokenBytes, err := base64.StdEncoding.DecodeString(idTokenHint)
			if err != nil {
				decodedTokenBytes, err = base64.RawStdEncoding.DecodeString(idTokenHint)
			}
			if err != nil {
				renderErrorUi("Failed to base64 decode the id_token_hint: " + err.Error())
				return
			}

			clientSecretDecrypted, err := encryption.DecryptText(client.ClientSecretEncrypted, settings.AESEncryptionKey)
			if err != nil {
				httpHelper.InternalServerError(w, r, errors.Wrap(err, "failed to decrypt client secret"))
				return
			}
			clientSecretDecryptedBytes := []byte(clientSecretDecrypted)

			// use the first 32 bytes only
			if len(clientSecretDecryptedBytes) > 32 {
				clientSecretDecryptedBytes = clientSecretDecryptedBytes[:32]
			}

			decryptedToken, err := encryption.DecryptText(decodedTokenBytes, clientSecretDecryptedBytes)
			if err != nil {
				renderErrorUi("Failed to decrypt the id_token_hint: " + err.Error())
				return
			}
			idTokenHint = decryptedToken
		}

		idToken, err := tokenParser.DecodeAndValidateTokenString(r.Context(), idTokenHint, nil)
		if err != nil {
			renderErrorUi("The id_token_hint parameter is invalid: " + err.Error())
			return
		}

		// check if the issuer is this auth server
		issuer := idToken.GetStringClaim("iss")
		if len(issuer) == 0 {
			renderErrorUi("The id_token_hint parameter is invalid: the iss claim is missing.")
			return
		}

		if issuer != config.AuthServerBaseUrl {
			renderErrorUi("The id_token_hint parameter is invalid: the iss claim does not match the issuer of this server.")
			return
		}

		clientIdentifier := idToken.GetStringClaim("aud")
		if len(clientIdentifier) == 0 {
			renderErrorUi("The id_token_hint parameter is invalid: the aud claim is missing.")
			return
		}

		client, err := database.GetClientByClientIdentifier(nil, clientIdentifier)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		if client == nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		err = database.ClientLoadRedirectURIs(nil, client)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		// check if postLogoutRedirectURI is a valid redirect uri for the client
		found := false
		for _, uri := range client.RedirectURIs {
			if uri.URI == postLogoutRedirectURI {
				found = true
				break
			}
		}

		if !found {
			renderErrorUi("The post_logout_redirect_uri parameter is invalid: it is not registered as a redirect URI for the client.")
			return
		}

		sess, err := httpSession.Get(r, constants.SessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		sessionIdentifier := ""
		if r.Context().Value(constants.ContextKeySessionIdentifier) != nil {
			sessionIdentifier = r.Context().Value(constants.ContextKeySessionIdentifier).(string)
		}

		if len(sessionIdentifier) > 0 {

			sid := idToken.GetStringClaim("sid")
			if len(sid) == 0 {
				renderErrorUi("The id_token_hint parameter is invalid: the sid claim is missing.")
				return
			}

			if sid != sessionIdentifier {
				renderErrorUi("The id_token_hint parameter is invalid: the sid claim does not match the session identifier of the current session.")
				return
			}

			userSession, err := database.GetUserSessionBySessionIdentifier(nil, sessionIdentifier)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			if userSession != nil {

				err = database.UserSessionLoadClients(nil, userSession)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}

				err = database.UserSessionClientsLoadClients(nil, userSession.Clients)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}

				// find the user session client
				var userSessionClient *models.UserSessionClient
				for idx, client := range userSession.Clients {
					if client.Client.ClientIdentifier == clientIdentifier {
						userSessionClient = &userSession.Clients[idx]
						break
					}
				}

				if userSessionClient != nil {
					err := database.DeleteUserSessionClient(nil, userSessionClient.Id)
					if err != nil {
						httpHelper.InternalServerError(w, r, err)
						return
					}

					audit.Log(constants.AuditDeletedUserSessionClient, map[string]interface{}{
						"userId":        userSession.UserId,
						"userSessionId": userSession.Id,
						"clientId":      userSessionClient.Client.Id,
						"loggedInUser":  authHelper.GetLoggedInSubject(r),
					})

					if len(userSession.Clients) == 1 {
						// this was the only client in the session, so delete the session
						err := database.DeleteUserSession(nil, userSession.Id)
						if err != nil {
							httpHelper.InternalServerError(w, r, err)
							return
						}

						audit.Log(constants.AuditLogout, map[string]interface{}{
							"userId":            userSession.UserId,
							"sessionIdentifier": sessionIdentifier,
							"loggedInUser":      authHelper.GetLoggedInSubject(r),
						})
					}
				}
			}
		}

		// clear the session state
		sess.Values = make(map[interface{}]interface{})
		err = sess.Save(r, w)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		state := getFromUrlQueryOrFormPost("state")
		sid := sessionIdentifier

		logoutUri := postLogoutRedirectURI + "?sid=" + sid
		if len(state) > 0 {
			logoutUri += "&state=" + state
		}

		http.Redirect(w, r, logoutUri, http.StatusFound)
	}
}

func HandleAccountLogoutPost(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	authHelper handlers.AuthHelper,
	database data.Database,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		sess, err := httpSession.Get(r, constants.SessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		sessionIdentifier := ""
		if r.Context().Value(constants.ContextKeySessionIdentifier) != nil {
			sessionIdentifier = r.Context().Value(constants.ContextKeySessionIdentifier).(string)
		}

		userId := int64(0)

		if len(sessionIdentifier) > 0 {
			userSession, err := database.GetUserSessionBySessionIdentifier(nil, sessionIdentifier)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			if userSession != nil {
				userId = userSession.UserId
			}
		}

		// clear the session state
		sess.Values = make(map[interface{}]interface{})
		err = sess.Save(r, w)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		audit.Log(constants.AuditLogout, map[string]interface{}{
			"userId":            userId,
			"sessionIdentifier": sessionIdentifier,
			"loggedInUser":      authHelper.GetLoggedInSubject(r),
		})

		http.Redirect(w, r, config.AuthServerBaseUrl, http.StatusFound)
	}
}
