package server

import (
	"encoding/base64"
	"net/http"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/pkg/errors"
)

func (s *Server) handleAccountLogoutGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settings := r.Context().Value(common.ContextKeySettings).(*entitiesv2.Settings)

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

			err := s.renderTemplate(w, r, "/layouts/auth_layout.html", "/logout_consent.html", bind)
			if err != nil {
				s.internalServerError(w, r, err)
			}
			return
		}

		renderErrorUi := func(message string) {
			bind := map[string]interface{}{
				"title": "Logout error",
				"error": message,
			}

			err := s.renderTemplate(w, r, "/layouts/no_menu_layout.html", "/auth_error.html", bind)
			if err != nil {
				s.internalServerError(w, r, err)
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

			client, err := s.databasev2.GetClientByClientIdentifier(nil, clientId)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
			if client == nil {
				s.internalServerError(w, r, err)
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

			clientSecretDecrypted, err := lib.DecryptText(client.ClientSecretEncrypted, settings.AESEncryptionKey)
			if err != nil {
				s.internalServerError(w, r, errors.Wrap(err, "failed to decrypt client secret"))
				return
			}
			clientSecretDecryptedBytes := []byte(clientSecretDecrypted)

			// use the first 32 bytes only
			if len(clientSecretDecryptedBytes) > 32 {
				clientSecretDecryptedBytes = clientSecretDecryptedBytes[:32]
			}

			decryptedToken, err := lib.DecryptText(decodedTokenBytes, clientSecretDecryptedBytes)
			if err != nil {
				renderErrorUi("Failed to decrypt the id_token_hint: " + err.Error())
				return
			}
			idTokenHint = decryptedToken
		}

		idToken, err := s.tokenParser.ParseToken(r.Context(), idTokenHint, false)
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

		if issuer != lib.GetBaseUrl() {
			renderErrorUi("The id_token_hint parameter is invalid: the iss claim does not match the issuer of this server.")
			return
		}

		clientIdentifier := idToken.GetStringClaim("aud")
		if len(clientIdentifier) == 0 {
			renderErrorUi("The id_token_hint parameter is invalid: the aud claim is missing.")
			return
		}

		client, err := s.databasev2.GetClientByClientIdentifier(nil, clientIdentifier)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		if client == nil {
			s.internalServerError(w, r, err)
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

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		sessionIdentifier := ""
		if r.Context().Value(common.ContextKeySessionIdentifier) != nil {
			sessionIdentifier = r.Context().Value(common.ContextKeySessionIdentifier).(string)
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

			userSession, err := s.databasev2.GetUserSessionBySessionIdentifier(nil, sessionIdentifier)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}

			if userSession != nil {

				// find the user session client
				var userSessionClient *entitiesv2.UserSessionClient
				for idx, client := range userSession.Clients {
					if client.Client.ClientIdentifier == clientIdentifier {
						userSessionClient = &userSession.Clients[idx]
						break
					}
				}

				if userSessionClient != nil {
					err := s.databasev2.DeleteUserSessionClient(nil, userSessionClient.Id)
					if err != nil {
						s.internalServerError(w, r, err)
						return
					}

					lib.LogAudit(constants.AuditDeletedUserSessionClient, map[string]interface{}{
						"userId":        userSession.UserId,
						"userSessionId": userSession.Id,
						"clientId":      userSessionClient.Client.Id,
						"loggedInUser":  s.getLoggedInSubject(r),
					})

					if len(userSession.Clients) == 1 {
						// this was the only client in the session, so delete the session
						err := s.databasev2.DeleteUserSession(nil, userSession.Id)
						if err != nil {
							s.internalServerError(w, r, err)
							return
						}

						lib.LogAudit(constants.AuditLogout, map[string]interface{}{
							"userId":            userSession.UserId,
							"sessionIdentifier": sessionIdentifier,
							"loggedInUser":      s.getLoggedInSubject(r),
						})
					}
				}
			}
		}

		// clear the session state
		sess.Values = make(map[interface{}]interface{})
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
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

func (s *Server) handleAccountLogoutPost() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		sessionIdentifier := ""
		if r.Context().Value(common.ContextKeySessionIdentifier) != nil {
			sessionIdentifier = r.Context().Value(common.ContextKeySessionIdentifier).(string)
		}

		userId := int64(0)

		if len(sessionIdentifier) > 0 {
			userSession, err := s.databasev2.GetUserSessionBySessionIdentifier(nil, sessionIdentifier)
			if err != nil {
				s.internalServerError(w, r, err)
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
			s.internalServerError(w, r, err)
			return
		}

		lib.LogAudit(constants.AuditLogout, map[string]interface{}{
			"userId":            userId,
			"sessionIdentifier": sessionIdentifier,
			"loggedInUser":      s.getLoggedInSubject(r),
		})

		http.Redirect(w, r, lib.GetBaseUrl(), http.StatusFound)
	}
}
