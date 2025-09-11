package handlers

import (
    "encoding/base64"
    "net/http"
    "strings"

	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/models"
    "github.com/leodip/goiabada/core/oauth"
    oauthdb "github.com/leodip/goiabada/core/oauthdb"
	"github.com/pkg/errors"
)

func HandleAccountLogoutGet(
	httpHelper HttpHelper,
	httpSession sessions.Store,
	authHelper AuthHelper,
	database data.Database,
	tokenParser TokenParser,
	auditLogger AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idTokenHint := httpHelper.GetFromUrlQueryOrFormPost(r, "id_token_hint")

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

		doLogoutWithIdToken(w, r, httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)
	}
}

func renderAuthError(w http.ResponseWriter, r *http.Request, httpHelper HttpHelper, message string) {
	bind := map[string]interface{}{
		"title": "Logout error",
		"error": message,
	}
	err := httpHelper.RenderTemplate(w, r, "/layouts/no_menu_layout.html", "/auth_error.html", bind)
	if err != nil {
		httpHelper.InternalServerError(w, r, err)
	}
}

func decryptIDTokenHint(idTokenHint, clientID string, database data.Database, settings *models.Settings) (string, error) {
	client, err := database.GetClientByClientIdentifier(nil, clientID)
	if err != nil || client == nil {
		return "", errors.New("Invalid client")
	}

	decodedTokenBytes, err := base64.StdEncoding.DecodeString(idTokenHint)
	if err != nil {
		decodedTokenBytes, err = base64.RawStdEncoding.DecodeString(idTokenHint)
	}
	if err != nil {
		return "", errors.Wrap(err, "Failed to base64 decode the id_token_hint")
	}

	clientSecretDecrypted, err := encryption.DecryptText(client.ClientSecretEncrypted, settings.AESEncryptionKey)
	if err != nil {
		return "", errors.Wrap(err, "Failed to decrypt client secret")
	}

	clientSecretDecrypted = padClientSecret(clientSecretDecrypted)
	clientSecretDecryptedBytes := []byte(clientSecretDecrypted)[:32]

	decryptedToken, err := encryption.DecryptText(decodedTokenBytes, clientSecretDecryptedBytes)
	if err != nil {
		return "", errors.Wrap(err, "Failed to decrypt the id_token_hint")
	}

	return decryptedToken, nil
}

func padClientSecret(secret string) string {
	if len(secret) < 32 {
		return secret + strings.Repeat("0", 32-len(secret))
	}
	return secret
}

func validateClientAndRedirectURI(idToken *oauth.JwtToken, postLogoutRedirectURI string, database data.Database, clientId string) (*models.Client, error) {
	clientIdentifier := idToken.GetStringClaim("aud")
	if len(clientIdentifier) == 0 {
		return nil, errors.New("The aud claim is missing in id_token_hint")
	}

	client, err := database.GetClientByClientIdentifier(nil, clientIdentifier)
	if err != nil || client == nil {
		return nil, errors.New("Invalid client: " + clientIdentifier)
	}

	if len(clientId) > 0 && clientId != clientIdentifier {
		return nil, errors.New("The client_id parameter does not match the aud claim in id_token_hint")
	}

	err = database.ClientLoadRedirectURIs(nil, client)
	if err != nil {
		return nil, err
	}

	for _, uri := range client.RedirectURIs {
		if uri.URI == postLogoutRedirectURI {
			return client, nil
		}
	}

	return nil, errors.New("Invalid post_logout_redirect_uri")
}

func handleExistingSessionOnLogout(
	r *http.Request,
	sessionIdentifier string,
	idToken *oauth.JwtToken,
	client *models.Client,
	database data.Database,
	auditLogger AuditLogger,
	authHelper AuthHelper,
) error {
	sid := idToken.GetStringClaim("sid")
	if len(sid) == 0 || sid != sessionIdentifier {
		return errors.New("Invalid session identifier in id_token_hint")
	}

	userSession, err := database.GetUserSessionBySessionIdentifier(nil, sessionIdentifier)
	if err != nil || userSession == nil {
		return err
	}

	err = database.UserSessionLoadClients(nil, userSession)
	if err != nil {
		return err
	}

	err = database.UserSessionClientsLoadClients(nil, userSession.Clients)
	if err != nil {
		return err
	}

	for idx, sessionClient := range userSession.Clients {
		if sessionClient.Client.ClientIdentifier == client.ClientIdentifier {
			err = database.DeleteUserSessionClient(nil, userSession.Clients[idx].Id)
			if err != nil {
				return err
			}

			auditLogger.Log(constants.AuditDeletedUserSessionClient, map[string]interface{}{
				"userId":        userSession.UserId,
				"userSessionId": userSession.Id,
				"clientId":      sessionClient.Client.Id,
				"loggedInUser":  authHelper.GetLoggedInSubject(r),
			})

			if len(userSession.Clients) == 1 {
				err = database.DeleteUserSession(nil, userSession.Id)
				if err != nil {
					return err
				}

				auditLogger.Log(constants.AuditLogout, map[string]interface{}{
					"userId":            userSession.UserId,
					"sessionIdentifier": sessionIdentifier,
					"loggedInUser":      authHelper.GetLoggedInSubject(r),
				})
			}
			break
		}
	}

	return nil
}

func HandleAccountLogoutPost(
    httpHelper HttpHelper,
    httpSession sessions.Store,
    authHelper AuthHelper,
    database data.Database,
    auditLogger AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// If id_token_hint is present in the POST body, handle same as GET flow
        if hint := httpHelper.GetFromUrlQueryOrFormPost(r, "id_token_hint"); len(hint) > 0 {
            // Use a fresh token parser based on database
            tp := oauthdb.NewTokenParser(database)
            doLogoutWithIdToken(w, r, httpHelper, httpSession, authHelper, database, tp, auditLogger)
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
		err = httpSession.Save(r, w, sess)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		auditLogger.Log(constants.AuditLogout, map[string]interface{}{
			"userId":            userId,
			"sessionIdentifier": sessionIdentifier,
			"loggedInUser":      authHelper.GetLoggedInSubject(r),
		})

		http.Redirect(w, r, config.GetAuthServer().BaseURL, http.StatusFound)
	}
}

// doLogoutWithIdToken contains the shared logic used by both GET and POST flows when an id_token_hint is provided.
func doLogoutWithIdToken(
    w http.ResponseWriter,
    r *http.Request,
    httpHelper HttpHelper,
    httpSession sessions.Store,
    authHelper AuthHelper,
    database data.Database,
    tokenParser TokenParser,
    auditLogger AuditLogger,
) {
	settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

	idTokenHint := httpHelper.GetFromUrlQueryOrFormPost(r, "id_token_hint")
	postLogoutRedirectURI := httpHelper.GetFromUrlQueryOrFormPost(r, "post_logout_redirect_uri")
	if len(postLogoutRedirectURI) == 0 {
		renderAuthError(w, r, httpHelper, "The post_logout_redirect_uri parameter is required. This parameter must match one of the redirect URIs that was registered for this client.")
		return
	}

	clientId := httpHelper.GetFromUrlQueryOrFormPost(r, "client_id")
	if len(clientId) > 0 {
		var err error
		idTokenHint, err = decryptIDTokenHint(idTokenHint, clientId, database, settings)
		if err != nil {
			renderAuthError(w, r, httpHelper, "Failed to decrypt the id_token_hint: "+err.Error())
			return
		}
	}

	idToken, err := tokenParser.DecodeAndValidateTokenString(idTokenHint, nil, true)
	if err != nil {
		renderAuthError(w, r, httpHelper, "The id_token_hint parameter is invalid: "+err.Error())
		return
	}

	issuer := idToken.GetStringClaim("iss")
	if len(issuer) == 0 {
		renderAuthError(w, r, httpHelper, "The id_token_hint parameter is invalid: the iss claim is missing.")
		return
	}
	if issuer != settings.Issuer {
		renderAuthError(w, r, httpHelper, "The id_token_hint parameter is invalid: the iss claim does not match the issuer of this server.")
		return
	}

	client, err := validateClientAndRedirectURI(idToken, postLogoutRedirectURI, database, clientId)
	if err != nil {
		renderAuthError(w, r, httpHelper, err.Error())
		return
	}

    sessionIdentifier := ""
    if r.Context().Value(constants.ContextKeySessionIdentifier) != nil {
        sessionIdentifier = r.Context().Value(constants.ContextKeySessionIdentifier).(string)
    }
    // Fallback: if no session cookie/context, use sid from id_token_hint
    if len(sessionIdentifier) == 0 {
        if sidClaim := idToken.GetStringClaim("sid"); len(sidClaim) > 0 {
            sessionIdentifier = sidClaim
        }
    }

    if len(sessionIdentifier) > 0 {
        err = handleExistingSessionOnLogout(r, sessionIdentifier, idToken, client, database, auditLogger, authHelper)
        if err != nil {
            httpHelper.InternalServerError(w, r, err)
            return
        }
    }

	sess, err := httpSession.Get(r, constants.SessionName)
	if err != nil {
		httpHelper.InternalServerError(w, r, err)
		return
	}
	sess.Values = make(map[interface{}]interface{})
	if err = httpSession.Save(r, w, sess); err != nil {
		httpHelper.InternalServerError(w, r, err)
		return
	}

	state := httpHelper.GetFromUrlQueryOrFormPost(r, "state")
    sid := sessionIdentifier
    logoutUri := postLogoutRedirectURI + "?sid=" + sid
	if len(state) > 0 {
		logoutUri += "&state=" + state
	}
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, logoutUri, http.StatusFound)
}
