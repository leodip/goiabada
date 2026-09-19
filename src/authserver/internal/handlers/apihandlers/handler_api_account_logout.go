package apihandlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/models"
	"net/url"
)

// HandleAPIAccountLogoutRequestPost - POST /api/v1/account/logout-request
// Returns a prepared logout instruction: a self-submitting form's parameters when the request asks
// for api.AccountLogoutResponseModeFormPost, and a ready-to-follow redirect URL otherwise.
func HandleAPIAccountLogoutRequestPost(
	database data.Database,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Access token + required scope enforced by middleware
		jwtToken, ok := middleware.GetValidatedToken(r)
		if !ok {
			writeJSONError(w, "Access token required", "ACCESS_TOKEN_REQUIRED", http.StatusUnauthorized)
			return
		}

		// Parse request
		var req api.AccountLogoutRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		postLogout := req.PostLogoutRedirectUri
		if postLogout == "" {
			writeJSONError(w, "postLogoutRedirectUri is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

		// Resolve client
		var client *models.Client
		var err error
		if req.ClientIdentifier != "" {
			client, err = database.GetClientByClientIdentifier(nil, req.ClientIdentifier)
			if err != nil || client == nil {
				writeJSONError(w, "Invalid client identifier", "VALIDATION_ERROR", http.StatusBadRequest)
				return
			}
		} else {
			// Automatic resolution by post_logout_redirect_uri
			clients, err := database.GetAllClients(nil)
			if err != nil {
				writeInternalServerError(w, r, err)
				return
			}
			var matches []*models.Client
			for i := range clients {
				c := &clients[i]
				if derr := database.ClientLoadRedirectURIs(nil, c); derr != nil {
					writeInternalServerError(w, r, err)
					return
				}
				for _, uri := range c.RedirectURIs {
					if uri.URI == postLogout {
						matches = append(matches, c)
						break
					}
				}
			}
			if len(matches) != 1 {
				writeJSONError(w, "Unable to resolve client from postLogoutRedirectUri; supply clientIdentifier.", "VALIDATION_ERROR", http.StatusBadRequest)
				return
			}
			client = matches[0]
		}

		// Validate redirect URI belongs to client
		if err = database.ClientLoadRedirectURIs(nil, client); err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		found := false
		for _, uri := range client.RedirectURIs {
			if uri.URI == postLogout {
				found = true
				break
			}
		}
		if !found {
			writeJSONError(w, "postLogoutRedirectUri is not registered for the client", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Strict session check: current sid must belong to a live session and be associated with this client
		sid := jwtToken.GetStringClaim("sid")
		if sid == "" {
			writeJSONError(w, "Current token lacks session identifier", "INVALID_SESSION", http.StatusUnauthorized)
			return
		}
		userSession, err := database.GetUserSessionBySessionIdentifier(nil, sid)
		if err != nil || userSession == nil {
			writeJSONError(w, "Session not found", "INVALID_SESSION", http.StatusUnauthorized)
			return
		}
		if err = database.UserSessionLoadClients(nil, userSession); err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if err = database.UserSessionClientsLoadClients(nil, userSession.Clients); err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		hasClient := false
		for _, sc := range userSession.Clients {
			if sc.Client.Id == client.Id {
				hasClient = true
				break
			}
		}
		if !hasClient {
			writeJSONError(w, "Client not part of the current session", "INVALID_SESSION", http.StatusUnauthorized)
			return
		}

		// Build a short-lived ID Token (id_token_hint)
		privKeyPair, err := database.GetCurrentSigningKey(nil)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		privKey, err := privKeyPair.ParsePrivateKey()
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		now := time.Now().UTC()
		claims := jwt.MapClaims{}
		claims["iss"] = settings.Issuer
		claims["sub"] = jwtToken.GetStringClaim("sub")
		claims["iat"] = now.Unix()
		claims["sid"] = sid
		claims["aud"] = client.ClientIdentifier
		// short TTL for logout hint
		claims["exp"] = now.Add(60 * time.Second).Unix()

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = privKeyPair.KeyIdentifier
		idToken, err := token.SignedString(privKey)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Both response modes carry the same parameters to the same endpoint, and the only
		// difference is how the browser gets them there. state is present in neither when the
		// request sent none: /auth/logout distinguishes an absent state from an empty one, and
		// answers a different redirect for each, so a mode that sent "state=" where the other
		// sent nothing would log the user out to a different place (RP-Initiated Logout 1.0
		// section 2, where state is OPTIONAL; #350 decision 2).
		if req.ResponseMode == api.AccountLogoutResponseModeFormPost {
			// The form binding keeps the id_token_hint out of a top-level navigation's URL,
			// and so out of the address bar, the browser history and the Referer of anything
			// the landing page loads. Referrer-Policy and the 60-second exp do not reach an
			// intermediary proxy's access log, which is what this mode is for (#109, #350).
			params := map[string]string{
				"id_token_hint":            idToken,
				"post_logout_redirect_uri": postLogout,
			}
			if req.State != "" {
				params["state"] = req.State
			}
			writeJSON(w, r, http.StatusOK, api.AccountLogoutFormPostResponse{
				Method:   http.MethodPost,
				Endpoint: config.GetAuthServer().BaseURL + "/auth/logout",
				Params:   params,
			})
			return
		}

		// Build logout redirect URL
		logoutUrl := fmt.Sprintf("%s/auth/logout?id_token_hint=%s&post_logout_redirect_uri=%s", config.GetAuthServer().BaseURL, url.QueryEscape(idToken), url.QueryEscape(postLogout))
		if req.State != "" {
			logoutUrl += "&state=" + url.QueryEscape(req.State)
		}
		resp := api.AccountLogoutRedirectResponse{LogoutUrl: logoutUrl}
		writeJSON(w, r, http.StatusOK, resp)
	}
}
