package apihandlers

import (
    "encoding/json"
    "fmt"
    "net/http"
    "time"

    "github.com/golang-jwt/jwt/v5"
    "github.com/leodip/goiabada/authserver/internal/handlers"
    "github.com/leodip/goiabada/authserver/internal/middleware"
    "github.com/leodip/goiabada/core/api"
    "github.com/leodip/goiabada/core/config"
    "github.com/leodip/goiabada/core/constants"
    "github.com/leodip/goiabada/core/data"
    "github.com/leodip/goiabada/core/models"
    "net/url"
)

// HandleAPIAccountLogoutRequestPost - POST /api/v1/account/logout-request
// Returns a prepared logout instruction (form_post preferred) or a redirect URL.
func HandleAPIAccountLogoutRequestPost(
    httpHelper handlers.HttpHelper,
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
            writeJSONError(w, "Invalid request body", "INVALID_REQUEST", http.StatusBadRequest)
            return
        }

        postLogout := req.PostLogoutRedirectUri
        if postLogout == "" {
            writeJSONError(w, "postLogoutRedirectUri is required", "VALIDATION_ERROR", http.StatusBadRequest)
            return
        }
        // We only support redirect mode now; ignore responseMode input

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
                writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
                return
            }
            var matches []*models.Client
            for i := range clients {
                c := &clients[i]
                if derr := database.ClientLoadRedirectURIs(nil, c); derr != nil {
                    writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
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
            writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
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
            writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
            return
        }
        if err = database.UserSessionClientsLoadClients(nil, userSession.Clients); err != nil {
            writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
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
            writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
            return
        }
        privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privKeyPair.PrivateKeyPEM)
        if err != nil {
            writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
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
            writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
            return
        }

        // Build logout redirect URL
        logoutUrl := fmt.Sprintf("%s/auth/logout?id_token_hint=%s&post_logout_redirect_uri=%s", config.GetAuthServer().BaseURL, url.QueryEscape(idToken), url.QueryEscape(postLogout))
        if req.State != "" {
            logoutUrl += "&state=" + url.QueryEscape(req.State)
        }
        resp := api.AccountLogoutRedirectResponse{LogoutUrl: logoutUrl}
        w.Header().Set("Content-Type", "application/json")
        httpHelper.EncodeJson(w, r, resp)
    }
}
