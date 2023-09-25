package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleTokenPost(tokenIssuer tokenIssuer, tokenValidator tokenValidator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		settings := r.Context().Value(common.ContextKeySettings).(*entities.Settings)
		grantType := r.FormValue("grant_type")

		if grantType == "authorization_code" {

			code := r.FormValue("code")
			redirectUri := r.FormValue("redirect_uri")
			codeVerifier := r.FormValue("code_verifier")
			clientId := r.FormValue("client_id")
			clientSecret := r.FormValue("client_secret")

			if len(code) == 0 {
				s.jsonError(w, r, customerrors.NewAppError(nil, "invalid_request", "Missing required code parameter", http.StatusBadRequest))
				return
			}

			if len(redirectUri) == 0 {
				s.jsonError(w, r, customerrors.NewAppError(nil, "invalid_request", "Missing required redirect_uri parameter", http.StatusBadRequest))
				return
			}

			if len(codeVerifier) == 0 {
				s.jsonError(w, r, customerrors.NewAppError(nil, "invalid_request", "Missing required code_verifier parameter", http.StatusBadRequest))
				return
			}

			if len(clientId) == 0 {
				s.jsonError(w, r, customerrors.NewAppError(nil, "invalid_request", "Missing required client_id parameter", http.StatusBadRequest))
				return
			}

			client, err := s.database.GetClientByClientIdentifier(clientId)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
			if client == nil {
				s.jsonError(w, r, customerrors.NewAppError(nil, "invalid_request", "Client does not exist", http.StatusBadRequest))
				return
			}

			codeEntity, err := s.database.GetCode(code, false)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
			if codeEntity == nil {
				s.jsonError(w, r, customerrors.NewAppError(nil, "invalid_grant", "Code is invalid", http.StatusBadRequest))
				return
			}

			if codeEntity.RedirectUri != redirectUri {
				s.jsonError(w, r, customerrors.NewAppError(nil, "invalid_grant", "Invalid redirect_uri", http.StatusBadRequest))
				return
			}

			if codeEntity.Client.ClientIdentifier != clientId {
				s.jsonError(w, r, customerrors.NewAppError(nil, "invalid_grant", "The client_id provided does not match the client_id from code", http.StatusBadRequest))
				return
			}

			if !client.IsPublic {
				if len(clientSecret) == 0 {
					s.jsonError(w, r, customerrors.NewAppError(nil, "invalid_request", "This client is registered as confidential (not public), which means a client_secret is required for authentication. Please provide a valid client_secret to proceed", http.StatusBadRequest))
					return
				}

				clientSecretDecrypted, err := lib.DecryptText(client.ClientSecretEncrypted, settings.AESEncryptionKey)
				if err != nil {
					s.internalServerError(w, r, err)
					return
				}
				if clientSecretDecrypted != clientSecret {
					s.jsonError(w, r, customerrors.NewAppError(nil, "invalid_grant", "Client authentication failed. Please review your client_secret.", http.StatusBadRequest))
					return
				}
			}

			codeChallenge := lib.GeneratePKCECodeChallenge(codeVerifier)
			if codeEntity.CodeChallenge != codeChallenge {
				s.jsonError(w, r, customerrors.NewAppError(nil, "invalid_grant", "Invalid code_verifier (PKCE)", http.StatusBadRequest))
				return
			}

			keyPair, err := s.database.GetSigningKey()
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}

			tokenResp, err := tokenIssuer.GenerateTokenForAuthCode(r.Context(), codeEntity, keyPair)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
			codeEntity.Used = true
			_, err = s.database.UpdateCode(codeEntity)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(tokenResp)

		} else if grantType == "client_credentials" {

			clientId := r.FormValue("client_id")
			clientSecret := r.FormValue("client_secret")
			scope := r.FormValue("scope")

			client, err := s.database.GetClientByClientIdentifier(clientId)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
			if client == nil {
				s.jsonError(w, r, customerrors.NewAppError(nil, "invalid_client", "The client with this identifier could not be found", http.StatusBadRequest))
				return
			}
			if client.IsPublic {
				s.jsonError(w, r, customerrors.NewAppError(nil, "unauthorized_client", "A public client is not eligible for the client credentials flow. Kindly review the client configuration", http.StatusBadRequest))
				return
			}

			clientSecretDescrypted, err := lib.DecryptText(client.ClientSecretEncrypted, settings.AESEncryptionKey)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
			if clientSecretDescrypted != clientSecret {
				s.jsonError(w, r, customerrors.NewAppError(nil, "invalid_client", "Client authentication failed", http.StatusBadRequest))
				return
			}

			if len(scope) == 0 {
				// no scope was passed, let's include all possible permissions
				for _, perm := range client.Permissions {
					res, err := s.database.GetResourceByResourceIdentifier(perm.Resource.ResourceIdentifier)
					if err != nil {
						s.jsonError(w, r, err)
						return
					}
					scope = scope + " " + res.ResourceIdentifier + ":" + perm.PermissionIdentifier
				}
				scope = strings.TrimSpace(scope)
			}

			err = tokenValidator.ValidateScopes(r.Context(), scope, client.ClientIdentifier)
			if err != nil {
				s.jsonError(w, r, err)
				return
			}

			keyPair, err := s.database.GetSigningKey()
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}

			tokenResp, err := tokenIssuer.GenerateTokenForClientCred(r.Context(), client, scope, keyPair)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(tokenResp)
		} else {
			s.jsonError(w, r, customerrors.NewAppError(nil, "unsupported_grant_type", "Unsupported grant_type", http.StatusBadRequest))
			return
		}
	}
}
