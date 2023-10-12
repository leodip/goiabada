package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminManageClientGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		settings := r.Context().Value(common.ContextKeySettings).(*entities.Settings)

		allowedScopes := []string{"authserver:admin-website"}
		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
		}

		if !s.isAuthorizedToAccessResource(jwtInfo, allowedScopes) {
			if s.isLoggedIn(jwtInfo) {
				http.Redirect(w, r, lib.GetBaseUrl()+"/unauthorized", http.StatusFound)
				return
			} else {
				s.redirToAuthorize(w, r, "admin-website", lib.GetBaseUrl()+r.RequestURI, "openid authserver:admin-website")
				return
			}
		}

		idStr := chi.URLParam(r, "clientID")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.New("clientID is required"))
			return
		}

		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		client, err := s.database.GetClientById(uint(id))
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if client == nil {
			s.internalServerError(w, r, errors.New("client not found"))
			return
		}

		clientSecretDecrypted := ""
		if !client.IsPublic {
			clientSecretDecrypted, err = lib.DecryptText(client.ClientSecretEncrypted, settings.AESEncryptionKey)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
		}

		adminClient := dtos.AdminClient{
			ClientIdentifier:         client.ClientIdentifier,
			ClientDescription:        client.Description,
			Enabled:                  client.Enabled,
			ConsentRequired:          client.ConsentRequired,
			IsPublic:                 client.IsPublic,
			ClientSecret:             clientSecretDecrypted,
			AuthorizationCodeEnabled: client.AuthorizationCodeEnabled,
			ClientCredentialsEnabled: client.ClientCredentialsEnabled,
		}

		for _, redirectUri := range client.RedirectUris {
			adminClient.RedirectUris = append(adminClient.RedirectUris, redirectUri.Uri)
		}

		bind := map[string]interface{}{
			"adminClient": adminClient,
		}

		err = s.renderTemplate(w, r, "/layouts/admin_layout.html", "/admin_manage_client.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleGenerateNewSecretGet() http.HandlerFunc {

	type generateNewSecretResult struct {
		RequiresAuth bool
		NewSecret    string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		result := generateNewSecretResult{
			RequiresAuth: true,
		}

		allowedScopes := []string{"authserver:admin-website"}
		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
		}

		if s.isAuthorizedToAccessResource(jwtInfo, allowedScopes) {
			result.RequiresAuth = false
		} else {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(result)
			return
		}

		result.NewSecret = lib.GenerateSecureRandomString(60)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}
