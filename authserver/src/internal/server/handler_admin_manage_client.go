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
	"golang.org/x/exp/slices"
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
		slices.Sort(adminClient.RedirectUris)

		for _, permission := range client.Permissions {

			res, err := s.database.GetResourceById(permission.ResourceID)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}

			adminClient.Permissions = append(adminClient.Permissions, dtos.AdminClientPermission{
				ID:    permission.ID,
				Scope: res.ResourceIdentifier + ":" + permission.PermissionIdentifier,
			})
		}

		resources, err := s.database.GetAllResources()
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"adminClient": adminClient,
			"resources":   resources,
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

func (s *Server) handlePermissionsGet() http.HandlerFunc {

	type getPermissionsResult struct {
		RequiresAuth bool
		Permissions  []entities.Permission
	}

	return func(w http.ResponseWriter, r *http.Request) {
		result := getPermissionsResult{
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

		resourceIDStr := r.URL.Query().Get("resourceID")
		resourceID, err := strconv.ParseUint(resourceIDStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		permissions, err := s.database.GetResourcePermissions(uint(resourceID))
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		result.Permissions = permissions
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}
