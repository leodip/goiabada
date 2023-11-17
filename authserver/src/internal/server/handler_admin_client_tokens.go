package server

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminClientTokensGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "clientId")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.New("clientId is required"))
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

		settingsInfo := struct {
			TokenExpirationInSeconds                int
			RefreshTokenOfflineIdleTimeoutInSeconds int
			RefreshTokenOfflineMaxLifetimeInSeconds int
			IncludeOpenIDConnectClaimsInAccessToken string
		}{
			TokenExpirationInSeconds:                client.TokenExpirationInSeconds,
			RefreshTokenOfflineIdleTimeoutInSeconds: client.RefreshTokenOfflineIdleTimeoutInSeconds,
			RefreshTokenOfflineMaxLifetimeInSeconds: client.RefreshTokenOfflineMaxLifetimeInSeconds,
			IncludeOpenIDConnectClaimsInAccessToken: client.IncludeOpenIDConnectClaimsInAccessToken,
		}

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		savedSuccessfully := sess.Flashes("savedSuccessfully")
		if savedSuccessfully != nil {
			err = sess.Save(r, w)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
		}

		bind := map[string]interface{}{
			"settings":          settingsInfo,
			"client":            client,
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"csrfField":         csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_tokens.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminClientTokensPost() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "clientId")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.New("clientId is required"))
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

		isSystemLevelClient := client.IsSystemLevelClient()
		if isSystemLevelClient {
			s.internalServerError(w, r, errors.New("trying to edit a system level client"))
			return
		}

		settingsInfo := struct {
			TokenExpirationInSeconds                string
			RefreshTokenOfflineIdleTimeoutInSeconds string
			RefreshTokenOfflineMaxLifetimeInSeconds string
			IncludeOpenIDConnectClaimsInAccessToken string
		}{
			TokenExpirationInSeconds:                r.FormValue("tokenExpirationInSeconds"),
			RefreshTokenOfflineIdleTimeoutInSeconds: r.FormValue("refreshTokenOfflineIdleTimeoutInSeconds"),
			RefreshTokenOfflineMaxLifetimeInSeconds: r.FormValue("refreshTokenOfflineMaxLifetimeInSeconds"),
			IncludeOpenIDConnectClaimsInAccessToken: r.FormValue("includeOpenIDConnectClaimsInAccessToken"),
		}

		renderError := func(message string) {

			bind := map[string]interface{}{
				"settings":  settingsInfo,
				"client":    client,
				"csrfField": csrf.TemplateField(r),
				"error":     message,
			}

			err := s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_tokens.html", bind)
			if err != nil {
				s.internalServerError(w, r, err)
			}
		}

		tokenExpirationInSeconds, err := strconv.Atoi(settingsInfo.TokenExpirationInSeconds)
		if err != nil {
			settingsInfo.TokenExpirationInSeconds = strconv.Itoa(client.TokenExpirationInSeconds)
			renderError("Invalid value for token expiration in seconds.")
			return
		}

		const maxValue = 160000000
		if tokenExpirationInSeconds > maxValue {
			renderError(fmt.Sprintf("Token expiration in seconds cannot be greater than %v.", maxValue))
			return
		}

		refreshTokenOfflineIdleTimeoutInSeconds, err := strconv.Atoi(settingsInfo.RefreshTokenOfflineIdleTimeoutInSeconds)
		if err != nil {
			settingsInfo.RefreshTokenOfflineIdleTimeoutInSeconds = strconv.Itoa(client.RefreshTokenOfflineIdleTimeoutInSeconds)
			renderError("Invalid value for refresh token offline - idle timeout in seconds.")
			return
		}

		if refreshTokenOfflineIdleTimeoutInSeconds > maxValue {
			renderError(fmt.Sprintf("Refresh token offline - idle timeout in seconds cannot be greater than %v.", maxValue))
			return
		}

		refreshTokenOfflineMaxLifetimeInSeconds, err := strconv.Atoi(settingsInfo.RefreshTokenOfflineMaxLifetimeInSeconds)
		if err != nil {
			settingsInfo.RefreshTokenOfflineMaxLifetimeInSeconds = strconv.Itoa(client.RefreshTokenOfflineMaxLifetimeInSeconds)
			renderError("Invalid value for refresh token offline - max lifetime in seconds.")
			return
		}

		if refreshTokenOfflineMaxLifetimeInSeconds > maxValue {
			renderError(fmt.Sprintf("Refresh token offline - max lifetime in seconds cannot be greater than %v.", maxValue))
			return
		}

		if refreshTokenOfflineIdleTimeoutInSeconds > refreshTokenOfflineMaxLifetimeInSeconds {
			renderError("Refresh token offline - idle timeout cannot be greater than max lifetime.")
			return
		}

		threeStateSetting, err := enums.ThreeStateSettingFromString(settingsInfo.IncludeOpenIDConnectClaimsInAccessToken)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		client.TokenExpirationInSeconds = tokenExpirationInSeconds
		client.RefreshTokenOfflineIdleTimeoutInSeconds = refreshTokenOfflineIdleTimeoutInSeconds
		client.RefreshTokenOfflineMaxLifetimeInSeconds = refreshTokenOfflineMaxLifetimeInSeconds
		client.IncludeOpenIDConnectClaimsInAccessToken = threeStateSetting.String()

		_, err = s.database.SaveClient(client)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		sess.AddFlash("true", "savedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("%v/admin/clients/%v/tokens", lib.GetBaseUrl(), client.Id), http.StatusFound)
	}
}