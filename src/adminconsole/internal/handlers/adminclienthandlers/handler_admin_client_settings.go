package adminclienthandlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"

	"github.com/leodip/goiabada/core/oauth"
)

func HandleAdminClientSettingsGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "clientId")
		if len(idStr) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("clientId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
			return
		}

		clientResp, err := apiClient.GetClientById(jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if clientResp == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New(fmt.Sprintf("client %v not found", id))))
			return
		}

		adminClientSettings := struct {
			ClientId                 int64
			ClientIdentifier         string
			Description              string
			WebsiteURL               string
			DisplayName              string
			Enabled                  bool
			ConsentRequired          bool
			ShowLogo                 bool
			ShowDisplayName          bool
			ShowDescription          bool
			ShowWebsiteURL           bool
			AuthorizationCodeEnabled bool
			DefaultAcrLevel          string
			IsSystemLevelClient      bool
		}{
			ClientId:                 clientResp.Id,
			ClientIdentifier:         clientResp.ClientIdentifier,
			Description:              clientResp.Description,
			WebsiteURL:               clientResp.WebsiteURL,
			DisplayName:              clientResp.DisplayName,
			Enabled:                  clientResp.Enabled,
			ConsentRequired:          clientResp.ConsentRequired,
			ShowLogo:                 clientResp.ShowLogo,
			ShowDisplayName:          clientResp.ShowDisplayName,
			ShowDescription:          clientResp.ShowDescription,
			ShowWebsiteURL:           clientResp.ShowWebsiteURL,
			AuthorizationCodeEnabled: clientResp.AuthorizationCodeEnabled,
			DefaultAcrLevel:          clientResp.DefaultAcrLevel,
			IsSystemLevelClient:      clientResp.IsSystemLevelClient,
		}

		sess, err := httpSession.Get(r, constants.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		savedSuccessfully := sess.Flashes("savedSuccessfully")
		if savedSuccessfully != nil {
			err = httpSession.Save(r, w, sess)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		bind := map[string]interface{}{
			"client":            adminClientSettings,
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"csrfField":         csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_settings.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminClientSettingsPost(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		idStr := chi.URLParam(r, "clientId")
		if len(idStr) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("clientId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		enabled := r.FormValue("enabled") == "on"
		consentRequired := r.FormValue("consentRequired") == "on"
		showLogo := r.FormValue("showLogo") == "on"
		showDisplayName := r.FormValue("showDisplayName") == "on"
		showDescription := r.FormValue("showDescription") == "on"
		showWebsiteURL := r.FormValue("showWebsiteUrl") == "on"

		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
			return
		}

		clientResp, err := apiClient.GetClientById(jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if clientResp == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New(fmt.Sprintf("client %v not found", id))))
			return
		}

		isSystemLevelClient := clientResp.IsSystemLevelClient

		adminClientSettings := struct {
			ClientId                 int64
			ClientIdentifier         string
			Description              string
			WebsiteURL               string
			DisplayName              string
			Enabled                  bool
			ConsentRequired          bool
			ShowLogo                 bool
			ShowDisplayName          bool
			ShowDescription          bool
			ShowWebsiteURL           bool
			AuthorizationCodeEnabled bool
			DefaultAcrLevel          string
			IsSystemLevelClient      bool
		}{
			ClientId:                 id,
			ClientIdentifier:         r.FormValue("clientIdentifier"),
			Description:              r.FormValue("description"),
			WebsiteURL:               r.FormValue("websiteUrl"),
			DisplayName:              r.FormValue("displayName"),
			Enabled:                  enabled,
			ConsentRequired:          consentRequired,
			ShowLogo:                 showLogo,
			ShowDisplayName:          showDisplayName,
			ShowDescription:          showDescription,
			ShowWebsiteURL:           showWebsiteURL,
			AuthorizationCodeEnabled: clientResp.AuthorizationCodeEnabled,
			DefaultAcrLevel:          r.FormValue("defaultAcrLevel"),
			IsSystemLevelClient:      isSystemLevelClient,
		}

		renderError := func(message string) {
			bind := map[string]interface{}{
				"client":    adminClientSettings,
				"error":     message,
				"csrfField": csrf.TemplateField(r),
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_settings.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		// Build API request
		updateReq := &api.UpdateClientSettingsRequest{
			ClientIdentifier: strings.TrimSpace(adminClientSettings.ClientIdentifier),
			Description:      strings.TrimSpace(adminClientSettings.Description),
			WebsiteURL:       strings.TrimSpace(adminClientSettings.WebsiteURL),
			DisplayName:      strings.TrimSpace(adminClientSettings.DisplayName),
			Enabled:          adminClientSettings.Enabled,
			ConsentRequired:  adminClientSettings.ConsentRequired,
			ShowLogo:         adminClientSettings.ShowLogo,
			ShowDisplayName:  adminClientSettings.ShowDisplayName,
			ShowDescription:  adminClientSettings.ShowDescription,
			ShowWebsiteURL:   adminClientSettings.ShowWebsiteURL,
		}
		if clientResp.AuthorizationCodeEnabled {
			updateReq.DefaultAcrLevel = r.FormValue("defaultAcrLevel")
		}

		_, err = apiClient.UpdateClient(jwtInfo.TokenResponse.AccessToken, id, updateReq)
		if err != nil {
			handlers.HandleAPIErrorWithCallback(httpHelper, w, r, err, renderError)
			return
		}

		sess, err := httpSession.Get(r, constants.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		sess.AddFlash("true", "savedSuccessfully")
		err = httpSession.Save(r, w, sess)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("%v/admin/clients/%v/settings", config.GetAdminConsole().BaseURL, id), http.StatusFound)
	}
}
