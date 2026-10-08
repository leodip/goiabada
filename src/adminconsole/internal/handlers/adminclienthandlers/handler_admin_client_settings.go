package adminclienthandlers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/sessionstore"
)

// clientSettingsAPI is what the client settings page needs: the client, and the write.
type clientSettingsAPI interface {
	GetClientById(ctx context.Context, accessToken string, clientId int64) (*api.ClientResponse, error)
	UpdateClient(ctx context.Context, accessToken string, clientId int64, request *api.UpdateClientSettingsRequest) (*api.ClientResponse, error)
}

// ClientSettings is what the Settings tab is drawn from. AdministrativeScopesAllowed is shown
// beside the settings, under Consent required, but saved by a form of its own on a route of its
// own, so the settings save never carries it (#499 decision 5).
//
// The tab binds two: "client", the values its inputs show, and "storedClient", the client as the
// auth server holds it, which the page title and the confirmation dialogs' original identifier and
// enabled state are drawn from. They differ only when a refused save is drawn again, with the
// inputs keeping what was typed (#522).
type ClientSettings struct {
	ClientId                    int64
	ClientIdentifier            string
	Description                 string
	WebsiteURL                  string
	DisplayName                 string
	Enabled                     bool
	ConsentRequired             bool
	AdministrativeScopesAllowed bool
	ShowLogo                    bool
	ShowDisplayName             bool
	ShowDescription             bool
	ShowWebsiteURL              bool
	AuthorizationCodeEnabled    bool
	DefaultAcrLevel             string
	IsSystemLevelClient         bool
	CreatedViaDCR               bool
}

// clientSettingsFrom draws the Settings tab from the client as the auth server answers it.
func clientSettingsFrom(c *api.ClientResponse) ClientSettings {
	return ClientSettings{
		ClientId:                    c.Id,
		ClientIdentifier:            c.ClientIdentifier,
		Description:                 c.Description,
		WebsiteURL:                  c.WebsiteURL,
		DisplayName:                 c.DisplayName,
		Enabled:                     c.Enabled,
		ConsentRequired:             c.ConsentRequired,
		AdministrativeScopesAllowed: c.AdministrativeScopesAllowed,
		ShowLogo:                    c.ShowLogo,
		ShowDisplayName:             c.ShowDisplayName,
		ShowDescription:             c.ShowDescription,
		ShowWebsiteURL:              c.ShowWebsiteURL,
		AuthorizationCodeEnabled:    c.AuthorizationCodeEnabled,
		DefaultAcrLevel:             c.DefaultAcrLevel,
		IsSystemLevelClient:         c.IsSystemLevelClient,
		CreatedViaDCR:               c.CreatedViaDCR,
	}
}

func HandleSettingsGet(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient clientSettingsAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "clientId")
		if len(idStr) == 0 {
			httpHelper.NotFound(w, r)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.NotFound(w, r)
			return
		}
		// Get JWT info from context to extract access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		clientResp, err := apiClient.GetClientById(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if clientResp == nil {
			httpHelper.NotFound(w, r)
			return
		}

		adminClientSettings := clientSettingsFrom(clientResp)

		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		_, savedSuccessfully := sess.TakeFlash("savedSuccessfully")
		_, administrativeScopesSaved := sess.TakeFlash(administrativeScopesSavedFlash)
		if savedSuccessfully || administrativeScopesSaved {
			err = httpSession.Save(r, w, sess)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		bind := map[string]interface{}{
			"client":                    adminClientSettings,
			"storedClient":              adminClientSettings,
			"savedSuccessfully":         savedSuccessfully,
			"administrativeScopesSaved": administrativeScopesSaved,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_settings.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleSettingsPost(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient clientSettingsAPI,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		idStr := chi.URLParam(r, "clientId")
		if len(idStr) == 0 {
			httpHelper.NotFound(w, r)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.NotFound(w, r)
			return
		}

		enabled := r.FormValue("enabled") == "on"
		consentRequired := r.FormValue("consentRequired") == "on"
		showLogo := r.FormValue("showLogo") == "on"
		showDisplayName := r.FormValue("showDisplayName") == "on"
		showDescription := r.FormValue("showDescription") == "on"
		showWebsiteURL := r.FormValue("showWebsiteUrl") == "on"

		// Get JWT info from context to extract access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		clientResp, err := apiClient.GetClientById(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if clientResp == nil {
			httpHelper.NotFound(w, r)
			return
		}

		isSystemLevelClient := clientResp.IsSystemLevelClient

		adminClientSettings := ClientSettings{
			ClientId:                    id,
			ClientIdentifier:            r.FormValue("clientIdentifier"),
			Description:                 r.FormValue("description"),
			WebsiteURL:                  r.FormValue("websiteUrl"),
			DisplayName:                 r.FormValue("displayName"),
			Enabled:                     enabled,
			ConsentRequired:             consentRequired,
			AdministrativeScopesAllowed: clientResp.AdministrativeScopesAllowed,
			ShowLogo:                    showLogo,
			ShowDisplayName:             showDisplayName,
			ShowDescription:             showDescription,
			ShowWebsiteURL:              showWebsiteURL,
			AuthorizationCodeEnabled:    clientResp.AuthorizationCodeEnabled,
			DefaultAcrLevel:             r.FormValue("defaultAcrLevel"),
			IsSystemLevelClient:         isSystemLevelClient,
			CreatedViaDCR:               clientResp.CreatedViaDCR,
		}

		// A refusal draws the tab again with the inputs as typed, and the title and the dialogs'
		// original values from the client as stored, so a second save of the same rename or
		// disable still asks first.
		renderError := func(message string) {
			bind := map[string]interface{}{
				"client":       adminClientSettings,
				"storedClient": clientSettingsFrom(clientResp),
				"error":        message,
			}

			renderErr := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_settings.html", bind)
			if renderErr != nil {
				httpHelper.InternalServerError(w, r, renderErr)
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

		_, err = apiClient.UpdateClient(r.Context(), jwtInfo.TokenResponse.AccessToken, id, updateReq)
		if err != nil {
			render.HandleAPIErrorWithCallback(httpHelper, w, r, err, renderError)
			return
		}

		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		sess.SetFlash("savedSuccessfully", "true")
		err = httpSession.Save(r, w, sess)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("%v/admin/clients/%v/settings", baseURL, id), http.StatusFound)
	}
}
