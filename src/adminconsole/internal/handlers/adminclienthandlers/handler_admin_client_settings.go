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

// clientSettingsAPI is what the client settings page needs: the client, the settings' write, and
// the allowance's own write.
type clientSettingsAPI interface {
	GetClientById(ctx context.Context, accessToken string, clientId int64) (*api.ClientResponse, error)
	UpdateClient(ctx context.Context, accessToken string, clientId int64, request *api.UpdateClientSettingsRequest) (*api.ClientResponse, error)
	UpdateClientAdministrativeScopes(ctx context.Context, accessToken string, clientId int64,
		request *api.UpdateClientAdministrativeScopesRequest) (*api.ClientResponse, error)
}

// ClientSettings is what the Settings tab is drawn from. AdministrativeScopesAllowed is a field of
// the settings form like the others, under Consent required, saved by the same Save. The auth server
// keeps it on a route of its own, which only authserver:manage may write (#499 decisions 4 and 5),
// so HandleSettingsPost writes it there, and only when it changed (#542).
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
		if savedSuccessfully {
			err = httpSession.Save(r, w, sess)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		bind := map[string]interface{}{
			"client":            adminClientSettings,
			"storedClient":      adminClientSettings,
			"savedSuccessfully": savedSuccessfully,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_settings.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

// HandleSettingsPost saves the Settings tab: the settings through the client's update, then the
// administrative scopes allowance through its own route when the switch differs from the stored
// allowance. One Save stores the whole tab; until #542 the allowance had a Save of its own in the
// middle of the form, which saved it alone and reloaded the page, dropping every other change.
//
// The allowance is written only when it changed, and the auth server's record of it,
// updated_client_administrative_scopes, with it, not for every save of the tab. It is never written
// for a system-level client, or by an administrator without authserver:manage, the one scope the
// auth server lets switch it: for both the switch is drawn disabled, and the stored allowance stands,
// so such an administrator saves every other setting as before. The switch is read from the body alone: a browser submits an unticked checkbox as
// nothing, so its absence means "not allowed", and a value in the query is no submission of this
// form. Only the checkbox's own value switches it on.
//
// The two writes are two requests, so a refused allowance leaves the settings saved: the tab is drawn
// again from the client as it now stands, saying the settings were saved, with the refusal beside
// the switch.
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

		// The switch as submitted, kept for a refusal to draw again as typed. Only authserver:manage
		// switches the allowance (#499 decision 4), so for anyone else it is drawn disabled, as it is
		// for a system-level client, and a disabled switch is never submitted: its absence there is
		// no "off", and the stored allowance stands.
		allowed := r.PostFormValue("administrativeScopesAllowed") == "on"
		mayManage := jwtInfo.HasScope(builtin.AuthServerResourceIdentifier + ":" + builtin.ManagePermissionIdentifier)
		if isSystemLevelClient || !mayManage {
			allowed = clientResp.AdministrativeScopesAllowed
		}

		adminClientSettings := ClientSettings{
			ClientId:                    id,
			ClientIdentifier:            r.FormValue("clientIdentifier"),
			Description:                 r.FormValue("description"),
			WebsiteURL:                  r.FormValue("websiteUrl"),
			DisplayName:                 r.FormValue("displayName"),
			Enabled:                     enabled,
			ConsentRequired:             consentRequired,
			AdministrativeScopesAllowed: allowed,
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

		updated, err := apiClient.UpdateClient(r.Context(), jwtInfo.TokenResponse.AccessToken, id, updateReq)
		if err != nil {
			render.HandleAPIErrorWithCallback(httpHelper, w, r, err, renderError)
			return
		}

		if allowed != clientResp.AdministrativeScopesAllowed {
			renderAllowanceError := func(message string) {
				stored := clientResp
				if updated != nil {
					stored = updated
				}
				saved := clientSettingsFrom(stored)
				bind := map[string]interface{}{
					"client":                    saved,
					"storedClient":              saved,
					"savedSuccessfully":         true,
					"administrativeScopesError": message,
				}
				renderErr := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_settings.html", bind)
				if renderErr != nil {
					httpHelper.InternalServerError(w, r, renderErr)
				}
			}
			_, err = apiClient.UpdateClientAdministrativeScopes(r.Context(), jwtInfo.TokenResponse.AccessToken, id,
				&api.UpdateClientAdministrativeScopesRequest{Allowed: &allowed})
			if err != nil {
				render.HandleAPIErrorWithCallback(httpHelper, w, r, err, renderAllowanceError)
				return
			}
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
