package adminclienthandlers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/sessionstore"
)

// clientSettingsAPI is what the client settings page needs: the client, the brands its Brand
// select offers, the settings' write, and the allowance's and the brand's own writes.
type clientSettingsAPI interface {
	GetClientById(ctx context.Context, accessToken string, clientId int64) (*api.ClientResponse, error)
	GetAllBrands(ctx context.Context, accessToken string) ([]api.BrandResponse, error)
	UpdateClient(ctx context.Context, accessToken string, clientId int64, request *api.UpdateClientSettingsRequest) (*api.ClientResponse, error)
	UpdateClientAdministrativeScopes(ctx context.Context, accessToken string, clientId int64,
		request *api.UpdateClientAdministrativeScopesRequest) (*api.ClientResponse, error)
	UpdateClientBrand(ctx context.Context, accessToken string, clientId int64,
		request *api.UpdateClientBrandRequest) (*api.ClientResponse, error)
}

// settingsInvalidator drops the console's cached copy of the public settings, whose brand is the
// brand of the console's own client, so the next page is drawn in the brand just saved.
type settingsInvalidator interface {
	Invalidate()
}

// BrandOption is one brand the Brand select offers by name: its id is the value the select sends.
type BrandOption struct {
	Id   int64
	Name string
}

// ClientSettings is what the Settings tab is drawn from. AdministrativeScopesAllowed is a field of
// the settings form like the others, under Consent required, saved by the same Save. The auth server
// keeps it on a route of its own, which only authserver:manage may write (#499 decisions 4 and 5),
// so HandleSettingsPost writes it there, and only when it changed (#542). RememberConsent sits
// under Consent required too, drawn and sent for a public client only: a confidential client's is
// always on, and its tab draws no checkbox (#711 decisions 4 and 8).
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
	PrivacyPolicyURL            string
	TermsOfServiceURL           string
	DisplayName                 string
	Enabled                     bool
	ConsentRequired             bool
	RememberConsent             bool
	AdministrativeScopesAllowed bool
	ShowLogo                    bool
	ShowDisplayName             bool
	ShowDescription             bool
	ShowWebsiteURL              bool
	AuthorizationCodeEnabled    bool
	DefaultAcrLevel             string
	IsSystemLevelClient         bool
	CreatedViaDCR               bool
	// BrandId is the client's own brand, or 0 for a client with none, drawn in the default brand.
	BrandId int64
	// IsPublic is not edited here; the tab bar reads it, from the client as stored, to leave out
	// the Introspection tab of a public client.
	IsPublic bool
}

// clientSettingsFrom draws the Settings tab from the client as the auth server answers it.
func clientSettingsFrom(c *api.ClientResponse) ClientSettings {
	return ClientSettings{
		ClientId:                    c.Id,
		ClientIdentifier:            c.ClientIdentifier,
		Description:                 c.Description,
		WebsiteURL:                  c.WebsiteURL,
		PrivacyPolicyURL:            c.PrivacyPolicyURL,
		TermsOfServiceURL:           c.TermsOfServiceURL,
		DisplayName:                 c.DisplayName,
		Enabled:                     c.Enabled,
		ConsentRequired:             c.ConsentRequired,
		RememberConsent:             c.RememberConsent,
		AdministrativeScopesAllowed: c.AdministrativeScopesAllowed,
		ShowLogo:                    c.ShowLogo,
		ShowDisplayName:             c.ShowDisplayName,
		ShowDescription:             c.ShowDescription,
		ShowWebsiteURL:              c.ShowWebsiteURL,
		AuthorizationCodeEnabled:    c.AuthorizationCodeEnabled,
		DefaultAcrLevel:             c.DefaultAcrLevel,
		IsSystemLevelClient:         c.IsSystemLevelClient,
		CreatedViaDCR:               c.CreatedViaDCR,
		BrandId:                     brandIdOf(c.BrandId),
		IsPublic:                    c.IsPublic,
	}
}

// brandIdOf is the Brand select's value for a client's brand: the brand's id, or 0 for none.
func brandIdOf(brandId *int64) int64 {
	if brandId == nil {
		return 0
	}
	return *brandId
}

// submittedBrand is the brand the save gives the client, as the Brand select sent it in the body:
// empty puts it on the default brand, which is nil, and a brand's id gives it that brand. A select
// that was not submitted, or a value it never sends, keeps the stored brand, so a save that says
// nothing about the brand cannot reset it.
func submittedBrand(r *http.Request, stored *int64) *int64 {
	_ = r.PostFormValue("brandId") // parses the body
	values, sent := r.PostForm["brandId"]
	if !sent || len(values) == 0 {
		return stored
	}
	if values[0] == "" {
		return nil
	}
	id, err := strconv.ParseInt(values[0], 10, 64)
	if err != nil || id <= 0 {
		return stored
	}
	return &id
}

func sameBrand(a, b *int64) bool {
	return brandIdOf(a) == brandIdOf(b)
}

// bindBrands adds what the Brand select is drawn from to bind: every brand by name, in the auth
// server's order, and the name of the default brand, which its first choice names. It answers
// false, having answered the page that says why, when the brands cannot be read.
func bindBrands(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request, apiClient clientSettingsAPI,
	accessToken string, bind map[string]interface{}) bool {

	brands, err := apiClient.GetAllBrands(r.Context(), accessToken)
	if err != nil {
		render.HandleAPIError(httpHelper, w, r, err)
		return false
	}
	options := make([]BrandOption, 0, len(brands))
	defaultName := ""
	for _, brand := range brands {
		options = append(options, BrandOption{Id: brand.Id, Name: brand.Name})
		if brand.IsDefault {
			defaultName = brand.Name
		}
	}
	bind["brands"] = options
	bind["defaultBrandName"] = defaultName
	return true
}

// renderSettings draws the Settings tab from bind, with the Brand select's brands.
func renderSettings(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request, apiClient clientSettingsAPI,
	accessToken string, bind map[string]interface{}) {

	if !bindBrands(httpHelper, w, r, apiClient, accessToken, bind) {
		return
	}
	if err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_settings.html", bind); err != nil {
		httpHelper.InternalServerError(w, r, err)
	}
}

func HandleSettingsGet(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient clientSettingsAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := r.PathValue("clientId")
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

		renderSettings(httpHelper, w, r, apiClient, jwtInfo.TokenResponse.AccessToken, map[string]interface{}{
			"client":            adminClientSettings,
			"storedClient":      adminClientSettings,
			"savedSuccessfully": savedSuccessfully,
		})
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
// The Brand select is saved the same way, last and only when it differs from the client's stored
// brand, through the brand's own route (#812 decision 6): an empty value puts the client back on
// the default brand, and a brand's id gives it that brand. A save of the admin console's own client
// that changes its brand drops the console's cached public settings, whose brand is that client's,
// so the console's pages take it at once rather than when the cache expires.
//
// The writes are separate requests, so a refused allowance or brand leaves the settings saved: the
// tab is drawn again from the client as it now stands, saying the settings were saved, with the
// refusal beside its control. A refused allowance writes no brand.
func HandleSettingsPost(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient clientSettingsAPI,
	settingsCache settingsInvalidator,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		idStr := r.PathValue("clientId")
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

		// Remember consent is drawn and sent for a client public as loaded here only (#711 decision
		// 8). It is read from the body alone, as the allowance is: an unticked checkbox is submitted
		// as nothing, so its absence means off, and only the checkbox's own value turns it on. A
		// confidential client's save carries no value, and the auth server keeps it on; were the
		// client made public since it was loaded, the auth server applies nothing either way.
		rememberConsent := clientResp.RememberConsent
		var sentRememberConsent *bool
		if clientResp.IsPublic {
			rememberConsent = r.PostFormValue("rememberConsent") == "on"
			sentRememberConsent = &rememberConsent
		}

		brandId := submittedBrand(r, clientResp.BrandId)

		adminClientSettings := ClientSettings{
			ClientId:                    id,
			ClientIdentifier:            r.FormValue("clientIdentifier"),
			Description:                 r.FormValue("description"),
			WebsiteURL:                  r.FormValue("websiteUrl"),
			PrivacyPolicyURL:            r.PostFormValue("privacyPolicyUrl"),
			TermsOfServiceURL:           r.PostFormValue("termsOfServiceUrl"),
			DisplayName:                 r.FormValue("displayName"),
			Enabled:                     enabled,
			ConsentRequired:             consentRequired,
			RememberConsent:             rememberConsent,
			AdministrativeScopesAllowed: allowed,
			ShowLogo:                    showLogo,
			ShowDisplayName:             showDisplayName,
			ShowDescription:             showDescription,
			ShowWebsiteURL:              showWebsiteURL,
			AuthorizationCodeEnabled:    clientResp.AuthorizationCodeEnabled,
			DefaultAcrLevel:             r.FormValue("defaultAcrLevel"),
			IsSystemLevelClient:         isSystemLevelClient,
			CreatedViaDCR:               clientResp.CreatedViaDCR,
			BrandId:                     brandIdOf(brandId),
			IsPublic:                    clientResp.IsPublic,
		}
		accessToken := jwtInfo.TokenResponse.AccessToken

		// A refusal draws the tab again with the inputs as typed, and the title and the dialogs'
		// original values from the client as stored, so a second save of the same rename or
		// disable still asks first.
		renderError := func(message, errorField string) {
			renderSettings(httpHelper, w, r, apiClient, accessToken, map[string]interface{}{
				"client":       adminClientSettings,
				"storedClient": clientSettingsFrom(clientResp),
				"error":        message,
				"errorField":   errorField,
			})
		}

		// Build API request
		updateReq := &api.UpdateClientSettingsRequest{
			ClientIdentifier:  strings.TrimSpace(adminClientSettings.ClientIdentifier),
			Description:       strings.TrimSpace(adminClientSettings.Description),
			WebsiteURL:        strings.TrimSpace(adminClientSettings.WebsiteURL),
			PrivacyPolicyURL:  strings.TrimSpace(adminClientSettings.PrivacyPolicyURL),
			TermsOfServiceURL: strings.TrimSpace(adminClientSettings.TermsOfServiceURL),
			DisplayName:       strings.TrimSpace(adminClientSettings.DisplayName),
			Enabled:           adminClientSettings.Enabled,
			ConsentRequired:   adminClientSettings.ConsentRequired,
			RememberConsent:   sentRememberConsent,
			ShowLogo:          adminClientSettings.ShowLogo,
			ShowDisplayName:   adminClientSettings.ShowDisplayName,
			ShowDescription:   adminClientSettings.ShowDescription,
			ShowWebsiteURL:    adminClientSettings.ShowWebsiteURL,
		}
		if clientResp.AuthorizationCodeEnabled {
			updateReq.DefaultAcrLevel = r.FormValue("defaultAcrLevel")
		}

		updated, err := apiClient.UpdateClient(r.Context(), accessToken, id, updateReq)
		if err != nil {
			render.HandleAPIErrorWithCallback(httpHelper, w, r, err, func(message string) {
				renderError(message, render.ErrorField(err, clientErrorFields))
			})
			return
		}

		// stored is the client as the writes so far have left it, which a later refusal draws the tab
		// from, saying the settings were saved, with the refusal named by errorKey.
		stored := clientResp
		if updated != nil {
			stored = updated
		}
		renderSavedWith := func(errorKey string) func(message string) {
			return func(message string) {
				saved := clientSettingsFrom(stored)
				renderSettings(httpHelper, w, r, apiClient, accessToken, map[string]interface{}{
					"client":            saved,
					"storedClient":      saved,
					"savedSuccessfully": true,
					errorKey:            message,
				})
			}
		}

		if allowed != clientResp.AdministrativeScopesAllowed {
			answered, allowanceErr := apiClient.UpdateClientAdministrativeScopes(r.Context(), accessToken, id,
				&api.UpdateClientAdministrativeScopesRequest{Allowed: &allowed})
			if allowanceErr != nil {
				render.HandleAPIErrorWithCallback(httpHelper, w, r, allowanceErr, renderSavedWith("administrativeScopesError"))
				return
			}
			if answered != nil {
				stored = answered
			}
		}

		if !sameBrand(brandId, clientResp.BrandId) {
			_, err = apiClient.UpdateClientBrand(r.Context(), accessToken, id, &api.UpdateClientBrandRequest{BrandId: brandId})
			if err != nil {
				render.HandleAPIErrorWithCallback(httpHelper, w, r, err, renderSavedWith("brandError"))
				return
			}
			if clientResp.ClientIdentifier == builtin.AdminConsoleClientIdentifier {
				settingsCache.Invalidate()
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
