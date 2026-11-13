package handlers

import (
	"context"
	"database/sql"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/apiresponse"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/render"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/errs"
)

// publicSettingsDatabase is what the public settings endpoint needs: the settings row, and the brand
// the admin console's own client is drawn in, its own or the default the row points at.
type publicSettingsDatabase interface {
	GetSettingsById(ctx context.Context, tx *sql.Tx, settingsId int64) (*record.Settings, error)
	render.PageBrandReader
}

// HandlePublicSettingsGet answers GET /api/public/settings, which needs no authentication: the
// settings the admin console needs before anyone holds a token, the application name, whether SMTP
// is configured, the issuer, the brand the console draws its pages in, the stored password policy's
// rules and whether users may delete their own account, as JSON, or the API's JSON 500 when the
// settings row cannot be read (#279 decision 17). openapi.yaml describes it as getPublicSettings
// (#783).
//
// The brand is the admin console's own client's, or the default brand when that client has none of
// its own (#812 decision 7): the one the auth server draws that client's sign-in pages in, read
// through the same render.ClientPageBrand, with its two stylesheets' URLs made absolute on baseURL,
// as a client logo's is, so the console links them and draws its pages alike (#810 decision 3): the
// full one, which the auth server's own pages link, and the colors-only one for the console's admin
// pages (#813 decision 9), and its two safe stylesheets' beside them, with whether the operator's
// safe mode switch is on (#816 decision 3). Its logo's, dark logo's and favicon's URLs are made absolute alike, and
// the switch says whether the name gives way to the logo. A brand that cannot be read leaves brand
// out rather than failing the answer: the console then draws automatic in the built-in colors, as
// the auth server's own pages are drawn then.
//
// The route is registered for GET only, so the router answers any other method itself, 405 with
// an Allow header and no body, as it does for every API route (#522 decision 5).
func HandlePublicSettingsGet(database publicSettingsDatabase, baseURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get settings from database
		settings, err := database.GetSettingsById(r.Context(), nil, 1)
		if err != nil {
			apiresponse.WriteInternalServerError(w, r, errs.Wrap(err, "unable to retrieve the settings"))
			return
		}
		// GetSettingsById returns (nil, nil) when the row is absent, so this guard is
		// what stops an unauthenticated request from panicking the handler.
		if settings == nil {
			apiresponse.WriteInternalServerError(w, r, errs.New("the settings row is absent"))
			return
		}

		// Map to public response DTO. Only the fields below may ever appear here:
		// this endpoint needs no authentication, so the DTO is the whole boundary
		// between an anonymous caller and every field of record.Settings, which
		// include the legacy AES encryption key and the encrypted SMTP password.
		// handler_public_settings_test.go fails if that boundary widens.
		//
		// Issuer is here because the admin console needs the value this server
		// stamps into the iss claim, and OIDC Core 1.0 section 3.1.3.7 requires a
		// relying party to match it exactly. It discloses nothing new: the same
		// value is already served to anonymous callers at
		// /.well-known/openid-configuration, which OIDC Discovery 1.0 section 3
		// requires ("REQUIRED. URL using the https scheme ... that the OP asserts
		// as its Issuer Identifier").
		//
		// PasswordRules is here because the admin console states them under its password fields
		// (#550 decision 11). The registration form already states them to anyone while registration
		// is on, and NIST SP 800-63B assumes an attacker knows them.
		//
		// AccountDeletionEnabled is here because the admin console's account menu and page read it,
		// as SMTPEnabled gates Email verification (#783 decision 6). It is a policy, not data about
		// anyone.
		//
		// Brand is here because the admin console draws its pages in its own client's brand (#810
		// decision 3, #812 decision 7). It is its appearance, its two stylesheets' URLs, its logo's,
		// dark logo's and favicon's URLs and whether the name gives way to the logo (#813 decision
		// 9), whether it has a background image, and its footer links with every label and its support contact (#814 decision 9), all
		// of which that client's sign-in pages already show anyone.
		response := api.PublicSettingsResponse{
			AppName:       settings.AppName,
			SMTPEnabled:   settings.SMTPEnabled,
			Issuer:        settings.Issuer,
			PasswordRules: apimapping.ToPasswordRulesResponse(settings.PasswordPolicy),

			AccountDeletionEnabled: settings.AccountDeletionEnabled,

			Brand: publicBrand(r.Context(), database, baseURL),
		}

		apiresponse.WriteJSON(w, r, http.StatusOK, response)
	}
}

// publicBrand is the admin console's own client's brand as the public settings carry it, or nil when
// it cannot be read, which render.ClientPageBrand says by naming no stylesheet. Its data-theme is
// empty for automatic alone, so an empty one is published as auto.
func publicBrand(ctx context.Context, brands render.PageBrandReader, baseURL string) *api.PublicBrandResponse {
	brand := render.ClientPageBrand(ctx, brands, builtin.AdminConsoleClientIdentifier)
	if brand.Stylesheet == "" {
		return nil
	}
	appearance := brand.DataTheme
	if appearance == "" {
		appearance = string(record.BrandAppearanceAuto)
	}
	response := &api.PublicBrandResponse{
		Appearance:          appearance,
		StylesheetURL:       baseURL + brand.Stylesheet,
		ColorsStylesheetURL: baseURL + brand.ColorsStylesheet,
		// The safe links, which the console links while its own session is in safe mode, and whether
		// the operator's switch is on. While it is, the two links above are the safe ones already, as
		// render.ClientPageBrand answers them on every page, so the console follows it with no state
		// of its own (#816 decision 2).
		SafeStylesheetURL:       baseURL + brand.SafeStylesheet,
		SafeColorsStylesheetURL: baseURL + brand.SafeColorsStylesheet,
		SafeMode:                reqctx.BrandSafeMode(ctx),
		HideAppName:             brand.HideAppName,
		// Whether a background image is set, whatever its fit, so the console draws its card pages'
		// footer on a panel over it, as the auth server's own pages do (#814 decision 6, D1).
		HasBackground: brand.Background,
	}
	// An empty slot is left out, as the URL of nothing.
	absolute := func(path string) string {
		if path == "" {
			return ""
		}
		return baseURL + path
	}
	response.LogoURL = absolute(brand.Logo)
	response.DarkLogoURL = absolute(brand.DarkLogo)
	response.FaviconURL = absolute(brand.Favicon)
	// The footer is the brand's own, every label included, so the console picks each link's label by
	// the language of the page it draws; all four are always carried, as a brand's answer carries
	// them (#814 decision 9).
	response.FooterLinks = apimapping.ToBrandFooterLinkResponses(brand.FooterLinks)
	response.SupportEmail = brand.SupportEmail
	response.SupportURL = brand.SupportURL
	response.SupportPhone = brand.SupportPhone
	return response
}
