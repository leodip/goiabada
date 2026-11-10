package handlers

import (
	"context"
	"database/sql"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/apiresponse"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/render"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
)

// publicSettingsDatabase is what the public settings endpoint needs: the settings row, and the
// default brand it points at.
type publicSettingsDatabase interface {
	GetSettingsById(ctx context.Context, tx *sql.Tx, settingsId int64) (*record.Settings, error)
	render.DefaultBrandReader
}

// HandlePublicSettingsGet answers GET /api/public/settings, which needs no authentication: the
// settings the admin console needs before anyone holds a token, the application name, whether SMTP
// is configured, the issuer, the default brand, the stored password policy's rules and whether users
// may delete their own account, as JSON, or the API's JSON 500 when the settings row cannot be read
// (#279 decision 17). openapi.yaml describes it as getPublicSettings (#783).
//
// The default brand is the one the auth server's own pages are drawn in, read through the same
// render.DefaultPageBrand, with its stylesheet's URL made absolute on baseURL, as a client logo's is,
// so the console links it and draws its pages alike (#810 decision 3). A default brand that cannot be
// read leaves brand out rather than failing the answer: the console then draws automatic in the
// built-in colors, as the auth server's own pages are drawn then.
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
		// between an anonymous caller and the 32 fields of record.Settings, which
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
		// Brand is here because the admin console draws its pages in the default brand (#810
		// decision 3). It is its appearance and stylesheet URL alone, which every page the auth server
		// serves to anyone already carries.
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

// publicBrand is the default brand as the public settings carry it, or nil when it cannot be read,
// which render.DefaultPageBrand says by naming no stylesheet. Its data-theme is empty for automatic
// alone, so an empty one is published as auto.
func publicBrand(ctx context.Context, brands render.DefaultBrandReader, baseURL string) *api.PublicBrandResponse {
	brand := render.DefaultPageBrand(ctx, brands)
	if brand.Stylesheet == "" {
		return nil
	}
	appearance := brand.DataTheme
	if appearance == "" {
		appearance = string(record.BrandAppearanceAuto)
	}
	return &api.PublicBrandResponse{Appearance: appearance, StylesheetURL: baseURL + brand.Stylesheet}
}
