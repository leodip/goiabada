package handlers

import (
	"context"
	"database/sql"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/apiresponse"
	"github.com/leodip/goiabada/authserver/internal/legaldocuments"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
)

// publicSettingsDatabase is what the public settings endpoint needs: the settings row.
type publicSettingsDatabase interface {
	GetSettingsById(ctx context.Context, tx *sql.Tx, settingsId int64) (*record.Settings, error)
}

// publicLegalDocuments is what the public settings need of the legal documents: those in effect
// for all apps.
type publicLegalDocuments interface {
	ForAllApps(ctx context.Context) ([]legaldocuments.InEffect, error)
}

type PublicSettings struct {
	database       publicSettingsDatabase
	legalDocuments publicLegalDocuments
	baseURL        string
}

// NewPublicSettings answers the public settings from database and legalDocuments; baseURL is the auth
// server's public base URL, which each document's page address is built on.
func NewPublicSettings(database publicSettingsDatabase, legalDocuments publicLegalDocuments, baseURL string) *PublicSettings {
	return &PublicSettings{
		database:       database,
		legalDocuments: legalDocuments,
		baseURL:        baseURL,
	}
}

// ServeHTTP answers GET /api/public/settings, which needs no authentication: the settings the
// admin console needs before anyone holds a token, the application name, the UI theme, whether
// SMTP is configured, the issuer, the stored password policy's rules and the legal documents in
// effect for all apps, as JSON, or the API's JSON 500 when the settings row cannot
// be read (#279 decision 17).
//
// The route is registered for GET only, so the router answers any other method itself, 405 with
// an Allow header and no body, as it does for every API route (#522 decision 5).
func (h *PublicSettings) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Get settings from database
	settings, err := h.database.GetSettingsById(r.Context(), nil, 1)
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
	// LegalDocuments is here because My Account's footer links the documents in effect for all apps
	// (#622 decision 10). Each one's page is public, and the sign-in pages' footer links them too.
	inEffect, err := h.legalDocuments.ForAllApps(r.Context())
	if err != nil {
		apiresponse.WriteInternalServerError(w, r, errs.Wrap(err, "unable to retrieve the legal documents"))
		return
	}
	legalDocuments := make([]api.PublicLegalDocumentResponse, len(inEffect))
	for i, d := range inEffect {
		legalDocuments[i] = api.PublicLegalDocumentResponse{
			Title:     d.Current.Title,
			ShortName: d.Document.ShortName,
			URL:       h.baseURL + "/legal/" + d.Document.ShortName,
		}
	}

	response := api.PublicSettingsResponse{
		AppName:        settings.AppName,
		UITheme:        settings.UITheme,
		SMTPEnabled:    settings.SMTPEnabled,
		Issuer:         settings.Issuer,
		PasswordRules:  apimapping.ToPasswordRulesResponse(settings.PasswordPolicy),
		LegalDocuments: legalDocuments,
	}

	apiresponse.WriteJSON(w, r, http.StatusOK, response)
}
