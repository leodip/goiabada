package handlers

import (
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/apiresponse"
	"github.com/leodip/goiabada/authserver/internal/dtos"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/errs"
)

type HandlerPublicSettings struct {
	database data.Database
}

func NewHandlerPublicSettings(database data.Database) *HandlerPublicSettings {
	return &HandlerPublicSettings{
		database: database,
	}
}

func (h *HandlerPublicSettings) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Only allow GET requests. This endpoint answers JSON, so its refusals answer JSON too:
	// until now a caller that mis-spelled the method, or hit a settings failure, got
	// text/plain from a route it had every reason to parse (#279 decision 17).
	if r.Method != http.MethodGet {
		apiresponse.WriteError(w, "Method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
		return
	}

	// Get settings from database
	settings, err := h.database.GetSettingsById(nil, 1)
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
	// between an anonymous caller and the 32 fields of models.Settings, which
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
	response := dtos.PublicSettingsResponse{
		AppName:     settings.AppName,
		UITheme:     settings.UITheme,
		SMTPEnabled: settings.SMTPEnabled,
		Issuer:      settings.Issuer,
	}

	apiresponse.WriteJSON(w, r, http.StatusOK, response)
}
