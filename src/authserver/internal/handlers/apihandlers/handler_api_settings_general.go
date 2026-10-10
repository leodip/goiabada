package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"
)

// HandleSettingsGeneralGet - GET /api/v1/admin/settings/general
func HandleSettingsGeneralGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			writeInternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}

		resp := api.SettingsGeneralResponse{
			AppName:                 settings.AppName,
			Issuer:                  settings.Issuer,
			SelfRegistrationEnabled: settings.SelfRegistrationEnabled,
			SelfRegistrationRequiresEmailVerification: settings.SelfRegistrationRequiresEmailVerification,
			DynamicClientRegistrationEnabled:          settings.DynamicClientRegistrationEnabled,
			PasswordPolicy:                            settings.PasswordPolicy.String(),
			PKCERequired:                              settings.PKCERequired,
			ImplicitFlowEnabled:                       settings.ImplicitFlowEnabled,
			ResourceOwnerPasswordCredentialsEnabled:   settings.ResourceOwnerPasswordCredentialsEnabled,
		}

		writeJSON(w, r, http.StatusOK, resp)
	}
}

// settingsGeneralDatabase is what the general settings endpoint needs: the settings write.
type settingsGeneralDatabase interface {
	UpdateSettings(ctx context.Context, tx *sql.Tx, settings *record.Settings) error
}

// HandleSettingsGeneralPut - PUT /api/v1/admin/settings/general
func HandleSettingsGeneralPut(
	database settingsGeneralDatabase,
	auditLogger AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		currentSettings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			writeInternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}

		var req api.UpdateSettingsGeneralRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// Validation: AppName
		const appNameMaxLength = 30
		if len(req.AppName) > appNameMaxLength {
			writeJSONError(w, fmt.Sprintf("App name is too long. The maximum length is %v characters.", appNameMaxLength), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		if err := accountvalidation.ValidateNoAngleBrackets(req.AppName, i18n.ErrCodeSettingsAppNameAngleBrackets); err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Validation: Issuer
		issuer := strings.TrimSpace(req.Issuer)
		if strings.Contains(issuer, ":") {
			parsedUri, err := url.ParseRequestURI(issuer)
			if err != nil || parsedUri.Scheme == "" || parsedUri.Host == "" {
				writeJSONError(w, "Invalid issuer. Please enter a valid URI.", "VALIDATION_ERROR", http.StatusBadRequest)
				return
			}
		} else {
			errorMsg := "Invalid issuer. It must start with a letter, can include letters, numbers, dashes, and underscores, but cannot end with a dash or underscore, or have two consecutive dashes or underscores."
			match, _ := regexp.MatchString("^[a-zA-Z]([a-zA-Z0-9_-]*[a-zA-Z0-9])?$", issuer)
			if !match {
				writeJSONError(w, errorMsg, "VALIDATION_ERROR", http.StatusBadRequest)
				return
			}
			if strings.Contains(issuer, "--") || strings.Contains(issuer, "__") {
				writeJSONError(w, errorMsg, "VALIDATION_ERROR", http.StatusBadRequest)
				return
			}
			const issuerMinLength = 3
			if len(issuer) < issuerMinLength {
				writeJSONError(w, fmt.Sprintf("Issuer is too short. The minimum length is %v characters.", issuerMinLength), "VALIDATION_ERROR", http.StatusBadRequest)
				return
			}
		}
		const issuerMaxLength = 60
		if len(issuer) > issuerMaxLength {
			writeJSONError(w, fmt.Sprintf("Issuer is too long. The maximum length is %v characters.", issuerMaxLength), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Both branches above pass this, but only the URL one can reach it holding a "<": the
		// identifier branch's regex has already refused the character with its own message, while
		// url.ParseRequestURI accepts "<" in a path or a host. The issuer is copied into the iss
		// claim of every token this server signs (#275).
		if err := accountvalidation.ValidateNoAngleBrackets(issuer, i18n.ErrCodeSettingsIssuerAngleBrackets); err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Validation: Password policy
		passwordPolicy, err := record.PasswordPolicyFromString(strings.TrimSpace(req.PasswordPolicy))
		if err != nil {
			writeJSONError(w, "Invalid password policy", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Apply updates
		currentSettings.AppName = strings.TrimSpace(req.AppName)
		currentSettings.Issuer = issuer
		currentSettings.SelfRegistrationEnabled = req.SelfRegistrationEnabled
		// Stored as sent, whether or not self-registration is on. It does nothing while
		// self-registration is off, since the registration page is then a 404, so keeping it
		// costs nothing, and clearing it did: an administrator who turned self-registration off
		// and on again got it back without email verification, which makes which addresses
		// have an account discoverable, with nothing on the page saying it had changed.
		currentSettings.SelfRegistrationRequiresEmailVerification = req.SelfRegistrationRequiresEmailVerification
		currentSettings.DynamicClientRegistrationEnabled = req.DynamicClientRegistrationEnabled
		currentSettings.PasswordPolicy = passwordPolicy
		currentSettings.PKCERequired = req.PKCERequired
		currentSettings.ImplicitFlowEnabled = req.ImplicitFlowEnabled
		currentSettings.ResourceOwnerPasswordCredentialsEnabled = req.ResourceOwnerPasswordCredentialsEnabled

		if err := database.UpdateSettings(r.Context(), nil, currentSettings); err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Audit log
		auditLogger.Log(r.Context(), audit.EventUpdatedGeneralSettings, map[string]interface{}{
			"logged_in_user": callerSubject(r),
		})

		resp := api.SettingsGeneralResponse{
			AppName:                 currentSettings.AppName,
			Issuer:                  currentSettings.Issuer,
			SelfRegistrationEnabled: currentSettings.SelfRegistrationEnabled,
			SelfRegistrationRequiresEmailVerification: currentSettings.SelfRegistrationRequiresEmailVerification,
			DynamicClientRegistrationEnabled:          currentSettings.DynamicClientRegistrationEnabled,
			PasswordPolicy:                            currentSettings.PasswordPolicy.String(),
			PKCERequired:                              currentSettings.PKCERequired,
			ImplicitFlowEnabled:                       currentSettings.ImplicitFlowEnabled,
			ResourceOwnerPasswordCredentialsEnabled:   currentSettings.ResourceOwnerPasswordCredentialsEnabled,
		}

		writeJSON(w, r, http.StatusOK, resp)
	}
}
