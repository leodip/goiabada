package apihandlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/validators"
)

// HandleAPISettingsGeneralGet - GET /api/v1/admin/settings/general
func HandleAPISettingsGeneralGet(
	httpHelper handlers.HttpHelper,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
		if settings == nil {
			writeInternalServerError(w, r, errs.New("settings are missing from the request context"))
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

// HandleAPISettingsGeneralPut - PUT /api/v1/admin/settings/general
func HandleAPISettingsGeneralPut(
	authHelper handlers.AuthHelper,
	database data.Database,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		currentSettings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
		if currentSettings == nil {
			writeInternalServerError(w, r, errs.New("settings are missing from the request context"))
			return
		}

		var req api.UpdateSettingsGeneralRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST", http.StatusBadRequest)
			return
		}

		// Validation: AppName
		const appNameMaxLength = 30
		if len(req.AppName) > appNameMaxLength {
			writeJSONError(w, fmt.Sprintf("App name is too long. The maximum length is %v characters.", appNameMaxLength), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		if err := validators.ValidateNoAngleBrackets(req.AppName, i18n.ErrCodeSettingsAppNameAngleBrackets); err != nil {
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
		if err := validators.ValidateNoAngleBrackets(issuer, i18n.ErrCodeSettingsIssuerAngleBrackets); err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Validation: Password policy
		passwordPolicy, err := enums.PasswordPolicyFromString(strings.TrimSpace(req.PasswordPolicy))
		if err != nil {
			writeJSONError(w, "Invalid password policy", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Apply updates
		currentSettings.AppName = strings.TrimSpace(req.AppName)
		currentSettings.Issuer = issuer
		currentSettings.SelfRegistrationEnabled = req.SelfRegistrationEnabled
		if req.SelfRegistrationEnabled {
			currentSettings.SelfRegistrationRequiresEmailVerification = req.SelfRegistrationRequiresEmailVerification
		} else {
			currentSettings.SelfRegistrationRequiresEmailVerification = false
		}
		currentSettings.DynamicClientRegistrationEnabled = req.DynamicClientRegistrationEnabled
		currentSettings.PasswordPolicy = passwordPolicy
		currentSettings.PKCERequired = req.PKCERequired
		currentSettings.ImplicitFlowEnabled = req.ImplicitFlowEnabled
		currentSettings.ResourceOwnerPasswordCredentialsEnabled = req.ResourceOwnerPasswordCredentialsEnabled

		if err := database.UpdateSettings(nil, currentSettings); err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Audit log
		auditLogger.Log(constants.AuditUpdatedGeneralSettings, map[string]interface{}{
			"loggedInUser": authHelper.GetLoggedInSubject(r),
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
