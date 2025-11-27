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
    "github.com/leodip/goiabada/core/inputsanitizer"
    "github.com/leodip/goiabada/core/models"
)

// HandleAPISettingsGeneralGet - GET /api/v1/admin/settings/general
func HandleAPISettingsGeneralGet(
    httpHelper handlers.HttpHelper,
) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
        if settings == nil {
            writeJSONError(w, "Failed to load settings", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }

        resp := api.SettingsGeneralResponse{
            AppName:                                   settings.AppName,
            Issuer:                                    settings.Issuer,
            SelfRegistrationEnabled:                   settings.SelfRegistrationEnabled,
            SelfRegistrationRequiresEmailVerification: settings.SelfRegistrationRequiresEmailVerification,
            DynamicClientRegistrationEnabled:          settings.DynamicClientRegistrationEnabled,
            PasswordPolicy:                            settings.PasswordPolicy.String(),
            PKCERequired:                              settings.PKCERequired,
            ImplicitFlowEnabled:                       settings.ImplicitFlowEnabled,
        }

        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        httpHelper.EncodeJson(w, r, resp)
    }
}

// HandleAPISettingsGeneralPut - PUT /api/v1/admin/settings/general
func HandleAPISettingsGeneralPut(
    httpHelper handlers.HttpHelper,
    authHelper handlers.AuthHelper,
    database data.Database,
    inputSanitizer *inputsanitizer.InputSanitizer,
    auditLogger handlers.AuditLogger,
) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        currentSettings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
        if currentSettings == nil {
            writeJSONError(w, "Failed to load settings", "INTERNAL_ERROR", http.StatusInternalServerError)
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

        // Validation: Password policy
        passwordPolicy, err := enums.PasswordPolicyFromString(strings.TrimSpace(req.PasswordPolicy))
        if err != nil {
            writeJSONError(w, "Invalid password policy", "VALIDATION_ERROR", http.StatusBadRequest)
            return
        }

        // Apply updates with sanitization
        currentSettings.AppName = inputSanitizer.Sanitize(strings.TrimSpace(req.AppName))
        currentSettings.Issuer = inputSanitizer.Sanitize(issuer)
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

        if err := database.UpdateSettings(nil, currentSettings); err != nil {
            writeJSONError(w, "Failed to update settings", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }

        // Audit log
        auditLogger.Log(constants.AuditUpdatedGeneralSettings, map[string]interface{}{
            "loggedInUser": authHelper.GetLoggedInSubject(r),
        })

        resp := api.SettingsGeneralResponse{
            AppName:                                   currentSettings.AppName,
            Issuer:                                    currentSettings.Issuer,
            SelfRegistrationEnabled:                   currentSettings.SelfRegistrationEnabled,
            SelfRegistrationRequiresEmailVerification: currentSettings.SelfRegistrationRequiresEmailVerification,
            DynamicClientRegistrationEnabled:          currentSettings.DynamicClientRegistrationEnabled,
            PasswordPolicy:                            currentSettings.PasswordPolicy.String(),
            PKCERequired:                              currentSettings.PKCERequired,
            ImplicitFlowEnabled:                       currentSettings.ImplicitFlowEnabled,
        }

        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        httpHelper.EncodeJson(w, r, resp)
    }
}

