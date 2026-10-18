package apihandlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/inputvalidation"
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

// settingsGeneralDatabase is what the general settings endpoint needs: the settings save.
type settingsGeneralDatabase interface {
	settingsSaveDatabase
}

// HandleSettingsGeneralPut - PUT /api/v1/admin/settings/general. baseURL is the auth server's
// configured base URL, the one issuer the rule accepts whatever its scheme.
func HandleSettingsGeneralPut(
	database settingsGeneralDatabase,
	auditLogger AuditLogger,
	baseURL string,
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
		if inputvalidation.TextLength(req.AppName) > appNameMaxLength {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsGeneralAppNameTooLong, map[string]any{"max": appNameMaxLength}))
			return
		}

		if err := accountvalidation.ValidateNoAngleBrackets(req.AppName, i18n.ErrCodeSettingsAppNameAngleBrackets); err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Validation: Issuer. Only the issuer rule is limited to an issuer that differs from the stored
		// one: a stored issuer the rule refuses stands until the operator changes it, because changing
		// it makes every relying party that checks iss reject tokens until reconfigured, so the
		// operator picks the moment, and the other general settings still save around it (#576
		// decision 4). The length limit and the angle-bracket refusal hold every save, as before it.
		issuer := strings.TrimSpace(req.Issuer)
		if issuer != currentSettings.Issuer && !oidc.IssuerIsAcceptable(issuer, baseURL) {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsGeneralIssuerURIInvalid, nil))
			return
		}
		if inputvalidation.TextLength(issuer) > oidc.IssuerMaxLength {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsGeneralIssuerTooLong, map[string]any{"max": oidc.IssuerMaxLength}))
			return
		}
		// The rule accepts "<" in a path or a host, and the issuer is copied into the iss claim of
		// every token this server signs (#275).
		if err := accountvalidation.ValidateNoAngleBrackets(issuer, i18n.ErrCodeSettingsIssuerAngleBrackets); err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Validation: Password policy
		passwordPolicy, err := record.PasswordPolicyFromString(strings.TrimSpace(req.PasswordPolicy))
		if err != nil {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsGeneralPasswordPolicyInvalid, nil))
			return
		}

		// Apply updates, onto the row as stored when the save runs (#407)
		appName := strings.TrimSpace(req.AppName)
		saved, err := saveSettingsSection(r.Context(), database, currentSettings.Id, func(stored *record.Settings) {
			stored.AppName = appName
			stored.Issuer = issuer
			stored.SelfRegistrationEnabled = req.SelfRegistrationEnabled
			// Stored as sent, whether or not self-registration is on. It does nothing while
			// self-registration is off, since the registration page is then a 404, so keeping it
			// costs nothing, and clearing it did: an administrator who turned self-registration off
			// and on again got it back without email verification, which makes which addresses
			// have an account discoverable, with nothing on the page saying it had changed.
			stored.SelfRegistrationRequiresEmailVerification = req.SelfRegistrationRequiresEmailVerification
			stored.DynamicClientRegistrationEnabled = req.DynamicClientRegistrationEnabled
			stored.PasswordPolicy = passwordPolicy
			stored.PKCERequired = req.PKCERequired
			stored.ImplicitFlowEnabled = req.ImplicitFlowEnabled
			stored.ResourceOwnerPasswordCredentialsEnabled = req.ResourceOwnerPasswordCredentialsEnabled
		})
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Audit log
		auditLogger.Log(r.Context(), audit.EventUpdatedGeneralSettings, map[string]interface{}{
			"logged_in_user": callerSubject(r),
		})

		resp := api.SettingsGeneralResponse{
			AppName:                 saved.AppName,
			Issuer:                  saved.Issuer,
			SelfRegistrationEnabled: saved.SelfRegistrationEnabled,
			SelfRegistrationRequiresEmailVerification: saved.SelfRegistrationRequiresEmailVerification,
			DynamicClientRegistrationEnabled:          saved.DynamicClientRegistrationEnabled,
			PasswordPolicy:                            saved.PasswordPolicy.String(),
			PKCERequired:                              saved.PKCERequired,
			ImplicitFlowEnabled:                       saved.ImplicitFlowEnabled,
			ResourceOwnerPasswordCredentialsEnabled:   saved.ResourceOwnerPasswordCredentialsEnabled,
		}

		writeJSON(w, r, http.StatusOK, resp)
	}
}
