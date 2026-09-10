package apihandlers

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/communication"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/validators"
)

// HandleAPISettingsEmailGet - GET /api/v1/admin/settings/email
func HandleAPISettingsEmailGet(
	httpHelper handlers.HttpHelper,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
		if settings == nil {
			writeInternalServerError(w, r, errs.New("settings are missing from the request context"))
			return
		}

		resp := api.SettingsEmailResponse{
			SMTPEnabled:     settings.SMTPEnabled,
			SMTPHost:        settings.SMTPHost,
			SMTPPort:        settings.SMTPPort,
			SMTPUsername:    settings.SMTPUsername,
			SMTPEncryption:  settings.SMTPEncryption,
			SMTPFromName:    settings.SMTPFromName,
			SMTPFromEmail:   settings.SMTPFromEmail,
			HasSMTPPassword: len(settings.SMTPPasswordEncrypted) > 0,
		}

		writeJSON(w, r, http.StatusOK, resp)
	}
}

// HandleAPISettingsEmailPut - PUT /api/v1/admin/settings/email
func HandleAPISettingsEmailPut(
	httpHelper handlers.HttpHelper,
	authHelper handlers.AuthHelper,
	database data.Database,
	emailValidator handlers.EmailValidator,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		currentSettings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
		if currentSettings == nil {
			writeInternalServerError(w, r, errs.New("settings are missing from the request context"))
			return
		}

		var req api.UpdateSettingsEmailRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST", http.StatusBadRequest)
			return
		}

		// When disabled, reset fields to defaults
		if !req.SMTPEnabled {
			currentSettings.SMTPEnabled = false
			currentSettings.SMTPHost = ""
			currentSettings.SMTPPort = 0
			currentSettings.SMTPEncryption = enums.SMTPEncryptionNone.String()
			currentSettings.SMTPUsername = ""
			currentSettings.SMTPPasswordEncrypted = nil
			currentSettings.SMTPFromName = ""
			currentSettings.SMTPFromEmail = ""

			if err := database.UpdateSettings(nil, currentSettings); err != nil {
				writeInternalServerError(w, r, err)
				return
			}

			auditLogger.Log(constants.AuditUpdatedSMTPSettings, map[string]interface{}{
				"loggedInUser": authHelper.GetLoggedInSubject(r),
			})

			resp := api.SettingsEmailResponse{
				SMTPEnabled:     currentSettings.SMTPEnabled,
				SMTPHost:        currentSettings.SMTPHost,
				SMTPPort:        currentSettings.SMTPPort,
				SMTPUsername:    currentSettings.SMTPUsername,
				SMTPEncryption:  currentSettings.SMTPEncryption,
				SMTPFromName:    currentSettings.SMTPFromName,
				SMTPFromEmail:   currentSettings.SMTPFromEmail,
				HasSMTPPassword: len(currentSettings.SMTPPasswordEncrypted) > 0,
			}
			writeJSON(w, r, http.StatusOK, resp)
			return
		}

		// Validation when enabled
		if strings.TrimSpace(req.SMTPHost) == "" {
			writeJSONError(w, "SMTP host is required.", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		if req.SMTPPort == 0 {
			writeJSONError(w, "SMTP port is required.", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.SMTPFromEmail) == "" {
			writeJSONError(w, "SMTP from email is required.", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		if len(req.SMTPHost) > 120 {
			writeJSONError(w, fmt.Sprintf("SMTP host must be less than %v characters.", 120), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		if req.SMTPPort < 1 || req.SMTPPort > 65535 {
			writeJSONError(w, "SMTP port must be between 1 and 65535.", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Encryption value
		smtpEncryption, err := enums.SMTPEncryptionFromString(req.SMTPEncryption)
		if err != nil {
			writeJSONError(w, "Invalid SMTP encryption.", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		if len(req.SMTPUsername) > 60 {
			writeJSONError(w, fmt.Sprintf("SMTP username must be less than %v characters.", 60), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		// An application bound, measured in bytes because len(string) counts bytes. No
		// PLAIN or LOGIN provider credential is known to exceed it, and it must not shrink
		// to the neighbours' 60: SendGrid's SMTP password is its 69-character API key.
		if len(req.SMTPPassword) > 256 {
			writeJSONError(w, fmt.Sprintf("SMTP password must be at most %v bytes.", 256), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		if len(req.SMTPFromName) > 60 {
			writeJSONError(w, fmt.Sprintf("SMTP from name must be less than %v characters.", 60), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		if err := validators.ValidateNoAngleBrackets(req.SMTPFromName, i18n.ErrCodeSettingsSmtpFromNameAngleBrackets); err != nil {
			writeValidationError(w, r, err)
			return
		}
		if len(req.SMTPFromEmail) > 60 {
			writeJSONError(w, fmt.Sprintf("SMTP from email must be less than %v characters.", 60), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		if err := emailValidator.ValidateEmailAddress(req.SMTPFromEmail); err != nil {
			writeValidationError(w, r, err)
			return
		}

		// TCP connectivity test with 3s timeout. Every check that needs no network runs
		// above, so a bad field is answered without waiting on the dial.
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(req.SMTPHost, strconv.Itoa(req.SMTPPort)), 3*time.Second)
		if err != nil {
			writeJSONError(w, "Unable to connect to the SMTP server: "+err.Error(), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		if conn != nil {
			_ = conn.Close()
		}

		// Apply updates
		currentSettings.SMTPEnabled = true
		currentSettings.SMTPHost = strings.TrimSpace(req.SMTPHost)
		currentSettings.SMTPPort = req.SMTPPort
		currentSettings.SMTPEncryption = smtpEncryption.String()
		currentSettings.SMTPUsername = strings.TrimSpace(req.SMTPUsername)

		if len(req.SMTPPassword) > 0 {
			encrypted, err := encryption.EncryptData(req.SMTPPassword)
			if err != nil {
				writeInternalServerError(w, r, err)
				return
			}
			currentSettings.SMTPPasswordEncrypted = encrypted
		} else {
			currentSettings.SMTPPasswordEncrypted = nil
		}

		currentSettings.SMTPFromName = strings.TrimSpace(req.SMTPFromName)
		currentSettings.SMTPFromEmail = strings.ToLower(req.SMTPFromEmail)

		if err := database.UpdateSettings(nil, currentSettings); err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		auditLogger.Log(constants.AuditUpdatedSMTPSettings, map[string]interface{}{
			"loggedInUser": authHelper.GetLoggedInSubject(r),
		})

		resp := api.SettingsEmailResponse{
			SMTPEnabled:     currentSettings.SMTPEnabled,
			SMTPHost:        currentSettings.SMTPHost,
			SMTPPort:        currentSettings.SMTPPort,
			SMTPUsername:    currentSettings.SMTPUsername,
			SMTPEncryption:  currentSettings.SMTPEncryption,
			SMTPFromName:    currentSettings.SMTPFromName,
			SMTPFromEmail:   currentSettings.SMTPFromEmail,
			HasSMTPPassword: len(currentSettings.SMTPPasswordEncrypted) > 0,
		}
		writeJSON(w, r, http.StatusOK, resp)
	}
}

// HandleAPISettingsEmailSendTestPost - POST /api/v1/admin/settings/email/send-test
func HandleAPISettingsEmailSendTestPost(
	httpHelper handlers.HttpHelper,
	emailValidator handlers.EmailValidator,
	emailSender handlers.EmailSender,
	authHelper handlers.AuthHelper,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
		if settings == nil {
			writeInternalServerError(w, r, errs.New("settings are missing from the request context"))
			return
		}
		if !settings.SMTPEnabled {
			writeJSONError(w, "SMTP is not enabled", "SMTP_NOT_ENABLED", http.StatusBadRequest)
			return
		}

		var req api.SendTestEmailRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.To) == "" {
			writeJSONError(w, "Destination email is required.", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		if err := emailValidator.ValidateEmailAddress(req.To); err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Construct simple plain content via core communication interface
		simpleBody := "This is a test email from Goiabada. Today is " + time.Now().Format("January 2, 2006 at 3:04pm (MST)") + "."
		input := &communication.SendEmailInput{
			To:       req.To,
			Subject:  "Test email",
			HtmlBody: simpleBody,
		}
		if err := emailSender.SendEmail(r.Context(), input); err != nil {
			writeJSONError(w, "Unable to send email: "+err.Error(), "SEND_FAILED", http.StatusBadRequest)
			return
		}

		auditLogger.Log(constants.AuditSentTestEmail, map[string]interface{}{
			"loggedInUser": authHelper.GetLoggedInSubject(r),
			"to":           req.To,
		})

		writeJSON(w, r, http.StatusOK, api.SuccessResponse{Success: true})
	}
}
