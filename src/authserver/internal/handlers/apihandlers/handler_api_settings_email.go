package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/hostport"
	"github.com/leodip/goiabada/core/i18n"
)

// HandleAPISettingsEmailGet - GET /api/v1/admin/settings/email
func HandleAPISettingsEmailGet() http.HandlerFunc {
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

// settingsEmailDatabase is what the email settings endpoint needs: the settings write.
type settingsEmailDatabase interface {
	UpdateSettings(ctx context.Context, tx *sql.Tx, settings *models.Settings) error
}

// HandleAPISettingsEmailPut - PUT /api/v1/admin/settings/email
func HandleAPISettingsEmailPut(
	database settingsEmailDatabase,
	emailValidator EmailValidator,
	auditLogger AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		currentSettings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
		if currentSettings == nil {
			writeInternalServerError(w, r, errs.New("settings are missing from the request context"))
			return
		}

		var req api.UpdateSettingsEmailRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// When disabled, reset fields to defaults
		if !req.SMTPEnabled {
			currentSettings.SMTPEnabled = false
			currentSettings.SMTPHost = ""
			currentSettings.SMTPPort = 0
			currentSettings.SMTPEncryption = emaildelivery.SMTPEncryptionNone.String()
			currentSettings.SMTPUsername = ""
			currentSettings.SMTPPasswordEncrypted = nil
			currentSettings.SMTPFromName = ""
			currentSettings.SMTPFromEmail = ""

			if err := database.UpdateSettings(r.Context(), nil, currentSettings); err != nil {
				writeInternalServerError(w, r, err)
				return
			}

			auditLogger.Log(r.Context(), audit.AuditUpdatedSMTPSettings, map[string]interface{}{
				"loggedInUser": callerSubject(r),
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

		// The host is normalised once, and the required check, the bound, the dial and the stored
		// value all take the result: surrounding space trimmed, and `[::1]` read as `::1`, which
		// RFC 4038 section 5.1 asks of anything parsing a literal address. The sender uses the
		// stored host on its own as the TLS server name, where brackets name nothing, so it is
		// stored bare (#424).
		smtpHost := hostport.Unbracket(strings.TrimSpace(req.SMTPHost))

		// Validation when enabled
		if smtpHost == "" {
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

		if len(smtpHost) > 120 {
			writeJSONError(w, fmt.Sprintf("SMTP host must be less than %v characters.", 120), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		if req.SMTPPort < 1 || req.SMTPPort > 65535 {
			writeJSONError(w, "SMTP port must be between 1 and 65535.", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Encryption value
		smtpEncryption, err := emaildelivery.SMTPEncryptionFromString(req.SMTPEncryption)
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

		if validateNoAngleBracketsErr := accountvalidation.ValidateNoAngleBrackets(req.SMTPFromName, i18n.ErrCodeSettingsSmtpFromNameAngleBrackets); validateNoAngleBracketsErr != nil {
			writeValidationError(w, r, validateNoAngleBracketsErr)
			return
		}
		if len(req.SMTPFromEmail) > 60 {
			writeJSONError(w, fmt.Sprintf("SMTP from email must be less than %v characters.", 60), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		if validateEmailAddressErr := emailValidator.ValidateEmailAddress(req.SMTPFromEmail); validateEmailAddressErr != nil {
			writeValidationError(w, r, validateEmailAddressErr)
			return
		}

		// TCP connectivity test with 3s timeout. Every check that needs no network runs
		// above, so a bad field is answered without waiting on the dial.
		conn, err := net.DialTimeout("tcp", hostport.Join(smtpHost, req.SMTPPort), 3*time.Second)
		if err != nil {
			writeJSONError(w, "Unable to connect to the SMTP server: "+err.Error(), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		if conn != nil {
			_ = conn.Close()
		}

		// Apply updates
		currentSettings.SMTPEnabled = true
		currentSettings.SMTPHost = smtpHost
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

		if err := database.UpdateSettings(r.Context(), nil, currentSettings); err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		auditLogger.Log(r.Context(), audit.AuditUpdatedSMTPSettings, map[string]interface{}{
			"loggedInUser": callerSubject(r),
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
	emailValidator EmailValidator,
	emailSender EmailSender,
	auditLogger AuditLogger,
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
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
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
		input := &emaildelivery.SendEmailInput{
			To:       req.To,
			Subject:  "Test email",
			HtmlBody: simpleBody,
		}
		if err := emailSender.SendEmail(r.Context(), input); err != nil {
			writeJSONError(w, "Unable to send email: "+err.Error(), "SEND_FAILED", http.StatusBadRequest)
			return
		}

		auditLogger.Log(r.Context(), audit.AuditSentTestEmail, map[string]interface{}{
			"loggedInUser": callerSubject(r),
			"to":           req.To,
		})

		writeJSON(w, r, http.StatusOK, api.SuccessResponse{Success: true})
	}
}
