package apihandlers

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/hostport"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/inputvalidation"
)

// HandleSettingsEmailGet - GET /api/v1/admin/settings/email
func HandleSettingsEmailGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			writeInternalServerError(w, r, reqctx.ErrNoSettings)
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

// settingsEmailDatabase is what the email settings endpoint needs: the settings save.
type settingsEmailDatabase interface {
	settingsSaveDatabase
}

// HandleSettingsEmailPut - PUT /api/v1/admin/settings/email
func HandleSettingsEmailPut(
	database settingsEmailDatabase,
	emailValidator EmailValidator,
	auditLogger AuditLogger,
	dataCipher *encryption.DataCipher,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		currentSettings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			writeInternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}

		var req api.UpdateSettingsEmailRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// When disabled, reset fields to defaults
		if !req.SMTPEnabled {
			// Reserved to authserver:manage: switching SMTP off is a change of where mail goes.
			if !settingsCeilingAllows(w, r, auditLogger) {
				return
			}

			saved, err := saveSettingsSection(r.Context(), database, currentSettings.Id, func(stored *record.Settings) {
				stored.SMTPEnabled = false
				stored.SMTPHost = ""
				stored.SMTPPort = 0
				stored.SMTPEncryption = emaildelivery.SMTPEncryptionNone.String()
				stored.SMTPUsername = ""
				stored.SMTPPasswordEncrypted = nil
				stored.SMTPFromName = ""
				stored.SMTPFromEmail = ""
			})
			if err != nil {
				writeInternalServerError(w, r, err)
				return
			}

			auditLogger.Log(r.Context(), audit.EventUpdatedSMTPSettings, map[string]interface{}{
				"logged_in_user": callerSubject(r),
			})

			writeJSON(w, r, http.StatusOK, settingsEmailResponse(saved))
			return
		}

		// The host is normalised once, and the required check, the bound, the dial and the stored
		// value all take the result: surrounding space trimmed, and `[::1]` read as `::1`, which
		// RFC 4038 section 5.1 asks of anything parsing a literal address. The sender uses the
		// stored host on its own as the TLS server name, where brackets name nothing, so it is
		// stored bare (#424).
		smtpHost := hostport.Unbracket(strings.TrimSpace(req.SMTPHost))

		// Validation when enabled. The sender address is an email address, so it takes the limit an
		// account's address does; the username takes the same, since for the hosted providers it is
		// the mailbox's own address, but stays free text. The sender name is a display name (#632).
		const (
			smtpHostMaxLength     = 120
			smtpUsernameMaxLength = accountvalidation.MaxEmailLength
			smtpFromNameMaxLength = 60
			smtpPasswordMaxBytes  = 256
		)
		if smtpHost == "" {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsEmailSMTPHostRequired, nil))
			return
		}
		if req.SMTPPort == 0 {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsEmailSMTPPortRequired, nil))
			return
		}
		if strings.TrimSpace(req.SMTPFromEmail) == "" {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsEmailSMTPFromEmailRequired, nil))
			return
		}

		if inputvalidation.TextLength(smtpHost) > smtpHostMaxLength {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsEmailSMTPHostTooLong, map[string]any{"max": smtpHostMaxLength}))
			return
		}

		if req.SMTPPort < 1 || req.SMTPPort > 65535 {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsEmailSMTPPortOutOfRange, nil))
			return
		}

		// Encryption value
		smtpEncryption, err := emaildelivery.SMTPEncryptionFromString(req.SMTPEncryption)
		if err != nil {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsEmailSMTPEncryptionInvalid, nil))
			return
		}

		if inputvalidation.TextLength(req.SMTPUsername) > smtpUsernameMaxLength {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsEmailSMTPUsernameTooLong, map[string]any{"max": smtpUsernameMaxLength}))
			return
		}
		// An application bound, measured in bytes because len(string) counts bytes. No
		// PLAIN or LOGIN provider credential is known to exceed it, and it must not shrink
		// to the sender name's 60: SendGrid's SMTP password is its 69-character API key.
		if len(req.SMTPPassword) > smtpPasswordMaxBytes {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsEmailSMTPPasswordTooLong, map[string]any{"max": smtpPasswordMaxBytes}))
			return
		}
		if inputvalidation.TextLength(req.SMTPFromName) > smtpFromNameMaxLength {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsEmailSMTPFromNameTooLong, map[string]any{"max": smtpFromNameMaxLength}))
			return
		}

		if validateNoAngleBracketsErr := accountvalidation.ValidateNoAngleBrackets(req.SMTPFromName, i18n.ErrCodeSettingsSmtpFromNameAngleBrackets); validateNoAngleBracketsErr != nil {
			writeValidationError(w, r, validateNoAngleBracketsErr)
			return
		}
		if inputvalidation.TextLength(req.SMTPFromEmail) > accountvalidation.MaxEmailLength {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsEmailSMTPFromEmailTooLong, map[string]any{"max": accountvalidation.MaxEmailLength}))
			return
		}

		if validateEmailAddressErr := emailValidator.ValidateEmailAddress(req.SMTPFromEmail); validateEmailAddressErr != nil {
			writeValidationError(w, r, validateEmailAddressErr)
			return
		}

		// The password is kept, replaced or removed (#410 decision 1). The API never answers it, so
		// an absent or empty one keeps what is stored, and only the flag removes it.
		if req.SMTPPassword != "" && req.ClearSMTPPassword {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsEmailSMTPPasswordAndClear, nil))
			return
		}
		// A stored password reaches only the host it was entered for: pointing it elsewhere needs
		// the password again, or its removal, or the next send would log in to the new host with a
		// password its caller cannot read (#410 decision 2). Both hosts are compared normalised.
		storedHost := hostport.Unbracket(strings.TrimSpace(currentSettings.SMTPHost))
		if len(currentSettings.SMTPPasswordEncrypted) > 0 && req.SMTPPassword == "" && !req.ClearSMTPPassword &&
			!strings.EqualFold(smtpHost, storedHost) {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsEmailSMTPHostChanged, nil))
			return
		}

		// Reserved to authserver:manage, refused after the request's own 400 answers and before
		// the dial, so a refused caller reaches no server through this one.
		if !settingsCeilingAllows(w, r, auditLogger) {
			return
		}

		// TCP connectivity test with 3s timeout, abandoned with the request. Every check that needs
		// no network runs above, so a bad field is answered without waiting on the dial. A failure
		// answers at most its coarse cause and the error goes to the log, so the answer is no probe
		// of the network the server sits on (#410 decision 4).
		dialer := net.Dialer{Timeout: 3 * time.Second}
		conn, err := dialer.DialContext(r.Context(), "tcp", hostport.Join(smtpHost, req.SMTPPort))
		if err != nil {
			slog.WarnContext(r.Context(), "unable to connect to the smtp server", "error", err)
			writeValidationError(w, r, connectionFailureMessage(smtpDialFailure,
				emaildelivery.ClassifyConnectionError(err)))
			return
		}
		if conn != nil {
			_ = conn.Close()
		}

		// The password written is decided here, against the row the host check above read: a kept
		// password is that row's, the one the check found entered for this host. Keeping the
		// password the save reads under its lock instead would let a save of another host and
		// password, committed meanwhile, have its password sent to this save's host (#410
		// decision 2). Two saves of the email settings are still last-writer-wins between them.
		smtpPasswordEncrypted := currentSettings.SMTPPasswordEncrypted
		switch {
		case req.ClearSMTPPassword:
			smtpPasswordEncrypted = nil
		case len(req.SMTPPassword) > 0:
			encrypted, encryptErr := dataCipher.Encrypt(req.SMTPPassword)
			if encryptErr != nil {
				writeInternalServerError(w, r, encryptErr)
				return
			}
			smtpPasswordEncrypted = encrypted
		}

		// Apply updates, onto the row as stored when the save runs (#407)
		smtpUsername := strings.TrimSpace(req.SMTPUsername)
		smtpFromName := strings.TrimSpace(req.SMTPFromName)
		smtpFromEmail := strings.ToLower(req.SMTPFromEmail)
		saved, err := saveSettingsSection(r.Context(), database, currentSettings.Id, func(stored *record.Settings) {
			stored.SMTPEnabled = true
			stored.SMTPHost = smtpHost
			stored.SMTPPort = req.SMTPPort
			stored.SMTPEncryption = smtpEncryption.String()
			stored.SMTPUsername = smtpUsername
			stored.SMTPPasswordEncrypted = smtpPasswordEncrypted
			stored.SMTPFromName = smtpFromName
			stored.SMTPFromEmail = smtpFromEmail
		})
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		auditLogger.Log(r.Context(), audit.EventUpdatedSMTPSettings, map[string]interface{}{
			"logged_in_user": callerSubject(r),
		})

		writeJSON(w, r, http.StatusOK, settingsEmailResponse(saved))
	}
}

// settingsEmailResponse is the email settings as the API answers them, the password only as
// whether one is stored.
func settingsEmailResponse(settings *record.Settings) api.SettingsEmailResponse {
	return api.SettingsEmailResponse{
		SMTPEnabled:     settings.SMTPEnabled,
		SMTPHost:        settings.SMTPHost,
		SMTPPort:        settings.SMTPPort,
		SMTPUsername:    settings.SMTPUsername,
		SMTPEncryption:  settings.SMTPEncryption,
		SMTPFromName:    settings.SMTPFromName,
		SMTPFromEmail:   settings.SMTPFromEmail,
		HasSMTPPassword: len(settings.SMTPPasswordEncrypted) > 0,
	}
}

// HandleSettingsEmailSendTestPost - POST /api/v1/admin/settings/email/send-test
func HandleSettingsEmailSendTestPost(
	emailValidator EmailValidator,
	emailSender EmailSender,
	auditLogger AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			writeInternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}
		if !settings.SMTPEnabled {
			writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSMTPNotEnabled, nil), "SMTP_NOT_ENABLED", http.StatusBadRequest)
			return
		}

		var req api.SendTestEmailRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.To) == "" {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsEmailDestinationRequired, nil))
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
		// A failure answers the fixed message of its kind and the error goes to the log: the error
		// carries addresses, operating-system strings and the server's own replies, and anyone who
		// can point the host somewhere would read them back here (#410 decision 5).
		if err := emailSender.SendEmail(r.Context(), emaildelivery.SMTPConfigFromSettings(settings), input); err != nil {
			slog.WarnContext(r.Context(), "unable to send the test email", "error", err)
			writeLocalizedError(w, r, sendFailureMessage(err), "SEND_FAILED", http.StatusBadRequest)
			return
		}

		auditLogger.Log(r.Context(), audit.EventSentTestEmail, map[string]interface{}{
			"logged_in_user": callerSubject(r),
			"to":             req.To,
		})

		writeJSON(w, r, http.StatusOK, api.SuccessResponse{Success: true})
	}
}

// connectionFailure is a failed connection's answer, one whole sentence per coarse cause, and none
// when the classification names no cause. The cause is never a fragment joined to an opening at run
// time, so each language words the whole sentence its own way (#559).
type connectionFailure struct {
	hostNotFound, timedOut, refused, noCause string
}

// smtpDialFailure is what a failed connectivity dial on save answers.
var smtpDialFailure = connectionFailure{
	hostNotFound: i18n.ErrCodeSettingsEmailConnectFailedHostNotFound,
	timedOut:     i18n.ErrCodeSettingsEmailConnectFailedTimedOut,
	refused:      i18n.ErrCodeSettingsEmailConnectFailedRefused,
	noCause:      i18n.ErrCodeSettingsEmailConnectFailed,
}

// testSendConnectionFailure is what a test send that could not connect answers.
var testSendConnectionFailure = connectionFailure{
	hostNotFound: i18n.ErrCodeSettingsEmailSendFailedHostNotFound,
	timedOut:     i18n.ErrCodeSettingsEmailSendFailedTimedOut,
	refused:      i18n.ErrCodeSettingsEmailSendFailedRefused,
	noCause:      i18n.ErrCodeSettingsEmailSendFailed,
}

// connectionFailureMessage is failure's sentence for cause. It is the only text a failed connection
// answers: no address, port, resolver or operating-system string (#410 decision 4).
func connectionFailureMessage(failure connectionFailure, cause emaildelivery.ConnectionCause) *i18n.LocalizedError {
	switch cause {
	case emaildelivery.ConnectionCauseHostNotFound:
		return i18n.NewLocalizedError(failure.hostNotFound, nil)
	case emaildelivery.ConnectionCauseTimedOut:
		return i18n.NewLocalizedError(failure.timedOut, nil)
	case emaildelivery.ConnectionCauseRefused:
		return i18n.NewLocalizedError(failure.refused, nil)
	default:
		return i18n.NewLocalizedError(failure.noCause, nil)
	}
}

// sendFailureMessage is the one message a failed test send answers, chosen by the kind the sender
// labelled the failure with and, for a connection failure, by its coarse cause; nothing in it is read
// from the error's text. The four refusals the sender composes itself keep its wording, without the
// part that quotes the server (#410 decision 5).
func sendFailureMessage(err error) *i18n.LocalizedError {
	switch emaildelivery.SendFailureKindOf(err) {
	case emaildelivery.SendFailureConnection:
		return connectionFailureMessage(testSendConnectionFailure, emaildelivery.ClassifyConnectionError(err))
	case emaildelivery.SendFailureSTARTTLSNotOffered:
		return i18n.NewLocalizedError(i18n.ErrCodeSettingsEmailSTARTTLSNotOffered, nil)
	case emaildelivery.SendFailureUnencryptedPassword:
		return i18n.NewLocalizedError(i18n.ErrCodeSettingsEmailPasswordUnencrypted, nil)
	case emaildelivery.SendFailureNoAuthentication:
		return i18n.NewLocalizedError(i18n.ErrCodeSettingsEmailNoAuthentication, nil)
	case emaildelivery.SendFailureNoSupportedMechanism:
		return i18n.NewLocalizedError(i18n.ErrCodeSettingsEmailNoSupportedMechanism, nil)
	case emaildelivery.SendFailureTLS:
		return i18n.NewLocalizedError(i18n.ErrCodeSettingsEmailTLSFailed, nil)
	case emaildelivery.SendFailureAuthenticationRejected:
		return i18n.NewLocalizedError(i18n.ErrCodeSettingsEmailAuthenticationRejected, nil)
	case emaildelivery.SendFailureMessageRefused:
		return i18n.NewLocalizedError(i18n.ErrCodeSettingsEmailMessageRefused, nil)
	default:
		return i18n.NewLocalizedError(i18n.ErrCodeSettingsEmailSendFailed, nil)
	}
}
