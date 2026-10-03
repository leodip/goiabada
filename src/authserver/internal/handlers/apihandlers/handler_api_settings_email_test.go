package apihandlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	"github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// sendTestEmailRequest is an administrator's POST /api/v1/admin/settings/email/send-test to
// "admin@example.com", carrying the settings middleware.Settings would have put on it.
func sendTestEmailRequest(t *testing.T, settings *record.Settings) *http.Request {
	t.Helper()

	body, err := json.Marshal(map[string]string{"to": "admin@example.com"})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/settings/email/send-test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = setTokenContextWithClaims(req, map[string]interface{}{"sub": adminSubject})
	return req.WithContext(reqctx.WithSettings(req.Context(), settings))
}

// The test send goes out through the relay the request's settings configure, the password still
// encrypted: SendEmail decrypts it, so the handler never holds the plaintext (#433 decision 10).
func TestHandleSettingsEmailSendTestPost_SendsThroughTheSettingsRelay(t *testing.T) {
	emailSender := accounthandlersmocks.NewEmailSender(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	settings := &record.Settings{
		SMTPEnabled:           true,
		SMTPHost:              "smtp.example.com",
		SMTPPort:              465,
		SMTPUsername:          "relay-user",
		SMTPPasswordEncrypted: []byte("ciphertext"),
		SMTPEncryption:        "ssltls",
		SMTPFromName:          "Acme",
		SMTPFromEmail:         "noreply@example.com",
	}

	emailSender.On("SendEmail", mock.Anything, emaildelivery.SMTPConfig{
		Host:              "smtp.example.com",
		Port:              465,
		FromName:          "Acme",
		FromEmail:         "noreply@example.com",
		Encryption:        "ssltls",
		Username:          "relay-user",
		PasswordEncrypted: []byte("ciphertext"),
	}, mock.MatchedBy(func(input *emaildelivery.SendEmailInput) bool {
		return input.To == "admin@example.com" && input.Subject == "Test email"
	})).Return(nil).Once()
	auditLogger.On("Log", mock.Anything, audit.EventSentTestEmail, mock.Anything).Return().Once()

	rr := httptest.NewRecorder()
	HandleSettingsEmailSendTestPost(accountvalidation.NewEmailValidator(nil), emailSender, auditLogger).
		ServeHTTP(rr, sendTestEmailRequest(t, settings))

	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
}

// A failed send answers the administrator with the sender's own error after the fixed prefix, which
// is the wording the admin console shows. Moving the decryption into SendEmail's caller would have
// moved this text; keeping it in SendEmail keeps it (#433 decision 10).
func TestHandleSettingsEmailSendTestPost_AFailedSendNamesTheCause(t *testing.T) {
	emailSender := accounthandlersmocks.NewEmailSender(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	emailSender.On("SendEmail", mock.Anything, mock.Anything, mock.Anything).
		Return(errs.New("unable to decrypt the SMTP password")).Once()

	rr := httptest.NewRecorder()
	HandleSettingsEmailSendTestPost(accountvalidation.NewEmailValidator(nil), emailSender, auditLogger).
		ServeHTTP(rr, sendTestEmailRequest(t, &record.Settings{SMTPEnabled: true}))

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Unable to send email: unable to decrypt the SMTP password")
	assert.Contains(t, rr.Body.String(), "SEND_FAILED")
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}
