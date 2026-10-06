package apihandlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/internal/audit"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
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

// storedSMTPPassword is the password the email save cases start with stored, when they start with one.
const storedSMTPPassword = "stored-relay-secret"

// emailSaveSettings is the settings row an email save starts from: SMTP on, relaying through host on
// port 587, with storedSMTPPassword sealed under the test cipher when withPassword is set.
func emailSaveSettings(t *testing.T, host string, withPassword bool) *record.Settings {
	t.Helper()
	settings := &record.Settings{
		SMTPEnabled:    true,
		SMTPHost:       host,
		SMTPPort:       587,
		SMTPEncryption: "none",
		SMTPUsername:   "relay-user",
		SMTPFromName:   "Acme",
		SMTPFromEmail:  "noreply@example.com",
	}
	if withPassword {
		ciphertext, err := testDataCipher.Encrypt(storedSMTPPassword)
		require.NoError(t, err)
		settings.SMTPPasswordEncrypted = ciphertext
	}
	return settings
}

// emailSaveBody is an enabled email save of host and port, carrying extra beside the fields every
// save sends; a password, or its removal, is sent only when extra names it.
func emailSaveBody(t *testing.T, host string, port int, extra map[string]interface{}) string {
	t.Helper()
	body := map[string]interface{}{
		"smtpEnabled":    true,
		"smtpHost":       host,
		"smtpPort":       port,
		"smtpEncryption": "none",
		"smtpUsername":   "relay-user",
		"smtpFromName":   "Acme",
		"smtpFromEmail":  "noreply@example.com",
	}
	for key, value := range extra {
		body[key] = value
	}
	encoded, err := json.Marshal(body)
	require.NoError(t, err)
	return string(encoded)
}

// serveEmailSave runs PUT /api/v1/admin/settings/email as an authserver:manage caller, starting from
// settings, and answers what the save wrote, or nil when it wrote nothing.
func serveEmailSave(t *testing.T, settings *record.Settings, body string) (*httptest.ResponseRecorder, *record.Settings) {
	t.Helper()
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	var written *record.Settings
	database.On("UpdateSettings", mock.Anything, (*sql.Tx)(nil), mock.AnythingOfType("*record.Settings")).
		Run(func(args mock.Arguments) {
			saved := *args.Get(2).(*record.Settings)
			saved.SMTPPasswordEncrypted = bytes.Clone(saved.SMTPPasswordEncrypted)
			written = &saved
		}).Return(nil).Maybe()
	auditLogger.On("Log", mock.Anything, audit.EventUpdatedSMTPSettings, mock.Anything).Return().Maybe()

	r := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings/email", strings.NewReader(body))
	r = r.WithContext(reqctx.WithSettings(r.Context(), settings))
	r = setTokenContextWithClaims(r, map[string]interface{}{"scope": "authserver:manage", "sub": grantCaller})
	rr := httptest.NewRecorder()
	HandleSettingsEmailPut(database, accountvalidation.NewEmailValidator(nil), auditLogger, testDataCipher).ServeHTTP(rr, r)

	if rr.Code != http.StatusOK {
		database.AssertNotCalled(t, "UpdateSettings", mock.Anything, mock.Anything, mock.Anything)
		auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	}
	return rr, written
}

// hasSMTPPasswordIn reads hasSmtpPassword from a successful save's answer.
func hasSMTPPasswordIn(t *testing.T, rr *httptest.ResponseRecorder) bool {
	t.Helper()
	var body struct {
		HasSMTPPassword *bool `json:"hasSmtpPassword"`
	}
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&body))
	require.NotNil(t, body.HasSMTPPassword, "the answer carries hasSmtpPassword")
	return *body.HasSMTPPassword
}

// An absent or empty smtpPassword keeps the stored password: the API never answers it, so a client
// that sends the form back as it read it has nothing to put there. The row is written with the
// stored ciphertext byte for byte, not a fresh encryption of the same password, and a change of
// port, username, encryption or sender does not ask for it again (#410 decisions 1 and 2).
func TestHandleSettingsEmailPut_AnAbsentOrEmptyPasswordKeepsTheStoredOne(t *testing.T) {
	cases := []struct {
		name  string
		extra map[string]interface{}
	}{
		{name: "smtpPassword absent", extra: nil},
		{name: "smtpPassword empty", extra: map[string]interface{}{"smtpPassword": ""}},
		{name: "smtpPassword empty, clearSmtpPassword false", extra: map[string]interface{}{"smtpPassword": "", "clearSmtpPassword": false}},
		{name: "port, username, encryption and sender changed", extra: map[string]interface{}{
			"smtpUsername": "another-user", "smtpEncryption": "starttls",
			"smtpFromName": "Another", "smtpFromEmail": "another@example.com",
		}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			settings := emailSaveSettings(t, "127.0.0.1", true)
			stored := bytes.Clone(settings.SMTPPasswordEncrypted)

			rr, written := serveEmailSave(t, settings, emailSaveBody(t, "127.0.0.1", listeningSMTPPort(t), c.extra))

			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			require.NotNil(t, written)
			assert.Equal(t, stored, written.SMTPPasswordEncrypted, "the stored ciphertext, byte for byte")
			assert.True(t, hasSMTPPasswordIn(t, rr))
		})
	}
}

// A non-empty smtpPassword replaces the stored one, whether or not one was stored.
func TestHandleSettingsEmailPut_ANewPasswordReplacesTheStoredOne(t *testing.T) {
	for _, withPassword := range []bool{true, false} {
		t.Run(fmt.Sprintf("password stored: %v", withPassword), func(t *testing.T) {
			settings := emailSaveSettings(t, "127.0.0.1", withPassword)

			rr, written := serveEmailSave(t, settings, emailSaveBody(t, "127.0.0.1", listeningSMTPPort(t),
				map[string]interface{}{"smtpPassword": "brand-new-secret"}))

			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			require.NotNil(t, written)
			plaintext, err := testDataCipher.Decrypt(written.SMTPPasswordEncrypted)
			require.NoError(t, err)
			assert.Equal(t, "brand-new-secret", plaintext)
			assert.True(t, hasSMTPPasswordIn(t, rr))
		})
	}
}

// clearSmtpPassword removes the stored password, and with nothing stored it is a save like any other.
func TestHandleSettingsEmailPut_ClearSmtpPasswordRemovesTheStoredOne(t *testing.T) {
	for _, withPassword := range []bool{true, false} {
		t.Run(fmt.Sprintf("password stored: %v", withPassword), func(t *testing.T) {
			settings := emailSaveSettings(t, "127.0.0.1", withPassword)

			rr, written := serveEmailSave(t, settings, emailSaveBody(t, "127.0.0.1", listeningSMTPPort(t),
				map[string]interface{}{"smtpPassword": "", "clearSmtpPassword": true}))

			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			require.NotNil(t, written)
			assert.Empty(t, written.SMTPPasswordEncrypted)
			assert.False(t, hasSMTPPasswordIn(t, rr))
		})
	}
}

// A new password together with its removal says two things at once: it is refused and nothing is
// written, whether or not a password is stored.
func TestHandleSettingsEmailPut_APasswordTogetherWithItsRemovalIsRefused(t *testing.T) {
	for _, withPassword := range []bool{true, false} {
		t.Run(fmt.Sprintf("password stored: %v", withPassword), func(t *testing.T) {
			settings := emailSaveSettings(t, "127.0.0.1", withPassword)

			rr, written := serveEmailSave(t, settings, emailSaveBody(t, "127.0.0.1", listeningSMTPPort(t),
				map[string]interface{}{"smtpPassword": "brand-new-secret", "clearSmtpPassword": true}))

			assert.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
			code, description := decodeErrorEnvelope(t, rr)
			assert.Equal(t, "VALIDATION_ERROR", code)
			assert.Equal(t, "Send either a new SMTP password or clearSmtpPassword, not both.", description)
			assert.Nil(t, written)
		})
	}
}

// Pointing a stored password at another host needs the password again, or its removal, so a
// stored password only ever reaches the host it was entered for. The refusal is answered before
// the dial: the port here is one nothing listens on, which the dial would have answered instead
// (#410 decision 2).
func TestHandleSettingsEmailPut_AHostChangeWithAStoredPasswordNeedsItAgain(t *testing.T) {
	settings := emailSaveSettings(t, "smtp.example.test", true)

	rr, written := serveEmailSave(t, settings, emailSaveBody(t, "127.0.0.1", unreachableSMTPPort(t),
		map[string]interface{}{"smtpPassword": ""}))

	assert.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	code, description := decodeErrorEnvelope(t, rr)
	assert.Equal(t, "VALIDATION_ERROR", code)
	assert.Equal(t, "The SMTP host has changed: enter the SMTP password again, or remove it.", description)
	assert.Nil(t, written)
}

// A host change carrying the password again, or its removal, or reaching a row with no password
// stored, saves as any other.
func TestHandleSettingsEmailPut_AHostChangeWithTheAnswerSaves(t *testing.T) {
	cases := []struct {
		name         string
		withPassword bool
		extra        map[string]interface{}
		wantPassword string
	}{
		{name: "with a new password", withPassword: true,
			extra: map[string]interface{}{"smtpPassword": "brand-new-secret"}, wantPassword: "brand-new-secret"},
		{name: "with clearSmtpPassword", withPassword: true,
			extra: map[string]interface{}{"clearSmtpPassword": true}},
		{name: "with no password stored", withPassword: false, extra: nil},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			settings := emailSaveSettings(t, "smtp.example.test", c.withPassword)

			rr, written := serveEmailSave(t, settings, emailSaveBody(t, "127.0.0.1", listeningSMTPPort(t), c.extra))

			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			require.NotNil(t, written)
			assert.Equal(t, "127.0.0.1", written.SMTPHost)
			if c.wantPassword == "" {
				assert.Empty(t, written.SMTPPasswordEncrypted)
				assert.False(t, hasSMTPPasswordIn(t, rr))
				return
			}
			plaintext, err := testDataCipher.Decrypt(written.SMTPPasswordEncrypted)
			require.NoError(t, err)
			assert.Equal(t, c.wantPassword, plaintext)
			assert.True(t, hasSMTPPasswordIn(t, rr))
		})
	}
}

// The hosts are compared in the form the save normalises to, surrounding space trimmed and one pair
// of brackets taken off an IPv6 literal, and without regard to case: a host that differs from the
// stored one only so is the same host, and the stored password is kept without asking.
func TestHandleSettingsEmailPut_TheSameHostSpelledAnotherWayKeepsThePassword(t *testing.T) {
	cases := []struct {
		name      string
		stored    string
		requested string
	}{
		{name: "case", stored: "LocalHost", requested: "localhost"},
		{name: "surrounding space", stored: "127.0.0.1", requested: "  127.0.0.1 "},
		// An IPv4-mapped literal dials 127.0.0.1, so no IPv6 loopback is needed to reach the save.
		{name: "brackets and case", stored: "::ffff:127.0.0.1", requested: "[::FFFF:127.0.0.1]"},
		// Both sides are normalised: a row written before #424 normalised the host can hold it as typed.
		{name: "a stored host not yet normalised", stored: " [::FFFF:127.0.0.1] ", requested: "::ffff:127.0.0.1"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			settings := emailSaveSettings(t, c.stored, true)
			stored := bytes.Clone(settings.SMTPPasswordEncrypted)

			rr, written := serveEmailSave(t, settings, emailSaveBody(t, c.requested, listeningSMTPPort(t), nil))

			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			require.NotNil(t, written)
			assert.Equal(t, stored, written.SMTPPasswordEncrypted, "the stored ciphertext, byte for byte")
			assert.True(t, hasSMTPPasswordIn(t, rr))
		})
	}
}
