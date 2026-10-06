package apihandlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/internal/audit"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	"github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/logging/logtest"
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

// sendTestRequestId is the request id every failed test send case carries, as the request id
// middleware would have put it on the request.
const sendTestRequestId = "req-send-test"

// leakyRelayError is a send failure carrying everything the answer must not: an address and port, an
// operating-system string, and text the server sent.
func leakyRelayError(cause error) error {
	return errs.Wrap(&net.OpError{
		Op:   "dial",
		Net:  "tcp",
		Addr: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 25), Port: 2587},
		Err:  cause,
	}, "220 internal-banner.corp.example ready")
}

// A failed test send answers 400 SEND_FAILED with the fixed message of the kind the sender labelled
// it with, and the connection's coarse cause for a connection failure, naming no address, port,
// operating-system string or server text; the whole error goes to the log at Warn, on the request's
// id (#410 decision 5).
func TestHandleSettingsEmailSendTestPost_AFailedSendAnswersTheFixedMessageOfItsKind(t *testing.T) {
	labelled := func(kind emaildelivery.SendFailureKind, err error) error {
		return errs.WithStack(&emaildelivery.SendError{Kind: kind, Err: err})
	}
	refused := &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED}
	serverText := errs.New("535 5.7.8 internal-banner.corp.example says no to 192.0.2.25:2587")

	testCases := []struct {
		name string
		err  error
		want string
	}{
		{"a host name not found",
			labelled(emaildelivery.SendFailureConnection, leakyRelayError(&net.DNSError{Err: "no such host", Name: "internal-banner.corp.example", IsNotFound: true})),
			"Unable to send the test email: host name not found."},
		{"a connection that timed out",
			labelled(emaildelivery.SendFailureConnection, leakyRelayError(os.ErrDeadlineExceeded)),
			"Unable to send the test email: connection timed out."},
		{"a refused connection",
			labelled(emaildelivery.SendFailureConnection, leakyRelayError(refused)),
			"Unable to send the test email: connection refused."},
		{"a connection failure with no cause the classification names",
			labelled(emaildelivery.SendFailureConnection, leakyRelayError(&os.SyscallError{Syscall: "connect", Err: syscall.ENETUNREACH})),
			"Unable to send the test email."},
		{"STARTTLS not offered",
			labelled(emaildelivery.SendFailureSTARTTLSNotOffered, serverText),
			"The SMTP server did not offer STARTTLS; set the encryption to None only if the server has no TLS."},
		{"a password that would go unencrypted",
			labelled(emaildelivery.SendFailureUnencryptedPassword, serverText),
			"The SMTP server would receive the password unencrypted; set the encryption to STARTTLS or SSL/TLS."},
		{"credentials configured and no authentication offered",
			labelled(emaildelivery.SendFailureNoAuthentication, serverText),
			"SMTP credentials are configured but the server offers no authentication."},
		// The sender's error lists the mechanisms the server offered; the answer leaves them out.
		{"no supported mechanism",
			labelled(emaildelivery.SendFailureNoSupportedMechanism,
				errs.New("the SMTP server offers none of PLAIN, LOGIN or CRAM-MD5 (offered: XOAUTH2 internal-banner.corp.example)")),
			"The SMTP server offers none of PLAIN, LOGIN or CRAM-MD5."},
		// The TLS kind answers its own message even when the chain also reads as a refused
		// connection: the kind decides, not the classification.
		{"a failed TLS handshake",
			labelled(emaildelivery.SendFailureTLS, leakyRelayError(refused)),
			"The TLS connection failed; check the encryption setting and the server's certificate."},
		{"rejected credentials",
			labelled(emaildelivery.SendFailureAuthenticationRejected, serverText),
			"The SMTP server rejected the username or password."},
		{"a refused message",
			labelled(emaildelivery.SendFailureMessageRefused, serverText),
			"The SMTP server refused the message."},
		{"anything else",
			labelled(emaildelivery.SendFailureOther, errs.New("unable to decrypt the SMTP password")),
			"Unable to send the test email."},
		{"an error carrying no kind",
			leakyRelayError(refused),
			"Unable to send the test email."},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			capture := logtest.CaptureSlog(t)
			emailSender := accounthandlersmocks.NewEmailSender(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			emailSender.On("SendEmail", mock.Anything, mock.Anything, mock.Anything).Return(tc.err).Once()

			r := sendTestEmailRequest(t, &record.Settings{SMTPEnabled: true})
			r = r.WithContext(context.WithValue(r.Context(), middleware.RequestIDKey, sendTestRequestId))
			rr := httptest.NewRecorder()
			HandleSettingsEmailSendTestPost(accountvalidation.NewEmailValidator(nil), emailSender, auditLogger).ServeHTTP(rr, r)

			assert.Equal(t, http.StatusBadRequest, rr.Code)
			for _, leak := range []string{"192.0.2.25", "2587", "internal-banner", "535", "XOAUTH2", "connect:"} {
				assert.NotContains(t, rr.Body.String(), leak, "the answer carries none of the error's own text")
			}
			code, description := decodeErrorEnvelope(t, rr)
			assert.Equal(t, "SEND_FAILED", code)
			assert.Equal(t, tc.want, description)
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)

			records := capture.Records()
			require.Len(t, records, 1, "one failed send writes one record")
			assert.Equal(t, slog.LevelWarn, records[0].Level)
			assert.Equal(t, "unable to send the test email", records[0].Message)
			assert.Equal(t, sendTestRequestId, records[0].Attrs["request_id"], "logged through the request's context")
			logged, ok := records[0].Attrs["error"].(error)
			require.True(t, ok, "the error attribute is the error itself")
			assert.Equal(t, tc.err, logged, "the log keeps what the answer leaves out")
		})
	}
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

// emailSaveRequestId is the request id every email save case carries, as the request id middleware
// would have put it on the request.
const emailSaveRequestId = "req-email-save"

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
	r = r.WithContext(context.WithValue(reqctx.WithSettings(r.Context(), settings), middleware.RequestIDKey, emailSaveRequestId))
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

// A refused dial answers the fixed message and its coarse cause, naming neither the address nor the
// port it dialled, and the whole error goes to the log at Warn, on the request's id (#410 decision 4).
func TestHandleSettingsEmailPut_ARefusedDialAnswersItsCauseAndLogsTheError(t *testing.T) {
	capture := logtest.CaptureSlog(t)
	port := unreachableSMTPPort(t)

	rr, written := serveEmailSave(t, emailSaveSettings(t, "127.0.0.1", false), emailSaveBody(t, "127.0.0.1", port, nil))

	assert.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	assert.NotContains(t, rr.Body.String(), "127.0.0.1", "the answer names no address")
	assert.NotContains(t, rr.Body.String(), strconv.Itoa(port), "the answer names no port")
	code, description := decodeErrorEnvelope(t, rr)
	assert.Equal(t, "VALIDATION_ERROR", code)
	assert.Equal(t, "Unable to connect to the SMTP server: connection refused.", description)
	assert.Nil(t, written)

	records := capture.Records()
	require.Len(t, records, 1, "one refused dial writes one record")
	assert.Equal(t, slog.LevelWarn, records[0].Level)
	assert.Equal(t, "unable to connect to the smtp server", records[0].Message)
	assert.Equal(t, emailSaveRequestId, records[0].Attrs["request_id"], "logged through the request's context")
	logged, ok := records[0].Attrs["error"].(error)
	require.True(t, ok, "the error attribute is the error itself")
	assert.ErrorIs(t, logged, syscall.ECONNREFUSED)
	assert.Contains(t, logged.Error(), "127.0.0.1:"+strconv.Itoa(port), "the log keeps what the answer leaves out")
}

// Each coarse cause adds its own words to a failed connection's answer, and a failure with no cause
// the classification names ends at the fixed message (#410 decision 4). The dial's other failures
// cannot be produced on every machine alike, so the words are pinned here, from the cause.
func TestConnectionFailureMessage(t *testing.T) {
	testCases := []struct {
		cause emaildelivery.ConnectionCause
		want  string
	}{
		{emaildelivery.ConnectionCauseHostNotFound, "Unable to connect to the SMTP server: host name not found."},
		{emaildelivery.ConnectionCauseTimedOut, "Unable to connect to the SMTP server: connection timed out."},
		{emaildelivery.ConnectionCauseRefused, "Unable to connect to the SMTP server: connection refused."},
		{emaildelivery.ConnectionCauseNone, "Unable to connect to the SMTP server."},
	}

	for _, tc := range testCases {
		t.Run(tc.want, func(t *testing.T) {
			assert.Equal(t, tc.want, connectionFailureMessage("Unable to connect to the SMTP server", tc.cause))
		})
	}
}
