package emaildelivery

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// assertSendFailure holds err to being labelled with want, read the way a caller reads it, with
// errors.As (#410 decision 5).
func assertSendFailure(t *testing.T, err error, want SendFailureKind) {
	t.Helper()
	var sendErr *SendError
	require.ErrorAs(t, err, &sendErr, "the failure carries no kind: %v", err)
	assert.Equal(t, want, sendErr.Kind, "labelled with the wrong kind: %v", err)
	assert.Equal(t, want, SendFailureKindOf(err))
}

func sendTo(t *testing.T, sender *Sender, smtpConfig SMTPConfig) error {
	t.Helper()
	_, err := sendReporting(t, sender, smtpConfig)
	return err
}

// sendReporting is sendTo with what the sender reports about the send as well.
func sendReporting(t *testing.T, sender *Sender, smtpConfig SMTPConfig) (SendResult, error) {
	t.Helper()
	return sender.SendEmail(context.Background(), smtpConfig, &SendEmailInput{
		To:       fixtureRecipient,
		Subject:  "Test email",
		HtmlBody: "<p>hello</p>",
	})
}

// A port nothing listens on is a connection failure whose cause is a refusal.
func TestSendEmail_ARefusedDialIsAConnectionFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	require.NoError(t, listener.Close())

	err = sendTo(t, &Sender{dataCipher: testDataCipher}, relayConfig(t, "127.0.0.1", port, "none", "", "", "Goiabada"))

	require.Error(t, err)
	assertSendFailure(t, err, SendFailureConnection)
	assert.Equal(t, ConnectionCauseRefused, ClassifyConnectionError(err))
}

// The server's 535 to the credentials is the authentication rejected, not the connection.
func TestSendEmail_RejectedCredentialsAreLabelledAsSuch(t *testing.T) {
	f := &fakeSMTP{ext: []string{"AUTH CRAM-MD5", "8BITMIME"}, expectPassword: "not-" + fixturePassword}
	port := f.start(t)

	err := sendTo(t, &Sender{dataCipher: testDataCipher}, relayConfig(t, "127.0.0.1", port, "none", fixtureUser, fixturePassword, "Goiabada"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "535", "the server's own reply stays in the error, for the log")
	assertSendFailure(t, err, SendFailureAuthenticationRejected)
	assert.False(t, f.hasLinePrefix("MAIL FROM:"))
}

// The server's 550 to a recipient is the message refused, as the same reply to the finished message
// is in TestSendEmail_FinalDataRejection.
func TestSendEmail_ARefusedRecipientIsTheMessageRefused(t *testing.T) {
	f := &fakeSMTP{ext: []string{"8BITMIME"}, rejectRcpt: true}
	port := f.start(t)

	err := sendTo(t, &Sender{dataCipher: testDataCipher}, relayConfig(t, "127.0.0.1", port, "none", "", "", "Goiabada"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "550")
	assertSendFailure(t, err, SendFailureMessageRefused)
	assert.Empty(t, f.data(), "no message follows a refused recipient")
}

// A relay's refusal that quotes the recipient's address reaches the error, and so every send-failure
// log line, with each occurrence replaced by <recipient>, whatever case the relay wrote it in (#779
// decision 4). The rest of the reply stays, the error still unwraps to it, and the refusal is still
// the message refused.
func TestSendEmail_ARefusalQuotingTheRecipientDoesNotCarryTheAddress(t *testing.T) {
	const refusal = "550 5.1.1 <RCPT@Example.COM>: Recipient address rejected: rcpt@example.com is unknown"
	const redacted = "5.1.1 <<recipient>>: Recipient address rejected: <recipient> is unknown"
	steps := []struct {
		name string
		fake *fakeSMTP
	}{
		{"recipient refused", &fakeSMTP{ext: []string{"8BITMIME"}, rejectRcpt: true, refusal: refusal}},
		{"finished message refused", &fakeSMTP{ext: []string{"8BITMIME"}, rejectAfterData: true, refusal: refusal}},
	}
	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			port := step.fake.start(t)

			err := sendTo(t, &Sender{dataCipher: testDataCipher}, relayConfig(t, "127.0.0.1", port, "none", "", "", "Goiabada"))

			require.Error(t, err)
			assert.Equal(t, `unable to send SMTP message: 550 "`+redacted+`"`, err.Error())
			assert.NotContains(t, strings.ToLower(err.Error()), "rcpt@example.com")
			assert.NotContains(t, strings.ToLower(fmt.Sprintf("%+v", err)), "rcpt@example.com")
			var reply *textproto.Error
			require.ErrorAs(t, err, &reply, "the error still unwraps to the relay's reply")
			assert.Equal(t, 550, reply.Code)
			assert.Equal(t, redacted, reply.Msg)
			assertSendFailure(t, err, SendFailureMessageRefused)
		})
	}
}

// Every reply the relay sends passes through the same redaction before it reaches the send's error,
// not only a refusal of the sender, the recipient or the message (#779 decision 4). AUTH may echo a
// username that is also the recipient, and a reply that is no SMTP reply at all reaches the error
// as its raw line. The greeting, EHLO and STARTTLS come before anything names the address, and are
// held to it all the same. Each failure keeps its kind.
func TestSendEmail_NoRelayReplyInTheErrorCarriesTheRecipient(t *testing.T) {
	tests := []struct {
		name     string
		fake     *fakeSMTP
		mode     string
		username string
		want     SendFailureKind
	}{
		{
			name: "greeting refused",
			fake: &fakeSMTP{replies: map[string]string{"greeting": "554 5.3.2 not taking mail for RCPT@Example.COM"}},
			mode: "none", want: SendFailureOther,
		},
		{
			name: "EHLO and HELO refused",
			fake: &fakeSMTP{replies: map[string]string{"EHLO": "550 5.7.1 RCPT@Example.COM may not say hello"}},
			mode: "none", want: SendFailureOther,
		},
		{
			name: "STARTTLS refused",
			fake: &fakeSMTP{ext: []string{"STARTTLS"}, refuseSTARTTLS: true,
				replies: map[string]string{"STARTTLS": "454 4.7.0 no TLS for RCPT@Example.COM"}},
			mode: "starttls", want: SendFailureTLS,
		},
		{
			name: "authentication rejected",
			fake: &fakeSMTP{ext: []string{"AUTH CRAM-MD5", "8BITMIME"}, expectPassword: "a-different-password",
				replies: map[string]string{"AUTH": "535 5.7.8 Authentication rejected for RCPT@Example.COM"}},
			mode: "none", username: fixtureUser, want: SendFailureAuthenticationRejected,
		},
		{
			name: "a recipient answered with a line that is no SMTP reply",
			fake: &fakeSMTP{ext: []string{"8BITMIME"}, rejectRcpt: true, refusal: "rejected RCPT@Example.COM"},
			mode: "none", want: SendFailureOther,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			port := test.fake.start(t)
			password := ""
			if test.username != "" {
				password = fixturePassword
			}

			err := sendTo(t, &Sender{dataCipher: testDataCipher},
				relayConfig(t, "127.0.0.1", port, test.mode, test.username, password, "Goiabada"))

			require.Error(t, err)
			assert.NotContains(t, strings.ToLower(err.Error()), "rcpt@example.com")
			assert.NotContains(t, strings.ToLower(fmt.Sprintf("%+v", err)), "rcpt@example.com")
			assert.Contains(t, err.Error(), "<recipient>", "the rest of the reply stays")
			assertSendFailure(t, err, test.want)
		})
	}
}

// The two relay replies a send that goes on logs rather than returns are held to the same
// redaction: a refused STARTTLS under STARTTLS if available, which carries on in plaintext, and a
// failed QUIT after the relay accepted the message (#779 decision 4). Both sends still succeed.
func TestSendEmail_NoLoggedRelayReplyCarriesTheRecipient(t *testing.T) {
	tests := []struct {
		name    string
		fake    *fakeSMTP
		level   slog.Level
		message string
	}{
		{
			name: "STARTTLS refused, sent unencrypted",
			fake: &fakeSMTP{ext: []string{"STARTTLS", "8BITMIME"}, refuseSTARTTLS: true,
				replies: map[string]string{"STARTTLS": "454 4.7.0 no TLS for RCPT@Example.COM"}},
			level: slog.LevelInfo, message: "sending the email unencrypted",
		},
		{
			name: "QUIT failed after the message was accepted",
			fake: &fakeSMTP{ext: []string{"8BITMIME"},
				replies: map[string]string{"QUIT": "421 4.3.0 closing after delivery to RCPT@Example.COM"}},
			level: slog.LevelWarn, message: quitFailedAfterAcceptance,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture := logtest.CaptureSlog(t)
			port := test.fake.start(t)

			err := sendTo(t, &Sender{dataCipher: testDataCipher},
				relayConfig(t, "127.0.0.1", port, "none", "", "", "Goiabada"))

			require.NoError(t, err)
			records := recordsAt(capture, test.level)
			require.Len(t, records, 1)
			assert.Equal(t, test.message, records[0].Message)
			logged := records[0].Attrs["error"]
			require.NotNil(t, logged, "the reply rides under error")
			assert.NotContains(t, strings.ToLower(fmt.Sprint(logged)), "rcpt@example.com")
			assert.NotContains(t, strings.ToLower(fmt.Sprintf("%+v", logged)), "rcpt@example.com")
			assert.Contains(t, fmt.Sprint(logged), "<recipient>")
		})
	}
}

// SSL/TLS against a server that speaks plain SMTP fails in the handshake, before any certificate is
// read: a TLS failure, as a certificate that does not verify is in
// TestSendEmail_CertificateVerification, and not a connection failure, although the TCP connection
// was made.
func TestSendEmail_ImplicitTLSAgainstAPlainServerIsATLSFailure(t *testing.T) {
	f := &fakeSMTP{ext: []string{"AUTH PLAIN", "8BITMIME"}}
	port := f.start(t)
	cert := newFakeCert(t)

	err := sendTo(t, &Sender{dataCipher: testDataCipher, rootCAs: cert.pool},
		relayConfig(t, "127.0.0.1", port, "ssltls", fixtureUser, fixturePassword, "Goiabada"))

	require.Error(t, err)
	assertSendFailure(t, err, SendFailureTLS)
	assert.False(t, f.hasLinePrefix("AUTH"))
}

// A relay that greets and then breaks the connection at EHLO is a connection failure, in every mode,
// with the network error kept on the chain for the log. net/smtp's Extension swallows a failed
// hello, so without the explicit one before it this was read as a server offering no STARTTLS, or no
// authentication, and the timeout or the disconnect was lost (#410 decision 5). That a hello which
// succeeds without either still gets the guidance is TestSendEmail_FailsClosed's.
func TestSendEmail_AFailedHelloIsAConnectionFailure(t *testing.T) {
	modes := []struct {
		name               string
		encryption         string
		username, password string
	}{
		{"starttls", "starttls", "", ""},
		{"none with credentials", "none", fixtureUser, fixturePassword},
		{"none without credentials", "none", "", ""},
	}
	for _, mode := range modes {
		for _, brk := range connectionBreaks {
			t.Run(mode.name+", "+brk.name, func(t *testing.T) {
				f := &fakeSMTP{ext: []string{"STARTTLS", "AUTH PLAIN"}, breakOn: "EHLO", breakHow: brk.how}
				port := f.start(t)

				err := sendTo(t, &Sender{dataCipher: testDataCipher, commandTimeout: brk.deadline},
					relayConfig(t, "127.0.0.1", port, mode.encryption, mode.username, mode.password, "Goiabada"))

				require.Error(t, err)
				assertSendFailure(t, err, SendFailureConnection)
				assert.Equal(t, brk.cause, ClassifyConnectionError(err))
				assertBrokenConnectionOnChain(t, err)
				assert.False(t, f.hasLinePrefix("STARTTLS"))
				assert.False(t, f.hasLinePrefix("AUTH"))
				assert.False(t, f.hasLinePrefix("MAIL FROM:"))
			})
		}
	}
}

// A relay that offers STARTTLS and breaks the TCP connection on the command, before its 220 and so
// before any handshake, is a connection failure and not a TLS one, whether or not the break has a
// cause ClassifyConnectionError names (#410 decision 5).
func TestSendEmail_AConnectionBrokenAtSTARTTLSIsAConnectionFailure(t *testing.T) {
	for _, brk := range connectionBreaks {
		t.Run(brk.name, func(t *testing.T) {
			f := &fakeSMTP{ext: []string{"STARTTLS"}, breakOn: "STARTTLS", breakHow: brk.how}
			port := f.start(t)

			err := sendTo(t, &Sender{dataCipher: testDataCipher, commandTimeout: brk.deadline},
				relayConfig(t, "127.0.0.1", port, "starttls", "", "", "Goiabada"))

			require.Error(t, err)
			assertSendFailure(t, err, SendFailureConnection)
			assert.Equal(t, brk.cause, ClassifyConnectionError(err))
			assertBrokenConnectionOnChain(t, err)
			assert.False(t, f.hasLinePrefix("MAIL FROM:"))
		})
	}
}

// connectionBreaks are the three ways the fake breaks a connection, each with the cause it is read
// as: a close and a reset name none, a stall runs into the read's deadline. Each runs under
// its own deadline: the stall's is short so that the test reaches it, and the close's and reset's
// long, so that a slow machine cannot turn either into a timeout before the break arrives.
var connectionBreaks = []struct {
	name     string
	how      connectionBreak
	cause    ConnectionCause
	deadline time.Duration
}{
	{"closed", breakClose, ConnectionCauseNone, time.Minute},
	{"reset", breakReset, ConnectionCauseNone, time.Minute},
	{"stalled", breakStall, ConnectionCauseTimedOut, 200 * time.Millisecond},
}

// assertBrokenConnectionOnChain holds err to still carrying what broke the connection, which is what
// the send-test route logs.
func assertBrokenConnectionOnChain(t *testing.T, err error) {
	t.Helper()
	var netErr net.Error
	assert.True(t, errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.As(err, &netErr),
		"the network failure is no longer on the chain: %v", err)
}

// An error nothing labelled is the catch-all kind, so a caller never needs a case for "no kind".
func TestSendFailureKindOf_AnUnlabelledErrorIsOther(t *testing.T) {
	assert.Equal(t, SendFailureOther, SendFailureKindOf(errs.New("unable to do something")))
	assert.Equal(t, SendFailureOther, SendFailureKindOf(nil))
	assert.Equal(t, SendFailureTLS,
		SendFailureKindOf(errs.Wrap(&SendError{Kind: SendFailureTLS, Err: errs.New("handshake")}, "wrapped")),
		"the label is read anywhere on the chain")
}
