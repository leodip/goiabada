package emaildelivery

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// assertSendFailure holds err to being labelled with want, read the way a caller reads it, with
// errors.As (#410 decision 5).
func assertSendFailure(t *testing.T, err error, want SendFailureKind) {
	t.Helper()
	var sendErr *SendError
	require.True(t, errors.As(err, &sendErr), "the failure carries no kind: %v", err)
	assert.Equal(t, want, sendErr.Kind, "labelled with the wrong kind: %v", err)
	assert.Equal(t, want, SendFailureKindOf(err))
}

func sendTo(t *testing.T, sender *Sender, smtpConfig SMTPConfig) error {
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

				err := sendTo(t, &Sender{dataCipher: testDataCipher, convTimeout: 200 * time.Millisecond},
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

			err := sendTo(t, &Sender{dataCipher: testDataCipher, convTimeout: 200 * time.Millisecond},
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
// as: a close and a reset name none, a stall runs into the conversation deadline.
var connectionBreaks = []struct {
	name  string
	how   connectionBreak
	cause ConnectionCause
}{
	{"closed", breakClose, ConnectionCauseNone},
	{"reset", breakReset, ConnectionCauseNone},
	{"stalled", breakStall, ConnectionCauseTimedOut},
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
