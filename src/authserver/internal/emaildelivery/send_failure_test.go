package emaildelivery

import (
	"context"
	"errors"
	"net"
	"testing"

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

// An error nothing labelled is the catch-all kind, so a caller never needs a case for "no kind".
func TestSendFailureKindOf_AnUnlabelledErrorIsOther(t *testing.T) {
	assert.Equal(t, SendFailureOther, SendFailureKindOf(errs.New("unable to do something")))
	assert.Equal(t, SendFailureOther, SendFailureKindOf(nil))
	assert.Equal(t, SendFailureTLS,
		SendFailureKindOf(errs.Wrap(&SendError{Kind: SendFailureTLS, Err: errs.New("handshake")}, "wrapped")),
		"the label is read anywhere on the chain")
}
