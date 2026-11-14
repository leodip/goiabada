// Package emaildelivery sends the auth server's mail: one message per call, over the SMTP relay
// the settings row configures. SSL/TLS and STARTTLS are refused rather than downgraded; STARTTLS if
// available, the `none` mode, upgrades when it can and says when it could not. It renders nothing;
// the handlers build the HTML body from their templates and pass the relay as an SMTPConfig, and
// the sender works the message's plain-text part out of that HTML.
package emaildelivery

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/netip"
	"net/smtp"
	"net/textproto"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/hostport"
)

const (
	// RFC 5322 section 2.1.1: a line SHOULD be no more than 78 characters excluding the CRLF.
	maxHeaderLineBytes = 78
	// RFC 2047 section 2: each line of a header field that holds an encoded word is limited to 76
	// characters. Every byte the encoders write is ASCII, so characters and bytes count the same.
	maxEncodedWordLineBytes = 76
	// The same sentence's other half, which is a MUST rather than a SHOULD: no more than 998
	// characters, excluding the CRLF.
	maxHeaderLineHardBytes = 998

	// How long a send may wait on the relay (#718 decision 7). The connect, the implicit-TLS
	// handshake included, has 10 seconds. After it every read and every write on the connection has
	// a fresh 20 seconds, so a relay that stalls on one step is given up on while one that is slow
	// but making progress, such as on a large HTML body, is not cut off mid-DATA. However it
	// progresses, the send ends 40 seconds after the connect began. These are far shorter than RFC
	// 5321 section 4.5.3.2's recommended minima, 2 to 10 minutes per command (a SHOULD), because a
	// send can hold a browser request open: 40 seconds stays under the server's 60-second HTTP
	// write timeout, and bounds the after-response jobs that send mail. They are constants, not
	// settings; longer tolerances belong to an outbox (#731).
	defaultDialTimeout    = 10 * time.Second
	defaultCommandTimeout = 20 * time.Second
	defaultSendTimeout    = 40 * time.Second
)

type Sender struct {
	// dataCipher opens the relay password the settings row stores encrypted.
	dataCipher *encryption.DataCipher
	// rootCAs is nil in production, meaning the system roots. The in-package tests point it at
	// their fake server's certificate so the TLS paths can be exercised with verification left on.
	rootCAs *x509.CertPool
	// Zero means the defaults above.
	dialTimeout    time.Duration
	commandTimeout time.Duration
	sendTimeout    time.Duration
	// randReader is nil in production, meaning crypto/rand.Reader. It exists so a test can make
	// the Message-ID's entropy read fail and show the send fails closed.
	randReader io.Reader
	// ehloName is the name the sender introduces itself by in EHLO, and in HELO to a relay that
	// refuses EHLO. Empty, each connection uses the address of its own end, written as an address
	// literal (#718 decision 9).
	ehloName string
}

// NewSender builds the sender. ehloName is GOIABADA_AUTHSERVER_SMTP_EHLO_NAME as the configuration
// validated it, a domain or an address literal, or empty for the connection's local address.
func NewSender(dataCipher *encryption.DataCipher, ehloName string) *Sender {
	return &Sender{dataCipher: dataCipher, ehloName: ehloName}
}

// SMTPConfig is the relay a message is sent through, as the settings row stores it. The password
// stays encrypted and the encryption mode stays the stored string: SendEmail decrypts and parses
// both at send time, so building one cannot fail and no handler holds the plaintext password
// (#433).
type SMTPConfig struct {
	Host              string
	Port              int
	FromName          string
	FromEmail         string
	Encryption        string
	Username          string
	PasswordEncrypted []byte
}

// SMTPConfigFromSettings copies the relay's fields off the settings row.
func SMTPConfigFromSettings(settings *record.Settings) SMTPConfig {
	return SMTPConfig{
		Host:              settings.SMTPHost,
		Port:              settings.SMTPPort,
		FromName:          settings.SMTPFromName,
		FromEmail:         settings.SMTPFromEmail,
		Encryption:        settings.SMTPEncryption,
		Username:          settings.SMTPUsername,
		PasswordEncrypted: settings.SMTPPasswordEncrypted,
	}
}

type SendEmailInput struct {
	To       string
	Subject  string
	HtmlBody string
}

// SendResult is what a send that succeeded reports about how it went.
type SendResult struct {
	// Encrypted is whether the message went over TLS: always for SSL/TLS and STARTTLS, and for
	// STARTTLS if available whether the upgrade held (#718 decision 16).
	Encrypted bool
}

// SendEmail sends one message through the relay smtpConfig names. Every failure it returns carries
// a *SendError labelling its kind, which SendFailureKindOf reads: the steps that can tell label their
// own, and anything else is SendFailureOther (#410 decision 5).
//
// A caller whose ctx ends closes the connection, which ends the send; the failure then carries
// ctx's error on its chain as well as the one the closed connection caused.
func (e *Sender) SendEmail(ctx context.Context, smtpConfig SMTPConfig, input *SendEmailInput) (SendResult, error) {
	result, err := e.send(ctx, smtpConfig, input)
	if err == nil {
		return result, nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil && !errors.Is(err, ctxErr) {
		err = errs.Join(err, ctxErr)
	}
	var sendErr *SendError
	if errors.As(err, &sendErr) {
		return SendResult{}, err
	}
	return SendResult{}, labelled(SendFailureOther, err)
}

// The reasons logSentUnencrypted gives under `reason`.
const (
	unencryptedReasonSTARTTLSNotOffered = "starttls_not_offered"
	unencryptedReasonSTARTTLSRefused    = "starttls_refused"
	unencryptedReasonSTARTTLSFailed     = "starttls_failed"
	unencryptedReasonTLSFailed          = "tls_failed"
)

// logSentUnencrypted writes the one Info record a send under STARTTLS if available writes when it
// goes in plaintext, with its reason and, for a STARTTLS that failed, how (#718 decision 14). Info
// is the default log level, so a relay that stops offering STARTTLS, or an attacker who strips it,
// can be seen.
func logSentUnencrypted(ctx context.Context, reason string, cause error) {
	if cause == nil {
		slog.InfoContext(ctx, "sending the email unencrypted", "reason", reason)
		return
	}
	slog.InfoContext(ctx, "sending the email unencrypted", "reason", reason, "error", cause)
}

// relayDial is how one send reaches its relay, the same for a fallback's second connection as for
// the first.
type relayDial struct {
	addr      string
	host      string
	tlsConfig *tls.Config
	// implicitTLS is the SSL/TLS mode: the handshake is part of the connect.
	implicitTLS    bool
	dialTimeout    time.Duration
	commandTimeout time.Duration
	// sendDeadline is when the whole send ends, however many connections it takes.
	sendDeadline time.Time
	// recipient is the address every relay reply is cleared of before it reaches an error or a log
	// line (#779 decision 4).
	recipient string
}

func (e *Sender) send(ctx context.Context, smtpConfig SMTPConfig, input *SendEmailInput) (SendResult, error) {

	var password string
	if len(smtpConfig.PasswordEncrypted) > 0 {
		decryptedPassword, err := e.dataCipher.Decrypt(smtpConfig.PasswordEncrypted)
		if err != nil {
			return SendResult{}, errs.Wrap(err, "unable to decrypt the SMTP password")
		}
		password = decryptedPassword
	}

	smtpEnc, err := SMTPEncryptionFromString(smtpConfig.Encryption)
	if err != nil {
		return SendResult{}, errs.Wrap(err, "unable to parse the SMTP encryption")
	}

	// Build the whole message before dialing, so a bad address or a failed entropy read costs no
	// connection and reaches the admin as its own error rather than as a mid-conversation failure.
	from := &mail.Address{Name: smtpConfig.FromName, Address: smtpConfig.FromEmail}
	to, err := mail.ParseAddress(input.To)
	if err != nil {
		// The parser's error quotes what it could not take, which is the recipient's address or a
		// part of it, and a send failure reaches a log line, so its text is left out (#779
		// decision 4).
		return SendResult{}, errs.New("invalid recipient address")
	}
	message, err := e.buildMessage(from, to, input)
	if err != nil {
		return SendResult{}, err
	}

	// The settings handler stores the host bare, but a row written some other way may carry
	// `[::1]`. Every use below takes the host on its own as well as in the address -- the TLS
	// server name, the SMTP client's host, the local-host check -- and brackets name nothing in
	// any of them (#424).
	host := hostport.Unbracket(smtpConfig.Host)

	dial := relayDial{
		addr: hostport.Join(host, smtpConfig.Port),
		host: host,
		// One config for every TLS path. Certificate and hostname verification are never
		// disabled: RFC 8314 section 3.3 requires the implicit-TLS client to validate, and a
		// STARTTLS session that does not verify buys nothing over cleartext (#274), STARTTLS if
		// available's upgrade included (#718 decision 14).
		tlsConfig:      &tls.Config{ServerName: host, RootCAs: e.rootCAs},
		implicitTLS:    smtpEnc == SMTPEncryptionSSLTLS,
		dialTimeout:    cmp.Or(e.dialTimeout, defaultDialTimeout),
		commandTimeout: cmp.Or(e.commandTimeout, defaultCommandTimeout),
		recipient:      to.Address,
	}
	// The send's budget runs from the start of the connect, so a slow connect or handshake leaves
	// the conversation less of it.
	dial.sendDeadline = time.Now().Add(cmp.Or(e.sendTimeout, defaultSendTimeout))

	// A relay's reply may quote the recipient's address, or an authentication username that is the
	// same address, and every send-failure log line records the reply (#779 decision 4). Each reply
	// that reaches an error or a log line goes through this first, wherever the conversation
	// stopped.
	redact := func(err error) error { return withoutRecipient(err, to.Address) }

	client, closeConnection, err := e.connect(ctx, dial)
	if err != nil {
		return SendResult{}, err
	}
	// Called through a closure, since a fallback replaces the connection.
	defer func() { closeConnection() }()

	encrypted := smtpEnc != SMTPEncryptionNone
	switch smtpEnc {
	case SMTPEncryptionSTARTTLS:
		// The operator asked for STARTTLS, so a server that does not offer it is refused rather
		// than continued with in the clear. RFC 3207 section 4 leaves the choice to the client,
		// and a silent downgrade here is indistinguishable from a STARTTLS-stripping attacker
		// (#274).
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return SendResult{}, labelled(SendFailureSTARTTLSNotOffered, errs.Wrap(
				errs.New("the SMTP server did not offer STARTTLS; check the port, or choose STARTTLS if available only if the server has no TLS"),
				"unable to send SMTP message"))
		}
		// StartTLS re-issues EHLO, per RFC 3207 section 4.2: everything learned before the
		// handshake has to be discarded.
		if startTLSErr := client.StartTLS(dial.tlsConfig); startTLSErr != nil {
			return SendResult{}, tlsFailure(errs.Wrap(redact(startTLSErr), "unable to send SMTP message"))
		}
	case SMTPEncryptionNone:
		upgrade, upgradeErr := startTLSIfAvailable(client, dial.tlsConfig)
		upgradeErr = redact(upgradeErr)
		switch upgrade {
		case upgraded:
			encrypted = true
		case upgradeNotOffered:
			logSentUnencrypted(ctx, unencryptedReasonSTARTTLSNotOffered, nil)
		case upgradeRefused:
			// The relay answered STARTTLS with a refusal and the connection is still in
			// plaintext, so the send carries on over it.
			logSentUnencrypted(ctx, unencryptedReasonSTARTTLSRefused, upgradeErr)
		case upgradeCommandFailed, upgradeHandshakeFailed:
			// The connection lost its STARTTLS command's reply, or is part-way into a TLS
			// session that did not hold, so nothing more can be said over it: the send reconnects
			// once and does not try STARTTLS again, within the same budget. A caller who has
			// given up is not reconnected for.
			if ctx.Err() != nil {
				return SendResult{}, tlsFailure(errs.Wrap(upgradeErr, "unable to send SMTP message"))
			}
			closeConnection()
			reconnected, closeReconnected, reconnectErr := e.connect(ctx, dial)
			if reconnectErr != nil {
				closeConnection = func() {}
				// Nothing went unencrypted, so no record says it did, and the failure keeps why
				// the upgrade failed. That reason goes in as text: on the chain, a timed-out
				// upgrade could pass as the cause of a reconnect that failed for another reason.
				return SendResult{}, errs.Wrapf(reconnectErr, "unable to reconnect after the STARTTLS upgrade failed (%v)", upgradeErr)
			}
			client, closeConnection = reconnected, closeReconnected
			reason := unencryptedReasonTLSFailed
			if upgrade == upgradeCommandFailed {
				reason = unencryptedReasonSTARTTLSFailed
			}
			logSentUnencrypted(ctx, reason, upgradeErr)
		default:
			return SendResult{}, tlsFailure(errs.Wrap(upgradeErr, "unable to send SMTP message"))
		}
	}

	if len(smtpConfig.Username) > 0 {
		if authenticateErr := authenticate(client, host, smtpEnc, smtpConfig.Username, password, redact); authenticateErr != nil {
			return SendResult{}, errs.Wrap(authenticateErr, "unable to send SMTP message")
		}
	}

	messageRefused := func(err error) error {
		return replyFailure(errs.Wrap(redact(err), "unable to send SMTP message"), SendFailureMessageRefused)
	}
	if mailErr := client.Mail(from.Address); mailErr != nil {
		return SendResult{}, messageRefused(mailErr)
	}
	if rcptErr := client.Rcpt(to.Address); rcptErr != nil {
		return SendResult{}, messageRefused(rcptErr)
	}
	w, err := client.Data()
	if err != nil {
		return SendResult{}, messageRefused(err)
	}
	if _, err := w.Write(message); err != nil {
		return SendResult{}, messageRefused(err)
	}
	if err := w.Close(); err != nil {
		return SendResult{}, messageRefused(err)
	}
	// The relay answered the end of the data with a positive reply, so it has taken responsibility
	// for the message (RFC 5321 sections 4.1.1.4 and 6.1). Whatever happens to QUIT or to closing
	// the connection, the send succeeded: reporting it failed would invite a retry that delivers the
	// message twice. The failure is still logged. A lost reply to the data never reaches here: no
	// reply is no acceptance, and w.Close returned it above (#718 decision 1).
	if err := client.Quit(); err != nil {
		slog.WarnContext(ctx, "unable to end the smtp session after the server accepted the message", "error", redact(err))
	}

	return SendResult{Encrypted: encrypted}, nil
}

// connect opens one connection to the relay, with its implicit-TLS handshake for SSL/TLS, and says
// hello over it. The close it returns ends the SMTP client and stops ctx from closing the connection.
func (e *Sender) connect(ctx context.Context, dial relayDial) (*smtp.Client, func(), error) {

	// The dial timeout bounds the connect and, for implicit TLS, the handshake after it, as
	// tls.Dialer bounds both with its NetDialer's timeout. The two are separate steps so that a
	// failed handshake is told from a failed connect (#410 decision 5). A fallback's second connect
	// is held to what is left of the send's budget as well.
	dialDeadline := time.Now().Add(dial.dialTimeout)
	if dialDeadline.After(dial.sendDeadline) {
		dialDeadline = dial.sendDeadline
	}
	dialCtx, cancelDial := context.WithDeadline(ctx, dialDeadline)
	defer cancelDial()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", dial.addr)
	if err != nil {
		return nil, nil, labelled(SendFailureConnection, errs.Wrap(err, "unable to connect to SMTP server"))
	}
	// A caller that gives up ends its send: closing the TCP connection fails whatever read or write
	// is waiting on it, the TLS layers above it included. The dial and the implicit-TLS handshake
	// already end with ctx through dialCtx. The TCP connection is held in a variable of its own,
	// since conn is rewrapped below and the close runs on another goroutine.
	tcpConn := conn
	stopClosingOnCancel := context.AfterFunc(ctx, func() { _ = tcpConn.Close() })

	// Wrapped directly around the TCP connection, under both the implicit TLS and the STARTTLS one
	// net/smtp adds later, so every read and write the conversation makes, a STARTTLS handshake's
	// included, has its own deadline. Under rather than over the implicit TLS because net/smtp
	// recognizes TLS only by being handed the *tls.Conn itself: hidden inside a wrapper, the
	// connection reads as plaintext, and smtp.PlainAuth refuses to send credentials over it to any
	// relay but a loopback one.
	deadlines := &deadlineConn{Conn: conn, commandTimeout: dial.commandTimeout, sendDeadline: dial.sendDeadline}
	conn = deadlines
	if dial.implicitTLS {
		// The handshake is part of the connect, so it is held to the connect's deadline rather
		// than given a fresh per-command one for each of its reads and writes.
		deadlines.connectDeadline = dialDeadline
		tlsConn := tls.Client(conn, dial.tlsConfig)
		if handshakeErr := tlsConn.HandshakeContext(dialCtx); handshakeErr != nil {
			stopClosingOnCancel()
			_ = tcpConn.Close()
			return nil, nil, tlsFailure(errs.Wrap(handshakeErr, "unable to connect to SMTP server"))
		}
		deadlines.connectDeadline = time.Time{}
		conn = tlsConn
	}

	client, err := smtp.NewClient(conn, dial.host)
	if err != nil {
		stopClosingOnCancel()
		_ = conn.Close()
		return nil, nil, replyFailure(errs.Wrap(withoutRecipient(err, dial.recipient), "unable to connect to SMTP server"), SendFailureOther)
	}
	closeConnection := func() {
		_ = client.Close()
		stopClosingOnCancel()
	}

	// The hello every command after it would send first, sent here so its failure is seen:
	// Extension swallows a failed hello and answers false, which would read a relay that broke or
	// stalled at EHLO as one offering no STARTTLS or no authentication, and lose the error (#410
	// decision 5). net/smtp keeps the name for the HELO it falls back to when EHLO is refused and
	// for the EHLO StartTLS repeats, so all three carry it (#718 decision 9).
	if helloErr := client.Hello(e.helloName(tcpConn)); helloErr != nil {
		closeConnection()
		return nil, nil, replyFailure(errs.Wrap(withoutRecipient(helloErr, dial.recipient), "unable to send SMTP message"), SendFailureOther)
	}
	return client, closeConnection, nil
}

// upgradeOutcome is how STARTTLS if available's attempt at TLS ended.
type upgradeOutcome int

const (
	// upgradeBroke is a TLS session whose handshake completed and that then failed, which ends the
	// send.
	upgradeBroke upgradeOutcome = iota
	upgraded
	upgradeNotOffered
	// upgradeRefused is a STARTTLS command the relay answered with a refusal, leaving the
	// connection in plaintext and usable.
	upgradeRefused
	// upgradeCommandFailed is a STARTTLS command with no usable reply: the connection closed,
	// reset or stalled on it, or the relay answered with a line that is no SMTP reply. No TLS was
	// attempted, but nothing more can be said over a connection in an unknown state.
	upgradeCommandFailed
	// upgradeHandshakeFailed is a TLS handshake that did not complete, a certificate or host name
	// that did not verify included, leaving a connection nothing more can be said over.
	upgradeHandshakeFailed
)

// startTLSIfAvailable upgrades the connection through STARTTLS when the relay offers it, verified
// as the STARTTLS mode verifies (#718 decision 14), and says how the attempt ended. The error is the
// reason for any outcome but upgraded and upgradeNotOffered.
func startTLSIfAvailable(client *smtp.Client, tlsConfig *tls.Config) (upgradeOutcome, error) {
	if ok, _ := client.Extension("STARTTLS"); !ok {
		return upgradeNotOffered, nil
	}
	err := client.StartTLS(tlsConfig)
	if err == nil {
		return upgraded, nil
	}
	// net/smtp starts the TLS client only once the relay has answered STARTTLS with its 220, and
	// the handshake then runs under the EHLO it repeats. So no TLS state is a STARTTLS command that
	// failed: refused with a reply, or lost to a connection that closed, reset or stalled, or to a
	// line that is no reply. TLS state without a completed handshake is the handshake failing,
	// however it failed: a certificate, an alert, a stall, or a relay closing on a ClientHello it
	// cannot take. Each of those works in plaintext today, so each falls back; stripping STARTTLS
	// from the EHLO reply already forces plaintext, so a lost command gives an attacker nothing
	// more. A completed handshake whose EHLO then failed is an encrypted session that broke, which
	// falls back to nothing.
	state, tlsStarted := client.TLSConnectionState()
	var reply *textproto.Error
	switch {
	case !tlsStarted && errors.As(err, &reply):
		return upgradeRefused, err
	case !tlsStarted:
		return upgradeCommandFailed, err
	case !state.HandshakeComplete:
		return upgradeHandshakeFailed, err
	default:
		return upgradeBroke, err
	}
}

// helloName is the configured EHLO name or, with none, the local address of conn as an RFC 5321
// section 4.1.3 address literal: `[192.0.2.10]`, or `[IPv6:2001:db8::10]` with any zone dropped,
// which no literal can carry. An IPv4 address a dual-stack socket reports in its IPv6-mapped form
// is written as IPv4. RFC 5321 section 4.1.4 has a client without a meaningful domain name send an
// address literal, and the connection's own end is the address the relay sees (section 2.3.5).
func (e *Sender) helloName(conn net.Conn) string {
	if e.ehloName != "" {
		return e.ehloName
	}
	var local netip.Addr
	if tcpAddr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		local = tcpAddr.AddrPort().Addr().Unmap().WithZone("")
	}
	switch {
	case local.Is4():
		return "[" + local.String() + "]"
	case local.Is6():
		return "[IPv6:" + local.String() + "]"
	default:
		// A dialed TCP connection always knows its local address; should it ever not, the
		// unspecified address is still a literal a relay can parse, where a name would be a guess.
		return "[0.0.0.0]"
	}
}

// deadlineConn gives every read and every write its own deadline, commandTimeout from when it
// starts, but never later than sendDeadline (#718 decision 7). A deadline renewed per call rather
// than per SMTP command still bounds each command, whose reply is at least one read, and lets a
// long reply or a large body that keeps arriving or leaving run past commandTimeout. net/smtp
// writes the body through a buffered writer in chunks of a few kilobytes, so each chunk is a write
// of its own.
type deadlineConn struct {
	net.Conn
	commandTimeout time.Duration
	sendDeadline   time.Time
	// connectDeadline, while set, is every read's and write's deadline instead: the implicit-TLS
	// handshake runs under it, as part of the connect.
	connectDeadline time.Time
}

func (c *deadlineConn) Read(p []byte) (int, error) {
	if err := c.SetReadDeadline(c.deadline()); err != nil {
		return 0, err
	}
	return c.Conn.Read(p)
}

func (c *deadlineConn) Write(p []byte) (int, error) {
	if err := c.SetWriteDeadline(c.deadline()); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}

func (c *deadlineConn) deadline() time.Time {
	if !c.connectDeadline.IsZero() {
		return c.connectDeadline
	}
	next := time.Now().Add(c.commandTimeout)
	if next.After(c.sendDeadline) {
		return c.sendDeadline
	}
	return next
}

// labelled is err labelled with kind. The label sits under a frameless errs wrapper, so %+v still
// reaches err's stack.
func labelled(kind SendFailureKind, err error) error {
	return errs.WithStack(&SendError{Kind: kind, Err: err})
}

// replyFailure labels a failed exchange after the connection is up. A reply the server sent is
// refused, the step's own kind; a connection that broke or stalled is a connection failure; and
// anything else, a reply that was no SMTP reply at all or a mechanism's own refusal, is other.
func replyFailure(err error, refused SendFailureKind) error {
	var reply *textproto.Error
	var netErr net.Error
	switch {
	case errors.As(err, &reply):
		return labelled(refused, err)
	case errors.As(err, &netErr), errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return labelled(SendFailureConnection, err)
	default:
		return labelled(SendFailureOther, err)
	}
}

// recipientPlaceholder is what a relay's reply shows in place of the recipient's address.
const recipientPlaceholder = "<recipient>"

// withoutRecipient is err with every occurrence of address in the relay's reply, matched
// case-insensitively, replaced with recipientPlaceholder. A reply stays a *textproto.Error with its
// code, and a line that is no SMTP reply stays a textproto.ProtocolError, so replyFailure labels
// either as before and errors.As still reaches it. net/smtp returns both as the error itself, so
// the copy takes err's place; any other error, which carries no relay text, is returned as it is.
// The match is best-effort: an address the relay quotes in another form, such as encoded, stays.
func withoutRecipient(err error, address string) error {
	if err == nil || address == "" {
		return err
	}
	quoted := regexp.MustCompile("(?i)" + regexp.QuoteMeta(address))
	var reply *textproto.Error
	if errors.As(err, &reply) {
		return &textproto.Error{Code: reply.Code, Msg: quoted.ReplaceAllLiteralString(reply.Msg, recipientPlaceholder)}
	}
	var garbled textproto.ProtocolError
	if errors.As(err, &garbled) {
		return textproto.ProtocolError(quoted.ReplaceAllLiteralString(string(garbled), recipientPlaceholder))
	}
	return err
}

// tlsFailure labels a failed STARTTLS or handshake. Every failure there is the TLS connection's,
// whatever shape it reaches the client in -- a certificate that did not verify, a server that does
// not speak TLS, an alert, a refused STARTTLS command -- except the TCP connection itself failing:
// one whose connection cause ClassifyConnectionError names, such as a handshake that timed out, and
// one closed or reset under it, which is no TLS failure whether or not a handshake had begun.
func tlsFailure(err error) error {
	if ClassifyConnectionError(err) != ConnectionCauseNone || connectionBroke(err) {
		return labelled(SendFailureConnection, err)
	}
	return labelled(SendFailureTLS, err)
}

// connectionBroke reports whether err is the TCP connection closing or failing under the
// conversation: an EOF, or an error the socket's own system call returned, such as a reset. A TLS
// alert reaches the client as a *net.OpError too, but carries no system call error, so it is not
// one.
func connectionBroke(err error) bool {
	var syscallErr *os.SyscallError
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.As(err, &syscallErr)
}

// authenticate picks a mechanism and runs it. The password is only put on the wire when the
// connection protects it, or when it never leaves the machine. redact clears the relay's reply of
// the recipient's address, which a relay echoing the username quotes when the two are the same.
func authenticate(client *smtp.Client, host string, smtpEnc SMTPEncryption, username, password string, redact func(error) error) error {

	ok, mechs := client.Extension("AUTH")
	if !ok {
		// The operator configured credentials, so a server offering no authentication is the
		// wrong host, the wrong port, or a STARTTLS-only server reached as None. Sending
		// unauthenticated instead would hide all three (#274).
		return labelled(SendFailureNoAuthentication, errs.New("SMTP credentials are configured but the server offers no authentication"))
	}
	offered := strings.Fields(strings.ToUpper(mechs))

	// Client preference, deliberately not the server's advertised order: the order a relay
	// announces carries no meaning, and following it would let the server choose the mechanism.
	var mechanism string
	for _, m := range []string{"PLAIN", "LOGIN", "CRAM-MD5"} {
		if slices.Contains(offered, m) {
			mechanism = m
			break
		}
	}

	// PLAIN and LOGIN both hand the password to the server in the clear, so they are refused under
	// STARTTLS if available unless the server is on this machine. The gate reads the configured mode,
	// not whether the upgrade held: a remote relay's authentication then fails closed at every send,
	// rather than working or not connection by connection as a certificate expires or an attacker
	// strips STARTTLS (#718 decision 15). RFC 4616 section 1 says a
	// client SHOULD only use PLAIN with adequate data security in place, and RFC 4954 section 4
	// requires the pairing on the server side. The gate covers both mechanisms here, before any
	// AUTH command, rather than leaning on net/smtp.PlainAuth's own refusal, which loginAuth has
	// no counterpart to and whose message names no setting (#274).
	secure := smtpEnc != SMTPEncryptionNone || isLocalHost(host)
	if (mechanism == "PLAIN" || mechanism == "LOGIN") && !secure {
		return labelled(SendFailureUnencryptedPassword,
			errs.New("with STARTTLS if available, the password is sent only to a server on this machine; set the encryption to STARTTLS or SSL/TLS"))
	}

	var auth smtp.Auth
	switch mechanism {
	case "PLAIN":
		// Checked before either form below is chosen, so the challenge form a long password takes
		// is held to it too.
		if !plainCredentialsCarriable(username, password) {
			return labelled(SendFailureUnusablePlainCredentials, errs.New(
				"the SMTP username and password can't be sent with PLAIN: the password is empty, or one of them contains a null character or is not valid UTF-8"))
		}
		// The inline initial response is what smtp.PlainAuth writes and what all but a pathological
		// password uses. One long enough to push the AUTH line past RFC 5321's 512 octets has to go
		// through the challenge form instead, which RFC 4954 section 4 makes a MUST (#274).
		if plainInitialResponseFits(username, password) {
			auth = smtp.PlainAuth("", username, password, host)
		} else {
			auth = &plainAuth{username: username, password: password}
		}
	case "LOGIN":
		auth = &loginAuth{username: username, password: password}
	case "CRAM-MD5":
		// CRAM-MD5 never sends the password, which is the one reason a relay without TLS
		// legitimately offers a login, so it is not gated above.
		auth = smtp.CRAMMD5Auth(username, password)
	default:
		// What the server offered is its own text, so it rides in the error, for the log, and the
		// kind is what a caller answers with.
		return labelled(SendFailureNoSupportedMechanism,
			errs.New("the SMTP server offers none of PLAIN, LOGIN or CRAM-MD5 (offered: "+strings.TrimSpace(mechs)+")"))
	}

	if err := client.Auth(auth); err != nil {
		return replyFailure(errs.WithStack(redact(err)), SendFailureAuthenticationRejected)
	}
	return nil
}

// isLocalHost reports whether the password would stay on this machine. The three names are
// net/smtp.PlainAuth's own exception list.
func isLocalHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// buildMessage writes the RFC 5322 message: a fixed header order, then a multipart/alternative
// body of two quoted-printable parts, the plain text worked out of the HTML and then the HTML.
// go-simple-mail emitted the headers in Go map order, so nothing downstream can have depended on
// the old order (#274).
func (e *Sender) buildMessage(from, to *mail.Address, input *SendEmailInput) ([]byte, error) {

	// No email is sent without its text (#817 decision 10).
	text, err := plainText(input.HtmlBody)
	if err != nil {
		return nil, err
	}

	messageID, err := e.newMessageID(from.Address)
	if err != nil {
		return nil, err
	}
	boundary, err := e.newBoundary()
	if err != nil {
		return nil, err
	}

	var b bytes.Buffer
	// From and To go through net/mail, which quotes or RFC 2047 encodes anything that would
	// otherwise break the syntax, and Subject through mime.QEncoding, which encodes CR and LF.
	// That is what makes a header value out of an operator-editable setting safe (#274). All three
	// then go through the one folding writer (#718 decision 3).
	if err := writeFoldedHeader(&b, "From", addressTokens(from)); err != nil {
		return nil, err
	}
	if err := writeFoldedHeader(&b, "To", addressTokens(to)); err != nil {
		return nil, err
	}
	if err := writeFoldedHeader(&b, "Subject", unstructuredTokens(mime.QEncoding.Encode("UTF-8", input.Subject))); err != nil {
		return nil, err
	}
	writeHeader(&b, "Date", time.Now().Format(time.RFC1123Z))
	writeHeader(&b, "Message-ID", messageID)
	writeHeader(&b, "MIME-Version", "1.0")
	// Every part is quoted-printable, so the message as a whole is 7-bit, the default a multipart
	// message names no Content-Transfer-Encoding for (RFC 2045 section 6.1).
	writeHeader(&b, "Content-Type", mime.FormatMediaType("multipart/alternative", map[string]string{"boundary": boundary}))
	b.WriteString("\r\n")

	parts := multipart.NewWriter(&b)
	if err := parts.SetBoundary(boundary); err != nil {
		return nil, errs.WithStack(err)
	}
	// RFC 2046 section 5.1.4: the parts in increasing order of preference, the plainest first and
	// the richest last.
	for _, part := range []struct{ contentType, content string }{
		{"text/plain; charset=UTF-8", text},
		{"text/html; charset=UTF-8", input.HtmlBody},
	} {
		w, err := parts.CreatePart(textproto.MIMEHeader{
			"Content-Type":              {part.contentType},
			"Content-Transfer-Encoding": {"quoted-printable"},
		})
		if err != nil {
			return nil, errs.WithStack(err)
		}
		// Quoted-printable rather than raw 8-bit: BODY=8BITMIME does not lift RFC 5322's 998-byte
		// line limit, and a rendered HTML line can exceed it. net/smtp's data writer dot-stuffs.
		qp := quotedprintable.NewWriter(w)
		if _, err := qp.Write([]byte(part.content)); err != nil {
			return nil, errs.WithStack(err)
		}
		if err := qp.Close(); err != nil {
			return nil, errs.WithStack(err)
		}
	}
	if err := parts.Close(); err != nil {
		return nil, errs.WithStack(err)
	}

	return b.Bytes(), nil
}

// newBoundary returns the multipart boundary of one message: "=_" and 24 random hex characters.
// RFC 2046 section 5.1.1 requires that it appear in no part, and a quoted-printable part never
// holds "=_", since its "=" is always followed by two hex digits or a line end. 26 characters stay
// within the 70 it allows, and keep the Content-Type header that quotes it within RFC 5322's 78.
func (e *Sender) newBoundary() (string, error) {
	raw := make([]byte, 12)
	if err := e.random(raw); err != nil {
		return "", errs.Wrap(err, "unable to generate a multipart boundary")
	}
	return "=_" + hex.EncodeToString(raw), nil
}

// random fills raw from the sender's source of randomness.
func (e *Sender) random(raw []byte) error {
	reader := e.randReader
	if reader == nil {
		reader = rand.Reader
	}
	_, err := io.ReadFull(reader, raw)
	return err
}

// newMessageID returns `<32 hex characters@domain>`, per RFC 5322 section 3.6.4's SHOULD. The
// domain is the part of the from address after its last '@'; the address is validated as an email
// on the way into the settings (apihandlers.HandleSettingsEmailPut), which is what keeps this
// from being a header injection point (#274).
func (e *Sender) newMessageID(fromAddress string) (string, error) {
	raw := make([]byte, 16)
	// crypto/rand.Read is documented never to fail, so in production this branch is unreachable.
	// It is still an error rather than an empty left-hand side: `<@domain>` would be emitted on
	// every send, which is worse than no Message-ID at all.
	if err := e.random(raw); err != nil {
		return "", errs.Wrap(err, "unable to generate a Message-ID")
	}

	domain := fromAddress
	if i := strings.LastIndex(fromAddress, "@"); i >= 0 {
		domain = fromAddress[i+1:]
	}

	return "<" + hex.EncodeToString(raw) + "@" + domain + ">", nil
}

func writeHeader(b *bytes.Buffer, name, value string) {
	b.WriteString(name)
	b.WriteString(": ")
	b.WriteString(value)
	b.WriteString("\r\n")
}

// addressTokens splits an address as net/mail writes it into the pieces a fold may separate: each
// encoded word of the display name, or the display name's quoted string whole, and then the
// <address>. Nothing inside a quoted string or an address is a fold point: a quoted local part may
// itself hold a space.
func addressTokens(a *mail.Address) []string {
	angleAddr := (&mail.Address{Address: a.Address}).String()
	if a.Name == "" {
		return []string{angleAddr}
	}
	full := a.String()
	displayName, found := strings.CutSuffix(full, " "+angleAddr)
	if !found {
		// net/mail always writes the name, one space, then the address; should that ever change,
		// the field is written unfolded rather than split at a guess.
		return []string{full}
	}
	// net/mail quotes a printable ASCII name and RFC 2047 encodes any other, and its encoded words
	// are joined by single spaces and hold none themselves.
	if strings.HasPrefix(displayName, `"`) {
		return []string{displayName, angleAddr}
	}
	return append(strings.Split(displayName, " "), angleAddr)
}

// unstructuredTokens splits an encoded Subject at its spaces. mime.QEncoding joins its encoded
// words with single spaces and writes a space inside one as '_', so every space of an encoded value
// is a join between two of them. A value it returns unchanged is plain ASCII, which folds at its own
// spaces as before. A run of spaces stays with the word after it, so no continuation line is only
// whitespace, which RFC 5322 section 3.2.2 forbids; strings.Join(tokens, " ") is the value again.
func unstructuredTokens(value string) []string {
	var tokens []string
	carry, carrying := "", false
	for _, part := range strings.Split(value, " ") {
		if carrying {
			part = carry + " " + part
		}
		if strings.TrimLeft(part, " ") == "" {
			carry, carrying = part, true
			continue
		}
		tokens = append(tokens, part)
		carrying = false
	}
	if carrying {
		if len(tokens) > 0 {
			tokens[len(tokens)-1] += " " + carry
		} else {
			tokens = append(tokens, carry)
		}
	}
	return tokens
}

// isEncodedWord reports whether token reads as an RFC 2047 encoded word. A plain ASCII subject
// shaped like one is passed through unencoded and a reader decodes it all the same, so it is held to
// the same 76 characters.
func isEncodedWord(token string) bool {
	trimmed := strings.TrimSpace(token)
	return strings.HasPrefix(trimmed, "=?") && strings.HasSuffix(trimmed, "?=")
}

// writeFoldedHeader writes a header field whose value is tokens joined by single spaces, folding
// only at those spaces, so no encoded word, quoted name or address is ever split (#718 decision 3).
// A line holding an encoded word is kept within RFC 2047 section 2's 76 characters and any other
// within RFC 5322 section 2.1.1's 78, both counted without the CRLF.
//
// A fold replaces exactly one space: every token is written preceded by one space, either on the
// current line or as the continuation line's leading whitespace. Unfolding per RFC 5322 section
// 2.2.3, which removes the CRLF and keeps the whitespace, therefore restores the value byte for
// byte, double spaces included.
func writeFoldedHeader(b *bytes.Buffer, name string, tokens []string) error {
	b.WriteString(name)
	b.WriteString(":")
	lineLen := len(name) + 1
	lineHasEncodedWord := false
	tokensOnLine := 0

	for _, token := range tokens {
		encoded := isEncodedWord(token)
		limit := lineLimit(lineHasEncodedWord || encoded)
		if lineLen+1+len(token) > limit && strings.TrimLeft(token, " ") != "" {
			// After a token, a fold always helps. On the field's first line, still empty, it
			// helps only when the token then fits its own line, or when staying would pass 998.
			ownLine := 1 + len(token)
			if tokensOnLine > 0 || ownLine <= lineLimit(encoded) || lineLen+ownLine > maxHeaderLineHardBytes {
				b.WriteString("\r\n")
				lineLen = 0
				lineHasEncodedWord = false
				tokensOnLine = 0
			}
		}
		b.WriteString(" ")
		b.WriteString(token)
		lineLen += 1 + len(token)
		lineHasEncodedWord = lineHasEncodedWord || encoded
		tokensOnLine++

		// A token has no legal fold point inside it, so one too long for a line of its own cannot
		// be written at all. 76 and 78 are what folding serves; 998 is a MUST that nothing here can
		// serve, so this refuses rather than writing a line a conforming server may reject mid-DATA
		// with a message the admin cannot act on. Every subject the callers pass is a catalog
		// string with at most a 30-character app name in it, and the settings bound the sender, so
		// this is a bound on the package's API rather than a path a deployment can reach (#274).
		if lineLen > maxHeaderLineHardBytes {
			return errs.New("the " + name + " header contains a word of " +
				strconv.Itoa(len(token)) + " bytes, which cannot be folded under RFC 5322 section 2.1.1's 998-byte line limit")
		}
	}

	b.WriteString("\r\n")
	return nil
}

// lineLimit is the length a header line may reach before the line folds.
func lineLimit(holdsEncodedWord bool) int {
	if holdsEncodedWord {
		return maxEncodedWordLineBytes
	}
	return maxHeaderLineBytes
}
