package communication

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

const (
	// RFC 5322 section 2.1.1: a line SHOULD be no more than 78 characters excluding the CRLF.
	maxHeaderLineBytes = 78
	// The same sentence's other half, which is a MUST rather than a SHOULD: no more than 998
	// characters, excluding the CRLF.
	maxHeaderLineHardBytes = 998

	defaultDialTimeout = 10 * time.Second
	// One deadline covers EHLO through QUIT rather than a per-command one, so a slow relay is not
	// cut off mid-DATA on a large HTML body (#274).
	defaultConversationTimeout = 30 * time.Second
)

type EmailSender struct {
	// rootCAs is nil in production, meaning the system roots. The in-package tests point it at
	// their fake server's certificate so the TLS paths can be exercised with verification left on.
	rootCAs *x509.CertPool
	// Zero means the defaults above.
	dialTimeout time.Duration
	convTimeout time.Duration
	// randReader is nil in production, meaning crypto/rand.Reader. It exists so a test can make
	// the Message-ID's entropy read fail and show the send fails closed.
	randReader io.Reader
}

func NewEmailSender() *EmailSender {
	return &EmailSender{}
}

type SendEmailInput struct {
	To       string
	Subject  string
	HtmlBody string
}

func (e *EmailSender) SendEmail(ctx context.Context, input *SendEmailInput) error {

	settings := ctx.Value(constants.ContextKeySettings).(*models.Settings)

	var password string
	if len(settings.SMTPPasswordEncrypted) > 0 {
		decryptedPassword, err := encryption.DecryptData(settings.SMTPPasswordEncrypted)
		if err != nil {
			return errors.Wrap(err, "unable to decrypt the SMTP password")
		}
		password = decryptedPassword
	}

	smtpEnc, err := enums.SMTPEncryptionFromString(settings.SMTPEncryption)
	if err != nil {
		return errors.Wrap(err, "unable to parse the SMTP encryption")
	}

	// Build the whole message before dialing, so a bad address or a failed entropy read costs no
	// connection and reaches the admin as its own error rather than as a mid-conversation failure.
	from := &mail.Address{Name: settings.SMTPFromName, Address: settings.SMTPFromEmail}
	to, err := mail.ParseAddress(input.To)
	if err != nil {
		return errors.Wrap(err, "invalid recipient address")
	}
	message, err := e.buildMessage(from, to, input)
	if err != nil {
		return err
	}

	host := settings.SMTPHost
	addr := net.JoinHostPort(host, strconv.Itoa(settings.SMTPPort))

	dialTimeout := e.dialTimeout
	if dialTimeout == 0 {
		dialTimeout = defaultDialTimeout
	}
	convTimeout := e.convTimeout
	if convTimeout == 0 {
		convTimeout = defaultConversationTimeout
	}

	netDialer := &net.Dialer{Timeout: dialTimeout}
	// One config for both TLS paths. Certificate and hostname verification are never disabled:
	// RFC 8314 section 3.3 requires the implicit-TLS client to validate, and a STARTTLS session
	// that does not verify buys nothing over cleartext (#274).
	tlsConfig := &tls.Config{ServerName: host, RootCAs: e.rootCAs}

	var conn net.Conn
	if smtpEnc == enums.SMTPEncryptionSSLTLS {
		conn, err = (&tls.Dialer{NetDialer: netDialer, Config: tlsConfig}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = netDialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return errors.Wrap(err, "unable to connect to SMTP server")
	}

	if err := conn.SetDeadline(time.Now().Add(convTimeout)); err != nil {
		_ = conn.Close()
		return errors.Wrap(err, "unable to connect to SMTP server")
	}

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return errors.Wrap(err, "unable to connect to SMTP server")
	}
	defer func() { _ = client.Close() }()

	if smtpEnc == enums.SMTPEncryptionSTARTTLS {
		// The operator asked for STARTTLS, so a server that does not offer it is refused rather
		// than continued with in the clear. RFC 3207 section 4 leaves the choice to the client,
		// and a silent downgrade here is indistinguishable from a STARTTLS-stripping attacker
		// (#274).
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return errors.Wrap(errors.New("the SMTP server did not offer STARTTLS; set the encryption to None only if the server has no TLS"),
				"unable to send SMTP message")
		}
		// StartTLS re-issues EHLO, per RFC 3207 section 4.2: everything learned before the
		// handshake has to be discarded.
		if err := client.StartTLS(tlsConfig); err != nil {
			return errors.Wrap(err, "unable to send SMTP message")
		}
	}

	if len(settings.SMTPUsername) > 0 {
		if err := authenticate(client, host, smtpEnc, settings.SMTPUsername, password); err != nil {
			return errors.Wrap(err, "unable to send SMTP message")
		}
	}

	if err := client.Mail(from.Address); err != nil {
		return errors.Wrap(err, "unable to send SMTP message")
	}
	if err := client.Rcpt(to.Address); err != nil {
		return errors.Wrap(err, "unable to send SMTP message")
	}
	w, err := client.Data()
	if err != nil {
		return errors.Wrap(err, "unable to send SMTP message")
	}
	if _, err := w.Write(message); err != nil {
		return errors.Wrap(err, "unable to send SMTP message")
	}
	if err := w.Close(); err != nil {
		return errors.Wrap(err, "unable to send SMTP message")
	}
	if err := client.Quit(); err != nil {
		return errors.Wrap(err, "unable to send SMTP message")
	}

	return nil
}

// authenticate picks a mechanism and runs it. The password is only put on the wire when the
// connection protects it, or when it never leaves the machine.
func authenticate(client *smtp.Client, host string, smtpEnc enums.SMTPEncryption, username, password string) error {

	ok, mechs := client.Extension("AUTH")
	if !ok {
		// The operator configured credentials, so a server offering no authentication is the
		// wrong host, the wrong port, or a STARTTLS-only server reached as None. Sending
		// unauthenticated instead would hide all three (#274).
		return errors.WithStack(errors.New("SMTP credentials are configured but the server offers no authentication"))
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

	// PLAIN and LOGIN both hand the password to the server in the clear, so they are refused on a
	// connection that is not TLS unless the server is on this machine. RFC 4616 section 1 says a
	// client SHOULD only use PLAIN with adequate data security in place, and RFC 4954 section 4
	// requires the pairing on the server side. The gate covers both mechanisms here, before any
	// AUTH command, rather than leaning on net/smtp.PlainAuth's own refusal, which loginAuth has
	// no counterpart to and whose message names no setting (#274).
	secure := smtpEnc != enums.SMTPEncryptionNone || isLocalHost(host)
	if (mechanism == "PLAIN" || mechanism == "LOGIN") && !secure {
		return errors.WithStack(errors.New("the SMTP server would receive the password unencrypted; set the encryption to STARTTLS or SSL/TLS"))
	}

	var auth smtp.Auth
	switch mechanism {
	case "PLAIN":
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
		return errors.WithStack(errors.New("the SMTP server offers none of PLAIN, LOGIN or CRAM-MD5 (offered: " + strings.TrimSpace(mechs) + ")"))
	}

	return errors.WithStack(client.Auth(auth))
}

// isLocalHost reports whether the password would stay on this machine. The three names are
// net/smtp.PlainAuth's own exception list.
func isLocalHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// buildMessage writes the RFC 5322 message: a fixed header order, then a quoted-printable
// text/html body. go-simple-mail emitted the headers in Go map order, so nothing downstream can
// have depended on the old order (#274).
func (e *EmailSender) buildMessage(from, to *mail.Address, input *SendEmailInput) ([]byte, error) {

	messageID, err := e.newMessageID(from.Address)
	if err != nil {
		return nil, err
	}

	var b bytes.Buffer
	// From and To go through net/mail, which quotes or RFC 2047 encodes anything that would
	// otherwise break the syntax, and Subject through mime.QEncoding, which encodes CR and LF.
	// That is what makes a header value out of an operator-editable setting safe (#274).
	writeHeader(&b, "From", from.String())
	writeHeader(&b, "To", to.String())
	if err := writeFoldedHeader(&b, "Subject", mime.QEncoding.Encode("UTF-8", input.Subject)); err != nil {
		return nil, err
	}
	writeHeader(&b, "Date", time.Now().Format(time.RFC1123Z))
	writeHeader(&b, "Message-ID", messageID)
	writeHeader(&b, "MIME-Version", "1.0")
	writeHeader(&b, "Content-Type", "text/html; charset=UTF-8")
	writeHeader(&b, "Content-Transfer-Encoding", "quoted-printable")
	b.WriteString("\r\n")

	// Quoted-printable rather than raw 8-bit: BODY=8BITMIME does not lift RFC 5322's 998-byte
	// line limit, and a rendered HTML line can exceed it. net/smtp's data writer dot-stuffs.
	qp := quotedprintable.NewWriter(&b)
	if _, err := qp.Write([]byte(input.HtmlBody)); err != nil {
		return nil, errors.WithStack(err)
	}
	if err := qp.Close(); err != nil {
		return nil, errors.WithStack(err)
	}

	return b.Bytes(), nil
}

// newMessageID returns `<32 hex characters@domain>`, per RFC 5322 section 3.6.4's SHOULD. The
// domain is the part of the from address after its last '@'; the address is validated as an email
// on the way into the settings (apihandlers.HandleAPISettingsEmailPut), which is what keeps this
// from being a header injection point (#274).
func (e *EmailSender) newMessageID(fromAddress string) (string, error) {
	reader := e.randReader
	if reader == nil {
		reader = rand.Reader
	}

	raw := make([]byte, 16)
	// crypto/rand.Read is documented never to fail, so in production this branch is unreachable.
	// It is still an error rather than an empty left-hand side: `<@domain>` would be emitted on
	// every send, which is worse than no Message-ID at all.
	if _, err := io.ReadFull(reader, raw); err != nil {
		return "", errors.Wrap(err, "unable to generate a Message-ID")
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

// writeFoldedHeader packs an already-encoded value onto lines of at most 78 bytes, RFC 5322
// section 2.1.1's SHOULD. mime.QEncoding splits a long value into encoded-words joined by single
// spaces and folds nothing itself, and Q encoding writes a space as '_', so every space in an
// encoded value is a join and every one of them is a legal fold point. Plain ASCII values are
// returned unchanged by the encoder and fold at their own spaces by the same rule.
//
// A fold replaces exactly one space: every token is written preceded by one space, either on the
// current line or as the continuation line's leading whitespace. Unfolding per section 2.2.3,
// which removes the CRLF and keeps the whitespace, therefore restores the value byte for byte,
// double spaces included.
func writeFoldedHeader(b *bytes.Buffer, name, value string) error {
	b.WriteString(name)
	b.WriteString(":")
	lineLen := len(name) + 1

	firstLine := true
	tokensOnLine := 0
	for _, token := range strings.Split(value, " ") {
		// A token has no legal fold point inside it, so one too long for a line of its own cannot
		// be emitted at all. 78 is a SHOULD and folding serves it; 998 is a MUST and nothing here
		// can serve it, so this refuses rather than writing a line a conforming server may reject
		// mid-DATA with a message the admin cannot act on. Every subject the callers pass is a
		// catalog string with at most a 30-character app name in it, so this is a bound on the
		// package's API rather than a path a deployment can reach (#274).
		if 1+len(token) > maxHeaderLineHardBytes {
			return errors.WithStack(errors.New("the " + name + " header contains a word of " +
				strconv.Itoa(len(token)) + " bytes, which cannot be folded under RFC 5322 section 2.1.1's 998-byte line limit"))
		}
		// Fold unless the line has nothing on it yet: a single token longer than a whole line
		// cannot be split here, and folding before it would loop forever.
		if lineLen+1+len(token) > maxHeaderLineBytes && (tokensOnLine > 0 || firstLine) {
			b.WriteString("\r\n")
			lineLen = 0
			tokensOnLine = 0
			firstLine = false
		}
		b.WriteString(" ")
		b.WriteString(token)
		lineLen += 1 + len(token)
		tokensOnLine++
	}

	b.WriteString("\r\n")
	return nil
}
