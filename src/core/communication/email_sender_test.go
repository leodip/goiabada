package communication

import (
	"context"
	"fmt"
	"io"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"regexp"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/testutil"
	"github.com/leodip/goiabada/core/testutil/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSendEmail(t *testing.T) {

	emailSender := NewEmailSender()

	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, &models.Settings{
		SMTPHost:              "mailpit",
		SMTPPort:              1025,
		SMTPUsername:          "",
		SMTPPasswordEncrypted: nil,
		SMTPEncryption:        "none",
		SMTPFromName:          "Test Sender",
		SMTPFromEmail:         "sender@example.com",
	})

	recipient := fake.Email()

	input := &SendEmailInput{
		To:       recipient,
		Subject:  "Test Email",
		HtmlBody: "<p>This is a test email</p>",
	}

	err := emailSender.SendEmail(ctx, input)
	assert.NoError(t, err)

	testutil.AssertEmailSent(t, recipient, "<p>This is a test email</p>")
}

// The fixtures the table below shares. The from address's domain is what the Message-ID assertion
// reads.
const (
	fixtureUser      = "smtp-user@example.com"
	fixturePassword  = "s3cret-p4ss"
	fixtureFromEmail = "noreply@example.com"
	fixtureRecipient = "rcpt@example.com"
)

// fakeSettings builds the settings context SendEmail reads, encrypting the password through the
// package's test cipher (test_main_test.go) exactly as the real settings carry it.
func fakeSettings(t *testing.T, host string, port int, smtpEncryption string, username, password, fromName string) context.Context {
	t.Helper()

	settings := &models.Settings{
		SMTPHost:       host,
		SMTPPort:       port,
		SMTPUsername:   username,
		SMTPEncryption: smtpEncryption,
		SMTPFromName:   fromName,
		SMTPFromEmail:  fixtureFromEmail,
	}

	if password != "" {
		encrypted, err := encryption.EncryptData(password)
		require.NoError(t, err)
		settings.SMTPPasswordEncrypted = encrypted
	}

	return context.WithValue(context.Background(), constants.ContextKeySettings, settings)
}

// TestSendEmail_EncryptionModes covers the three modes end to end against the fake, each with
// credentials, and pins that a STARTTLS session issues no AUTH and no MAIL before the handshake.
func TestSendEmail_EncryptionModes(t *testing.T) {

	cert := newFakeCert(t)

	tests := []struct {
		name         string
		encryption   string
		ext          []string
		tlsExt       []string
		tlsFromStart bool
	}{
		{
			name:       "none",
			encryption: "none",
			ext:        []string{"AUTH PLAIN", "8BITMIME"},
		},
		{
			name:       "starttls",
			encryption: "starttls",
			// AUTH is advertised only after the handshake, which is what a relay that requires
			// TLS for authentication actually does.
			ext:    []string{"STARTTLS", "8BITMIME"},
			tlsExt: []string{"AUTH PLAIN", "8BITMIME"},
		},
		{
			name:         "ssltls",
			encryption:   "ssltls",
			tlsExt:       []string{"AUTH PLAIN", "8BITMIME"},
			tlsFromStart: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := &fakeSMTP{
				ext:            test.ext,
				tlsExt:         test.tlsExt,
				tlsFromStart:   test.tlsFromStart,
				expectPassword: fixturePassword,
				cert:           cert,
			}
			port := f.start(t)

			// 127.0.0.1 is a SAN on the fake's certificate and is one of the three hosts
			// decision 1 treats as local, so this row is about the mode and nothing else.
			ctx := fakeSettings(t, "127.0.0.1", port, test.encryption, fixtureUser, fixturePassword, "Goiabada")
			sender := &EmailSender{rootCAs: cert.pool}

			err := sender.SendEmail(ctx, &SendEmailInput{
				To:       fixtureRecipient,
				Subject:  "Test email",
				HtmlBody: "<p>hello</p>",
			})
			require.NoError(t, err)

			user, password := f.credentials()
			assert.Equal(t, fixtureUser, user)
			assert.Equal(t, fixturePassword, password)

			assert.True(t, f.hasLinePrefix("EHLO localhost"), "RFC 5321 4.1.1.1: the client has no name of its own, so it greets as localhost")
			assert.True(t, f.hasLinePrefix("MAIL FROM:"))
			assert.True(t, f.hasLinePrefix("RCPT TO:"))
			assert.True(t, f.hasLinePrefix("DATA"))
			assert.True(t, f.hasLinePrefix("QUIT"))
			assert.Contains(t, f.data(), "Subject: Test email\r\n")

			if test.encryption == "starttls" {
				startTLS := f.indexOfLinePrefix("STARTTLS")
				require.GreaterOrEqual(t, startTLS, 0, "the client never issued STARTTLS")
				assert.Greater(t, f.indexOfLinePrefix("AUTH"), startTLS,
					"RFC 3207 section 4: no command may precede the TLS negotiation once STARTTLS is answered")
				assert.Greater(t, f.indexOfLinePrefix("MAIL FROM:"), startTLS)
			}
		})
	}
}

// TestSendEmail_MechanismChoice pins decision 3: PLAIN, then LOGIN, then CRAM-MD5, in the client's
// order and not the server's. Every row runs over `none` to 127.0.0.1, which decision 1 permits,
// so the mechanism is the only thing under test.
func TestSendEmail_MechanismChoice(t *testing.T) {

	tests := []struct {
		name      string
		authExt   string
		wantLine  string
		wantPass  string
		wantError string
	}{
		{
			name:     "all three offered picks PLAIN",
			authExt:  "AUTH PLAIN LOGIN CRAM-MD5",
			wantLine: "AUTH PLAIN ",
			wantPass: fixturePassword,
		},
		{
			// The same three, advertised worst-first. Taking the server's first token would pick
			// CRAM-MD5 here, so this row is what tells client preference from server order.
			name:     "all three offered in reverse still picks PLAIN",
			authExt:  "AUTH CRAM-MD5 LOGIN PLAIN",
			wantLine: "AUTH PLAIN ",
			wantPass: fixturePassword,
		},
		{
			name:     "only LOGIN offered picks LOGIN",
			authExt:  "AUTH LOGIN",
			wantLine: "AUTH LOGIN",
			wantPass: fixturePassword,
		},
		{
			// CRAM-MD5 never puts the password on the wire, so the fake has nothing to record
			// for it: it verifies the digest instead.
			name:     "only CRAM-MD5 offered picks CRAM-MD5",
			authExt:  "AUTH CRAM-MD5",
			wantLine: "AUTH CRAM-MD5",
			wantPass: "",
		},
		{
			name:      "only XOAUTH2 offered is refused",
			authExt:   "AUTH XOAUTH2",
			wantError: "the SMTP server offers none of PLAIN, LOGIN or CRAM-MD5 (offered: XOAUTH2)",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := &fakeSMTP{ext: []string{test.authExt, "8BITMIME"}, expectPassword: fixturePassword}
			port := f.start(t)

			ctx := fakeSettings(t, "127.0.0.1", port, "none", fixtureUser, fixturePassword, "Goiabada")

			err := (&EmailSender{}).SendEmail(ctx, &SendEmailInput{
				To:       fixtureRecipient,
				Subject:  "Test email",
				HtmlBody: "<p>hello</p>",
			})

			if test.wantError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.wantError)
				assert.Contains(t, err.Error(), "unable to send SMTP message")
				assert.False(t, f.hasLinePrefix("AUTH"), "no mechanism was usable, so no AUTH may have been attempted")
				assert.False(t, f.hasLinePrefix("MAIL FROM:"))
				return
			}

			require.NoError(t, err)
			assert.True(t, f.hasLinePrefix(test.wantLine), "expected an %q line in %q", test.wantLine, f.lines())

			user, password := f.credentials()
			assert.Equal(t, fixtureUser, user)
			assert.Equal(t, test.wantPass, password)
			assert.True(t, f.hasLinePrefix("MAIL FROM:"))
		})
	}
}

// TestSendEmail_FailsClosed covers decisions 1, 2 and 4. Every refusal sits next to the row it
// would succeed under, differing in one field, so the named gate is demonstrably the reason.
func TestSendEmail_FailsClosed(t *testing.T) {

	cert := newFakeCert(t)
	hostname := fakeHostname(t)

	tests := []struct {
		name       string
		encryption string
		host       string
		ext        []string
		tlsExt     []string
		wantError  string
	}{
		{
			name:       "starttls offered, delivers",
			encryption: "starttls",
			host:       "127.0.0.1",
			ext:        []string{"STARTTLS", "8BITMIME"},
			tlsExt:     []string{"AUTH PLAIN", "8BITMIME"},
		},
		{
			// Decision 2: the operator asked for STARTTLS, so cleartext is not a fallback.
			name:       "starttls not offered, refused",
			encryption: "starttls",
			host:       "127.0.0.1",
			ext:        []string{"AUTH PLAIN", "8BITMIME"},
			wantError:  "the SMTP server did not offer STARTTLS; set the encryption to None only if the server has no TLS",
		},
		{
			name:       "none with credentials to a loopback host, PLAIN offered",
			encryption: "none",
			host:       "127.0.0.1",
			ext:        []string{"AUTH PLAIN", "8BITMIME"},
		},
		{
			// Decision 1: the same settings, one host further away.
			name:       "none with credentials to a non-loopback host, PLAIN offered",
			encryption: "none",
			host:       hostname,
			ext:        []string{"AUTH PLAIN", "8BITMIME"},
			wantError:  "the SMTP server would receive the password unencrypted; set the encryption to STARTTLS or SSL/TLS",
		},
		{
			// The same refusal with PLAIN off the table, so net/smtp.PlainAuth's own guard
			// cannot be what produced it.
			name:       "none with credentials to a non-loopback host, only LOGIN offered",
			encryption: "none",
			host:       hostname,
			ext:        []string{"AUTH LOGIN", "8BITMIME"},
			wantError:  "the SMTP server would receive the password unencrypted; set the encryption to STARTTLS or SSL/TLS",
		},
		{
			// Decision 3's cleartext exception: CRAM-MD5 never sends the password, so the same
			// non-loopback cleartext connection is allowed to authenticate.
			name:       "none with credentials to a non-loopback host, only CRAM-MD5 offered",
			encryption: "none",
			host:       hostname,
			ext:        []string{"AUTH CRAM-MD5", "8BITMIME"},
		},
		{
			// Decision 4: credentials were configured, so a server with no AUTH is the wrong
			// host, the wrong port, or a STARTTLS-only server reached as None.
			name:       "credentials configured, no AUTH advertised",
			encryption: "none",
			host:       "127.0.0.1",
			ext:        []string{"8BITMIME"},
			wantError:  "SMTP credentials are configured but the server offers no authentication",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := &fakeSMTP{
				ext:            test.ext,
				tlsExt:         test.tlsExt,
				expectPassword: fixturePassword,
				cert:           cert,
			}
			port := f.start(t)

			ctx := fakeSettings(t, test.host, port, test.encryption, fixtureUser, fixturePassword, "Goiabada")
			sender := &EmailSender{rootCAs: cert.pool}

			err := sender.SendEmail(ctx, &SendEmailInput{
				To:       fixtureRecipient,
				Subject:  "Test email",
				HtmlBody: "<p>hello</p>",
			})

			if test.wantError == "" {
				require.NoError(t, err)
				assert.True(t, f.hasLinePrefix("AUTH"), "the row is meant to authenticate")
				assert.True(t, f.hasLinePrefix("MAIL FROM:"))
				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), test.wantError)
			assert.Contains(t, err.Error(), "unable to send SMTP message")
			assert.False(t, f.hasLinePrefix("MAIL FROM:"), "the refusal has to precede the message")
			assert.False(t, f.hasLinePrefix("AUTH"), "every gate has to precede any AUTH command")
		})
	}
}

// TestSendEmail_CertificateVerification holds §4's "verification is never off" for both TLS
// paths: an unknown authority and a name the certificate does not carry each fail the send. The
// positive counterpart of every row is the matching mode in TestSendEmail_EncryptionModes, which
// differs from it in exactly the pool or the host.
func TestSendEmail_CertificateVerification(t *testing.T) {

	cert := newFakeCert(t)
	// Generated the same way and never presented by the fake, so a chain built against it cannot
	// verify.
	untrusted := newFakeCert(t)

	tests := []struct {
		name         string
		encryption   string
		host         string
		trusted      bool
		tlsFromStart bool
		ext          []string
		tlsExt       []string
		wantInError  []string
		wantNoLines  bool
	}{
		{
			name:        "starttls against an unknown authority",
			encryption:  "starttls",
			host:        "127.0.0.1",
			ext:         []string{"STARTTLS", "8BITMIME"},
			tlsExt:      []string{"AUTH PLAIN", "8BITMIME"},
			wantInError: []string{"x509:", "unknown authority"},
		},
		{
			// The certificate deliberately does not carry "localhost" as a SAN, so this reaches a
			// trusted chain whose names do not match: hostname verification, not chain
			// verification.
			name:        "starttls to a name the certificate does not carry",
			encryption:  "starttls",
			host:        "localhost",
			trusted:     true,
			ext:         []string{"STARTTLS", "8BITMIME"},
			tlsExt:      []string{"AUTH PLAIN", "8BITMIME"},
			wantInError: []string{"x509:", "localhost"},
		},
		{
			name:         "ssltls against an unknown authority",
			encryption:   "ssltls",
			host:         "127.0.0.1",
			tlsFromStart: true,
			tlsExt:       []string{"AUTH PLAIN", "8BITMIME"},
			wantInError:  []string{"x509:", "unknown authority"},
			wantNoLines:  true,
		},
		{
			name:         "ssltls to a name the certificate does not carry",
			encryption:   "ssltls",
			host:         "localhost",
			trusted:      true,
			tlsFromStart: true,
			tlsExt:       []string{"AUTH PLAIN", "8BITMIME"},
			wantInError:  []string{"x509:", "localhost"},
			wantNoLines:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := &fakeSMTP{
				ext:            test.ext,
				tlsExt:         test.tlsExt,
				tlsFromStart:   test.tlsFromStart,
				expectPassword: fixturePassword,
				cert:           cert,
			}
			port := f.start(t)

			pool := untrusted.pool
			if test.trusted {
				pool = cert.pool
			}

			ctx := fakeSettings(t, test.host, port, test.encryption, fixtureUser, fixturePassword, "Goiabada")

			err := (&EmailSender{rootCAs: pool}).SendEmail(ctx, &SendEmailInput{
				To:       fixtureRecipient,
				Subject:  "Test email",
				HtmlBody: "<p>hello</p>",
			})
			require.Error(t, err)
			for _, want := range test.wantInError {
				assert.Contains(t, err.Error(), want)
			}

			assert.False(t, f.hasLinePrefix("AUTH"), "a failed handshake may not be followed by credentials")
			assert.False(t, f.hasLinePrefix("MAIL FROM:"))
			assert.Empty(t, f.data(), "no message may reach a server whose certificate did not verify")
			if test.wantNoLines {
				assert.Empty(t, f.lines(), "implicit TLS fails before any SMTP command is exchanged")
			}
		})
	}
}

// sentMessage is a DATA payload taken apart: the headers unfolded per RFC 5322 section 2.2.3, the
// names in the order they arrived, the raw header lines for the line-length assertions, and the
// body with the SMTP dot-stuffing removed.
type sentMessage struct {
	headers    map[string]string
	order      []string
	rawHeaders []string
	body       string
	raw        string
}

func parseMessage(t *testing.T, data string) sentMessage {
	t.Helper()

	require.NotEmpty(t, data, "the fake recorded no DATA block")
	separator := strings.Index(data, "\r\n\r\n")
	require.GreaterOrEqual(t, separator, 0, "the message has no header/body separator")

	headerBlock := data[:separator]
	rawHeaders := strings.Split(headerBlock, "\r\n")

	// Unfolding removes the CRLF of a fold and keeps the whitespace that follows it.
	unfolded := strings.ReplaceAll(headerBlock, "\r\n ", " ")

	m := sentMessage{headers: map[string]string{}, rawHeaders: rawHeaders, raw: data}
	for _, line := range strings.Split(unfolded, "\r\n") {
		name, value, found := strings.Cut(line, ":")
		require.True(t, found, "header line without a colon: %q", line)
		m.headers[name] = strings.TrimPrefix(value, " ")
		m.order = append(m.order, name)
	}

	// The client dot-stuffs, so a body line of "." arrives as "..".
	var body strings.Builder
	for _, line := range strings.SplitAfter(data[separator+4:], "\r\n") {
		body.WriteString(strings.TrimPrefix(line, "."))
	}
	m.body = body.String()

	return m
}

// send runs one message through a plain fake on loopback and returns it taken apart. Everything
// about the message is independent of the encryption mode, so the cheapest mode carries the table.
func send(t *testing.T, fromName string, input *SendEmailInput) sentMessage {
	t.Helper()

	f := &fakeSMTP{ext: []string{"8BITMIME"}}
	port := f.start(t)

	ctx := fakeSettings(t, "127.0.0.1", port, "none", "", "", fromName)
	require.NoError(t, (&EmailSender{}).SendEmail(ctx, input))

	return parseMessage(t, f.data())
}

func TestSendEmail_MessageHeaderOrder(t *testing.T) {

	m := send(t, "Goiabada", &SendEmailInput{
		To:       fixtureRecipient,
		Subject:  "Test email",
		HtmlBody: "<p>hello</p>",
	})

	// go-simple-mail wrote these in Go map order. Pinning the order is what makes the wire
	// reproducible; nothing downstream depended on the old one.
	assert.Equal(t, []string{
		"From",
		"To",
		"Subject",
		"Date",
		"Message-ID",
		"MIME-Version",
		"Content-Type",
		"Content-Transfer-Encoding",
	}, m.order)

	assert.Equal(t, "<"+fixtureRecipient+">", m.headers["To"])
	assert.Equal(t, "1.0", m.headers["MIME-Version"])
	assert.Equal(t, "text/html; charset=UTF-8", m.headers["Content-Type"])
	assert.Equal(t, "quoted-printable", m.headers["Content-Transfer-Encoding"])

	_, err := time.Parse(time.RFC1123Z, m.headers["Date"])
	assert.NoError(t, err, "Date must parse as RFC 1123Z, which is what the old library emitted")
}

// TestSendEmail_FromHeader holds decision 6: a from-name carrying a comma, a quote or angle
// brackets fails every send today, because the name was concatenated into the address unquoted.
func TestSendEmail_FromHeader(t *testing.T) {

	tests := []struct {
		name          string
		fromName      string
		wantEncoded   bool
		wantSubstring string
	}{
		{
			name:     "plain ascii",
			fromName: "Goiabada",
		},
		{
			name:        "non-ascii becomes an encoded-word",
			fromName:    "José Açúcar",
			wantEncoded: true,
		},
		{
			// The name that cannot be sent at all before this change: net/mail quotes it.
			name:          "comma, quotes and angle brackets",
			fromName:      `D'Ippolito, Leo "the" <admin>`,
			wantSubstring: `"`,
		},
		{
			name:     "empty",
			fromName: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m := send(t, test.fromName, &SendEmailInput{
				To:       fixtureRecipient,
				Subject:  "Test email",
				HtmlBody: "<p>hello</p>",
			})

			value := m.headers["From"]
			address, err := mail.ParseAddress(value)
			require.NoError(t, err, "the From header %q does not parse", value)
			assert.Equal(t, test.fromName, address.Name)
			assert.Equal(t, fixtureFromEmail, address.Address)

			if test.wantEncoded {
				assert.Contains(t, strings.ToLower(value), "=?utf-8?")
			}
			if test.wantSubstring != "" {
				assert.Contains(t, value, test.wantSubstring)
			}
		})
	}
}

// TestSendEmail_SubjectHeader holds the encoding and the folding: RFC 2047 encoded-words for
// anything not plain ASCII, and RFC 5322 section 2.1.1's 78-byte SHOULD for the line length,
// which mime.QEncoding does not do on its own.
func TestSendEmail_SubjectHeader(t *testing.T) {

	tests := []struct {
		name        string
		subject     string
		wantLiteral bool
		wantFolded  bool
	}{
		{
			name:        "ascii passes through unchanged",
			subject:     "Test email",
			wantLiteral: true,
		},
		{
			name:    "non-ascii becomes an encoded-word",
			subject: "Verificação de e-mail: código 123456",
		},
		{
			name:       "long non-ascii folds",
			subject:    strings.Repeat("verificação ", 10),
			wantFolded: true,
		},
		{
			// Plain ASCII is returned by the encoder untouched, so it has to fold at its own
			// spaces. The double space is what shows the fold is reversible byte for byte.
			name:       "long ascii with a double space folds",
			subject:    strings.Repeat("subject ", 6) + " " + strings.Repeat("tail ", 5) + "tail",
			wantFolded: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m := send(t, "Goiabada", &SendEmailInput{
				To:       fixtureRecipient,
				Subject:  test.subject,
				HtmlBody: "<p>hello</p>",
			})

			if test.wantLiteral {
				assert.Equal(t, test.subject, m.headers["Subject"])
			}

			decoded, err := new(mime.WordDecoder).DecodeHeader(m.headers["Subject"])
			require.NoError(t, err)
			assert.Equal(t, test.subject, decoded, "unfolding and decoding must return the subject byte for byte")

			for _, line := range m.rawHeaders {
				assert.LessOrEqual(t, len(line), maxHeaderLineBytes,
					"RFC 5322 section 2.1.1: no header line may exceed 78 bytes before the CRLF: %q", line)
			}

			folded := len(m.rawHeaders) > len(m.order)
			assert.Equal(t, test.wantFolded, folded, "raw header lines: %q", m.rawHeaders)
		})
	}
}

// TestSendEmail_MessageID holds decision 5: RFC 5322 section 3.6.4's SHOULD, and that a failed
// entropy read is an error rather than a repeatable `<@domain>`.
func TestSendEmail_MessageID(t *testing.T) {

	pattern := regexp.MustCompile(`^<[0-9a-f]{32}@example\.com>$`)

	t.Run("present and rooted in the from domain", func(t *testing.T) {
		m := send(t, "Goiabada", &SendEmailInput{
			To:       fixtureRecipient,
			Subject:  "Test email",
			HtmlBody: "<p>hello</p>",
		})
		assert.Regexp(t, pattern, m.headers["Message-ID"])
	})

	t.Run("two sends through one sender differ", func(t *testing.T) {
		sender := &EmailSender{}
		seen := make([]string, 0, 2)

		for i := 0; i < 2; i++ {
			f := &fakeSMTP{ext: []string{"8BITMIME"}}
			port := f.start(t)
			ctx := fakeSettings(t, "127.0.0.1", port, "none", "", "", "Goiabada")
			require.NoError(t, sender.SendEmail(ctx, &SendEmailInput{
				To:       fixtureRecipient,
				Subject:  fmt.Sprintf("Test email %d", i),
				HtmlBody: "<p>hello</p>",
			}))
			seen = append(seen, parseMessage(t, f.data()).headers["Message-ID"])
		}

		assert.Regexp(t, pattern, seen[0])
		assert.NotEqual(t, seen[0], seen[1])
	})

	t.Run("a failed entropy read fails the send before any connection", func(t *testing.T) {
		f := &fakeSMTP{ext: []string{"8BITMIME"}}
		port := f.start(t)

		ctx := fakeSettings(t, "127.0.0.1", port, "none", "", "", "Goiabada")
		sender := &EmailSender{randReader: iotest.ErrReader(io.ErrUnexpectedEOF)}

		err := sender.SendEmail(ctx, &SendEmailInput{
			To:       fixtureRecipient,
			Subject:  "Test email",
			HtmlBody: "<p>hello</p>",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unable to generate a Message-ID")
		assert.False(t, f.sawConnection(), "the message is built before the dial, so nothing should have connected")
	})
}

// TestSendEmail_Body holds the quoted-printable part and the dot-stuffing net/smtp performs.
func TestSendEmail_Body(t *testing.T) {

	body := "<p>line with a dot\n.\nat the start</p>"

	m := send(t, "Goiabada", &SendEmailInput{
		To:       fixtureRecipient,
		Subject:  "Test email",
		HtmlBody: body,
	})

	assert.Contains(t, m.raw, "\r\n..\r\n", "RFC 5321 4.5.2: a body line of '.' has to be stuffed on the wire")

	decoded, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(m.body)))
	require.NoError(t, err)
	// The quoted-printable writer turns every LF into a CRLF, which is what a message body has to
	// carry, and net/smtp's dot writer terminates the block with one more so the dot lands on a
	// line of its own.
	assert.Equal(t, strings.ReplaceAll(body, "\n", "\r\n")+"\r\n", string(decoded))
}

// TestSendEmail_HeaderInjection holds that no operator-editable or catalog-sourced value can add a
// header. Neither the encoding nor which of Q or B net/mail picks is pinned: mail.Address.String
// switches to B when the name carries ':' or '@', so only the outcome is asserted.
func TestSendEmail_HeaderInjection(t *testing.T) {

	const attempt = "x\r\nBcc: evil@example.com"

	t.Run("through the subject", func(t *testing.T) {
		m := send(t, "Goiabada", &SendEmailInput{
			To:       fixtureRecipient,
			Subject:  attempt,
			HtmlBody: "<p>hello</p>",
		})

		assertNoInjectedHeader(t, m, m.headers["Subject"])

		decoded, err := new(mime.WordDecoder).DecodeHeader(m.headers["Subject"])
		require.NoError(t, err)
		assert.Equal(t, attempt, decoded)
	})

	t.Run("through the from-name", func(t *testing.T) {
		m := send(t, attempt, &SendEmailInput{
			To:       fixtureRecipient,
			Subject:  "Test email",
			HtmlBody: "<p>hello</p>",
		})

		assertNoInjectedHeader(t, m, m.headers["From"])

		address, err := mail.ParseAddress(m.headers["From"])
		require.NoError(t, err)
		assert.Equal(t, attempt, address.Name)
		assert.Equal(t, fixtureFromEmail, address.Address)
	})
}

func assertNoInjectedHeader(t *testing.T, m sentMessage, value string) {
	t.Helper()

	assert.NotContains(t, m.order, "Bcc")
	assert.NotContains(t, value, "\r")
	assert.NotContains(t, value, "\n")
	for _, line := range m.rawHeaders {
		assert.False(t, strings.HasPrefix(line, "Bcc:"), "an injected header reached the wire: %q", line)
	}
}

func TestSendEmail_InvalidRecipient(t *testing.T) {

	f := &fakeSMTP{ext: []string{"8BITMIME"}}
	port := f.start(t)

	ctx := fakeSettings(t, "127.0.0.1", port, "none", "", "", "Goiabada")

	err := (&EmailSender{}).SendEmail(ctx, &SendEmailInput{
		To:       "not an address",
		Subject:  "Test email",
		HtmlBody: "<p>hello</p>",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid recipient address")
	assert.False(t, f.sawConnection(), "the address is parsed before the dial, so nothing should have connected")
}

// TestSendEmail_ConversationTimeout holds decision 7: one deadline covers EHLO through QUIT, so a
// relay that stops answering cannot hang the request that is sending the mail.
func TestSendEmail_ConversationTimeout(t *testing.T) {

	f := &fakeSMTP{ext: []string{"8BITMIME"}, stallAfterData: true}
	port := f.start(t)

	ctx := fakeSettings(t, "127.0.0.1", port, "none", "", "", "Goiabada")
	sender := &EmailSender{convTimeout: time.Second}

	started := time.Now()
	err := sender.SendEmail(ctx, &SendEmailInput{
		To:       fixtureRecipient,
		Subject:  "Test email",
		HtmlBody: "<p>hello</p>",
	})
	elapsed := time.Since(started)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to send SMTP message")
	assert.Less(t, elapsed, 2*time.Second, "the deadline was one second, so the send must not outlive it")
}
