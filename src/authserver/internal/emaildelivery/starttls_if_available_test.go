package emaildelivery

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The rows below hold #718 decision 14: the `none` mode, STARTTLS if available, upgrades through
// STARTTLS when the relay offers it, with the certificate and host name verified as the STARTTLS
// mode verifies them, and otherwise sends in plaintext. A refused STARTTLS command carries on over
// the same connection; a STARTTLS command with no usable reply, or a handshake or certificate check
// that fails, reconnects once and sends without trying STARTTLS, within the send's budget. Every
// plaintext send writes one Info record with its reason (RFC 8314 section 5.2's "most secure means
// available").

// sentUnencrypted is the Info record a plaintext send under STARTTLS if available writes, as an
// operator searches for it.
const sentUnencrypted = "sending the email unencrypted"

// The reasons that record gives, under `reason`.
const (
	reasonSTARTTLSNotOffered = "starttls_not_offered"
	reasonSTARTTLSRefused    = "starttls_refused"
	reasonSTARTTLSFailed     = "starttls_failed"
	reasonTLSFailed          = "tls_failed"
)

// greetingsOf is every EHLO and HELO line in lines, in order.
func greetingsOf(lines []string) []string {
	var out []string
	for _, l := range lines {
		up := strings.ToUpper(l)
		if strings.HasPrefix(up, "EHLO") || strings.HasPrefix(up, "HELO") {
			out = append(out, l)
		}
	}
	return out
}

// hasPrefixIn reports whether any of lines starts with prefix, ignoring case.
func hasPrefixIn(lines []string, prefix string) bool {
	for _, l := range lines {
		if strings.HasPrefix(strings.ToUpper(l), strings.ToUpper(prefix)) {
			return true
		}
	}
	return false
}

func TestSendEmail_STARTTLSIfAvailable(t *testing.T) {

	cert := newFakeCert(t)
	// Generated the same way and never presented by the fake, so a chain built against it cannot
	// verify.
	untrusted := newFakeCert(t)

	type row struct {
		name           string
		host           string
		ext            []string
		tlsExt         []string
		refuseSTARTTLS bool
		garbleSTARTTLS bool
		// breakHow, when breakSTARTTLS is set, is how the first connection breaks at STARTTLS.
		breakSTARTTLS  bool
		breakHow       connectionBreak
		commandTimeout time.Duration
		trusted        bool

		wantEncrypted   bool
		wantConnections int
		// wantReason is the reason of the one Info record a plaintext send writes; empty, none.
		wantReason string
		// wantErrorIn is text the Info record's error carries; empty, any text.
		wantErrorIn string
	}
	tests := []row{
		{
			name:            "STARTTLS offered with a trusted certificate: upgraded",
			host:            "127.0.0.1",
			ext:             []string{"STARTTLS", "8BITMIME"},
			tlsExt:          []string{"8BITMIME"},
			trusted:         true,
			wantEncrypted:   true,
			wantConnections: 1,
		},
		{
			name:            "STARTTLS not offered: plaintext",
			host:            "127.0.0.1",
			ext:             []string{"8BITMIME"},
			trusted:         true,
			wantConnections: 1,
			wantReason:      reasonSTARTTLSNotOffered,
		},
		{
			name:            "STARTTLS refused: plaintext on the same connection",
			host:            "127.0.0.1",
			ext:             []string{"STARTTLS", "8BITMIME"},
			tlsExt:          []string{"8BITMIME"},
			refuseSTARTTLS:  true,
			trusted:         true,
			wantConnections: 1,
			wantReason:      reasonSTARTTLSRefused,
			wantErrorIn:     "454",
		},
		{
			name:            "a certificate from an unknown authority: plaintext over a second connection",
			host:            "127.0.0.1",
			ext:             []string{"STARTTLS", "8BITMIME"},
			tlsExt:          []string{"8BITMIME"},
			wantConnections: 2,
			wantReason:      reasonTLSFailed,
			wantErrorIn:     "unknown authority",
		},
		{
			// The certificate deliberately does not carry "localhost", so the chain verifies and
			// the name does not: the upgrade checks the host name as well as the chain.
			name:            "a certificate naming another host: plaintext over a second connection",
			host:            "localhost",
			ext:             []string{"STARTTLS", "8BITMIME"},
			tlsExt:          []string{"8BITMIME"},
			trusted:         true,
			wantConnections: 2,
			wantReason:      reasonTLSFailed,
			wantErrorIn:     "localhost",
		},
		{
			name:            "STARTTLS answered with no reply code: plaintext over a second connection",
			host:            "127.0.0.1",
			ext:             []string{"STARTTLS", "8BITMIME"},
			tlsExt:          []string{"8BITMIME"},
			garbleSTARTTLS:  true,
			trusted:         true,
			wantConnections: 2,
			wantReason:      reasonSTARTTLSFailed,
			wantErrorIn:     "short response",
		},
	}
	// A STARTTLS command whose connection breaks before any reply leaves nothing more to say over
	// it, so the send reconnects, as for a failed handshake. A reset reads as a reset or as an EOF,
	// depending on when it arrives, so its row names no text.
	breakErrorIn := map[connectionBreak]string{breakClose: "EOF", breakStall: "i/o timeout"}
	for _, brk := range connectionBreaks {
		tests = append(tests, row{
			name:            "a connection " + brk.name + " at STARTTLS: plaintext over a second connection",
			host:            "127.0.0.1",
			ext:             []string{"STARTTLS", "8BITMIME"},
			tlsExt:          []string{"8BITMIME"},
			breakSTARTTLS:   true,
			breakHow:        brk.how,
			commandTimeout:  brk.deadline,
			trusted:         true,
			wantConnections: 2,
			wantReason:      reasonSTARTTLSFailed,
			wantErrorIn:     breakErrorIn[brk.how],
		})
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture := logtest.CaptureSlog(t)

			f := &fakeSMTP{ext: test.ext, tlsExt: test.tlsExt, refuseSTARTTLS: test.refuseSTARTTLS, garbleSTARTTLS: test.garbleSTARTTLS, cert: cert}
			if test.breakSTARTTLS {
				f.breakOn, f.breakHow = "STARTTLS", test.breakHow
			}
			port := f.start(t)

			pool := untrusted.pool
			if test.trusted {
				pool = cert.pool
			}
			sender := &Sender{dataCipher: testDataCipher, rootCAs: pool, commandTimeout: test.commandTimeout}

			result, err := sendReporting(t, sender, relayConfig(t, test.host, port, "none", "", "", "Goiabada"))
			require.NoError(t, err, "STARTTLS if available sends whether or not TLS held")
			assert.Equal(t, SendResult{Encrypted: test.wantEncrypted}, result)
			assert.Contains(t, f.data(), "Subject: Test email\r\n", "the message reached the relay")

			sessions := f.connectionLines()
			require.Len(t, sessions, test.wantConnections)
			first, last := sessions[0], sessions[len(sessions)-1]

			if extensionOffered(test.ext, "STARTTLS") {
				assert.True(t, hasPrefixIn(first, "STARTTLS"), "an offered STARTTLS is tried")
			} else {
				assert.False(t, hasPrefixIn(first, "STARTTLS"), "STARTTLS is not sent to a relay that does not offer it")
			}
			if test.wantConnections == 2 {
				assert.False(t, hasPrefixIn(first, "MAIL FROM:"), "nothing of the message crosses the connection whose TLS failed")
				assert.False(t, hasPrefixIn(last, "STARTTLS"), "the reconnect does not try STARTTLS again")
				assert.Len(t, greetingsOf(last), 1, "the reconnect introduces itself once, in plaintext")
			}
			assert.True(t, hasPrefixIn(last, "MAIL FROM:"))

			infos := recordsAt(capture, slog.LevelInfo)
			if test.wantReason == "" {
				assert.Empty(t, infos, "an upgraded send writes no record")
				return
			}
			require.Len(t, infos, 1, "one Info record per plaintext send")
			assert.Equal(t, sentUnencrypted, infos[0].Message)
			assert.Equal(t, test.wantReason, infos[0].Attrs["reason"])
			if test.wantReason == reasonSTARTTLSNotOffered {
				assert.NotContains(t, infos[0].Attrs, "error", "a relay offering no STARTTLS has no error to give")
				return
			}
			logged, ok := infos[0].Attrs["error"].(error)
			require.True(t, ok, "the reason's error rides under error")
			assert.Contains(t, logged.Error(), test.wantErrorIn)
		})
	}
}

// A STARTTLS handshake the relay never answers is a failed handshake too: the read waiting on it
// ends at the per-command limit, and the send reconnects and delivers in plaintext, all within the
// send's budget.
func TestSendEmail_AStalledSTARTTLSHandshakeFallsBackWithinTheBudget(t *testing.T) {
	capture := logtest.CaptureSlog(t)

	f := &fakeSMTP{ext: []string{"STARTTLS", "8BITMIME"}, tlsExt: []string{"8BITMIME"}, stallHandshake: true}
	port := f.start(t)

	sender := &Sender{dataCipher: testDataCipher, rootCAs: f.cert.pool, commandTimeout: 300 * time.Millisecond, sendTimeout: 3 * time.Second}

	started := time.Now()
	result, err := sendReporting(t, sender, relayConfig(t, "127.0.0.1", port, "none", "", "", "Goiabada"))
	elapsed := time.Since(started)

	require.NoError(t, err)
	assert.Equal(t, SendResult{Encrypted: false}, result)
	assert.Equal(t, 2, f.connections(), "the stalled connection is given up on and a second one made")
	assert.NotEmpty(t, f.data(), "the message went over the second connection")
	assert.GreaterOrEqual(t, elapsed, sender.commandTimeout, "the handshake was given up on before its deadline")
	assert.Less(t, elapsed, sender.sendTimeout, "the fallback ran past the send's budget")

	infos := recordsAt(capture, slog.LevelInfo)
	require.Len(t, infos, 1)
	assert.Equal(t, reasonTLSFailed, infos[0].Attrs["reason"])
}

// stalledUpgrades are the two places STARTTLS if available's upgrade can stall, each falling back
// the same way: the STARTTLS command's reply, and the handshake after it.
var stalledUpgrades = []struct {
	name string
	fake func() *fakeSMTP
}{
	{"STARTTLS command", func() *fakeSMTP {
		return &fakeSMTP{ext: []string{"STARTTLS", "8BITMIME"}, tlsExt: []string{"8BITMIME"}, breakOn: "STARTTLS", breakHow: breakStall}
	}},
	{"handshake", func() *fakeSMTP {
		return &fakeSMTP{ext: []string{"STARTTLS", "8BITMIME"}, tlsExt: []string{"8BITMIME"}, stallHandshake: true}
	}},
}

// The reconnect has no budget of its own: it runs within the send's, which runs from the first
// connect. An upgrade that stalls until the budget is spent leaves nothing for a second connection,
// so the send fails as timed out without making one.
func TestSendEmail_AFallbackReconnectHasNoBudgetOfItsOwn(t *testing.T) {
	for _, stall := range stalledUpgrades {
		t.Run(stall.name, func(t *testing.T) {
			f := stall.fake()
			port := f.start(t)

			sender := &Sender{dataCipher: testDataCipher, rootCAs: f.cert.pool, commandTimeout: 300 * time.Millisecond, sendTimeout: 300 * time.Millisecond}

			started := time.Now()
			err := sendTo(t, sender, relayConfig(t, "127.0.0.1", port, "none", "", "", "Goiabada"))
			elapsed := time.Since(started)

			require.Error(t, err)
			assertSendFailure(t, err, SendFailureConnection)
			assert.Equal(t, ConnectionCauseTimedOut, ClassifyConnectionError(err))
			assert.Equal(t, 1, f.connections(), "a spent budget makes no second connection")
			assert.Empty(t, f.data())
			assert.GreaterOrEqual(t, elapsed, sender.sendTimeout, "the send ended before its budget")
			assert.Less(t, elapsed, 3*sender.sendTimeout, "the send ran well past its budget")
		})
	}
}

// A caller who gives up during the upgrade ends the send there: there is no reconnect, and no
// record of a plaintext send that never happened.
func TestSendEmail_ACancelledCallerIsNotFallenBackFor(t *testing.T) {
	for _, stall := range stalledUpgrades {
		t.Run(stall.name, func(t *testing.T) {
			capture := logtest.CaptureSlog(t)

			f := stall.fake()
			port := f.start(t)

			sender := &Sender{dataCipher: testDataCipher, rootCAs: f.cert.pool, commandTimeout: 5 * time.Second, sendTimeout: 5 * time.Second}
			const cancelAfter = 200 * time.Millisecond

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			time.AfterFunc(cancelAfter, cancel)

			started := time.Now()
			_, err := sender.SendEmail(ctx, relayConfig(t, "127.0.0.1", port, "none", "", "", "Goiabada"), &SendEmailInput{
				To:       fixtureRecipient,
				Subject:  "Test email",
				HtmlBody: "<p>hello</p>",
			})
			elapsed := time.Since(started)

			require.Error(t, err)
			require.ErrorIs(t, err, context.Canceled, "the caller's cancellation is not on the chain")
			assert.Equal(t, 1, f.connections(), "a cancelled send makes no second connection")
			assert.Empty(t, f.data())
			assert.Less(t, elapsed, sender.commandTimeout, "a deadline ended the send, not the caller")
			assert.Empty(t, recordsAt(capture, slog.LevelInfo), "nothing was sent unencrypted")
		})
	}
}
