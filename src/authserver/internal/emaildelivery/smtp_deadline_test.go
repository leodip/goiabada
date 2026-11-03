package emaildelivery

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The rows below hold #718 decision 7: 10 seconds to connect, then a fresh 20-second deadline for
// every read and every write, never later than 40 seconds from the start of the connect, and a
// caller whose context ends closing the connection. Each sets the sender's duration seams short and
// asserts both bounds, so none waits the real 20 or 40 seconds.

// dribble is the fake's pause before each reply line in the rows that make steady progress. The
// limits those rows set are several of it, so a slow machine cannot turn one pause into a timeout.
const dribble = 50 * time.Millisecond

// paddedExtensions is an EHLO extension list of n lines, so the EHLO reply is n+1 lines long and,
// dribbled, takes n+1 pauses to arrive.
func paddedExtensions(n int) []string {
	ext := []string{"8BITMIME"}
	for i := 1; i < n; i++ {
		ext = append(ext, "X-PAD-"+strconv.Itoa(i))
	}
	return ext
}

// dribbledReplyLines is how many reply lines a plain send through a fake offering paddedExtensions(12)
// waits for: the greeting, the 13-line EHLO reply, then one line each for MAIL, RCPT, DATA, the end
// of the data and QUIT.
const dribbledReplyLines = 1 + 13 + 5

func TestSendEmail_DeadlineDefaults(t *testing.T) {
	assert.Equal(t, 10*time.Second, defaultDialTimeout, "decision 7: ten seconds to connect")
	assert.Equal(t, 20*time.Second, defaultCommandTimeout, "decision 7: twenty seconds for each read or write")
	assert.Equal(t, 40*time.Second, defaultSendTimeout, "decision 7: forty seconds in all")
}

// A relay that stops answering ends the send at the per-command limit, long before the send's
// budget: the reply to the end of the data never comes.
func TestSendEmail_AStalledReplyEndsAtTheCommandLimit(t *testing.T) {

	f := &fakeSMTP{ext: []string{"8BITMIME"}, stallAfterData: true}
	port := f.start(t)

	sender := &Sender{dataCipher: testDataCipher, commandTimeout: 300 * time.Millisecond, sendTimeout: 3 * time.Second}

	started := time.Now()
	err := sendTo(t, sender, relayConfig(t, "127.0.0.1", port, "none", "", "", "Goiabada"))
	elapsed := time.Since(started)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to send SMTP message")
	assertSendFailure(t, err, SendFailureConnection)
	assert.Equal(t, ConnectionCauseTimedOut, ClassifyConnectionError(err))
	assert.GreaterOrEqual(t, elapsed, sender.commandTimeout, "the send ended before the reply's deadline")
	assert.Less(t, elapsed, sender.sendTimeout, "the send's budget ended it, not the per-command limit")
}

// A write the relay stops taking ends at the per-command limit too: the relay answers DATA and
// then reads nothing, so the body fills the socket buffers and the write blocks.
func TestSendEmail_AStalledWriteEndsAtTheCommandLimit(t *testing.T) {

	f := &fakeSMTP{ext: []string{"8BITMIME"}, stopReadingAtData: true}
	port := f.start(t)

	sender := &Sender{dataCipher: testDataCipher, commandTimeout: 300 * time.Millisecond, sendTimeout: 3 * time.Second}

	started := time.Now()
	err := sender.SendEmail(context.Background(), relayConfig(t, "127.0.0.1", port, "none", "", "", "Goiabada"), &SendEmailInput{
		To:      fixtureRecipient,
		Subject: "Test email",
		// About 20 MB, several times what the socket buffers between the two ends can hold: the dev
		// container's send buffer grows to at most 4 MiB, and the fake's receive buffer is minimal.
		HtmlBody: strings.Repeat("<p>hello, this line pads the body!</p>\n", 1<<19),
	})
	elapsed := time.Since(started)

	require.Error(t, err)
	var opErr *net.OpError
	require.ErrorAs(t, err, &opErr)
	assert.Equal(t, "write", opErr.Op, "the body never filled the buffers, so no write stalled: %v", err)
	assertSendFailure(t, err, SendFailureConnection)
	assert.Equal(t, ConnectionCauseTimedOut, ClassifyConnectionError(err))
	assert.GreaterOrEqual(t, elapsed, sender.commandTimeout, "the send ended before the write's deadline")
	assert.Less(t, elapsed, sender.sendTimeout, "the send's budget ended it, not the per-command limit")
}

// A relay that is slow but keeps making progress is not cut off by the per-command limit, which
// each read renews: the EHLO reply alone takes longer than the limit, line by line.
func TestSendEmail_SteadyProgressIsNotCutByTheCommandLimit(t *testing.T) {

	f := &fakeSMTP{ext: paddedExtensions(12), dribble: dribble}
	port := f.start(t)

	sender := &Sender{dataCipher: testDataCipher, commandTimeout: 8 * dribble, sendTimeout: time.Minute}
	require.Greater(t, 13*dribble, sender.commandTimeout, "the EHLO reply must outlast the limit for this row to hold anything")

	started := time.Now()
	err := sendTo(t, sender, relayConfig(t, "127.0.0.1", port, "none", "", "", "Goiabada"))
	elapsed := time.Since(started)

	require.NoError(t, err)
	assert.Contains(t, f.data(), "Subject: Test email", "the message was delivered")
	assert.GreaterOrEqual(t, elapsed, dribbledReplyLines*dribble, "the fake did not dribble its replies")
}

// The send's budget ends a send that keeps making progress: the dribbled conversation needs more
// time than the budget allows, and no single read comes near the per-command limit.
func TestSendEmail_TheSendBudgetEndsASteadySend(t *testing.T) {

	f := &fakeSMTP{ext: paddedExtensions(12), dribble: dribble}
	port := f.start(t)

	sender := &Sender{dataCipher: testDataCipher, commandTimeout: time.Minute, sendTimeout: 10 * dribble}
	require.Less(t, sender.sendTimeout, dribbledReplyLines*dribble, "the conversation must outlast the budget for this row to hold anything")

	started := time.Now()
	err := sendTo(t, sender, relayConfig(t, "127.0.0.1", port, "none", "", "", "Goiabada"))
	elapsed := time.Since(started)

	require.Error(t, err)
	assertSendFailure(t, err, SendFailureConnection)
	assert.Equal(t, ConnectionCauseTimedOut, ClassifyConnectionError(err))
	assert.GreaterOrEqual(t, elapsed, sender.sendTimeout, "the send ended before its budget")
	assert.Less(t, elapsed, dribbledReplyLines*dribble, "the send ran past its budget")
	assert.Empty(t, f.data(), "the budget ran out during EHLO, before any data")
}

// The budget runs from the start of the connect, so time spent in the implicit-TLS handshake counts
// against it. The handshake takes 20 pauses and the conversation after it 19, under a budget of 30:
// a budget started after the handshake would let the send finish.
func TestSendEmail_TheSendBudgetRunsFromTheConnect(t *testing.T) {

	cert := newFakeCert(t)
	f := &fakeSMTP{
		tlsFromStart:   true,
		tlsExt:         paddedExtensions(12),
		cert:           cert,
		dribble:        dribble,
		handshakeDelay: 20 * dribble,
	}
	port := f.start(t)

	sender := &Sender{dataCipher: testDataCipher, rootCAs: cert.pool, commandTimeout: time.Minute, sendTimeout: 30 * dribble}
	require.Less(t, sender.sendTimeout, f.handshakeDelay+dribbledReplyLines*dribble)
	require.Greater(t, sender.sendTimeout, dribbledReplyLines*dribble)

	started := time.Now()
	err := sendTo(t, sender, relayConfig(t, "127.0.0.1", port, "ssltls", "", "", "Goiabada"))
	elapsed := time.Since(started)

	require.Error(t, err, "the budget started after the handshake")
	assertSendFailure(t, err, SendFailureConnection)
	assert.Equal(t, ConnectionCauseTimedOut, ClassifyConnectionError(err))
	assert.GreaterOrEqual(t, elapsed, sender.sendTimeout, "the send ended before its budget")
	assert.Less(t, elapsed, f.handshakeDelay+dribbledReplyLines*dribble, "the send ran past its budget")
}

// A caller whose context ends closes the connection, so a send to a relay that has stopped answering
// ends then rather than at either limit, and the caller's reason is on the chain.
func TestSendEmail_ACancelledCallerEndsTheSend(t *testing.T) {

	f := &fakeSMTP{ext: []string{"8BITMIME"}, stallAfterData: true}
	port := f.start(t)

	sender := &Sender{dataCipher: testDataCipher, commandTimeout: 5 * time.Second, sendTimeout: 5 * time.Second}
	const cancelAfter = 200 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	time.AfterFunc(cancelAfter, cancel)

	started := time.Now()
	err := sender.SendEmail(ctx, relayConfig(t, "127.0.0.1", port, "none", "", "", "Goiabada"), &SendEmailInput{
		To:       fixtureRecipient,
		Subject:  "Test email",
		HtmlBody: "<p>hello</p>",
	})
	elapsed := time.Since(started)

	require.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled), "the caller's cancellation is not on the chain: %v", err)
	assertSendFailure(t, err, SendFailureConnection)
	assert.NotEmpty(t, f.data(), "the cancellation came while waiting for the reply to the data")
	assert.GreaterOrEqual(t, elapsed, cancelAfter, "the send ended before its caller gave up")
	assert.Less(t, elapsed, sender.commandTimeout, "a deadline ended the send, not the caller")
}
