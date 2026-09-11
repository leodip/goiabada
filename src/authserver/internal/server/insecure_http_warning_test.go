package server

import (
	"log/slog"
	"testing"

	"github.com/leodip/goiabada/core/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The HTTP-without-TLS warning, one of the banner blocks #320 decision 6 collapsed.
//
// Eleven Warn records became one, and the collapse is what this pins: eleven meant eleven
// timestamps and eleven level markers for one condition, a ruled box and two blank lines that no
// JSON collector can read, and a reader who greps for the warning finding a fragment of it.
//
// The condition that reaches it is Start's, and is not under test here: Start binds listeners and
// blocks. What is under test is the record an operator reads when it fires.
func TestLogHttpWithoutTlsWarning_IsOneWarnNamingTheServerAndTheRemedy(t *testing.T) {
	logs := testutil.CaptureSlog(t)

	logHttpWithoutTlsWarning()

	records := logs.Records()
	require.Len(t, records, 1, "one record for one condition, where the banner wrote eleven")

	assert.Equal(t, slog.LevelWarn, records[0].Level,
		"a condition met and accepted, not a failure: the server starts and serves")
	assert.Contains(t, records[0].Message, "auth server",
		"an operator running both servers has to be able to tell which one this is about")
	assert.Contains(t, records[0].Message, "HTTP",
		"and what the condition is, since the message is what gets grepped for")
	assert.Contains(t, records[0].Attrs["remedy"], "HTTPS",
		"the remedy is the reader's next action, so it is an attribute rather than eight lines of prose")
}
