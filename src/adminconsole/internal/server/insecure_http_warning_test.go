package server

import (
	"log/slog"
	"testing"

	"github.com/leodip/goiabada/core/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The admin console's copy of the HTTP-without-TLS warning, collapsed from eleven records to one
// (#320 decision 6). The two servers keep separate copies because each record names the server it
// is about and neither module imports the other, so each owes its own case: a copy that named the
// auth server here would send an operator to the wrong service's configuration.
func TestLogHttpWithoutTlsWarning_IsOneWarnNamingTheServerAndTheRemedy(t *testing.T) {
	logs := testutil.CaptureSlog(t)

	logHttpWithoutTlsWarning()

	records := logs.Records()
	require.Len(t, records, 1, "one record for one condition, where the banner wrote eleven")

	assert.Equal(t, slog.LevelWarn, records[0].Level,
		"a condition met and accepted, not a failure: the console starts and serves")
	assert.Contains(t, records[0].Message, "admin console",
		"this record must name the admin console, not the auth server it was copied from")
	assert.Contains(t, records[0].Message, "HTTP")
	assert.Contains(t, records[0].Attrs["remedy"], "HTTPS",
		"the remedy is the reader's next action, so it is an attribute rather than eight lines of prose")
}
