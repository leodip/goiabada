package server

import (
	"log/slog"
	"testing"

	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The admin console's copy of the HTTP-without-TLS warning, collapsed from eleven records to one
// (#320 decision 6). The two servers keep separate copies because each record names the server it
// is about and neither module imports the other, so each owes its own case: a copy that named the
// auth server here would send an operator to the wrong service's configuration.
func TestLogPlainHTTP_IsOneWarnNamingTheServerAndTheRemedy(t *testing.T) {
	logs := logtest.CaptureSlog(t)

	logPlainHTTP("http://localhost:9090", false)

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

// Behind a proxy that says it ends TLS, an https base URL with the forwarded headers trusted, as the
// setup wizard writes for every proxy, plain HTTP is the deployment working as intended: one Info
// record and no remedy, where a Warn greeted every healthy install (#542). Either half alone is no
// such statement, and keeps the Warn.
func TestLogPlainHTTP_IsInfoBehindAProxyThatEndsTLS(t *testing.T) {
	for _, tc := range []struct {
		baseURL string
		trusted bool
		level   slog.Level
	}{
		{"https://auth.example.com", true, slog.LevelInfo},
		{"HTTPS://auth.example.com", true, slog.LevelInfo},
		{"https://auth.example.com", false, slog.LevelWarn},
		{"http://auth.example.com", true, slog.LevelWarn},
	} {
		logs := logtest.CaptureSlog(t)
		logPlainHTTP(tc.baseURL, tc.trusted)
		records := logs.Records()
		require.Len(t, records, 1, "%s, trusted %v", tc.baseURL, tc.trusted)
		assert.Equal(t, tc.level, records[0].Level, "%s, trusted %v", tc.baseURL, tc.trusted)
		assert.Contains(t, records[0].Message, "admin console")
		if tc.level == slog.LevelInfo {
			assert.NotContains(t, records[0].Attrs, "remedy", "nothing is wrong, so there is nothing to remedy")
		}
	}
}
