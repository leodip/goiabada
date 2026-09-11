package data

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBootstrapEnvContent_CarriesNoClientId pins the whole point of #285 on the one artifact that
// hands an operator their configuration: the admin console's client id is not configurable, so the
// bootstrap file must not offer it as something to copy. Nothing else reaches this file, which is
// built inside Seed and would otherwise need a live database to observe.
func TestBootstrapEnvContent_CarriesNoClientId(t *testing.T) {
	content := bootstrapEnvContent("the-secret", "aaaa", "bbbb", "cccc", "dddd")

	assert.NotContains(t, content, "GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_ID",
		"the bootstrap file must not name a variable the admin console no longer reads")
	assert.NotContains(t, content, "admin-console-client",
		"nor the value under any other name")
}

// TestBootstrapEnvContent_CarriesEveryRemainingCredential is the other half: removing the client id
// must not have taken a neighbour with it. Each remaining variable is asserted with its value, so a
// line that survives with the wrong argument bound to it fails here rather than at an operator's
// first restart.
func TestBootstrapEnvContent_CarriesEveryRemainingCredential(t *testing.T) {
	content := bootstrapEnvContent("the-secret", "auth-key", "enc-key", "ac-auth-key", "ac-enc-key")

	expected := []string{
		"GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET=the-secret",
		"GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY=auth-key",
		"GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY=enc-key",
		"GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY=ac-auth-key",
		"GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY=ac-enc-key",
	}
	for _, line := range expected {
		assert.Contains(t, content, line)
	}

	// Five assignments and no sixth: an added variable has to be considered here rather than
	// arriving silently, since this file is copied by hand into a deployment.
	assignments := 0
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, "GOIABADA_") {
			assignments++
		}
	}
	assert.Equal(t, len(expected), assignments)
}

// TestLogBootstrapCredentialsGenerated_IsOneRecordNamingTheFile pins the console half of the same
// artifact: the record is the only place an operator is told the bootstrap file exists, and it is
// where the twelve-line banner went (#320 decision 6). Its own function for the same reason
// bootstrapEnvContent is one, since the block it came from sits inside Seed and needs a live
// database to reach.
func TestLogBootstrapCredentialsGenerated_IsOneRecordNamingTheFile(t *testing.T) {
	logs := testutil.CaptureSlog(t)

	logBootstrapCredentialsGenerated("/bootstrap/bootstrap.env")

	records := logs.Records()
	require.Len(t, records, 1, "one record, where the banner wrote twelve")
	assert.Equal(t, slog.LevelInfo, records[0].Level,
		"the seeder succeeded; this is the result, not a failure")
	assert.Equal(t, "/bootstrap/bootstrap.env", records[0].Attrs["bootstrap_file"],
		"the operator's next action is to open this file, so its path is the one thing the record must carry")
	assert.Equal(t, "0600", records[0].Attrs["file_mode"],
		"and that the file is readable by its owner alone, which is why leaving it in place is survivable")
	assert.Contains(t, records[0].Message, "copy",
		"the message has to say what to do with the file, or the path alone is an announcement")
}
