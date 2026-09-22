package data

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
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

	logBootstrapCredentialsGenerated(context.Background(), "/bootstrap/bootstrap.env")

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

// TestCheckAdminPasswordLength_CountsBytes holds the seeder to bcrypt's bound on either side of
// it, and in the unit bcrypt uses: 37 accented characters are 74 bytes, far fewer than 72
// characters, and are refused. Every refusal names the variable to change and both numbers, since
// an operator reading it has only the startup log to go on (#409).
func TestCheckAdminPasswordLength_CountsBytes(t *testing.T) {
	assert.NoError(t, checkAdminPasswordLength(strings.Repeat("a", passwordhash.MaxPasswordBytes)))
	assert.NoError(t, checkAdminPasswordLength(strings.Repeat("é", passwordhash.MaxPasswordBytes/2)))

	cases := []struct {
		name     string
		password string
		length   string
	}{
		{"one ASCII byte over", strings.Repeat("a", passwordhash.MaxPasswordBytes+1), "73 bytes"},
		{"37 two-byte characters", strings.Repeat("é", 37), "74 bytes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkAdminPasswordLength(tc.password)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "GOIABADA_ADMIN_PASSWORD")
			assert.Contains(t, err.Error(), tc.length)
			assert.Contains(t, err.Error(), "at most 72 bytes")
			assert.Contains(t, err.Error(), "non-ASCII")
		})
	}
}

// TestSeed_RefusesAnOverlongAdminPasswordBeforeAnyWrite drives Seed itself over a mock holding no
// expectations, so any write it reached would panic the test. Before #409 this password was
// hashed with the error discarded, after the first insert, and stored as an empty hash.
func TestSeed_RefusesAnOverlongAdminPasswordBeforeAnyWrite(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	seeder := NewDatabaseSeeder(database, "admin@example.com",
		strings.Repeat("a", passwordhash.MaxPasswordBytes+1), "Goiabada",
		"https://auth.example.com", "https://admin.example.com")

	err := seeder.Seed(context.Background())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "GOIABADA_ADMIN_PASSWORD")
	database.AssertExpectations(t)
}
