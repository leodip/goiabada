package bootstrap

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The three bootstrap banner blocks of the auth server's main, collapsed to one record each (#320
// decision 6), and moved here with the mode choice that writes them (#424).
//
// These are the records an operator reads when the server will not start, and two of them are the
// only place they are told which environment variables to set. The block they came from listed
// those names in hand-typed prose, twice, so the list is now one package-level value and the
// cases below assert that both records carry all of it: a credential added to the bootstrap file
// and to one list only would leave an operator following the other one with a startup failure
// naming a variable they were never told about.

func TestLogBootstrapComplete_NamesTheFileAndEveryRequiredVariable(t *testing.T) {
	logs := testutil.CaptureSlog(t)

	logBootstrapComplete(context.Background(), "/bootstrap/bootstrap.env")

	records := logs.Records()
	require.Len(t, records, 1, "one record, where the banner wrote twenty-two")

	assert.Equal(t, slog.LevelInfo, records[0].Level,
		"the bootstrap succeeded and the exit is the documented end of it, not a failure")
	assert.Equal(t, "/bootstrap/bootstrap.env", records[0].Attrs["bootstrap_file"])
	assert.Equal(t, bootstrapCredentialVars, records[0].Attrs["required"],
		"every variable the operator has to carry over, or they restart into the next failure")
	assert.Contains(t, records[0].Message, "restart",
		"the message has to say what to do next: the process is exiting and nothing else will tell them")
}

func TestLogCredentialsNotConfigured_CarriesTheErrorTheFileAndEveryRequiredVariable(t *testing.T) {
	logs := testutil.CaptureSlog(t)

	LogCredentialsNotConfigured(context.Background(), errs.New("session key is not 64 bytes"), "/somewhere/else.env")

	records := logs.Records()
	require.Len(t, records, 1, "one record, where the banner wrote twenty-one")

	assert.Equal(t, slog.LevelError, records[0].Level,
		"the server cannot start and somebody has to act, which is exactly what Error means")
	require.Implements(t, (*error)(nil), records[0].Attrs["error"],
		"the validation failure goes in as the error itself, so its stack reaches the log under both formats")
	assert.Contains(t, records[0].Attrs["error"].(error).Error(), "64 bytes",
		"and says which key was wrong")
	assert.Equal(t, "/somewhere/else.env", records[0].Attrs["bootstrap_file"],
		"read from the configuration: the banner printed ./bootstrap/bootstrap.env, which is the shipped compose files' path rather than this deployment's")
	assert.Equal(t, bootstrapCredentialVars, records[0].Attrs["required"],
		"the same five names as the bootstrap-complete record, from the same list, so the two cannot disagree")
}

func TestLogInitialSetupRequired_OffersBothBootstrapModes(t *testing.T) {
	logs := testutil.CaptureSlog(t)

	logInitialSetupRequired(context.Background())

	records := logs.Records()
	require.Len(t, records, 1, "one record, where the banner wrote fourteen")

	assert.Equal(t, slog.LevelError, records[0].Level,
		"the server cannot start and somebody has to act")

	options, ok := records[0].Attrs["options"].([]string)
	require.True(t, ok, "the two ways out are a list, not a paragraph")
	require.Len(t, options, 2, "both modes: the setup tool and the two-step bootstrap")
	assert.Contains(t, options[0], "goiabada-setup",
		"the recommended route first, since it is one step")
	assert.Contains(t, options[1], "GOIABADA_AUTHSERVER_BOOTSTRAP_ENV_OUTFILE",
		"and the legacy route naming the variable that selects it, which is the whole action")
}

// The five names are asserted as a set here rather than inside the two records above, so that
// adding a credential to the bootstrap file without adding it to this list fails on its own case
// rather than as a confusing diff on two others.
func TestBootstrapCredentialVars_CoverBothServices(t *testing.T) {
	assert.Equal(t, []string{
		"GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET",
		"GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY",
		"GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY",
		"GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY",
		"GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY",
	}, bootstrapCredentialVars,
		"the three the admin console needs and the two the auth server needs: the bootstrap file writes exactly these")

	content := bootstrapEnvContent("s", "a", "b", "c", "d")
	for _, name := range bootstrapCredentialVars {
		assert.Contains(t, content, name+"=", "the file the records point at carries every name they list")
	}
}

// TestBootstrapEnvContent_CarriesNoClientId pins the whole point of #285 on the one artifact that
// hands an operator their configuration: the admin console's client id is not configurable, so the
// bootstrap file must not offer it as something to copy.
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
// where the twelve-line banner went (#320 decision 6).
func TestLogBootstrapCredentialsGenerated_IsOneRecordNamingTheFile(t *testing.T) {
	logs := testutil.CaptureSlog(t)

	logBootstrapCredentialsGenerated(context.Background(), "/bootstrap/bootstrap.env")

	records := logs.Records()
	require.Len(t, records, 1, "one record, where the banner wrote twelve")
	assert.Equal(t, slog.LevelInfo, records[0].Level,
		"the seed succeeded; this is the result, not a failure")
	assert.Equal(t, "/bootstrap/bootstrap.env", records[0].Attrs["bootstrap_file"],
		"the operator's next action is to open this file, so its path is the one thing the record must carry")
	assert.Equal(t, "0600", records[0].Attrs["file_mode"],
		"and that the file is readable by its owner alone, which is why leaving it in place is survivable")
	assert.Contains(t, records[0].Message, "copy",
		"the message has to say what to do with the file, or the path alone is an announcement")
}
