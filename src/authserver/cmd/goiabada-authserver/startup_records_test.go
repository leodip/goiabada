package main

import (
	"log/slog"
	"testing"

	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The three bootstrap banner blocks of this main, collapsed to one record each (#320 decision 6).
//
// These are the records an operator reads when the server will not start, and two of them are the
// only place they are told which environment variables to set. The block they came from listed
// those names in hand-typed prose, twice, so the list is now one package-level value and the
// cases below assert that both records carry all of it: a credential added to the bootstrap file
// and to one list only would leave an operator following the other one with a startup failure
// naming a variable they were never told about.

func TestLogBootstrapComplete_NamesTheFileAndEveryRequiredVariable(t *testing.T) {
	logs := testutil.CaptureSlog(t)

	logBootstrapComplete("/bootstrap/bootstrap.env")

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

func TestLogBootstrapCredentialsNotConfigured_CarriesTheErrorTheFileAndEveryRequiredVariable(t *testing.T) {
	logs := testutil.CaptureSlog(t)

	logBootstrapCredentialsNotConfigured(errs.New("session key is not 64 bytes"), "/somewhere/else.env")

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

	logInitialSetupRequired()

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
}
