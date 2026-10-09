package main

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The admin console's bootstrap banner, collapsed to one record (#320 decision 6).
//
// It is the record an operator reads when the console will not start, and the only place they are
// told which three variables to set. The banner it replaced described them in prose under a
// "Required environment variables:" heading; the list is now an attribute, so a collector can
// read it and a reader cannot lose half of it to a truncated scroll.
func TestLogBootstrapCredentialsNotConfigured_NamesEveryRequiredVariable(t *testing.T) {
	logs := logtest.CaptureSlog(t)

	logBootstrapCredentialsNotConfigured()

	records := logs.Records()
	require.Len(t, records, 1, "one record, where the banner wrote thirteen")

	assert.Equal(t, slog.LevelError, records[0].Level,
		"the console cannot start and somebody has to act, which is exactly what Error means")
	assert.Equal(t, []string{
		"GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET",
		"GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY",
		"GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY",
	}, records[0].Attrs["required"],
		"all three, or the operator sets what they were told and restarts into the next failure")
	assert.Contains(t, records[0].Message, "auth server",
		"a first deployment has to start the auth server first, and this record is where they learn that")
}

// The session-key refusal, collapsed from three records to one (#320 decisions 4 and 6).
//
// The three it replaced were a failure, a "Please set ..." line and a "Generate keys with: ..."
// line: one instruction split across three records, two of them capitalised prose, and the
// validator's error concatenated into the first one's message rather than carried as a value. A
// deployment logging JSON received them as three unrelated records with the remedy in a message
// field nothing could query.
func TestLogSessionKeysNotConfigured_IsOneRecordCarryingTheErrorAndTheRemedy(t *testing.T) {
	logs := logtest.CaptureSlog(t)

	logSessionKeysNotConfigured(errs.New("the authentication key is not 128 hex characters"))

	records := logs.Records()
	require.Len(t, records, 1, "one record, where three used to be")

	assert.Equal(t, slog.LevelError, records[0].Level,
		"the console cannot start and somebody has to act, which is exactly what Error means")

	logged, _ := records[0].Attrs["error"].(error)
	require.Error(t, logged, "the validator's error rides as a value, not concatenated into the message")
	assert.Contains(t, logged.Error(), "128 hex characters",
		"which of the two keys is wrong is the whole content of this record")

	assert.Equal(t, []string{
		"GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY",
		"GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY",
	}, records[0].Attrs["required"],
		"both, or the operator sets what they were told and restarts into the next failure")
	assert.Contains(t, records[0].Attrs["generate_with"], "openssl rand -hex 64",
		"the command is the reader's next action, so it is an attribute rather than a third record")
}

// A previous pair set in part is a rotation mistake, not a key the deployment lacks: the record
// names the two _PREVIOUS variables to set both of or neither, where this record's required list
// and generate_with pointed the operator at the current keys, which were fine. The refusal is the
// rule's own, from ParseKeys, so the record is chosen for the type main receives.
func TestLogSessionKeysNotConfigured_APreviousPairIsARotationMistake(t *testing.T) {
	_, _, err := sessionstore.ParseKeys(sessionstore.ConfiguredKeys{
		Authentication:         sessionstore.ConfiguredKey{Name: "GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY", Value: strings.Repeat("ab", 64)},
		Encryption:             sessionstore.ConfiguredKey{Name: "GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY", Value: strings.Repeat("cd", 32)},
		PreviousAuthentication: sessionstore.ConfiguredKey{Name: "GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY_PREVIOUS", Value: strings.Repeat("12", 64)},
		PreviousEncryption:     sessionstore.ConfiguredKey{Name: "GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY_PREVIOUS"},
	})
	require.Error(t, err)
	logs := logtest.CaptureSlog(t)

	logSessionKeysNotConfigured(err)

	records := logs.Records()
	require.Len(t, records, 1)
	assert.Equal(t, slog.LevelError, records[0].Level, "the console cannot start and somebody has to act")
	assert.Contains(t, records[0].Message, "previous session key pair")
	assert.Equal(t, []string{
		"GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY_PREVIOUS",
		"GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY_PREVIOUS",
	}, records[0].Attrs["previous"])
	assert.NotContains(t, records[0].Attrs, "required", "the current keys are not what is wrong")
	assert.NotContains(t, records[0].Attrs, "generate_with")
	logged, _ := records[0].Attrs["error"].(error)
	require.Error(t, logged)
	assert.Contains(t, logged.Error(), "GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY_PREVIOUS is required when")
}
