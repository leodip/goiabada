package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// previousKeysRefusal is the refusal ParseKeys answers a previous pair set in part with, made by
// the rule itself rather than built here, so the record is chosen for the type main will receive.
func previousKeysRefusal(t *testing.T) error {
	t.Helper()
	_, _, err := sessionstore.ParseKeys(sessionstore.ConfiguredKeys{
		Authentication: sessionstore.ConfiguredKey{Name: sessionKeysRequired[0], Value: strings.Repeat("ab", 64)},
		Encryption:     sessionstore.ConfiguredKey{Name: sessionKeysRequired[1], Value: strings.Repeat("cd", 32)},
		// The authentication half is named and left empty, as an operator who added only the
		// encryption half leaves it.
		PreviousAuthentication: sessionstore.ConfiguredKey{Name: sessionKeysPrevious[0]},
		PreviousEncryption:     sessionstore.ConfiguredKey{Name: sessionKeysPrevious[1], Value: strings.Repeat("34", 32)},
	})
	var previousErr *sessionstore.PreviousKeysError
	require.ErrorAs(t, err, &previousErr, "ParseKeys answered %v, not a refusal of the previous pair", err)
	return err
}

// A previous pair set in part is a rotation mistake, whatever the bootstrap mode: the record says to
// set both halves or neither and names them. It went to the bootstrap record, which told the
// operator to copy every credential out of a bootstrap file, one that a deployment made with the
// setup wizard does not have.
func TestLogSessionKeysRefused_APreviousPairIsARotationMistake(t *testing.T) {
	for _, bootstrapFile := range []string{"", "/bootstrap/bootstrap.env"} {
		t.Run("bootstrap file "+bootstrapFile, func(t *testing.T) {
			logs := logtest.CaptureSlog(t)

			logSessionKeysRefused(context.Background(), previousKeysRefusal(t), bootstrapFile)

			records := logs.Records()
			require.Len(t, records, 1)
			assert.Equal(t, slog.LevelError, records[0].Level, "the server cannot start and somebody has to act")
			assert.Contains(t, records[0].Message, "previous session key pair")
			assert.NotContains(t, records[0].Message, "bootstrap")
			assert.Equal(t, sessionKeysPrevious, records[0].Attrs["previous"])
			assert.NotContains(t, records[0].Attrs, "bootstrap_file")
			logged, _ := records[0].Attrs["error"].(error)
			require.Error(t, logged, "the refusal rides as the error itself")
			assert.Contains(t, logged.Error(), "GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY_PREVIOUS is required when",
				"which half is missing is the refusal's own text")
		})
	}
}

// A current key refused where the legacy two-step bootstrap wrote a file is a credential not yet
// carried over from it, which is the case the bootstrap record was written for.
func TestLogSessionKeysRefused_ACurrentKeyWithABootstrapFileIsTheBootstrapRecord(t *testing.T) {
	logs := logtest.CaptureSlog(t)

	logSessionKeysRefused(context.Background(), errs.New("GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY is required"), "/bootstrap/bootstrap.env")

	records := logs.Records()
	require.Len(t, records, 1)
	assert.Contains(t, records[0].Message, "bootstrap credentials are not configured")
	assert.Equal(t, "/bootstrap/bootstrap.env", records[0].Attrs["bootstrap_file"])
}

// A current key refused with no bootstrap file, the single-step mode the setup wizard configures,
// has no file to copy from: the record names the two variables and how to generate them.
func TestLogSessionKeysRefused_ACurrentKeyWithNoBootstrapFileNamesTheVariables(t *testing.T) {
	logs := logtest.CaptureSlog(t)

	logSessionKeysRefused(context.Background(), errs.New("GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY must be 32 bytes"), "")

	records := logs.Records()
	require.Len(t, records, 1)
	assert.Equal(t, slog.LevelError, records[0].Level, "the server cannot start and somebody has to act")
	assert.Equal(t, "the auth server session keys are missing or malformed, so the auth server cannot start", records[0].Message)
	assert.Equal(t, sessionKeysRequired, records[0].Attrs["required"])
	assert.Contains(t, records[0].Attrs["generate_with"], "openssl rand -hex 64")
	assert.NotContains(t, records[0].Attrs, "bootstrap_file")
	logged, _ := records[0].Attrs["error"].(error)
	require.Error(t, logged)
	assert.Contains(t, logged.Error(), "must be 32 bytes")
}

// The configuration record says whether the rate limiter switch is on, since the limits counted
// by an IP address are the ones it can leave off and nothing else at startup says so (#503). It
// is Info either way: off is the default #219 chose, not a fault, and a Warn on every default
// install would teach operators to ignore warnings.
func TestLogConfiguration_NamesTheRateLimiterSwitch(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("switch %v", enabled), func(t *testing.T) {
			logs := logtest.CaptureSlog(t)
			cfg := &config.Config{}
			cfg.AuthServer.BaseURL = "https://auth.example.com"
			cfg.AuthServer.InternalBaseURL = "http://authserver:9090"
			cfg.AdminConsole.BaseURL = "https://admin.example.com"
			cfg.AuthServer.DebugAPIRequests = true
			cfg.AuthServer.RateLimiterEnabled = enabled

			logConfiguration(cfg)

			records := logs.Records()
			require.Len(t, records, 1, "the switch rides on the configuration record, with no record of its own")
			assert.Equal(t, slog.LevelInfo, records[0].Level)
			assert.Equal(t, "using configuration", records[0].Message)
			assert.Equal(t, map[string]any{
				"auth_server_base_url":          "https://auth.example.com",
				"auth_server_internal_base_url": "http://authserver:9090",
				"admin_console_base_url":        "https://admin.example.com",
				"debug_api_requests":            true,
				"rate_limiter_enabled":          enabled,
			}, records[0].Attrs)
		})
	}
}
