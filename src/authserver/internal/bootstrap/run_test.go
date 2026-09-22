package bootstrap

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The mode choice, over the Database mock where no row is written and over a real SQLite database
// where one is. A mock holding only an IsEmpty expectation panics on any write the case reaches,
// which is how "nothing is written" is asserted without a database.

func TestRun_AlreadySeeded_ContinuesWithoutWritingInEveryMode(t *testing.T) {
	for name, cfg := range map[string]Config{
		"single-step": {OAuthClientSecret: "secret"},
		"two-step":    {BootstrapEnvOutFile: filepath.Join(t.TempDir(), "bootstrap.env")},
		"neither":     {},
	} {
		t.Run(name, func(t *testing.T) {
			database := mocks_data.NewDatabase(t)
			database.On("IsEmpty", mock.Anything).Return(false, nil).Once()
			logs := testutil.CaptureSlog(t)

			outcome, err := Run(context.Background(), database, cfg)

			require.NoError(t, err)
			assert.Equal(t, Continue, outcome, "a seeded database starts, whatever the bootstrap variables say")
			if cfg.BootstrapEnvOutFile != "" {
				assert.NoFileExists(t, cfg.BootstrapEnvOutFile, "and no credentials are generated for it")
			}
			require.Len(t, logs.Records(), 1)
			assert.Equal(t, "database already initialized, proceeding with normal startup", logs.Records()[0].Message)
		})
	}
}

func TestRun_IsEmptyFails_RefusesAndSaysWhich(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	database.On("IsEmpty", mock.Anything).Return(false, errs.New("connection reset")).Once()

	outcome, err := Run(context.Background(), database, Config{OAuthClientSecret: "secret"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to check whether the database is empty")
	assert.Contains(t, err.Error(), "connection reset")
	assert.Equal(t, Refused, outcome)
}

func TestRun_NeitherModeConfigured_RefusesWithoutWriting(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	database.On("IsEmpty", mock.Anything).Return(true, nil).Once()
	logs := testutil.CaptureSlog(t)

	outcome, err := Run(context.Background(), database, Config{AdminEmail: "admin@example.com"})

	require.NoError(t, err, "the refusal is the operator's to act on, carried by its record, not an error")
	assert.Equal(t, Refused, outcome)
	messages := recordMessages(logs)
	assert.Contains(t, messages, "initial setup is required, because the database is empty and neither bootstrap mode is configured")
}

// The zero Outcome is the refusal, so a caller that read the outcome and dropped the error could
// not serve an empty database by accident.
func TestOutcome_ZeroValueRefuses(t *testing.T) {
	var outcome Outcome
	assert.Equal(t, Refused, outcome)
}

// TestRun_RefusesAnOverlongAdminPasswordBeforeAnyWrite drives Run over a mock holding only the
// emptiness check, so any write the seed reached would panic the test. Before #409 this password
// was hashed with the error discarded, after the first insert, and stored as an empty hash.
func TestRun_RefusesAnOverlongAdminPasswordBeforeAnyWrite(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	database.On("IsEmpty", mock.Anything).Return(true, nil).Once()
	target := filepath.Join(t.TempDir(), "bootstrap.env")

	outcome, err := Run(context.Background(), database, Config{
		AdminEmail:          "admin@example.com",
		AdminPassword:       strings.Repeat("a", passwordhash.MaxPasswordBytes+1),
		BootstrapEnvOutFile: target,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to seed the database")
	assert.Contains(t, err.Error(), "GOIABADA_ADMIN_PASSWORD")
	assert.Equal(t, Refused, outcome)
	entries, readErr := os.ReadDir(filepath.Dir(target))
	require.NoError(t, readErr)
	assert.Empty(t, entries, "refused before the bootstrap file is staged, so nothing is left to clean up")
}

// TestCheckAdminPasswordLength_CountsBytes holds the seed to bcrypt's bound on either side of it,
// and in the unit bcrypt uses: 37 accented characters are 74 bytes, far fewer than 72 characters,
// and are refused. Every refusal names the variable to change and both numbers, since an operator
// reading it has only the startup log to go on (#409).
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

// The production key size and the production rename, which the tests below replace: a runner built
// any other way than through newRunner does not reach production.
func TestNewRunner_ProductionDefaults(t *testing.T) {
	r := newRunner(mocks_data.NewDatabase(t), Config{})

	assert.Equal(t, 4096, r.keySizeBits)
	assert.Equal(t, reflect.ValueOf(os.Rename).Pointer(), reflect.ValueOf(r.rename).Pointer())
}

func recordMessages(logs *testutil.SlogCapture) []string {
	var messages []string
	for _, record := range logs.Records() {
		messages = append(messages, record.Message)
	}
	return messages
}
