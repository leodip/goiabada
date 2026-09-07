package migrator

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStartupRefusal_DatabaseAheadOfTheBinaryNamesEveryFactAnOperatorNeeds is decision 7's
// second refusal, and it is asserted as facts rather than as a sentence: the wording is the
// run's to change, and a test comparing the whole string would be a copy of it that fails
// whenever a comma moves.
//
// The situation it explains is an upgrade rolled back without the schema being stepped down. A
// replica of the newer release migrated the database to 000044, an older binary is started
// against it, and its own migration set stops at 000041. Nothing about that is corruption, and
// the operator's way out is either to put the newer release back or to step the schema down
// with it first, so the message has to say which.
func TestStartupRefusal_DatabaseAheadOfTheBinaryNamesEveryFactAnOperatorNeeds(t *testing.T) {
	err := StartupRefusal(ErrUnknownVersion{
		Version: 44,
		Engine:  "postgres",
		Head:    41,
		Below:   41,
		Above:   NilVersion,
	}, "v1.6.0")
	require.Error(t, err)
	msg := err.Error()

	assert.Containsf(t, msg, "000044", "the version the database records: %s", msg)
	assert.Containsf(t, msg, "000041", "the highest version this binary carries: %s", msg)
	assert.Containsf(t, msg, "v1.6.0", "the Goiabada version this binary is: %s", msg)
	assert.Containsf(t, msg, "postgres", "the engine whose set was searched, since the four differ: %s", msg)
	assert.Containsf(t, strings.ToLower(msg), "newer release",
		"the diagnosis, which is what stops an operator treating this as corruption: %s", msg)
	assert.Containsf(t, msg, "migrate to 000041",
		"the remedy, as a command the operator can run rather than a description of one: %s", msg)

	// Wrapped rather than replaced, so a caller that wants the numbers can still reach them.
	var unknown ErrUnknownVersion
	require.ErrorAs(t, err, &unknown, "the typed error survives the explanation")
	assert.Equal(t, 44, unknown.Version)
}

// TestStartupRefusal_LeavesEverythingElseExactlyAsItWas is the other half, and the one that
// matters for the dirty case: ErrDirty composes its own message where the direction of the
// interrupted step is known, and an explanation layered on top of it here would either
// duplicate that or contradict it.
func TestStartupRefusal_LeavesEverythingElseExactlyAsItWas(t *testing.T) {
	assert.NoError(t, StartupRefusal(nil, "v1.6.0"), "nil is not a refusal")

	dirty := ErrDirty{Version: 40, Applied: 40, Below: 39, Above: 41}
	assert.Equal(t, error(dirty), StartupRefusal(dirty, "v1.6.0"),
		"ErrDirty already carries decision 7's dirty message, composed where the direction is known")

	assert.Equal(t, ErrNoChange, StartupRefusal(ErrNoChange, "v1.6.0"),
		"ErrNoChange is not a failure at all and must stay testable with errors.Is")

	other := errors.New("dial tcp 127.0.0.1:5432: connection refused")
	assert.Equal(t, other, StartupRefusal(other, "v1.6.0"),
		"a driver error says what it says")
}
