package localzone

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Both mains' helper-process tests pin Install at the process boundary, but on Linux the runtime
// already reads an empty TZ as UTC before Install runs, so they cannot tell an Install that sets UTC
// from one that leaves the zone alone. Windows reads its zone from the operating system and never
// consults TZ, which is the host where the difference shows. These start from a local zone that is
// not UTC, the state a Windows host outside UTC is in, and call Install directly.

// hostZone stands in for a local zone the runtime read from the host.
var hostZone = time.FixedZone("UTC-3", -3*60*60)

// withLocal sets time.Local for one test and puts the process's own back after it.
func withLocal(t *testing.T, loc *time.Location) {
	t.Helper()

	saved := time.Local
	time.Local = loc
	t.Cleanup(func() { time.Local = saved })
}

func TestInstall_AnEmptyTZIsUTCWhateverTheHostZone(t *testing.T) {
	for _, tz := range []string{"", ":"} {
		t.Run("TZ="+tz, func(t *testing.T) {
			withLocal(t, hostZone)
			t.Setenv("TZ", tz)

			require.NoError(t, Install())

			assert.Same(t, time.UTC, time.Local, "TZ=%q must select UTC, not keep the host's zone", tz)
		})
	}
}

func TestInstall_AnUnsetTZKeepsTheHostZone(t *testing.T) {
	withLocal(t, hostZone)
	// t.Setenv first, so the process's TZ is put back after the test unsets it.
	t.Setenv("TZ", "")
	require.NoError(t, os.Unsetenv("TZ"))

	require.NoError(t, Install())

	assert.Same(t, hostZone, time.Local, "an unset TZ leaves the zone the runtime read from the host")
}
