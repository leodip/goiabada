package buildinfo

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestStampDefaults pins what a binary built without the release builds' -X flags reports. The
// release builds stamp all three, and TestReleaseBuilds_TheRealStampsNameVariables holds every
// -X target in them to naming one of these (#442).
func TestStampDefaults(t *testing.T) {
	assert.Equal(t, "development", Version)
	assert.Equal(t, "development", BuildDate)
	assert.Equal(t, "development", GitCommit)
}
