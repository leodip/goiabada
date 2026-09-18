package constants

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestContextKeySettings_IsDeclaredAndNonEmpty holds the admin console's own settings key.
//
// It carries the same spelling as the auth server's deliberately, and the two are not asserted
// against each other because they are not the same key: a context key never leaves the process
// that set it, and the two processes store different types under this one (#351).
func TestContextKeySettings_IsDeclaredAndNonEmpty(t *testing.T) {
	assert.Equal(t, "Settings", string(ContextKeySettings))
}
