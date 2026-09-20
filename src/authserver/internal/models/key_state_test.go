package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestKeyState_String owns the total String decision 16 of #385 settled for this type. The in-range
// rows are the values key_pairs.state carries, so they are pinned against literals: commondb builds
// a SQL WHERE from KeyStateCurrent.String() and the seeder writes rows with it, which makes them
// stored data rather than labels. The out-of-range rows are the guard, which stops a value the type
// can hold from panicking on the slice index.
func TestKeyState_String(t *testing.T) {
	testCases := []struct {
		name  string
		state KeyState
		want  string
	}{
		{"current is the zero value", KeyStateCurrent, "current"},
		{"previous", KeyStatePrevious, "previous"},
		{"next, the top of the range", KeyStateNext, "next"},
		{"one past the range", KeyState(3), ""},
		{"far past the range", KeyState(99), ""},
		{"negative", KeyState(-1), ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.state.String())
		})
	}
}

// TestKeyStateFromString covers the parse in both directions, including that the guard did not
// change what a stored value round-trips to.
func TestKeyStateFromString(t *testing.T) {
	for _, state := range []KeyState{KeyStateCurrent, KeyStatePrevious, KeyStateNext} {
		t.Run(state.String(), func(t *testing.T) {
			parsed, err := KeyStateFromString(state.String())
			assert.NoError(t, err)
			assert.Equal(t, state, parsed)
		})
	}

	t.Run("an unrecognized state is refused", func(t *testing.T) {
		for _, raw := range []string{"", "retired", "Current", "0"} {
			parsed, err := KeyStateFromString(raw)
			assert.Error(t, err, "%q must not parse", raw)
			assert.Equal(t, KeyStateCurrent, parsed, "the refused value returns the zero state")
		}
	})
}
