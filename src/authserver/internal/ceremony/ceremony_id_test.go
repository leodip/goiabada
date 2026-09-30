package ceremony

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// The id's shape is what the registration page relies on to echo one back into a link, so the table
// holds each way a value can fail it, varying one thing from an id that passes (#246, #437 seam 1).

func TestNewId_IsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		id := NewId()
		assert.Len(t, id, IdLength)
		assert.True(t, IsWellFormedId(id), "an id NewId drew must satisfy the shape check: %q", id)
		assert.False(t, seen[id], "two draws produced the same id")
		seen[id] = true
	}
}

func TestIsWellFormedId(t *testing.T) {
	valid := strings.Repeat("a", IdLength)

	testCases := []struct {
		name string
		id   string
		want bool
	}{
		{"an id at the length", valid, true},
		{"digits and lowercase", "0123456789abcdefghijklmnopqrstuv", true},
		{"uppercase and the three punctuation characters", "ABCDEFGHIJKLMNOPQRSTUVWXYZ-_.012", true},
		{"empty", "", false},
		{"one character short", valid[:IdLength-1], false},
		{"one character over", valid + "a", false},
		{"far over", strings.Repeat("a", 4*IdLength), false},
		{"a space in place of a character", valid[:IdLength-1] + " ", false},
		{"a slash", valid[:IdLength-1] + "/", false},
		{"a percent sign", valid[:IdLength-1] + "%", false},
		{"a quote", valid[:IdLength-1] + `"`, false},
		{"an angle bracket", valid[:IdLength-1] + "<", false},
		{"a newline", valid[:IdLength-1] + "\n", false},
		{"a NUL", valid[:IdLength-1] + "\x00", false},
		// Two bytes each, so the byte length is right and every byte is outside the alphabet.
		{"a multibyte character at the byte length", strings.Repeat("é", IdLength/2), false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, IsWellFormedId(tc.id))
		})
	}
}
