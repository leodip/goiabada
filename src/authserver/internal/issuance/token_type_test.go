package issuance

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestTokenType_String owns the total String decision 16 of #385 settled for this type. The
// out-of-range rows are the guard: no production site converts an int to a TokenType, but the
// panicking index was the same shape in all seven enums this change moved, and fixing six of them
// while leaving one would leave the next caller to find out which.
func TestTokenType_String(t *testing.T) {
	testCases := []struct {
		name      string
		tokenType TokenType
		want      string
	}{
		{"id is the zero value", TokenTypeId, "ID"},
		{"bearer", TokenTypeBearer, "Bearer"},
		{"refresh, the top of the range", TokenTypeRefresh, "Refresh"},
		{"one past the range", TokenType(3), ""},
		{"far past the range", TokenType(99), ""},
		{"negative", TokenType(-1), ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.tokenType.String())
		})
	}
}
