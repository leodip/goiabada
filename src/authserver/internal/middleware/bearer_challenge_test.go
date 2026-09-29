package middleware

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestBearerChallenge pins the value every bearer refusal carries. Which refusal carries which
// error code is bearer_guard_chain_test.go's; this owns the quoting and the conformance.
func TestBearerChallenge(t *testing.T) {
	tests := []struct {
		name        string
		errorCode   string
		description string
		want        string
	}{
		// RFC 6750 section 3.1: no credential, no error information; the realm is section 3's
		// one required auth-param.
		{name: "no error is the realm alone", want: `Bearer realm="goiabada"`},
		{name: "a description without an error is dropped with it", description: "ignored",
			want: `Bearer realm="goiabada"`},
		{name: "an error without a description", errorCode: "invalid_token",
			want: `Bearer realm="goiabada", error="invalid_token"`},
		{name: "an error and a description", errorCode: "insufficient_scope", description: "Insufficient scope.",
			want: `Bearer realm="goiabada", error="insufficient_scope", error_description="Insufficient scope."`},
		// RFC 6750 section 3 confines error_description to %x20-21 / %x23-5B / %x5D-7E, which leaves
		// out the two characters that could end the quoted-string or open an escape.
		{name: "a double quote cannot close the quoted-string", errorCode: "invalid_token", description: `a"b`,
			want: `Bearer realm="goiabada", error="invalid_token", error_description="a?b"`},
		{name: "a backslash cannot open an escape", errorCode: "invalid_token", description: `a\b`,
			want: `Bearer realm="goiabada", error="invalid_token", error_description="a?b"`},
		{name: "a control character and non-ASCII are replaced", errorCode: "invalid_token", description: "a\r\nbé",
			want: `Bearer realm="goiabada", error="invalid_token", error_description="a??b?"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, BearerChallenge(tc.errorCode, tc.description))
		})
	}

	t.Run("the description is bounded as every error_description is", func(t *testing.T) {
		challenge := BearerChallenge("invalid_token", strings.Repeat("x", 2000))
		assert.Less(t, len(challenge), 600, "ConformErrorDescription bounds the description to 512 bytes")
		assert.True(t, strings.HasSuffix(challenge, `..."`))
	})
}
