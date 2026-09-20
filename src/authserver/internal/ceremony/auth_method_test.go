package ceremony

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestAuthMethod_String owns the total String decision 16 of #385 settled for this type. The
// in-range rows are the amr values a token carries, which OIDC Core defines and a relying party
// reads, so they are pinned against literals. The out-of-range rows are the guard: nothing converts
// an int to an AuthMethod in production today, but AuthMethods is accumulated across hops and read
// back off a session row, so the type is the right place for the bound rather than each call site.
func TestAuthMethod_String(t *testing.T) {
	testCases := []struct {
		name   string
		method AuthMethod
		want   string
	}{
		{"password is the zero value", AuthMethodPassword, "pwd"},
		{"otp, the top of the range", AuthMethodOTP, "otp"},
		{"one past the range", AuthMethod(2), ""},
		{"far past the range", AuthMethod(99), ""},
		{"negative", AuthMethod(-1), ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.method.String())
		})
	}
}
