package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestPasswordPolicy_String owns the total String decision 16 of #385 settled for this type. This is
// the one of the six whose out-of-range rows are reachable from stored data rather than only from a
// future caller: Settings scans settings.password_policy straight into this type with no range
// check, so a column value outside 0..3 used to take down every page that rendered the policy.
// Nothing the application writes produces one.
func TestPasswordPolicy_String(t *testing.T) {
	testCases := []struct {
		name   string
		policy PasswordPolicy
		want   string
	}{
		{"none is the zero value", PasswordPolicyNone, "none"},
		{"low", PasswordPolicyLow, "low"},
		{"medium", PasswordPolicyMedium, "medium"},
		{"high, the top of the range", PasswordPolicyHigh, "high"},
		{"one past the range, which is what a stray column value looks like", PasswordPolicy(4), ""},
		{"far past the range", PasswordPolicy(99), ""},
		{"negative", PasswordPolicy(-1), ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.policy.String())
		})
	}
}

// TestPasswordPolicyFromString covers the parse in both directions.
func TestPasswordPolicyFromString(t *testing.T) {
	all := []PasswordPolicy{PasswordPolicyNone, PasswordPolicyLow, PasswordPolicyMedium, PasswordPolicyHigh}
	for _, policy := range all {
		t.Run(policy.String(), func(t *testing.T) {
			parsed, err := PasswordPolicyFromString(policy.String())
			assert.NoError(t, err)
			assert.Equal(t, policy, parsed)
		})
	}

	t.Run("an unrecognized policy is refused", func(t *testing.T) {
		for _, raw := range []string{"", "extreme", "High", "2"} {
			parsed, err := PasswordPolicyFromString(raw)
			assert.Error(t, err, "%q must not parse", raw)
			assert.Equal(t, PasswordPolicyNone, parsed, "the refused value returns the zero policy")
		}
	})
}
