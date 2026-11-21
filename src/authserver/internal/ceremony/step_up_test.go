package ceremony

import (
	"testing"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The whole table for the step-up rule. /auth/level1completed's and prompt=none's handler cases each
// drive one answer through to its redirect; which answer a session gets is decided here (#437 seam 1).

func TestTargetRequiresSecondFactor(t *testing.T) {
	testCases := []struct {
		target record.ACRLevel
		want   bool
	}{
		{record.ACRLevel1, false},
		{record.ACRLevel2Optional, true},
		{record.ACRLevel2Mandatory, true},
		// A level outside the three ranks below level 1, so it asks nothing.
		{"", false},
		{"urn:goiabada:level3", false},
	}

	for _, tc := range testCases {
		t.Run(string(tc.target), func(t *testing.T) {
			assert.Equal(t, tc.want, TargetRequiresSecondFactor(tc.target))
		})
	}
}

func TestStepUpOwed_NoSession(t *testing.T) {
	testCases := []struct {
		target record.ACRLevel
		want   StepUp
	}{
		{record.ACRLevel1, StepUpNone},
		{record.ACRLevel2Optional, StepUpLevel},
		{record.ACRLevel2Mandatory, StepUpLevel},
		{"", StepUpNone},
	}

	for _, tc := range testCases {
		t.Run(string(tc.target), func(t *testing.T) {
			got, err := StepUpOwed(tc.target, nil)

			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestStepUpOwed_Session(t *testing.T) {
	const (
		level1    = record.ACRLevel1
		optional  = record.ACRLevel2Optional
		mandatory = record.ACRLevel2Mandatory
	)

	testCases := []struct {
		name          string
		target        record.ACRLevel
		sessionACR    record.ACRLevel
		sessionOTPGen int64
		userOTPGen    int64
		want          StepUp
	}{
		// Generations equal: only the levels decide.
		{"level1 target, level1 session", level1, level1, 2, 2, StepUpNone},
		{"level1 target, optional session", level1, optional, 2, 2, StepUpNone},
		{"level1 target, mandatory session", level1, mandatory, 2, 2, StepUpNone},
		{"optional target, level1 session", optional, level1, 2, 2, StepUpLevel},
		{"optional target, optional session", optional, optional, 2, 2, StepUpNone},
		{"optional target, mandatory session", optional, mandatory, 2, 2, StepUpNone},
		{"mandatory target, level1 session", mandatory, level1, 2, 2, StepUpLevel},
		{"mandatory target, optional session", mandatory, optional, 2, 2, StepUpLevel},
		{"mandatory target, mandatory session", mandatory, mandatory, 2, 2, StepUpNone},

		// Generations differ: the authenticator changed since the session answered level 2.
		{"changed, level1 target, level1 session", level1, level1, 2, 3, StepUpNone},
		{"changed, level1 target, mandatory session", level1, mandatory, 2, 3, StepUpNone},
		{"changed, optional target, level1 session", optional, level1, 2, 3, StepUpLevel},
		{"changed, optional target, optional session", optional, optional, 2, 3, StepUpOTPConfigChanged},
		{"changed, optional target, mandatory session", optional, mandatory, 2, 3, StepUpOTPConfigChanged},
		{"changed, mandatory target, optional session", mandatory, optional, 2, 3, StepUpLevel},
		{"changed, mandatory target, mandatory session", mandatory, mandatory, 2, 3, StepUpOTPConfigChanged},

		// != rather than <: a snapshot ahead of the counter asks again too, and migration 000031's
		// -1 seed asks with no special case (#242).
		{"snapshot ahead of the counter", optional, optional, 4, 3, StepUpOTPConfigChanged},
		{"the -1 seed", mandatory, mandatory, -1, 0, StepUpOTPConfigChanged},

		// A target outside the three asks nothing of any session.
		{"unknown target, level1 session, changed", "", level1, 2, 3, StepUpNone},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Every row's user has an authenticator. TestStepUpOwed_UserWithNoAuthenticator is the
			// table for a user without one.
			session := &record.UserSession{
				ACRLevel:            tc.sessionACR,
				OTPConfigGeneration: tc.sessionOTPGen,
				User:                record.User{OTPEnabled: true, OTPConfigGeneration: tc.userOTPGen},
			}

			got, err := StepUpOwed(tc.target, session)

			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// A session at level 3 whose user has no authenticator now, because they or an administrator
// removed it. Level 3 asks them to set one up whether or not a level 2 optional sign-in has
// answered the changed generation since: that sign-in skips the code for a user with no
// authenticator and promotes the generation, and keyed on the generation alone the session went on
// answering level 3 with nothing to answer it, while prompt=none refused the same request.
func TestStepUpOwed_UserWithNoAuthenticator(t *testing.T) {
	const (
		level1    = record.ACRLevel1
		optional  = record.ACRLevel2Optional
		mandatory = record.ACRLevel2Mandatory
	)

	testCases := []struct {
		name          string
		target        record.ACRLevel
		sessionACR    record.ACRLevel
		sessionOTPGen int64
		userOTPGen    int64
		want          StepUp
	}{
		{"mandatory target, mandatory session, generation answered", mandatory, mandatory, 3, 3, StepUpAuthenticatorMissing},
		{"mandatory target, mandatory session, generation moved", mandatory, mandatory, 2, 3, StepUpAuthenticatorMissing},
		// A level the session has not reached is the level answer, as for any user.
		{"mandatory target, optional session", mandatory, optional, 3, 3, StepUpLevel},
		// Level 2 optional needs no authenticator: a moved generation is answered by the skip.
		{"optional target, mandatory session, generation answered", optional, mandatory, 3, 3, StepUpNone},
		{"optional target, mandatory session, generation moved", optional, mandatory, 2, 3, StepUpOTPConfigChanged},
		{"level1 target, mandatory session", level1, mandatory, 2, 3, StepUpNone},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			session := &record.UserSession{
				ACRLevel:            tc.sessionACR,
				OTPConfigGeneration: tc.sessionOTPGen,
				User:                record.User{OTPEnabled: false, OTPConfigGeneration: tc.userOTPGen},
			}

			got, err := StepUpOwed(tc.target, session)

			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestStepUpOwed_UnparsableSessionACR(t *testing.T) {
	for _, target := range []record.ACRLevel{record.ACRLevel1, record.ACRLevel2Mandatory} {
		t.Run(string(target), func(t *testing.T) {
			session := &record.UserSession{ACRLevel: "urn:goiabada:unknown"}

			_, err := StepUpOwed(target, session)

			require.Error(t, err, "each caller decides what an unknown session level answers")
			assert.Contains(t, err.Error(), "invalid ACR level urn:goiabada:unknown")
		})
	}
}
