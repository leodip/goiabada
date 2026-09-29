package ceremony

import (
	"testing"

	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The whole table for the step-up rule. /auth/level1completed's and prompt=none's handler cases each
// drive one answer through to its redirect; which answer a session gets is decided here (#437 seam 1).

func TestTargetRequiresSecondFactor(t *testing.T) {
	testCases := []struct {
		target models.AcrLevel
		want   bool
	}{
		{models.AcrLevel1, false},
		{models.AcrLevel2Optional, true},
		{models.AcrLevel2Mandatory, true},
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
		target models.AcrLevel
		want   StepUp
	}{
		{models.AcrLevel1, StepUpNone},
		{models.AcrLevel2Optional, StepUpLevel},
		{models.AcrLevel2Mandatory, StepUpLevel},
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
		level1    = models.AcrLevel1
		optional  = models.AcrLevel2Optional
		mandatory = models.AcrLevel2Mandatory
	)

	testCases := []struct {
		name          string
		target        models.AcrLevel
		sessionAcr    models.AcrLevel
		sessionOtpGen int64
		userOtpGen    int64
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
		{"changed, optional target, optional session", optional, optional, 2, 3, StepUpOtpConfigChanged},
		{"changed, optional target, mandatory session", optional, mandatory, 2, 3, StepUpOtpConfigChanged},
		{"changed, mandatory target, optional session", mandatory, optional, 2, 3, StepUpLevel},
		{"changed, mandatory target, mandatory session", mandatory, mandatory, 2, 3, StepUpOtpConfigChanged},

		// != rather than <: a snapshot ahead of the counter asks again too, and migration 000031's
		// -1 seed asks with no special case (#242).
		{"snapshot ahead of the counter", optional, optional, 4, 3, StepUpOtpConfigChanged},
		{"the -1 seed", mandatory, mandatory, -1, 0, StepUpOtpConfigChanged},

		// A target outside the three asks nothing of any session.
		{"unknown target, level1 session, changed", "", level1, 2, 3, StepUpNone},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			session := &models.UserSession{
				AcrLevel:            tc.sessionAcr,
				OtpConfigGeneration: tc.sessionOtpGen,
				User:                models.User{OtpConfigGeneration: tc.userOtpGen},
			}

			got, err := StepUpOwed(tc.target, session)

			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestStepUpOwed_UnparsableSessionAcr(t *testing.T) {
	for _, target := range []models.AcrLevel{models.AcrLevel1, models.AcrLevel2Mandatory} {
		t.Run(string(target), func(t *testing.T) {
			session := &models.UserSession{AcrLevel: "urn:goiabada:unknown"}

			_, err := StepUpOwed(target, session)

			require.Error(t, err, "each caller decides what an unknown session level answers")
			assert.Contains(t, err.Error(), "invalid ACR level urn:goiabada:unknown")
		})
	}
}
