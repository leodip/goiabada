package authflow

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/record"
)

// The whole table for /auth/level2's choice of arm. The cases of HandleAuthLevel2Get in handlers each
// drive one arm to its save and redirect; which arm a target and an enrolment get is decided here
// (#437 seam 1).
func TestDecideLevel2Arm(t *testing.T) {
	testCases := []struct {
		name       string
		target     record.AcrLevel
		userHasOTP bool
		wantState  ceremony.AuthState
		wantPath   string
		wantErr    string
	}{
		{"optional with OTP asks for it", record.AcrLevel2Optional, true, ceremony.AuthStateLevel2OTP, "/auth/otp", ""},
		{"optional without OTP skips it", record.AcrLevel2Optional, false, ceremony.AuthStateAuthenticationCompleted, "/auth/completed", ""},
		{"mandatory with OTP asks for it", record.AcrLevel2Mandatory, true, ceremony.AuthStateLevel2OTP, "/auth/otp", ""},
		{"mandatory without OTP enrols", record.AcrLevel2Mandatory, false, ceremony.AuthStateLevel2OTP, "/auth/otp", ""},
		{"level1 never reaches this hop", record.AcrLevel1, true, "", "", "invalid targetAcrLevel: urn:goiabada:level1"},
		{"an unknown level is refused", "urn:goiabada:level3", false, "", "", "invalid targetAcrLevel: urn:goiabada:level3"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			state, path, err := decideLevel2Arm(tc.target, tc.userHasOTP)

			if tc.wantErr != "" {
				require.EqualError(t, err, tc.wantErr)
				assert.Empty(t, state)
				assert.Empty(t, path)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantState, state)
			assert.Equal(t, tc.wantPath, path)
		})
	}
}
