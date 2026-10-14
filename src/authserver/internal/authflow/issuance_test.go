package authflow

import (
	"reflect"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/otpcredential"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
)

// TestNewCreateCodeInput_CopiesEveryFieldTheCodeIsWrittenFrom holds the one place /auth/issue hands
// the ceremony to issuance. Issuance names the fields a code is written from and newCreateCodeInput
// copies them, and a field copied from the wrong source or not at all would write a code that
// silently lacks it (#437). Every source field
// carries a distinct value, so a swap between two string fields fails as well as an omission.
func TestNewCreateCodeInput_CopiesEveryFieldTheCodeIsWrittenFrom(t *testing.T) {
	authenticatedAt := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	otpClaimGeneration := int64(5)
	authContext := &ceremony.AuthContext{
		ClientId:            "client-identifier",
		RedirectURI:         "https://app.example/callback",
		ResponseMode:        "form_post",
		Scope:               "openid profile email",
		ConsentedScope:      "openid profile",
		CodeChallenge:       "challenge-value",
		CodeChallengeMethod: "S256",
		State:               "state-value",
		Nonce:               "nonce-value",
		UserAgent:           "user-agent-value",
		IpAddress:           "203.0.113.7",
		UserId:              42,
		AcrLevel:            record.AcrLevel2Optional,
		AuthMethods:         "pwd otp",
		AuthenticatedAt:     &authenticatedAt,
		AuthStateGeneration: 9,
		OtpClaimGeneration:  &otpClaimGeneration,
		// Ceremony state issuance does not read, set so that copying it anywhere would show.
		CeremonyId: "ceremony-id",
		AuthState:  ceremony.AuthStateReadyToIssueCode,
	}

	got := newCreateCodeInput(authContext, "session-identifier")

	assert.Equal(t, &issuance.CreateCodeInput{
		ClientId:            "client-identifier",
		RedirectURI:         "https://app.example/callback",
		ResponseMode:        "form_post",
		Scope:               "openid profile email",
		ConsentedScope:      "openid profile",
		CodeChallenge:       "challenge-value",
		CodeChallengeMethod: "S256",
		State:               "state-value",
		Nonce:               "nonce-value",
		UserAgent:           "user-agent-value",
		IpAddress:           "203.0.113.7",
		UserId:              42,
		AcrLevel:            record.AcrLevel2Optional,
		AuthMethods:         "pwd otp",
		AuthenticatedAt:     &authenticatedAt,
		AuthStateGeneration: 9,
		SessionIdentifier:   "session-identifier",
		OTPClaim:            otpcredential.OTPClaim{Claimed: true, Generation: &otpClaimGeneration},
	}, got)

	// A field added to CreateCodeInput and not copied here is left zero, which the literal above
	// would not notice until someone remembered to extend it.
	value := reflect.ValueOf(*got)
	for i := 0; i < value.NumField(); i++ {
		assert.Falsef(t, value.Field(i).IsZero(), "CreateCodeInput.%s is never copied from the ceremony",
			value.Type().Field(i).Name)
	}
}
