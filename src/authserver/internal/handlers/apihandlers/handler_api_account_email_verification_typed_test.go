package apihandlers

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// A verification code typed in full-width, or with another script's digits, is the code it spells
// (#662 decision 9). The code is trimmed and upper-cased as before, so what was refused stays
// refused, and a wrong code still spends the failure budget. verificationCode is ABCD1234.
func TestHandleAccountEmailVerificationPost_ReadsFullWidthLettersAndTheDigitsOfAnyScript(t *testing.T) {
	for _, typed := range []string{
		"ＡＢＣＤ１２３４",
		"ａｂｃｄ１２３４",
		"ABCD１２３４",
		"ＡＢＣＤ١٢٣٤",
		"abcd१२३४",
		"ＡＢＣＤ1２٣४",
		"　ＡＢＣＤ１２３４　",
	} {
		t.Run(typed, func(t *testing.T) {
			env := newVerificationEnv(t)
			assert.Equal(t, http.StatusOK, env.post(t, typed).Code)
			assert.True(t, env.user.EmailVerified, "the address should have been verified")
		})
	}
}

func TestHandleAccountEmailVerificationPost_AWrongFullWidthCodeIsStillAGuess(t *testing.T) {
	const budget = 5

	for _, typed := range []string{
		"ＡＢＣＤ１２３５",  // a wrong digit
		"ＡＢＣＥ１２３４",  // a wrong letter
		"ＡＢＣＤ１２３",   // too short
		"ＡＢＣＤ１２３４５", // too long
		"ＡＢＣＤ　１２３４", // an ideographic space inside it
		"ABCD 1234", // a space inside it
		"ＡＢＣＤ－１２３４", // a full-width hyphen inside it
	} {
		t.Run(typed, func(t *testing.T) {
			env := newVerificationEnv(t)
			for i := 0; i < budget; i++ {
				assert.Equal(t, http.StatusBadRequest, env.post(t, typed).Code, "attempt %d is refused", i+1)
			}
			assert.False(t, env.user.EmailVerified)
			assert.Equal(t, http.StatusTooManyRequests, env.post(t, verificationCode).Code,
				"each refusal spent the budget, so the right code is now refused by the limiter")
		})
	}
}
