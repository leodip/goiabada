package integration

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/otp/otptest"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A code typed in full-width, as a Japanese keyboard in kana mode types it, or with the digits of
// any other script, is the code it spells, at every place one is read (#662 decision 9). What was
// refused stays refused, and a wrong code still counts as a failed attempt.

// inFullWidth writes an ASCII code's digits and Latin letters in their full-width forms.
func inFullWidth(code string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= '0' && r <= '9':
			return '０' + (r - '0')
		case r >= 'a' && r <= 'z':
			return 'ａ' + (r - 'a')
		case r >= 'A' && r <= 'Z':
			return 'Ａ' + (r - 'A')
		}
		return r
	}, code)
}

func TestAuthOTP_AFullWidthCodeSignsIn(t *testing.T) {
	client, redirectURI := createPublicClientAt(t, record.ACRLevel2Mandatory)
	_, _, user, password, otpSecret := createLevel2MandatoryUser(t, true)

	httpClient, page, otpURL := startOTPCeremony(t, client, redirectURI, user, password, "")
	resp := authenticateWithOTP(t, httpClient, otpURL, page, inFullWidth(otptest.Code(t, otpSecret, time.Now())))
	_ = page.Body.Close()
	idClaims, accessClaims := finishSignIn(t, httpClient, resp)

	for name, claims := range map[string]map[string]interface{}{"id_token": idClaims, "access_token": accessClaims} {
		assert.Equal(t, "urn:goiabada:level2_mandatory", claims["acr"], "%s's acr", name)
		assert.Equal(t, []interface{}{"pwd", "otp"}, claims["amr"], "%s's amr", name)
	}
	stored, err := database.GetUserByID(context.Background(), nil, user.ID)
	require.NoError(t, err)
	assert.NotZero(t, stored.LastOTPStep, "the code's step was claimed")
}

func TestAuthOTP_AnArabicIndicCodeSetsUpTheAuthenticator(t *testing.T) {
	client, redirectURI, user, password, _ := createLevel2MandatoryUser(t, false)

	httpClient, page, otpURL := startOTPCeremony(t, client, redirectURI, user, password, "")
	secret := getOTPSecretFromEnrollmentPage(t, page)
	typed := strings.Map(func(r rune) rune { return '٠' + (r - '0') }, otptest.Code(t, secret, time.Now()))
	resp := passSetupRecoveryCodes(t, httpClient, authenticateWithOTP(t, httpClient, otpURL, page, typed))
	_ = page.Body.Close()
	assertRedirect(t, resp, "/auth/completed")
	_ = resp.Body.Close()

	stored, err := database.GetUserByID(context.Background(), nil, user.ID)
	require.NoError(t, err)
	assert.True(t, stored.OTPEnabled, "the authenticator is set up")
}

func TestAuthOTP_AWrongFullWidthCodeCountsAsAFailedAttempt(t *testing.T) {
	client, redirectURI, user, password, otpSecret := createLevel2MandatoryUser(t, true)

	httpClient, page, otpURL := startOTPCeremony(t, client, redirectURI, user, password, "")
	// The code of two steps back, outside the window: well formed, and wrong.
	wrong := otptest.Code(t, otpSecret, time.Now().Add(-2*30*time.Second))
	if wrong == otptest.Code(t, otpSecret, time.Now()) || wrong == otptest.Code(t, otpSecret, time.Now().Add(-30*time.Second)) {
		t.Skip("the code two steps back is also one the window accepts, about twice in a million runs")
	}
	resp := authenticateWithOTP(t, httpClient, otpURL, page, inFullWidth(wrong))
	_ = page.Body.Close()
	assertOTPRefused(t, resp)
	_ = resp.Body.Close()

	stored, err := database.GetUserByID(context.Background(), nil, user.ID)
	require.NoError(t, err)
	assert.EqualValues(t, 1, stored.OTPConsecutiveFailures, "the wrong code counts against the authenticator")
	assert.Zero(t, stored.LastOTPStep, "and claims no step")
}

func TestRecoveryCode_AFullWidthCodeSignsIn(t *testing.T) {
	client, redirectURI := createPublicClientAt(t, record.ACRLevel2Mandatory)
	_, _, user, password, _ := createLevel2MandatoryUser(t, true)
	codes := giveRecoveryCodes(t, user.ID)

	httpClient, resp, _ := recoveryCodeSignInTo(t, client, redirectURI, user, password,
		strings.ToUpper(inFullWidth(codes[2])))
	idClaims, _ := finishSignIn(t, httpClient, resp)

	assert.Equal(t, []interface{}{"pwd", "recovery_code"}, idClaims["amr"])
	assert.Equal(t, 9, unusedRecoveryCodesForTest(t, user.ID), "the code is spent")
}

// A code typed wholly in full-width mode has full-width hyphens between its groups, and one whose
// hyphens are typed in kana mode has the long-vowel mark: each is taken out as the hyphen is, and the
// code signs in. A wrong letter between full-width hyphens is still refused.
func TestRecoveryCode_ACodeWithJapaneseHyphensSignsIn(t *testing.T) {
	client, redirectURI := createPublicClientAt(t, record.ACRLevel2Mandatory)
	_, _, user, password, _ := createLevel2MandatoryUser(t, true)
	codes := giveRecoveryCodes(t, user.ID)

	for i, hyphen := range []string{"－", "ー"} {
		httpClient, resp, _ := recoveryCodeSignInTo(t, client, redirectURI, user, password,
			strings.ReplaceAll(inFullWidth(codes[i]), "-", hyphen))
		idClaims, _ := finishSignIn(t, httpClient, resp)
		assert.Equal(t, []interface{}{"pwd", "recovery_code"}, idClaims["amr"], "%q", hyphen)
	}

	wrong := []rune(codes[2])
	if wrong[len(wrong)-1] == 'a' {
		wrong[len(wrong)-1] = 'b'
	} else {
		wrong[len(wrong)-1] = 'a'
	}
	_, resp, _ := recoveryCodeSignInTo(t, client, redirectURI, user, password,
		strings.ReplaceAll(inFullWidth(string(wrong)), "-", "－"))
	assertRecoveryCodeRefused(t, resp)

	assert.Equal(t, 8, unusedRecoveryCodesForTest(t, user.ID), "the two codes that signed in are spent")
}

func TestAPIAccountOTPPut_Enable_AFullWidthCodeEnables(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)
	userID := getAccountUserID(t, accessToken)
	setUserPasswordForOTP(t, userID, "Correct1!")
	resetOTPStateForTest(t, userID)

	issued := getOTPEnrollment(t, accessToken)
	code := otptest.Code(t, issued.SecretKey, time.Now())

	// A space around the code is refused by the six-digit check before the comparison, as it is
	// for an ASCII code, and claims nothing.
	status, body := putAccountOTP(t, accessToken, api.UpdateAccountOTPRequest{
		Enabled: true, Password: "Correct1!", OTPCode: " " + inFullWidth(code),
	})
	require.Equal(t, http.StatusBadRequest, status, body)
	assert.Contains(t, body, "INVALID_OTP_CODE")
	assert.Contains(t, body, "The code is 6 digits. Enter the one your authenticator app shows.")

	status, body = putAccountOTP(t, accessToken, api.UpdateAccountOTPRequest{
		Enabled: true, Password: "Correct1!", OTPCode: inFullWidth(code),
	})
	require.Equal(t, http.StatusOK, status, body)
	stored, err := database.GetUserByID(context.Background(), nil, userID)
	require.NoError(t, err)
	assert.True(t, stored.OTPEnabled)
}
