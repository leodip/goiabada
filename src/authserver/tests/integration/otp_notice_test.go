package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/otp/otptest"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The two-factor notices over real SMTP (#724). Setting up an authenticator, on the Account pages
// or during a level 3 sign-in, tells the account's verified address, mentioning the recovery codes
// it came with. Turning it off on the Account pages tells it, and an administrator turning it off
// tells it an administrator did. Each arrives once, in the user's language, with no link and no
// code. An address the account never verified is told nothing.

const (
	otpEnabledSubjectEn             = "Two-factor authentication was set up"
	otpDisabledSubjectEn            = "Two-factor authentication was turned off"
	otpDisabledByAdminSubjectEn     = "An administrator turned off your two-factor authentication"
	otpEnabledRecoveryCodesSentence = "It came with a new set of recovery codes"
)

// setUpAuthenticatorOnTheAccountPages enables two-factor authentication through the Account API, as
// the console does, requires the 200 and returns the recovery codes it answered.
func setUpAuthenticatorOnTheAccountPages(t *testing.T, accessToken string) []string {
	t.Helper()
	secret := getOTPEnrollment(t, accessToken).SecretKey
	status, body := putAccountOTP(t, accessToken, api.UpdateAccountOTPRequest{
		Enabled: true, Password: passwordNoticeCurrent, OtpCode: otptest.Code(t, secret, time.Now()),
	})
	require.Equal(t, http.StatusOK, status, body)
	var enabled api.UpdateAccountOTPResponse
	require.NoError(t, json.Unmarshal([]byte(body), &enabled))
	require.Len(t, enabled.RecoveryCodes, 10)
	return enabled.RecoveryCodes
}

func TestAPIAccountOTPPut_TellsTheUserTwoFactorWasSetUpAndTurnedOff(t *testing.T) {
	useMailpitSMTP(t)

	for _, tc := range []struct {
		locale       string
		setUp        string
		codes        string
		turnedOff    string
		turnedOffMsg string
	}{
		{"en", otpEnabledSubjectEn, otpEnabledRecoveryCodesSentence,
			otpDisabledSubjectEn, "Your authenticator app and your recovery codes no longer work for signing in."},
		{"pt-BR", "A autenticação de dois fatores foi configurada", "Ela veio com um novo conjunto de códigos de recuperação",
			"A autenticação de dois fatores foi desativada", "O seu aplicativo autenticador e os seus códigos de recuperação não servem mais para entrar."},
	} {
		t.Run(tc.locale, func(t *testing.T) {
			accessToken, u := passwordNoticeUser(t, tc.locale, true)

			codes := setUpAuthenticatorOnTheAccountPages(t, accessToken)

			setUp := awaitMailWithSubject(t, u.Email, tc.setUp, 1)
			require.Len(t, setUp, 1, "the account's address is told exactly once")
			assert.Contains(t, setUp[0].HTML, tc.codes, "the notice mentions the recovery codes it came with")
			assert.NotContains(t, setUp[0].HTML, "href", "the notice carries no link")
			for _, code := range codes {
				assert.NotContains(t, setUp[0].HTML+setUp[0].Text, code, "the notice carries no recovery code")
			}

			status, body := putAccountOTP(t, accessToken, api.UpdateAccountOTPRequest{
				Enabled: false, Password: passwordNoticeCurrent})
			require.Equal(t, http.StatusOK, status, body)

			turnedOff := awaitMailWithSubject(t, u.Email, tc.turnedOff, 1)
			require.Len(t, turnedOff, 1, "the account's address is told exactly once")
			assert.Contains(t, turnedOff[0].HTML, tc.turnedOffMsg)
			assert.NotContains(t, turnedOff[0].HTML, "href", "the notice carries no link")
			assert.Len(t, messagesTo(t, u.Email), 2, "one notice for each change")
		})
	}
}

// An address the account never verified is told nothing. The notice is sent after the response,
// so its absence is read once a verified user's set-up, made after it, has been told: that shows
// mail was on. The proof ordered on completion is the handler's
// TestHandleAccountOTPPut_SendsNoNoticeWhereNoneMayGo.
func TestAPIAccountOTPPut_SendsNoNoticeToAnUnverifiedAddress(t *testing.T) {
	useMailpitSMTP(t)

	unverifiedToken, unverified := passwordNoticeUser(t, "en", false)
	verifiedToken, verified := passwordNoticeUser(t, "en", true)

	setUpAuthenticatorOnTheAccountPages(t, unverifiedToken)
	setUpAuthenticatorOnTheAccountPages(t, verifiedToken)

	require.Len(t, awaitMailWithSubject(t, verified.Email, otpEnabledSubjectEn, 1), 1,
		"the verified user is told, so mail was on")
	assert.Empty(t, sentTo(t, unverified.Email), "an unverified address is sent nothing")
}

func TestAPIUserOTPPut_TellsTheUserAnAdministratorTurnedItOff(t *testing.T) {
	useMailpitSMTP(t)

	for _, tc := range []struct {
		locale  string
		subject string
		advice  string
	}{
		{"en", otpDisabledByAdminSubjectEn, "If you weren't expecting it, contact your administrator."},
		{"fr", "Un administrateur a désactivé votre authentification à deux facteurs",
			"Si vous ne vous y attendiez pas, contactez votre administrateur."},
	} {
		t.Run(tc.locale, func(t *testing.T) {
			user := adminNoticeUser(t, tc.locale, "the-hash")
			user.OTPEnabled = true
			user.OTPSecretEncrypted = encryptOTPSecretForTest(t, newOTPSecretForTest(t, user.Email))
			require.NoError(t, database.UpdateUser(context.Background(), nil, user))

			removeAuthenticatorAsAdministrator(t, user.Id)

			messages := awaitMailTo(t, user.Email)
			require.Len(t, messages, 1, "the account's address is told exactly once")
			assert.Equal(t, tc.subject, messages[0].Subject)
			assert.Contains(t, messages[0].HTML, tc.advice)
			assert.NotContains(t, messages[0].HTML, "href", "the notice carries no link")
		})
	}
}

// signInSettingUpAnAuthenticator signs user in at a level 3 client, setting up an authenticator on
// the code step, and returns the recovery codes the next page shows.
func signInSettingUpAnAuthenticator(t *testing.T, client *record.Client, redirectUri *record.RedirectURI,
	user *record.User, password string) []string {
	t.Helper()
	httpClient, setupPage, otpUrl := startOtpCeremony(t, client, redirectUri, user, password, "")
	secret := getOtpSecretFromEnrollmentPage(t, setupPage)
	accepted := authenticateWithOtp(t, httpClient, otpUrl, setupPage, otptest.Code(t, secret, time.Now()))
	_ = setupPage.Body.Close()
	location := assertRedirect(t, accepted, "/auth/recovery-codes")
	_ = accepted.Body.Close()
	page := loadPage(t, httpClient, location)
	defer func() { _ = page.Body.Close() }()
	require.Equal(t, http.StatusOK, page.StatusCode)
	codes := recoveryCodesOnPage(t, page)
	require.Len(t, codes, 10)
	return codes
}

// level3NoticeUser is a user with no authenticator, signing in at a level 3 client, with the
// address verified or not and the locale given.
func level3NoticeUser(t *testing.T, locale string, verified bool) (*record.Client, *record.RedirectURI, *record.User, string) {
	t.Helper()
	client, redirectUri, user, password, _ := createLevel2MandatoryUser(t, false)
	user.Email = plusAddress()
	user.EmailVerified = verified
	user.Locale = locale
	require.NoError(t, database.UpdateUser(context.Background(), nil, user))
	return client, redirectUri, user, password
}

func TestOtpCeremony_SettingUpAnAuthenticatorDuringTheSignInTellsTheUser(t *testing.T) {
	useMailpitSMTP(t)

	for _, tc := range []struct {
		locale  string
		subject string
		codes   string
	}{
		{"en", otpEnabledSubjectEn, otpEnabledRecoveryCodesSentence},
		{"de", "Die Zwei-Faktor-Authentifizierung wurde eingerichtet", "Dazu wurde ein neuer Satz Wiederherstellungscodes erstellt"},
	} {
		t.Run(tc.locale, func(t *testing.T) {
			client, redirectUri, user, password := level3NoticeUser(t, tc.locale, true)

			codes := signInSettingUpAnAuthenticator(t, client, redirectUri, user, password)

			messages := awaitMailTo(t, user.Email)
			require.Len(t, messages, 1, "the account's address is told exactly once")
			assert.Equal(t, tc.subject, messages[0].Subject)
			assert.Contains(t, messages[0].HTML, tc.codes, "the notice mentions the recovery codes it came with")
			assert.NotContains(t, messages[0].HTML, "href", "the notice carries no link")
			for _, code := range codes {
				assert.NotContains(t, messages[0].HTML+messages[0].Text, code, "the notice carries no recovery code")
			}
		})
	}
}

// A sign-in that sets up an authenticator for an unverified address tells it nothing, read once a
// verified user's set-up, made after it, has been told.
func TestOtpCeremony_SettingUpAnAuthenticatorSendsNothingToAnUnverifiedAddress(t *testing.T) {
	useMailpitSMTP(t)

	client, redirectUri, unverified, unverifiedPassword := level3NoticeUser(t, "en", false)
	verifiedClient, verifiedRedirectUri, verified, verifiedPassword := level3NoticeUser(t, "en", true)

	signInSettingUpAnAuthenticator(t, client, redirectUri, unverified, unverifiedPassword)
	signInSettingUpAnAuthenticator(t, verifiedClient, verifiedRedirectUri, verified, verifiedPassword)

	require.Len(t, awaitMailWithSubject(t, verified.Email, otpEnabledSubjectEn, 1), 1,
		"the verified user is told, so mail was on")
	assert.Empty(t, sentTo(t, unverified.Email), "an unverified address is sent nothing")
}
