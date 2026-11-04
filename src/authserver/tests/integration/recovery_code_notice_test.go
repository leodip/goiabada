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

// The recovery-code and lockout notices over real SMTP (#724, #737). A sign-in with a recovery code
// tells the account's verified address how many unused codes are left. A new set of recovery codes
// made on the Account pages tells it. The wrong code that disables the authenticator, after 100 in
// a row, tells it, once per lockout. Each arrives once, in the user's language, with no link and no
// code. An address the account never verified is told nothing.

const (
	recoveryCodeUsedSubjectEn      = "A recovery code was used to sign in"
	recoveryCodesReplacedSubjectEn = "Your recovery codes were replaced"
	otpLockoutSubjectEn            = "Your authenticator was disabled after too many wrong codes"
)

// enrolledNoticeUser is a user with an authenticator and a set of recovery codes, signing in at a
// level 3 client, with a plus address, verified or not, and the locale given. It returns the codes.
func enrolledNoticeUser(t *testing.T, locale string, verified bool) (*record.Client, *record.RedirectURI,
	*record.User, string, string, []string) {
	t.Helper()
	client, redirectUri, user, password, secret := createLevel2MandatoryUser(t, true)
	user.Email = plusAddress()
	user.EmailVerified = verified
	user.Locale = locale
	require.NoError(t, database.UpdateUser(context.Background(), nil, user))
	return client, redirectUri, user, password, secret, giveRecoveryCodes(t, user.Id)
}

// assertNoCodeIn asserts that none of codes appears in the message.
func assertNoCodeIn(t *testing.T, html, text string, codes []string) {
	t.Helper()
	for _, code := range codes {
		assert.NotContains(t, html+text, code, "the notice carries no recovery code")
	}
}

func TestRecoveryCode_SigningInTellsTheUserHowManyCodesAreLeft(t *testing.T) {
	useMailpitSMTP(t)

	for _, tc := range []struct {
		locale  string
		subject string
		left    string
		advice  string
	}{
		{"en", recoveryCodeUsedSubjectEn, "You have 9 unused recovery codes left.",
			"turn two-factor authentication off and set up a new authenticator"},
		{"es", "Se ha usado un código de recuperación para iniciar sesión", "Te quedan 9 códigos de recuperación sin usar.",
			"desactiva la autenticación de dos factores y configura una nueva aplicación de autenticación"}, //nolint:misspell // the es catalog's text: "factores" is Spanish, not a misspelling of "factors"
	} {
		t.Run(tc.locale, func(t *testing.T) {
			client, redirectUri, user, password, _, codes := enrolledNoticeUser(t, tc.locale, true)

			_, resp, _ := recoveryCodeSignInTo(t, client, redirectUri, user, password, codes[0])
			assertRedirect(t, resp, "/auth/completed")
			_ = resp.Body.Close()

			messages := awaitMailTo(t, user.Email)
			require.Len(t, messages, 1, "the account's address is told exactly once")
			assert.Equal(t, tc.subject, messages[0].Subject)
			assert.Contains(t, messages[0].HTML, tc.left, "the notice says how many unused codes are left")
			assert.Contains(t, messages[0].HTML, tc.advice, "the notice says to set up a new authenticator")
			assert.NotContains(t, messages[0].HTML, "href", "the notice carries no link")
			assertNoCodeIn(t, messages[0].HTML, messages[0].Text, codes)
		})
	}
}

// The last code says none are left.
func TestRecoveryCode_SigningInWithTheLastCodeSaysNoneAreLeft(t *testing.T) {
	useMailpitSMTP(t)

	client, redirectUri, user, password, _, codes := enrolledNoticeUser(t, "en", true)
	for _, code := range codes[1:] {
		require.True(t, claimRecoveryCodeForTest(t, user.Id, code))
	}

	_, resp, _ := recoveryCodeSignInTo(t, client, redirectUri, user, password, codes[0])
	assertRedirect(t, resp, "/auth/completed")
	_ = resp.Body.Close()

	messages := awaitMailTo(t, user.Email)
	require.Len(t, messages, 1)
	assert.Contains(t, messages[0].HTML, "You have no unused recovery codes left.")
}

// A refused recovery code, and a sign-in for an unverified address, tell nothing. Their absence is
// read once a verified user's sign-in, made after them, has been told: that shows mail was on.
func TestRecoveryCode_SendsNothingWhereNoneMayGo(t *testing.T) {
	useMailpitSMTP(t)

	client, redirectUri, refusedUser, refusedPassword, _, _ := enrolledNoticeUser(t, "en", true)
	_, resp, _ := recoveryCodeSignInTo(t, client, redirectUri, refusedUser, refusedPassword, "0000-0000-0000-0000-0000-0000")
	assertRecoveryCodeRefused(t, resp)

	unverifiedClient, unverifiedRedirect, unverified, unverifiedPassword, _, unverifiedCodes := enrolledNoticeUser(t, "en", false)
	_, resp, _ = recoveryCodeSignInTo(t, unverifiedClient, unverifiedRedirect, unverified, unverifiedPassword, unverifiedCodes[0])
	assertRedirect(t, resp, "/auth/completed")
	_ = resp.Body.Close()

	verifiedClient, verifiedRedirect, verified, verifiedPassword, _, verifiedCodes := enrolledNoticeUser(t, "en", true)
	_, resp, _ = recoveryCodeSignInTo(t, verifiedClient, verifiedRedirect, verified, verifiedPassword, verifiedCodes[0])
	assertRedirect(t, resp, "/auth/completed")
	_ = resp.Body.Close()

	require.Len(t, awaitMailWithSubject(t, verified.Email, recoveryCodeUsedSubjectEn, 1), 1,
		"the verified user is told, so mail was on")
	assert.Empty(t, sentTo(t, refusedUser.Email), "a refused code tells nothing")
	assert.Empty(t, sentTo(t, unverified.Email), "an unverified address is sent nothing")
}

func TestAPIAccountRecoveryCodesPost_TellsTheUserANewSetWasMade(t *testing.T) {
	useMailpitSMTP(t)

	for _, tc := range []struct {
		locale   string
		subject  string
		sentence string
	}{
		{"en", recoveryCodesReplacedSubjectEn, "Your previous recovery codes no longer work, used or not."},
		{"it", "I tuoi codici di recupero sono stati sostituiti", "I codici di recupero precedenti non funzionano più, usati o no."},
	} {
		t.Run(tc.locale, func(t *testing.T) {
			accessToken, u := passwordNoticeUser(t, tc.locale, true)
			oldCodes := setUpAuthenticatorOnTheAccountPages(t, accessToken)

			status, body := postRecoveryCodes(t, accessToken, passwordNoticeCurrent)
			require.Equal(t, http.StatusOK, status, string(body))
			var created api.CreateAccountRecoveryCodesResponse
			require.NoError(t, json.Unmarshal(body, &created))
			require.Len(t, created.RecoveryCodes, 10)

			replaced := awaitMailWithSubject(t, u.Email, tc.subject, 1)
			require.Len(t, replaced, 1, "the account's address is told exactly once")
			assert.Contains(t, replaced[0].HTML, tc.sentence)
			assert.NotContains(t, replaced[0].HTML, "href", "the notice carries no link")
			assertNoCodeIn(t, replaced[0].HTML, replaced[0].Text, append(oldCodes, created.RecoveryCodes...))
			assert.Len(t, messagesTo(t, u.Email), 2, "the set-up notice, then this one")
		})
	}
}

// A new set refused for a wrong password, and one for an unverified address, tell nothing, read
// once a verified user's new set, made after them, has been told.
func TestAPIAccountRecoveryCodesPost_SendsNothingWhereNoneMayGo(t *testing.T) {
	useMailpitSMTP(t)

	refusedToken, refused := passwordNoticeUser(t, "en", true)
	setUpAuthenticatorOnTheAccountPages(t, refusedToken)
	status, body := postRecoveryCodes(t, refusedToken, "Not-the-password-1")
	require.Equal(t, http.StatusBadRequest, status, string(body))

	unverifiedToken, unverified := passwordNoticeUser(t, "en", false)
	setUpAuthenticatorOnTheAccountPages(t, unverifiedToken)
	status, body = postRecoveryCodes(t, unverifiedToken, passwordNoticeCurrent)
	require.Equal(t, http.StatusOK, status, string(body))

	verifiedToken, verified := passwordNoticeUser(t, "en", true)
	setUpAuthenticatorOnTheAccountPages(t, verifiedToken)
	status, body = postRecoveryCodes(t, verifiedToken, passwordNoticeCurrent)
	require.Equal(t, http.StatusOK, status, string(body))

	require.Len(t, awaitMailWithSubject(t, verified.Email, recoveryCodesReplacedSubjectEn, 1), 1,
		"the verified user is told, so mail was on")
	for _, message := range messagesTo(t, refused.Email) {
		assert.NotEqual(t, recoveryCodesReplacedSubjectEn, message.Subject, "a refused new set tells nothing")
	}
	assert.Empty(t, sentTo(t, unverified.Email), "an unverified address is sent nothing")
}

// The wrong code that disables the authenticator tells the user, once: the right code refused
// after it, against an authenticator already disabled, tells nothing more. The recovery-code
// sign-in the notice points to comes after, and its own notice shows the mail that went before it
// has arrived.
func TestAuthOtp_TheRefusalThatDisablesTheAuthenticatorTellsTheUserOnce(t *testing.T) {
	useMailpitSMTP(t)

	for _, tc := range []struct {
		locale         string
		subject        string
		recoverySignIn string
		advice         string
	}{
		{"en", otpLockoutSubjectEn, recoveryCodeUsedSubjectEn, "Sign in with one of your recovery codes"},
		{"fr", "Votre application d’authentification a été bloquée après trop de codes erronés",
			"Un code de récupération a été utilisé pour vous connecter", "Connectez-vous avec l’un de vos codes de récupération"},
	} {
		t.Run(tc.locale, func(t *testing.T) {
			client, redirectUri, user, password, secret, codes := enrolledNoticeUser(t, tc.locale, true)
			// Seeded one short of the limit through the count's own statement, since reaching it
			// through the form would take 99 refusals behind the otp rate tier.
			for i := 0; i < record.OtpConsecutiveFailureLimit-1; i++ {
				disabled, err := database.IncrementUserOtpConsecutiveFailures(context.Background(), nil, user.Id,
					user.OtpConfigGeneration)
				require.NoError(t, err)
				require.False(t, disabled)
			}

			httpClient, otpPage, otpUrl := startOtpCeremony(t, client, redirectUri, user, password, "")
			right := otptest.Code(t, secret, time.Now())
			refused := authenticateWithOtp(t, httpClient, otpUrl, otpPage, wrongCodeBeside(right))
			_ = otpPage.Body.Close()
			assertOtpRefused(t, refused)
			refusedAgain := authenticateWithOtp(t, httpClient, otpUrl, refused, right)
			_ = refused.Body.Close()
			assertOtpRefused(t, refusedAgain)
			_ = refusedAgain.Body.Close()

			_, resp, _ := recoveryCodeSignInTo(t, client, redirectUri, user, password, codes[0])
			assertRedirect(t, resp, "/auth/completed")
			_ = resp.Body.Close()
			require.Len(t, awaitMailWithSubject(t, user.Email, tc.recoverySignIn, 1), 1,
				"the recovery-code sign-in after the lockout is told")

			lockout := awaitMailWithSubject(t, user.Email, tc.subject, 1)
			require.Len(t, lockout, 1, "the lockout is told exactly once")
			assert.Contains(t, lockout[0].HTML, tc.advice, "the notice says to sign in with a recovery code")
			assert.NotContains(t, lockout[0].HTML, "href", "the notice carries no link")
			assert.Len(t, messagesTo(t, user.Email), 2, "the lockout and the recovery-code sign-in, nothing more")
		})
	}
}
