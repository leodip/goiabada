package integration

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/authserver/internal/otp/otptest"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The sign-in setup shows its recovery codes (#257 decision 14). A user who sets up an authenticator
// during a level 3 sign-in gets the set it came with on one extra page, after the accepted setup
// code and before the sign-in goes on: the code's POST answers 303 to /auth/recovery-codes, which
// shows the ten codes once, and its Continue answers 303 to /auth/completed. A reload of the page
// shows that the codes were already shown, with the same Continue.

// recoveryCodesOnPage returns the codes a page lists in its #recovery-codes list, none on a page
// that lists none. The body is re-buffered, so a later reader of the same response still sees it.
func recoveryCodesOnPage(t *testing.T, resp *http.Response) []string {
	t.Helper()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	resp.Body = io.NopCloser(bytes.NewReader(body))
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	require.NoError(t, err)

	var codes []string
	doc.Find("#recovery-codes li").Each(func(_ int, item *goquery.Selection) {
		codes = append(codes, strings.TrimSpace(item.Text()))
	})
	return codes
}

// continuePastRecoveryCodes submits the Continue form of the recovery-codes page, naming the
// ceremony the page names.
func continuePastRecoveryCodes(t *testing.T, httpClient *http.Client, codesPage *http.Response) *http.Response {
	t.Helper()

	destUrl := appConfig.AuthServer.BaseURL + "/auth/recovery-codes"
	request, err := http.NewRequest(http.MethodPost, destUrl, strings.NewReader(url.Values{
		"ceremonyId": {getCeremonyIdFromPage(t, codesPage)},
	}.Encode()))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Referer", destUrl)
	request.Header.Set("Origin", appConfig.AuthServer.BaseURL)

	resp, err := httpClient.Do(request)
	require.NoError(t, err)
	return resp
}

// passSetupRecoveryCodes is what a user who just set up an authenticator during a sign-in does with
// the page that follows: accepted is the answer to the setup code, which must send them to the
// recovery-codes page; the page must list ten codes, and its Continue is submitted. The answer to
// Continue is returned, for the caller to follow to /auth/completed as it followed the setup code
// before the page existed. accepted is closed.
func passSetupRecoveryCodes(t *testing.T, httpClient *http.Client, accepted *http.Response) *http.Response {
	t.Helper()

	location := assertRedirect(t, accepted, "/auth/recovery-codes")
	_ = accepted.Body.Close()
	page := loadPage(t, httpClient, location)
	defer func() { _ = page.Body.Close() }()
	require.Equal(t, http.StatusOK, page.StatusCode)
	require.Len(t, recoveryCodesOnPage(t, page), 10, "the page after the setup code shows the set")
	return continuePastRecoveryCodes(t, httpClient, page)
}

// TestSetupRecoveryCodes_AreShownOnceBeforeTheSignInGoesOn sets up an authenticator during a level 3
// sign-in. The accepted code answers 303 to the recovery-codes page, which lists the ten codes the
// account now holds, each as it is typed, and is not storable. A reload lists none and says they
// were already shown; /auth/completed is not reached until Continue, which answers 303 to it, and
// the sign-in then finishes with the code that set up the authenticator in its amr. A code the page
// showed then signs in on its own.
func TestSetupRecoveryCodes_AreShownOnceBeforeTheSignInGoesOn(t *testing.T) {
	client, redirectUri := createPublicClientAt(t, record.AcrLevel2Mandatory)
	_, _, user, password, _ := createLevel2MandatoryUser(t, false)

	httpClient, setupPage, otpUrl := startOtpCeremony(t, client, redirectUri, user, password, "")
	secret := getOtpSecretFromEnrollmentPage(t, setupPage)
	accepted := authenticateWithOtp(t, httpClient, otpUrl, setupPage, otptest.Code(t, secret, time.Now()))
	_ = setupPage.Body.Close()

	codesLocation := assertRedirect(t, accepted, "/auth/recovery-codes")
	_ = accepted.Body.Close()

	page := loadPage(t, httpClient, codesLocation)
	defer func() { _ = page.Body.Close() }()
	require.Equal(t, http.StatusOK, page.StatusCode)
	assertNotStorable(t, page, "the page that shows the recovery codes")
	codes := recoveryCodesOnPage(t, page)
	require.Len(t, codes, 10)
	for _, code := range codes {
		assert.Regexp(t, `^[0-9a-hjkmnp-tv-z]{4}(-[0-9a-hjkmnp-tv-z]{4}){5}$`, code)
		// The set stores the SHA-256 of each code's 24 characters (decision 2).
		stored, err := database.UserRecoveryCodeExists(context.Background(), nil, user.Id,
			hashutil.HashString(strings.ReplaceAll(code, "-", "")))
		require.NoError(t, err)
		assert.True(t, stored, "the page shows a code of the account's set: %s", code)
	}
	assert.Equal(t, 10, unusedRecoveryCodesForTest(t, user.Id))

	reloaded := loadPage(t, httpClient, codesLocation)
	defer func() { _ = reloaded.Body.Close() }()
	require.Equal(t, http.StatusOK, reloaded.StatusCode)
	assert.Empty(t, recoveryCodesOnPage(t, reloaded), "a reload does not show the codes again")
	reloadedBody, err := io.ReadAll(reloaded.Body)
	require.NoError(t, err)
	reloaded.Body = io.NopCloser(bytes.NewReader(reloadedBody))
	for _, code := range codes {
		assert.NotContains(t, string(reloadedBody), code)
	}
	assert.Contains(t, string(reloadedBody), "Your recovery codes were already shown")

	// The step before Continue is this one: /auth/completed refuses the ceremony until then.
	skipped := loadPage(t, httpClient, stepURLOfTheSameCeremony(t, codesLocation, "/auth/completed"))
	_ = skipped.Body.Close()
	assert.Equal(t, http.StatusBadRequest, skipped.StatusCode)

	continued := continuePastRecoveryCodes(t, httpClient, reloaded)
	idClaims, _ := finishSignIn(t, httpClient, continued)
	assert.Equal(t, "urn:goiabada:level2_mandatory", idClaims["acr"])
	assert.Equal(t, []interface{}{"pwd", "otp"}, idClaims["amr"])

	// A code the page showed is a code that signs in.
	signIn, resp, _ := recoveryCodeSignInTo(t, client, redirectUri, user, password, codes[7])
	idClaims, _ = finishSignIn(t, signIn, resp)
	assert.Equal(t, []interface{}{"pwd", "recovery_code"}, idClaims["amr"])
	assert.Equal(t, 9, unusedRecoveryCodesForTest(t, user.Id))
}
