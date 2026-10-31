package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Signing in with a recovery code, end to end (#257 decisions 4 to 7 and 10): the code form's
// "Use a recovery code instead" link, the recovery-code form it opens on the same step, and a code
// taken there in place of the authenticator's, down to the tokens' acr and amr. A recovery code is
// a full second factor, claimed once, refused alike whether wrong or spent, working while the
// authenticator is disabled, and backed by the authenticator as a code is, so removing the
// authenticator lowers its sessions and restarts a sign-in in flight (#542).

const incorrectRecoveryCode = "That recovery code isn't right, or it was already used."

// giveRecoveryCodes stores a set of ten codes for the user, as setting up an authenticator does, and
// returns them as shown: 24 characters of Crockford base32 in six groups of four. What the set
// stores for each is the SHA-256, in hex, of its 24 characters with the hyphens taken out (decision
// 2).
func giveRecoveryCodes(t *testing.T, userId int64) []string {
	t.Helper()

	const alphabet = "0123456789abcdefghjkmnpqrstvwxyz"
	codes := make([]string, 10)
	hashes := make([]string, 10)
	for i := range codes {
		random := make([]byte, 24)
		_, err := rand.Read(random)
		require.NoError(t, err)
		var b strings.Builder
		for j, r := range random {
			if j > 0 && j%4 == 0 {
				b.WriteByte('-')
			}
			b.WriteByte(alphabet[r&0x1f])
		}
		codes[i] = b.String()
		hashes[i] = hashutil.HashString(strings.ReplaceAll(codes[i], "-", ""))
	}
	ctx := context.Background()
	require.NoError(t, database.RunInTransaction(ctx, func(tx *sql.Tx) error {
		return database.ReplaceUserRecoveryCodes(ctx, tx, userId, hashes)
	}))
	return codes
}

// createPublicClientAt creates a public client asking for level, which redeems its codes with
// testCodeVerifier alone.
func createPublicClientAt(t *testing.T, level record.AcrLevel) (*record.Client, *record.RedirectURI) {
	t.Helper()

	client := &record.Client{
		ClientIdentifier:         "test-client-" + fake.LetterN(8),
		Enabled:                  true,
		IsPublic:                 true,
		AuthorizationCodeEnabled: true,
		DefaultAcrLevel:          level,
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, client))
	redirectUri := &record.RedirectURI{ClientId: client.Id, URI: fake.URL()}
	require.NoError(t, database.CreateRedirectURI(context.Background(), nil, redirectUri))
	return client, redirectUri
}

// openRecoveryCodeForm follows the code form's "Use a recovery code instead" link, which the code
// form shows to every user with an authenticator, and returns the recovery-code form. codePage is
// closed.
func openRecoveryCodeForm(t *testing.T, httpClient *http.Client, codePage *http.Response) *http.Response {
	t.Helper()

	defer func() { _ = codePage.Body.Close() }()
	require.Equal(t, http.StatusOK, codePage.StatusCode)
	doc, err := goquery.NewDocumentFromReader(codePage.Body)
	require.NoError(t, err)
	require.Equal(t, 1, doc.Find(`input[name="otp"]`).Length(), "the code form")
	link := doc.Find(`a[href*="form=recovery-code"]`)
	require.Equal(t, 1, link.Length(), "the code form links to the recovery-code form")
	assert.Equal(t, "Use a recovery code instead", strings.TrimSpace(link.Text()))
	href, _ := link.Attr("href")

	form := loadPage(t, httpClient, appConfig.AuthServer.BaseURL+href)
	require.Equal(t, http.StatusOK, form.StatusCode)
	return form
}

// submitRecoveryCode posts code from the recovery-code form, naming the ceremony the form names.
func submitRecoveryCode(t *testing.T, httpClient *http.Client, otpUrl string, formPage *http.Response,
	code string) *http.Response {
	t.Helper()

	resp, err := httpClient.Do(recoveryCodeRequest(t, otpUrl, formPage, code))
	require.NoError(t, err)
	return resp
}

// recoveryCodeRequest is the POST submitRecoveryCode sends.
func recoveryCodeRequest(t *testing.T, otpUrl string, formPage *http.Response, code string) *http.Request {
	t.Helper()

	body, err := io.ReadAll(formPage.Body)
	require.NoError(t, err)
	formPage.Body = io.NopCloser(bytes.NewReader(body))
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	require.NoError(t, err)
	require.Equal(t, 1, doc.Find(`input[name="recoveryCode"]`).Length(), "the recovery-code form")
	formPage.Body = io.NopCloser(bytes.NewReader(body))

	request, err := http.NewRequest(http.MethodPost, otpUrl, strings.NewReader(url.Values{
		"recoveryCode": {code},
		"ceremonyId":   {getCeremonyIdFromPage(t, formPage)},
	}.Encode()))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", appConfig.AuthServer.BaseURL)
	return request
}

// assertRecoveryCodeRefused asserts the recovery-code form drawn again with its refusal.
func assertRecoveryCodeRefused(t *testing.T, resp *http.Response) {
	t.Helper()

	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode, "refused, not accepted: Location %q", resp.Header.Get("Location"))
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, incorrectRecoveryCode, strings.TrimSpace(doc.Find(`[role="alert"]`).Text()))
	assert.Equal(t, 1, doc.Find(`input[name="recoveryCode"]`).Length(), "on the recovery-code form")
}

// recoveryCodeSignInTo starts a ceremony at client for user, opens the recovery-code form and
// submits code, returning the browser, the answer and the URL the form posts to.
func recoveryCodeSignInTo(t *testing.T, client *record.Client, redirectUri *record.RedirectURI, user *record.User,
	password string, code string) (*http.Client, *http.Response, string) {
	t.Helper()

	httpClient, codePage, otpUrl := startOtpCeremony(t, client, redirectUri, user, password, "")
	form := openRecoveryCodeForm(t, httpClient, codePage)
	resp := submitRecoveryCode(t, httpClient, otpUrl, form, code)
	_ = form.Body.Close()
	return httpClient, resp, otpUrl
}

// finishSignIn follows an accepted code through /auth/completed and /auth/issue, and redeems the
// code the client is answered with, returning the ID token's and the access token's claims.
func finishSignIn(t *testing.T, httpClient *http.Client, accepted *http.Response) (idClaims, accessClaims map[string]interface{}) {
	t.Helper()

	location := assertRedirect(t, accepted, "/auth/completed")
	_ = accepted.Body.Close()
	resp := loadPage(t, httpClient, location)
	location = assertRedirect(t, resp, "/auth/issue")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, location)
	code := issuedCode(t, resp)
	_ = resp.Body.Close()
	// The stored code holds only its hash, so the value redeemed is the one the client was sent.
	answered, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)

	tokens := postToTokenEndpoint(t, httpClient, appConfig.AuthServer.BaseURL+"/auth/token/", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {answered.Query().Get("code")},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {testCodeVerifier},
	})
	require.Nil(t, tokens["error"], "unexpected refusal at redemption: %v", tokens["error_description"])
	return decodeJWTPayload(t, tokens["id_token"].(string)), decodeJWTPayload(t, tokens["access_token"].(string))
}

// recoveryCodeEventsFor returns the details of every audit entry of event naming the user.
func recoveryCodeEventsFor(t *testing.T, event string, userId int64) []map[string]any {
	t.Helper()

	adminToken, _ := createAdminClientWithToken(t)
	logs, resp := getAuditLogs(t, adminToken, "auditEvent="+event+"&size=200")
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var found []map[string]any
	for _, entry := range logs.AuditLogs {
		var details map[string]any
		require.NoError(t, json.Unmarshal([]byte(entry.Details), &details))
		if id, ok := details["user_id"].(float64); ok && int64(id) == userId {
			found = append(found, details)
		}
	}
	return found
}

// TestRecoveryCode_SignsInAtLevel3: at a level 3 client, a user with an authenticator signs in with a
// recovery code, typed in capitals with spaces for its hyphens. The tokens say level 3, the level an
// authenticator code reaches, and amr ["pwd","recovery_code"]: the code the user entered, not an
// authenticator code they never did (decision 5). The code is spent, nine are left, the session
// claims the same, and the audit log records the sign-in with the count and never the code.
func TestRecoveryCode_SignsInAtLevel3(t *testing.T) {
	requireDatabaseAuditLogs(t)
	client, redirectUri := createPublicClientAt(t, record.AcrLevel2Mandatory)
	_, _, user, password, _ := createLevel2MandatoryUser(t, true)
	codes := giveRecoveryCodes(t, user.Id)

	typed := strings.ToUpper(strings.ReplaceAll(codes[3], "-", " "))
	httpClient, resp, _ := recoveryCodeSignInTo(t, client, redirectUri, user, password, typed)
	idClaims, accessClaims := finishSignIn(t, httpClient, resp)

	for name, claims := range map[string]map[string]interface{}{"id_token": idClaims, "access_token": accessClaims} {
		assert.Equal(t, "urn:goiabada:level2_mandatory", claims["acr"], "%s's acr", name)
		assert.Equal(t, []interface{}{"pwd", "recovery_code"}, claims["amr"], "%s's amr", name)
	}

	assert.Equal(t, 9, unusedRecoveryCodesForTest(t, user.Id))
	sessions, err := database.GetUserSessionsByUserId(context.Background(), nil, user.Id)
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	assert.Equal(t, record.AcrLevel2Mandatory, sessions[0].AcrLevel)
	assert.Equal(t, "pwd recovery_code", sessions[0].AuthMethods)

	events := recoveryCodeEventsFor(t, audit.EventAuthSuccessRecoveryCode, user.Id)
	require.Len(t, events, 1)
	assert.Equal(t, map[string]any{"user_id": float64(user.Id), "remaining": float64(9)}, events[0],
		"the user and the count, never the code or its hash")
	assert.Empty(t, recoveryCodeEventsFor(t, audit.EventAuthSuccessOtp, user.Id),
		"a recovery-code sign-in is not counted as an authenticator sign-in")
}

// TestRecoveryCode_SatisfiesLevel2Optional: the admin console's own level, which asks a user with an
// authenticator for a code, takes a recovery code too, so a user who lost their phone reaches My
// Account (decision 4).
func TestRecoveryCode_SatisfiesLevel2Optional(t *testing.T) {
	client, redirectUri := createPublicClientAt(t, record.AcrLevel2Optional)
	_, _, user, password, _ := createLevel2MandatoryUser(t, true)
	codes := giveRecoveryCodes(t, user.Id)

	httpClient, resp, _ := recoveryCodeSignInTo(t, client, redirectUri, user, password, codes[0])
	idClaims, _ := finishSignIn(t, httpClient, resp)

	assert.Equal(t, "urn:goiabada:level2_optional", idClaims["acr"])
	assert.Equal(t, []interface{}{"pwd", "recovery_code"}, idClaims["amr"])
}

// TestRecoveryCode_ACodeWorksOnce: a code that signed in is refused at the next sign-in with the
// answer a wrong code gets, and audited as a replay beside the failure. The count stays at nine.
func TestRecoveryCode_ACodeWorksOnce(t *testing.T) {
	requireDatabaseAuditLogs(t)
	client, redirectUri, user, password, _ := createLevel2MandatoryUser(t, true)
	codes := giveRecoveryCodes(t, user.Id)

	_, resp, _ := recoveryCodeSignInTo(t, client, redirectUri, user, password, codes[5])
	assertRedirect(t, resp, "/auth/completed")
	_ = resp.Body.Close()

	_, resp, _ = recoveryCodeSignInTo(t, client, redirectUri, user, password, codes[5])
	assertRecoveryCodeRefused(t, resp)

	assert.Equal(t, 9, unusedRecoveryCodesForTest(t, user.Id))
	replays := recoveryCodeEventsFor(t, audit.EventRecoveryCodeReplayDetected, user.Id)
	require.Len(t, replays, 1)
	assert.Equal(t, map[string]any{"user_id": float64(user.Id)}, replays[0])
	failures := recoveryCodeEventsFor(t, audit.EventAuthFailedRecoveryCode, user.Id)
	require.Len(t, failures, 1)
	assert.Equal(t, map[string]any{"user_id": float64(user.Id)}, failures[0])
}

// TestRecoveryCode_OfTwoSubmissionsOfOneCodeExactlyOneSignsIn: two browsers at the recovery-code form
// submit the same code at once. The claim is one conditional write, so one signs in and the other
// is refused (decision 3).
func TestRecoveryCode_OfTwoSubmissionsOfOneCodeExactlyOneSignsIn(t *testing.T) {
	client, redirectUri, user, password, _ := createLevel2MandatoryUser(t, true)
	codes := giveRecoveryCodes(t, user.Id)

	type browser struct {
		httpClient *http.Client
		form       *http.Response
		otpUrl     string
	}
	browsers := make([]browser, 2)
	for i := range browsers {
		httpClient, codePage, otpUrl := startOtpCeremony(t, client, redirectUri, user, password, "")
		browsers[i] = browser{httpClient, openRecoveryCodeForm(t, httpClient, codePage), otpUrl}
	}

	// The requests are built here, so the goroutines only send them.
	requests := make([]*http.Request, 2)
	for i, b := range browsers {
		requests[i] = recoveryCodeRequest(t, b.otpUrl, b.form, codes[1])
		_ = b.form.Body.Close()
	}
	statuses := make([]int, 2)
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i, b := range browsers {
		wg.Add(1)
		go func(i int, b browser) {
			defer wg.Done()
			resp, err := b.httpClient.Do(requests[i])
			if err != nil {
				errs[i] = err
				return
			}
			statuses[i] = resp.StatusCode
			_ = resp.Body.Close()
		}(i, b)
	}
	wg.Wait()
	require.NoError(t, errs[0])
	require.NoError(t, errs[1])

	assert.ElementsMatch(t, []int{http.StatusSeeOther, http.StatusOK}, statuses,
		"one signs in and the other is refused")
	assert.Equal(t, 9, unusedRecoveryCodesForTest(t, user.Id))
}

// TestRecoveryCode_ACodeOfAReplacedSetIsAWrongCode: once a new set replaces the old one, the old codes
// no longer exist, so one of them is refused as a wrong code, not audited as a replay (decision 10).
func TestRecoveryCode_ACodeOfAReplacedSetIsAWrongCode(t *testing.T) {
	requireDatabaseAuditLogs(t)
	client, redirectUri, user, password, _ := createLevel2MandatoryUser(t, true)
	old := giveRecoveryCodes(t, user.Id)
	giveRecoveryCodes(t, user.Id)

	_, resp, _ := recoveryCodeSignInTo(t, client, redirectUri, user, password, old[0])
	assertRecoveryCodeRefused(t, resp)

	assert.Equal(t, 10, unusedRecoveryCodesForTest(t, user.Id), "the new set is untouched")
	assert.Len(t, recoveryCodeEventsFor(t, audit.EventAuthFailedRecoveryCode, user.Id), 1)
	assert.Empty(t, recoveryCodeEventsFor(t, audit.EventRecoveryCodeReplayDetected, user.Id))
}

// TestRecoveryCode_WorksWhileTheAuthenticatorIsDisabled: an authenticator disabled after 100 wrong
// codes refuses every code, and a recovery code still signs in, which is the self-service way out.
// The authenticator stays disabled, its count where it was: only a new authenticator clears it
// (decision 6).
func TestRecoveryCode_WorksWhileTheAuthenticatorIsDisabled(t *testing.T) {
	client, redirectUri, user, password, _ := createLevel2MandatoryUser(t, true)
	codes := giveRecoveryCodes(t, user.Id)
	for i := 0; i < record.OtpConsecutiveFailureLimit; i++ {
		_, err := database.IncrementUserOtpConsecutiveFailures(context.Background(), nil, user.Id,
			user.OtpConfigGeneration)
		require.NoError(t, err)
	}

	// A wrong recovery code first, which counts nothing against the authenticator either.
	httpClient, codePage, otpUrl := startOtpCeremony(t, client, redirectUri, user, password, "")
	form := openRecoveryCodeForm(t, httpClient, codePage)
	refused := submitRecoveryCode(t, httpClient, otpUrl, form, strings.Repeat("0", 24))
	_ = form.Body.Close()
	body, err := io.ReadAll(refused.Body)
	require.NoError(t, err)
	refused.Body = io.NopCloser(bytes.NewReader(body))
	again := io.NopCloser(bytes.NewReader(body))
	assertRecoveryCodeRefused(t, refused)

	resp := submitRecoveryCode(t, httpClient, otpUrl, &http.Response{StatusCode: http.StatusOK, Body: again}, codes[2])
	assertRedirect(t, resp, "/auth/completed")
	_ = resp.Body.Close()

	stored, err := database.GetUserById(context.Background(), nil, user.Id)
	require.NoError(t, err)
	assert.True(t, stored.OTPEnabled)
	assert.EqualValues(t, record.OtpConsecutiveFailureLimit, stored.OtpConsecutiveFailures,
		"the authenticator stays disabled until it is rebound")
}

// TestRecoveryCode_RemovingTheAuthenticatorLowersTheSession: a recovery code is backed by the
// authenticator as a code is, so turning two-factor authentication off lowers a session it raised to
// what a password alone reaches (#542).
func TestRecoveryCode_RemovingTheAuthenticatorLowersTheSession(t *testing.T) {
	client, redirectUri, user, password, _ := createLevel2MandatoryUser(t, true)
	codes := giveRecoveryCodes(t, user.Id)
	httpClient, resp, _ := recoveryCodeSignInTo(t, client, redirectUri, user, password, codes[7])
	location := assertRedirect(t, resp, "/auth/completed")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, location)
	assertRedirect(t, resp, "/auth/issue")
	_ = resp.Body.Close()

	removeAuthenticatorAsAdministrator(t, user.Id)

	sessions, err := database.GetUserSessionsByUserId(context.Background(), nil, user.Id)
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	assert.Equal(t, record.AcrLevel2Optional, sessions[0].AcrLevel)
	assert.Equal(t, "pwd", sessions[0].AuthMethods, "the session no longer names the recovery code")
	assert.Equal(t, 0, unusedRecoveryCodesForTest(t, user.Id), "the codes went with the authenticator")
}

// TestRecoveryCode_ASignInInFlightWhenTheAuthenticatorIsRemovedStartsOver: the recovery code was
// accepted, and an administrator turns two-factor authentication off before the browser reaches
// /auth/completed. The sign-in's claim came from the authenticator removed, so it starts over from
// the password rather than creating a session that names it (#542).
func TestRecoveryCode_ASignInInFlightWhenTheAuthenticatorIsRemovedStartsOver(t *testing.T) {
	client, redirectUri, user, password, _ := createLevel2MandatoryUser(t, true)
	codes := giveRecoveryCodes(t, user.Id)
	httpClient, resp, _ := recoveryCodeSignInTo(t, client, redirectUri, user, password, codes[9])
	completedLocation := assertRedirect(t, resp, "/auth/completed")
	_ = resp.Body.Close()

	removeAuthenticatorAsAdministrator(t, user.Id)

	resp = loadPage(t, httpClient, completedLocation)
	assertRedirect(t, resp, "/auth/level1")
	_ = resp.Body.Close()

	sessions, err := database.GetUserSessionsByUserId(context.Background(), nil, user.Id)
	require.NoError(t, err)
	assert.Empty(t, sessions, "no session was created on the removed authenticator's claim")
}

// TestRecoveryCode_TheFormLinksBackToTheCodeForm: the recovery-code form links back to the code form
// of the same step, so a user who finds their phone can still use it.
func TestRecoveryCode_TheFormLinksBackToTheCodeForm(t *testing.T) {
	client, redirectUri, user, password, _ := createLevel2MandatoryUser(t, true)
	httpClient, codePage, _ := startOtpCeremony(t, client, redirectUri, user, password, "")
	form := openRecoveryCodeForm(t, httpClient, codePage)
	defer func() { _ = form.Body.Close() }()

	doc, err := goquery.NewDocumentFromReader(form.Body)
	require.NoError(t, err)
	back := doc.Find(`a[href^="/auth/otp"]`)
	require.Equal(t, 1, back.Length())
	href, _ := back.Attr("href")
	assert.NotContains(t, href, "form=recovery-code")

	resp := loadPage(t, httpClient, appConfig.AuthServer.BaseURL+href)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	codeForm, err := goquery.NewDocumentFromReader(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, 1, codeForm.Find(`input[name="otp"]`).Length())
}
