package integrationtests

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
)

// One-time use of TOTP codes at the browser OTP endpoint (#111, RFC 6238 Section 5.2).
// Observed end to end: nothing here reads users.last_otp_step, because a test asserting the
// marker directly would pass with the endpoint broken.

// createLevel2MandatoryClient creates a client whose default ACR is level2_mandatory, so any
// authorization request against it reaches the OTP screen. Separate from the user, because a
// user the account API created needs the same fixture to be driven through the browser flow.
func createLevel2MandatoryClient(t *testing.T) (*models.Client, *models.RedirectURI) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          false,
		DefaultAcrLevel:          enums.AcrLevel2Mandatory,
	}
	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}
	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	return client, redirectUri
}

// createLevel2MandatoryUser creates a client whose default ACR is level2_mandatory plus a
// user for it, and returns the generated password. Unlike createSessionWithAcrLevel2Mandatory
// it completes no ceremony, so the user's consumed-step marker is still 0 and the test owns
// every code ever submitted for them.
//
// With otpEnabled the user is enrolled with a fresh secret, kept in plaintext on the model for
// generating codes and encrypted in the column the way production stores it. Without it the
// first ceremony enrolls, which is what the second test needs.
func createLevel2MandatoryUser(t *testing.T, otpEnabled bool) (*models.Client, *models.RedirectURI,
	*models.User, string) {

	client, redirectUri := createLevel2MandatoryClient(t)

	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
	}

	if otpEnabled {
		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "Goiabada",
			AccountName: user.Email,
		})
		if err != nil {
			t.Fatal(err)
		}
		user.OTPSecret = key.Secret()
		user.OTPSecretEncrypted = encryptOTPSecretForTest(t, key.Secret())
		user.OTPEnabled = true
	}

	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	return client, redirectUri, user, password
}

// startOtpCeremony drives a brand new authorization request through the password form and
// stops at the OTP screen, returning the HTTP client it used, that page, and the URL to post
// the code to.
//
// **A fresh cookie jar per call is what makes it a new ceremony**, and it is not
// interchangeable with prompt=login. prompt=login re-runs level 1 only; the level1completed
// handler then loads the session the cookie still names and steps up to level 2 only when the
// target ACR is higher than the session's, which is false for a level2_mandatory session
// meeting a level2_mandatory request. Such a ceremony redirects straight to /auth/completed and
// never reaches the OTP form, so the replay would never be exercised. With no cookie there is
// no session, the target beats level 1, and the OTP form is shown.
//
// Resubmitting inside the first ceremony proves nothing either: the first success moves the
// auth context to AuthStateAuthenticationCompleted, so the handler's requiredState check
// rejects the second POST with a 500 before the replay guard is ever consulted.
func startOtpCeremony(t *testing.T, client *models.Client, redirectUri *models.RedirectURI,
	user *models.User, password string) (*http.Client, *http.Response, string) {

	httpClient := createHttpClient(t)

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + gofakeit.LetterN(43) +
		"&scope=" + url.QueryEscape("openid profile email") +
		"&state=" + gofakeit.LetterN(8) +
		"&nonce=" + gofakeit.LetterN(8)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, redirectLocation)

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, redirectLocation)

	_ = resp.Body.Close()
	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password)

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, redirectLocation)

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, redirectLocation)

	redirectLocation = assertRedirect(t, resp, "/auth/otp")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, redirectLocation)

	// Caller closes this one.
	return httpClient, resp, redirectLocation
}

// assertOtpRefused asserts that an OTP submission drew the generic incorrect-code page. A
// replay must be indistinguishable from a typo, so this is deliberately the same assertion the
// wrong-code tests make. The body is restored, so the caller can still read the rerendered form.
//
// The status is checked first and fatally: an accepted submission redirects with an empty
// body, and every later read of that body reports something unrelated. That mattered enough to
// write down: with the claim neutralised, the failure used to surface as a complaint about a
// missing CSRF token field, which was true and useless.
func assertOtpRefused(t *testing.T, resp *http.Response) {
	t.Helper()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected the OTP form rerendered with the generic incorrect-code error, got status %d "+
			"redirecting to %q: the submission was accepted", resp.StatusCode, resp.Header.Get("Location"))
	}

	byteArr, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body = io.NopCloser(bytes.NewReader(byteArr))

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(byteArr))
	if err != nil {
		t.Fatal(err)
	}
	assert.Contains(t, doc.Find("p.text-error").Text(), "Incorrect OTP Code")
}

// nextStepCode returns a code from one time step after the current one, which is inside the
// accepted skew window and, when the check below passes, canonicalizes strictly above the step
// the consumed code claimed, so it is the control every replay case here needs.
//
// **The skip is expressed in the steps MatchStep reports, not in the two codes differing.** A
// passcode does not name a time step: MatchStep answers with the bottom of the chain of steps
// producing it (#111 decision 12), and that answer is the same at every current step in one
// unbroken run of accepting steps, which is why the test can recompute it here: a code delayed
// past the end of its own run matches nothing and skips at the check above. So a control whose
// digits differ from the consumed code can still canonicalize to an older step at or below the
// marker, and the guard then refuses the control for exactly the right reason while the test
// reads as a regression. TestMatchStepWithCollidingSteps pins that shape at seam 1: steps 818665
// and 818667 produce one passcode and MatchStep reports 818665 for it. Comparing digits, which
// this helper did first, catches only a collision with the immediately preceding step and leaves
// the other two lookback steps, about 2 in a million per control.
//
// It skips rather than fails, because the control exists to separate the guard from a broken
// ceremony and a control the guard is entitled to refuse cannot do that.
func nextStepCode(t *testing.T, secret string, consumed string) string {
	t.Helper()

	now := time.Now().UTC()
	code, err := totp.GenerateCode(secret, now.Add(time.Duration(otp.StepSeconds)*time.Second))
	if err != nil {
		t.Fatal(err)
	}

	consumedStep, consumedMatched := otp.MatchStep(consumed, secret, now)
	controlStep, controlMatched := otp.MatchStep(code, secret, now)
	if !consumedMatched || !controlMatched {
		t.Skipf("a code fell outside the acceptance window before the control was built "+
			"(consumed matched %v, control matched %v); the two steps cannot be compared",
			consumedMatched, controlMatched)
	}
	if controlStep <= consumedStep {
		t.Skipf("the control canonicalizes to step %d, at or below the consumed step %d (~2e-06); "+
			"the guard refuses it correctly, so it cannot separate the guard from the ceremony",
			controlStep, consumedStep)
	}
	return code
}

// TestAuthOtp_ReplayedCodeIsRefused submits one code twice to an enrolled user's OTP form,
// across two ceremonies. The first submission authenticates and the second must not.
//
// The refusal is attributable to the claim and to nothing else: the code still validates
// against the user's secret, so the matcher accepts it and only the consumed-step guard can
// reject it. The control at the end submits a later-step code in that same second ceremony,
// which succeeds, so the refusal cannot be explained by a ceremony that was never going to
// work.
func TestAuthOtp_ReplayedCodeIsRefused(t *testing.T) {
	client, redirectUri, user, password := createLevel2MandatoryUser(t, true)

	httpClient, resp, otpUrl := startOtpCeremony(t, client, redirectUri, user, password)
	_ = resp.Body.Close()

	codeC, err := totp.GenerateCode(user.OTPSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	resp = authenticateWithOtp(t, httpClient, otpUrl, codeC)
	assertRedirect(t, resp, "/auth/completed")
	_ = resp.Body.Close()

	// Second ceremony, fresh cookie jar, same code.
	httpClient, resp, otpUrl = startOtpCeremony(t, client, redirectUri, user, password)
	_ = resp.Body.Close()

	resp = authenticateWithOtp(t, httpClient, otpUrl, codeC)
	assertOtpRefused(t, resp)
	_ = resp.Body.Close()

	// Control: the ceremony is alive and the form works, so only the replay was refused.
	resp = authenticateWithOtp(t, httpClient, otpUrl, nextStepCode(t, user.OTPSecret, codeC))
	assertRedirect(t, resp, "/auth/completed")
	_ = resp.Body.Close()
}

// TestAuthOtp_EnrolmentCodeIsRefusedAtVerification enrolls an authenticator in the browser flow
// with code C, then presents C again in a new ceremony, where the user is now enrolled and the
// code is checked against the stored secret.
//
// This is what pins #111 decision 3, that enrollment claims the step too. A successful
// enrollment sets otp_enabled, so without the claim the very same code takes the verification
// branch on the next request and is accepted a second time: an enrollment code would be usable
// exactly twice. As above, the later-step control shows the second ceremony was capable of
// succeeding.
func TestAuthOtp_EnrolmentCodeIsRefusedAtVerification(t *testing.T) {
	client, redirectUri, user, password := createLevel2MandatoryUser(t, false)

	httpClient, resp, otpUrl := startOtpCeremony(t, client, redirectUri, user, password)
	secret := getOtpSecretFromEnrollmentPage(t, resp)
	_ = resp.Body.Close()

	codeC, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	resp = authenticateWithOtp(t, httpClient, otpUrl, codeC)
	assertRedirect(t, resp, "/auth/completed")
	_ = resp.Body.Close()

	enrolled, err := database.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, enrolled.OTPEnabled, "the first ceremony must have enrolled, or the second one is not a verification")

	// Second ceremony, fresh cookie jar. The user is enrolled now, so this is the
	// verification branch validating C against the secret it just stored.
	httpClient, resp, otpUrl = startOtpCeremony(t, client, redirectUri, user, password)
	_ = resp.Body.Close()

	resp = authenticateWithOtp(t, httpClient, otpUrl, codeC)
	assertOtpRefused(t, resp)
	_ = resp.Body.Close()

	resp = authenticateWithOtp(t, httpClient, otpUrl, nextStepCode(t, secret, codeC))
	assertRedirect(t, resp, "/auth/completed")
	_ = resp.Body.Close()
}

// TestAuthOtp_APIEnrolmentCodeIsRefusedAtVerification is the case above with the enrollment moved
// to the third call site, PUT /api/v1/account/otp, so it pins that site's claim (#111 decision 3).
// It lives here rather than beside the other account API cases because it is the browser sibling
// with one step swapped, and because the ceremony helpers it needs are here.
//
// The attack it closes: a user enables OTP through the API, spending code C there, and anyone
// holding C plus that user's password presents C at the browser OTP prompt and reaches level 2,
// because the API acceptance was never recorded. Omitting TryConsumeUserOTPStep from the API
// handler alone left the whole suite green before this case existed: every other API OTP test
// submits one code per user, and the browser enrollment case above enrolls in the browser flow, so
// nothing crossed the boundary.
func TestAuthOtp_APIEnrolmentCodeIsRefusedAtVerification(t *testing.T) {
	accessToken, user := getUserAccessTokenWithAccountScope(t)
	setUserPasswordForOTP(t, user.Id, "Correct1!")

	key, err := totp.Generate(totp.GenerateOpts{Issuer: "Goiabada", AccountName: user.Email})
	if err != nil {
		t.Fatal(err)
	}
	secret := key.Secret()

	codeC, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// Enroll through the account API, which consumes codeC's step.
	enableUrl := config.GetAuthServer().BaseURL + "/api/v1/account/otp"
	resp := makeAPIRequest(t, "PUT", enableUrl, accessToken, api.UpdateAccountOTPRequest{
		Enabled:   true,
		Password:  "Correct1!",
		OtpCode:   codeC,
		SecretKey: secret,
	})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("expected the API enrollment to succeed, got %d. body: %s", resp.StatusCode, string(body))
	}
	_ = resp.Body.Close()

	enrolled, err := database.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, enrolled.OTPEnabled, "the API enrollment must have enrolled, or the ceremony below is not a verification")

	// Now the browser prompt, where the user is enrolled and codeC is checked against the
	// secret the API just stored.
	client, redirectUri := createLevel2MandatoryClient(t)
	httpClient, resp, otpUrl := startOtpCeremony(t, client, redirectUri, enrolled, "Correct1!")
	_ = resp.Body.Close()

	resp = authenticateWithOtp(t, httpClient, otpUrl, codeC)
	assertOtpRefused(t, resp)
	_ = resp.Body.Close()

	resp = authenticateWithOtp(t, httpClient, otpUrl, nextStepCode(t, secret, codeC))
	assertRedirect(t, resp, "/auth/completed")
	_ = resp.Body.Close()
}
