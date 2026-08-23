package integrationtests

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/models"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
)

// Seam 1 of #242, the browser ceremony end to end. Two properties nothing else in this suite can
// observe, both of them about WHEN a level 2 obligation is discharged.
//
// Nothing here reads user_sessions.otp_config_generation to decide whether the test passed. A test
// that asserted the column directly would pass with the ceremony broken, which is exactly the
// failure mode this seam exists to catch: what matters to a user is whether the OTP form appears.

// authorizeOnExistingSession starts an authorization on a cookie jar that already holds a session,
// follows the redirect chain, and returns where it stopped along with the page and the URL of that
// page.
//
// It stops at whichever of /auth/otp or /auth/issue it reaches. Those are the two answers these
// cases are asking about: "the second factor was demanded again" and "SSO went straight through".
// The caller closes the body.
func authorizeOnExistingSession(t *testing.T, httpClient *http.Client, client *models.Client,
	redirectUri *models.RedirectURI) (string, *http.Response, string) {

	t.Helper()

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

	// Bounded rather than a bare loop: a ceremony that started cycling would otherwise hang the
	// suite instead of failing it. Six is comfortably above the longest real chain here, which is
	// authorize, level1completed, level2, otp.
	for i := 0; i < 6; i++ {
		location := resp.Header.Get("Location")
		if resp.StatusCode != http.StatusFound || location == "" {
			t.Fatalf("the ceremony stopped at status %d with no redirect, at step %d", resp.StatusCode, i)
		}
		_ = resp.Body.Close()

		parsed, err := url.Parse(location)
		if err != nil {
			t.Fatal(err)
		}
		if parsed.Path == "/auth/otp" || parsed.Path == "/auth/issue" {
			return parsed.Path, loadPage(t, httpClient, location), location
		}
		resp = loadPage(t, httpClient, location)
	}

	_ = resp.Body.Close()
	t.Fatal("the ceremony did not reach /auth/otp or /auth/issue within six redirects")
	return "", nil, ""
}

// TestOtpCeremony_AbandonedLevel2LeavesTheObligationStanding is part 1.1 of #242, observed the way
// a user meets it.
//
// The user has a live level 2 session and their authenticator changes out of band, so the next
// ceremony against a level2_mandatory client must ask for OTP again. The visitor reaches that form
// and abandons it, which is the ordinary thing to do when a phone is in another room.
//
// **The next ceremony must ask again.** Before this change it did not: /auth/level1completed
// cleared the boolean and committed it at the moment it DECIDED to send the visitor to
// /auth/level2, so the obligation was spent by the redirect rather than by the answer. Closing the
// browser at the prompt therefore bought a password-only login for the rest of the session's life,
// on a client whose whole configuration says a second factor is mandatory.
//
// The counter cannot be spent that way because reading it is not writing it. The comparison at
// /auth/level1completed writes nothing at all now, and the only promotion happens at
// /auth/completed, after the OTP form has actually been answered.
//
// It fails for its stated reason in both directions: the third ceremony reaching /auth/issue is a
// bypass, and the second one failing to reach /auth/otp would mean the re-prompt never fired.
func TestOtpCeremony_AbandonedLevel2LeavesTheObligationStanding(t *testing.T) {
	client, redirectUri, user, password := createLevel2MandatoryUser(t, true)

	// Ceremony one: password and OTP, which leaves a live level 2 session on this jar.
	httpClient, otpPage, otpUrl := startOtpCeremony(t, client, redirectUri, user, password, "")
	firstCode, err := totp.GenerateCode(user.OTPSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp := authenticateWithOtp(t, httpClient, otpUrl, otpPage, firstCode)
	_ = otpPage.Body.Close()

	// Followed all the way through, not stopped at the redirect: the session row is created at
	// /auth/completed, so a ceremony abandoned before that point leaves this jar with no session
	// and the ceremonies below would take the password path instead of the SSO one.
	redirectLocation := assertRedirect(t, resp, "/auth/completed")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, redirectLocation)
	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, redirectLocation)
	_ = resp.Body.Close()

	// The authenticator changes somewhere else, so every session of this user owes a re-prompt.
	advanceOtpConfigGeneration(t, user.Id)

	// Ceremony two reaches the OTP form and is abandoned there. Nothing is submitted.
	where, page, _ := authorizeOnExistingSession(t, httpClient, client, redirectUri)
	_ = page.Body.Close()
	assert.Equal(t, "/auth/otp", where,
		"the changed authenticator must send this ceremony back to the OTP form")

	// Ceremony three, the same jar and the same session, is the whole point.
	where, page, _ = authorizeOnExistingSession(t, httpClient, client, redirectUri)
	_ = page.Body.Close()
	assert.Equal(t, "/auth/otp", where,
		"abandoning the OTP form must not have discharged the obligation: a visitor who closes the "+
			"browser at the prompt is not a visitor who answered it")
}

// TestOtpCeremony_BrowserEnrolmentDoesNotOweAnImmediatePrompt is the other side of the same
// boundary, and it is what the plan review forced IncrementUserOtpConfigGeneration to return its
// value for.
//
// A ceremony that enrolls an authenticator answers the level 2 question by MOVING the counter:
// /auth/level2 captured generation N, the enrollment advanced the user to N+1. Promoting the
// captured N at /auth/completed would leave the freshly created session behind the user's counter
// at the instant it was born, so the very next authorization would demand OTP again from somebody
// who had just enrolled and verified. The enrollment overwrites the capture with the value the
// increment returned, inside that transaction, which is why this passes.
//
// It fails for its stated reason in both directions: reaching /auth/otp again is the bug, and a
// first ceremony that never reached the enrollment form would fail at startOtpCeremony instead.
func TestOtpCeremony_BrowserEnrolmentDoesNotOweAnImmediatePrompt(t *testing.T) {
	client, redirectUri, user, password := createLevel2MandatoryUser(t, false)

	httpClient, otpPage, otpUrl := startOtpCeremony(t, client, redirectUri, user, password, "")
	secret := getOtpSecretFromEnrollmentPage(t, otpPage)

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp := authenticateWithOtp(t, httpClient, otpUrl, otpPage, code)
	_ = otpPage.Body.Close()

	redirectLocation := assertRedirect(t, resp, "/auth/completed")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, redirectLocation)
	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, redirectLocation)
	_ = resp.Body.Close()

	enrolled, err := database.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, enrolled.OTPEnabled, "the first ceremony must have enrolled")

	// Immediately again, same jar, same session, nothing changed in between.
	where, page, _ := authorizeOnExistingSession(t, httpClient, client, redirectUri)
	_ = page.Body.Close()
	assert.Equal(t, "/auth/issue", where,
		"a session created by the ceremony that enrolled must not owe another second factor at "+
			"once: it answered the level 2 question by establishing the authenticator")
}
