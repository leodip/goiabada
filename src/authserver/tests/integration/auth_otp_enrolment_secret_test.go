package integrationtests

import (
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
)

// The enrolment seed belongs to the ceremony that rendered it (#242 part 3, decision 4).
//
// Observed the way a user observes it: the secret is read out of the rendered page and the code
// is generated from what the page showed. A test asserting the auth context's field directly
// would be a side channel into storage, passing with the page broken, which is what §5 rejects
// at this seam.

// TestAuthOtp_EnrolmentReloadRendersTheSameSecret reloads /auth/otp part way through enrolment
// and requires the same secret back, then submits a code generated from the FIRST render.
//
// That second half is the defect stated as a user meets it. The seed used to live in one pair of
// slots on the browser session, rewritten by every GET, so a reload replaced the secret behind
// the QR code the user had already scanned into their authenticator. Their next code was then
// checked against a secret they had never been shown and refused, with the page still displaying
// the code's own QR code. Nothing about that is visible to them, and the only way out is to scan
// again.
//
// The code is generated before the reload deliberately: generating it afterwards from the first
// secret would pass even if the reload had replaced the stored seed with the same value by
// coincidence, and more to the point it would not be the code the user's authenticator holds.
func TestAuthOtp_EnrolmentReloadRendersTheSameSecret(t *testing.T) {
	client, redirectUri, user, password := createLevel2MandatoryUser(t, false)

	httpClient, otpPage, otpUrl := startOtpCeremony(t, client, redirectUri, user, password, "")
	first := getOtpSecretFromEnrollmentPage(t, otpPage)
	_ = otpPage.Body.Close()
	assert.NotEmpty(t, first, "the enrolment page must render a secret, or nothing below means anything")

	// The code the user's authenticator produces from the QR code on the first render.
	code, err := totp.GenerateCode(first, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	reloaded := loadPage(t, httpClient, otpUrl)
	second := getOtpSecretFromEnrollmentPage(t, reloaded)
	assert.Equal(t, first, second,
		"a reload of /auth/otp must render the secret the user has already scanned, not a fresh one")

	resp := authenticateWithOtp(t, httpClient, otpUrl, reloaded, code)
	_ = reloaded.Body.Close()
	assertRedirect(t, resp, "/auth/completed")
	_ = resp.Body.Close()

	enrolled, err := database.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, enrolled.OTPEnabled, "the ceremony must have enrolled the authenticator")

	// And it enrolled the seed the user actually scanned, rather than accepting the code against
	// one seed and storing another.
	stored, err := enrolled.GetOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, strings.ToUpper(first), strings.ToUpper(stored))
}

// TestAuthOtp_SecondAuthorizeInTheSameBrowserGetsANewSecret is the other half of decision 4: the
// seed is bound to its ceremony, and the binding is structural rather than compared.
//
// Both ceremonies run in ONE cookie jar, which is what makes the case worth anything. Two
// browsers would get different secrets under any storage at all; one browser is where a shared
// slot and a per-ceremony field disagree, because everything the seed used to be kept in is the
// same object across these two requests. A second /auth/authorize mints a new auth context at
// HandleAuthorizeGet and the old seed leaves with the old context, so the second enrolment page
// cannot be showing the first ceremony's secret.
func TestAuthOtp_SecondAuthorizeInTheSameBrowserGetsANewSecret(t *testing.T) {
	client, redirectUri, user, password := createLevel2MandatoryUser(t, false)

	httpClient, otpPage, _ := startOtpCeremony(t, client, redirectUri, user, password, "")
	first := getOtpSecretFromEnrollmentPage(t, otpPage)
	_ = otpPage.Body.Close()
	assert.NotEmpty(t, first)

	// Same jar, so the first ceremony's cookie is still there to be replaced. It never reached
	// /auth/completed, so no session exists and this request runs level 1 again.
	_, secondPage, _ := startOtpCeremonyOn(t, httpClient, client, redirectUri, user, password, "")
	second := getOtpSecretFromEnrollmentPage(t, secondPage)
	_ = secondPage.Body.Close()

	assert.NotEqual(t, first, second,
		"a second authorization request must enrol against its own secret, not the one the "+
			"abandoned ceremony left behind")
}
