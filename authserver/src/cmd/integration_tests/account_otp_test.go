package integrationtests

import (
	"net/url"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
)

func TestAccountOtp_Get_NotLoggedIn(t *testing.T) {
	setup()

	url := lib.GetBaseUrl() + "/account/otp"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/authorize")
}

func TestAccountOtp_Get_OtpDisabled(t *testing.T) {
	setup()

	user := getRandomUserWithOtpState(t, false)

	httpClient := loginToAccountArea(t, user.Email, "abc123")

	destUrl := lib.GetBaseUrl() + "/account/otp"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	elem := doc.Find("p:contains(\"Scan this QR code using your authenticator app\")")
	assert.Equal(t, 1, elem.Length())

	elem = doc.Find("img[src*='data:image/png;base64']")
	assert.Equal(t, 1, elem.Length())

	var preWith32Chars *goquery.Selection
	doc.Find("form pre").Each(func(i int, s *goquery.Selection) {
		if len(s.Text()) == 32 {
			preWith32Chars = s
		}
	})
	assert.Equal(t, 1, preWith32Chars.Length())
}

func TestAccountOtp_Get_OtpEnabled(t *testing.T) {
	setup()

	user := getRandomUserWithOtpState(t, true)

	httpClient := loginToAccountArea(t, user.Email, "abc123")

	destUrl := lib.GetBaseUrl() + "/account/otp"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	elem := doc.Find("button:contains(\"Disable OTP\")")
	assert.Equal(t, 1, elem.Length())

	elem = doc.Find("p:contains(\"One-time password (OTP) is enabled\")")
	assert.Equal(t, 1, elem.Length())
}

func TestAccountOtp_Post_PasswordIsWrong(t *testing.T) {
	setup()

	user := getRandomUserWithOtpState(t, false)

	httpClient := loginToAccountArea(t, user.Email, "abc123")

	destUrl := lib.GetBaseUrl() + "/account/otp"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
		"password":           {"invalid"},
		"gorilla.csrf.Token": {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	elem := doc.Find("p:contains(\"Authentication failed. Check your password and try again\")")
	assert.Equal(t, 1, elem.Length())
}

func TestAccountOtp_Post_OtpIsEnabled(t *testing.T) {
	setup()

	user := getRandomUserWithOtpState(t, true)
	assert.True(t, user.OTPEnabled)
	assert.NotEmpty(t, user.OTPSecret)

	httpClient := loginToAccountArea(t, user.Email, "abc123")

	destUrl := lib.GetBaseUrl() + "/account/otp"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
		"password":           {"abc123"},
		"gorilla.csrf.Token": {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// reload user to get the new otp state
	user, err = database.GetUserByEmail(user.Email)
	if err != nil {
		t.Fatal(err)
	}

	assert.False(t, user.OTPEnabled)
	assert.Empty(t, user.OTPSecret)
}

func TestAccountOtp_Post_OtpIsDisabled_OtpCodeIsCorrect(t *testing.T) {
	setup()

	user := getRandomUserWithOtpState(t, false)
	assert.False(t, user.OTPEnabled)
	assert.Empty(t, user.OTPSecret)

	httpClient := loginToAccountArea(t, user.Email, "abc123")

	destUrl := lib.GetBaseUrl() + "/account/otp"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	var preWith32Chars *goquery.Selection
	doc.Find("form pre").Each(func(i int, s *goquery.Selection) {
		if len(s.Text()) == 32 {
			preWith32Chars = s
		}
	})
	assert.Equal(t, 1, preWith32Chars.Length())
	otpSecret := preWith32Chars.Text()
	otpCode, err := totp.GenerateCode(otpSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	formData := url.Values{
		"otp":                {otpCode},
		"password":           {"abc123"},
		"gorilla.csrf.Token": {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// reload user to get the new otp state
	user, err = database.GetUserByEmail(user.Email)
	if err != nil {
		t.Fatal(err)
	}

	assert.True(t, user.OTPEnabled)
	assert.Equal(t, otpSecret, user.OTPSecret)
}

func TestAccountOtp_Post_OtpIsDisabled_OtpCodeIsInvalid(t *testing.T) {
	setup()

	user := getRandomUserWithOtpState(t, false)
	assert.False(t, user.OTPEnabled)
	assert.Empty(t, user.OTPSecret)

	httpClient := loginToAccountArea(t, user.Email, "abc123")

	destUrl := lib.GetBaseUrl() + "/account/otp"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
		"otp":                {"000000"},
		"password":           {"abc123"},
		"gorilla.csrf.Token": {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	elem := doc.Find("div.text-error p:contains(\"Incorrect OTP Code\")")
	assert.Equal(t, 1, elem.Length())

	// reload user to get the new otp state
	user, err = database.GetUserByEmail(user.Email)
	if err != nil {
		t.Fatal(err)
	}

	assert.False(t, user.OTPEnabled)
	assert.Empty(t, user.OTPSecret)
}
