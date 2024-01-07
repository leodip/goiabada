package integrationtests

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/stretchr/testify/assert"
)

func TestAccountEmail_Get_NotLoggedIn(t *testing.T) {
	setup()

	url := lib.GetBaseUrl() + "/account/email"

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

func TestAccountEmail_Get_EmailVerified(t *testing.T) {
	setup()

	setEmailVerified := func(email string, emailVerified bool) {
		user, err := database.GetUserByEmail(email)
		if err != nil {
			t.Fatal(err)
		}
		user.EmailVerified = emailVerified
		_, err = database.SaveUser(user)
		if err != nil {
			t.Fatal(err)
		}
	}
	setEmailVerified("viviane@gmail.com", true)

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/email"

	resp, err := httpClient.Get(destUrl)

	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	elem := doc.Find("head title")
	assert.Equal(t, "Goiabada - Account - Email", elem.Text())

	elem = doc.Find("input[name=email]")
	assert.Equal(t, "viviane@gmail.com", elem.AttrOr("value", ""))

	elem = doc.Find("span:contains('Your email is verified')")
	html, err := goquery.OuterHtml(elem)
	if err != nil {
		t.Fatal(err)
	}
	assert.Contains(t, html, "Your email is verified")

	elem = doc.Find("span:contains('Email verification pending')")
	assert.Equal(t, 0, elem.Length())
}

func TestAccountEmail_Get_EmailNotVerified(t *testing.T) {
	setup()

	setEmailVerified := func(email string, emailVerified bool) {
		user, err := database.GetUserByEmail(email)
		if err != nil {
			t.Fatal(err)
		}
		user.EmailVerified = emailVerified
		_, err = database.SaveUser(user)
		if err != nil {
			t.Fatal(err)
		}
	}
	setEmailVerified("viviane@gmail.com", false)

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/email"

	resp, err := httpClient.Get(destUrl)

	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	elem := doc.Find("head title")
	assert.Equal(t, "Goiabada - Account - Email", elem.Text())

	elem = doc.Find("input[name=email]")
	assert.Equal(t, "viviane@gmail.com", elem.AttrOr("value", ""))

	elem = doc.Find("span:contains('Email verification pending')")
	html, err := goquery.OuterHtml(elem)
	if err != nil {
		t.Fatal(err)
	}
	assert.Contains(t, html, "Email verification pending")

	elem = doc.Find("span:contains('Your email is verified')")
	assert.Equal(t, 0, elem.Length())
}

func TestAccountEmail_Get_SMTPEnabled(t *testing.T) {
	setup()

	setEmailVerified := func(email string, emailVerified bool) {
		user, err := database.GetUserByEmail(email)
		if err != nil {
			t.Fatal(err)
		}
		user.EmailVerified = emailVerified
		_, err = database.SaveUser(user)
		if err != nil {
			t.Fatal(err)
		}
	}
	setEmailVerified("viviane@gmail.com", false)

	settings, err := database.GetSettings()
	if err != nil {
		t.Fatal(err)
	}
	settings.SMTPEnabled = true
	_, err = database.SaveSettings(settings)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/email"

	resp, err := httpClient.Get(destUrl)

	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	elem := doc.Find("head title")
	assert.Equal(t, "Goiabada - Account - Email", elem.Text())

	elem = doc.Find("input[name=email]")
	assert.Equal(t, "viviane@gmail.com", elem.AttrOr("value", ""))

	elem = doc.Find("span:contains('Email verification pending')")
	html, err := goquery.OuterHtml(elem)
	if err != nil {
		t.Fatal(err)
	}
	assert.Contains(t, html, "Email verification pending")

	elem = doc.Find("span:contains('Your email is verified')")
	assert.Equal(t, 0, elem.Length())

	elem = doc.Find("button#btnVerifyYourEmail span:contains('Verify your email')")
	assert.Equal(t, 1, elem.Length())
}

func TestAccountEmail_Get_SMTPDisabled(t *testing.T) {
	setup()

	setEmailVerified := func(email string, emailVerified bool) {
		user, err := database.GetUserByEmail(email)
		if err != nil {
			t.Fatal(err)
		}
		user.EmailVerified = emailVerified
		_, err = database.SaveUser(user)
		if err != nil {
			t.Fatal(err)
		}
	}
	setEmailVerified("viviane@gmail.com", false)

	settings, err := database.GetSettings()
	if err != nil {
		t.Fatal(err)
	}
	settings.SMTPEnabled = false
	_, err = database.SaveSettings(settings)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/email"

	resp, err := httpClient.Get(destUrl)

	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	elem := doc.Find("head title")
	assert.Equal(t, "Goiabada - Account - Email", elem.Text())

	elem = doc.Find("input[name=email]")
	assert.Equal(t, "viviane@gmail.com", elem.AttrOr("value", ""))

	elem = doc.Find("span:contains('Email verification pending')")
	html, err := goquery.OuterHtml(elem)
	if err != nil {
		t.Fatal(err)
	}
	assert.Contains(t, html, "Email verification pending")

	elem = doc.Find("span:contains('Your email is verified')")
	assert.Equal(t, 0, elem.Length())

	elem = doc.Find("button#btnVerifyYourEmail span:contains('Verify your email')")
	assert.Equal(t, 0, elem.Length())
}

func TestAccountEmail_SendVerification(t *testing.T) {
	setup()

	user, err := database.GetUserByEmail("viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}
	user.EmailVerified = false
	user.EmailVerificationCodeEncrypted = nil
	user.EmailVerificationCodeIssuedAt = nil
	_, err = database.SaveUser(user)
	if err != nil {
		t.Fatal(err)
	}

	settings, err := database.GetSettings()
	if err != nil {
		t.Fatal(err)
	}
	settings.SMTPEnabled = true
	_, err = database.SaveSettings(settings)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/email"

	resp, err := httpClient.Get(destUrl)

	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)
	destUrl = lib.GetBaseUrl() + "/account/email-send-verification"

	req, err := http.NewRequest("POST", destUrl, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err = httpClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	result := unmarshalToMap(t, resp)
	assert.True(t, result["EmailVerificationSent"].(bool))
	assert.Equal(t, "viviane@gmail.com", result["EmailDestination"].(string))

	// wait 1 sec
	time.Sleep(1 * time.Second)

	// send again
	resp, err = httpClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	result = unmarshalToMap(t, resp)
	assert.False(t, result["EmailVerificationSent"].(bool))
	assert.True(t, result["TooManyRequests"].(bool))
}

func TestAccountEmail_Verify(t *testing.T) {
	setup()

	user, err := database.GetUserByEmail("viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}
	user.EmailVerified = false
	user.EmailVerificationCodeEncrypted = nil
	user.EmailVerificationCodeIssuedAt = nil
	_, err = database.SaveUser(user)
	if err != nil {
		t.Fatal(err)
	}

	settings, err := database.GetSettings()
	if err != nil {
		t.Fatal(err)
	}
	settings.SMTPEnabled = true
	_, err = database.SaveSettings(settings)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/email"

	resp, err := httpClient.Get(destUrl)

	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)
	destUrl = lib.GetBaseUrl() + "/account/email-send-verification"

	req, err := http.NewRequest("POST", destUrl, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err = httpClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	result := unmarshalToMap(t, resp)
	assert.True(t, result["EmailVerificationSent"].(bool))
	assert.Equal(t, "viviane@gmail.com", result["EmailDestination"].(string))

	user, err = database.GetUserByEmail("viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}

	verificationCode, err := lib.DecryptText(user.EmailVerificationCodeEncrypted, settings.AESEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}

	destUrl = lib.GetBaseUrl() + "/account/email-verify?code=invalid"
	resp, err = httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	elem := doc.Find("p:contains('Unable to verify the email address')")
	assert.Equal(t, 1, elem.Length())

	destUrl = lib.GetBaseUrl() + "/account/email-verify?code=" + verificationCode
	resp, err = httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/account/email")
}

func TestAccountEmail_Verify_CodeExpired(t *testing.T) {
	setup()

	settings, err := database.GetSettings()
	if err != nil {
		t.Fatal(err)
	}
	settings.SMTPEnabled = true
	_, err = database.SaveSettings(settings)
	if err != nil {
		t.Fatal(err)
	}

	user, err := database.GetUserByEmail("viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}
	user.EmailVerified = false
	verificationCodeEncrypted, err := lib.EncryptText("123456", settings.AESEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	user.EmailVerificationCodeEncrypted = verificationCodeEncrypted
	issuedAt := time.Now().UTC().Add(-6 * time.Minute) // expired
	user.EmailVerificationCodeIssuedAt = &issuedAt
	_, err = database.SaveUser(user)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/email"

	resp, err := httpClient.Get(destUrl)

	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	destUrl = lib.GetBaseUrl() + "/account/email-verify?code=123456"
	resp, err = httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	elem := doc.Find("p:contains('Unable to verify the email address')")
	assert.Equal(t, 1, elem.Length())
}

func TestAccountEmail_Post_EmailIsMissing(t *testing.T) {
	setup()

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/email"

	resp, err := httpClient.Get(destUrl)

	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)
	formData := url.Values{
		"email":              {""},
		"emailConfirmation":  {""},
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

	elem := doc.Find("div.text-error p")
	assert.Contains(t, elem.Text(), "Please enter an email address")
}

func TestAccountEmail_Post_EmailIsTooLong(t *testing.T) {
	setup()

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/email"

	resp, err := httpClient.Get(destUrl)

	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)
	formData := url.Values{
		"email":              {lib.GenerateSecureRandomString(60) + "@example.com"},
		"emailConfirmation":  {""},
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

	elem := doc.Find("div.text-error p")
	assert.Contains(t, elem.Text(), "The email address cannot exceed a maximum length of 60 characters")
}

func TestAccountEmail_Post_EmailConfirmationDoesNotMatch(t *testing.T) {
	setup()

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/email"

	resp, err := httpClient.Get(destUrl)

	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)
	formData := url.Values{
		"email":              {"new@example.com"},
		"emailConfirmation":  {"other@example.com"},
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

	elem := doc.Find("div.text-error p")
	assert.Contains(t, elem.Text(), "The email and email confirmation entries must be identical")
}

func TestAccountEmail_Post_EmailIsAlreadyRegistered(t *testing.T) {
	setup()

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/email"

	resp, err := httpClient.Get(destUrl)

	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)
	formData := url.Values{
		"email":              {"mauro@outlook.com"},
		"emailConfirmation":  {"mauro@outlook.com"},
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

	elem := doc.Find("div.text-error p")
	assert.Contains(t, elem.Text(), "Apologies, but this email address is already registered")
}

func TestAccountEmail_Post_EmailIsInvalid(t *testing.T) {
	setup()

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/email"

	resp, err := httpClient.Get(destUrl)

	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)
	formData := url.Values{
		"email":              {"@outlook.com"},
		"emailConfirmation":  {"@outlook.com"},
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

	elem := doc.Find("div.text-error p")
	assert.Contains(t, elem.Text(), "Please enter a valid email address")
}

func TestAccountEmail_Post(t *testing.T) {
	setup()

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/email"

	resp, err := httpClient.Get(destUrl)

	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)
	formData := url.Values{
		"email":              {"viviane2@gmail.com"},
		"emailConfirmation":  {"viviane2@gmail.com"},
		"gorilla.csrf.Token": {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/account/email")

	user, err := database.GetUserByEmail("viviane2@gmail.com")
	if err != nil {
		t.Fatal(err)
	}
	assert.NotNil(t, user)

	user.Email = "viviane@gmail.com"
	_, err = database.SaveUser(user)
	if err != nil {
		t.Fatal(err)
	}
}
