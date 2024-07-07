package integrationtests

import (
	"net/url"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/leodip/goiabada/internal/models"
	"github.com/stretchr/testify/assert"
)

func TestAccountRegister_Get_SelfRegistrationNotEnabled(t *testing.T) {
	setup()

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}

	settings.SelfRegistrationEnabled = false
	err = database.UpdateSettings(nil, settings)
	if err != nil {
		t.Fatal(err)
	}

	url := lib.GetBaseUrl() + "/account/register"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 500, resp.StatusCode)
}

func TestAccountRegister_Get(t *testing.T) {
	setup()

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}

	settings.SelfRegistrationEnabled = true
	err = database.UpdateSettings(nil, settings)
	if err != nil {
		t.Fatal(err)
	}

	url := lib.GetBaseUrl() + "/account/register"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	elem := doc.Find("h2:contains('Register')")
	assert.Equal(t, 1, elem.Length())

	elem = doc.Find("input[name='email']")
	assert.Equal(t, 1, elem.Length())

	elem = doc.Find("input[name='password']")
	assert.Equal(t, 1, elem.Length())

	elem = doc.Find("input[name='passwordConfirmation']")
	assert.Equal(t, 1, elem.Length())
}

func TestAccountRegister_Post_EmailEmpty(t *testing.T) {
	setup()

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}

	settings.SelfRegistrationEnabled = true
	err = database.UpdateSettings(nil, settings)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/account/register"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
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
	elem := doc.Find("p.text-error:contains('Email is required')")
	assert.Equal(t, 1, elem.Length())
}

func TestAccountRegister_Post_EmailInvalid(t *testing.T) {
	setup()

	testCases := []struct {
		email string
	}{
		{"invalid"},
		{"invalid@"},
		{"invalid@invalid"},
		{"invalid@invalid."},
		{"exampleemail.com"},
		{"example email@example.com"},
		{"example!email@example.com"},
		{"@example.com"},
		{"example..email@example.com"},
		{".example@example.com"},
		{"example.@example.com"},
		{"exam..ple@example.com"},
		{"example@example .com"},
		{"example@example.c"},
		{"user@[192.168.1.1]"},
	}

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}

	settings.SelfRegistrationEnabled = true
	err = database.UpdateSettings(nil, settings)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/account/register"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	for _, testCase := range testCases {

		resp, err := httpClient.Get(destUrl)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		csrf := getCsrfValue(t, resp)

		formData := url.Values{
			"email":                {testCase.email},
			"password":             {"asd123"},
			"passwordConfirmation": {"asd123"},
			"gorilla.csrf.Token":   {csrf},
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
		elem := doc.Find("p.text-error:contains('Please enter a valid email address')")
		assert.Equal(t, 1, elem.Length(), testCase.email)
	}
}

func TestAccountRegister_Post_EmailIsAlreadyRegistered_User(t *testing.T) {
	setup()

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}

	settings.SelfRegistrationEnabled = true
	err = database.UpdateSettings(nil, settings)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/account/register"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
		"email":              {"mauro@outlook.com"},
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
	elem := doc.Find("p.text-error:contains('Apologies, but this email address is already registered')")
	assert.Equal(t, 1, elem.Length())
}

func TestAccountRegister_Post_EmailIsAlreadyRegistered_PreRegistration(t *testing.T) {
	setup()

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}

	settings.SelfRegistrationEnabled = true
	err = database.UpdateSettings(nil, settings)
	if err != nil {
		t.Fatal(err)
	}

	email := gofakeit.Email()

	preRegistration := &models.PreRegistration{
		Email: email,
	}
	err = database.CreatePreRegistration(nil, preRegistration)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/account/register"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
		"email":              {email},
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
	elem := doc.Find("p.text-error:contains('Apologies, but this email address is already registered')")
	assert.Equal(t, 1, elem.Length())
}

func TestAccountRegister_Post_PasswordEmpty(t *testing.T) {
	setup()

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}

	settings.SelfRegistrationEnabled = true
	err = database.UpdateSettings(nil, settings)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/account/register"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}

	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
		"email":              {gofakeit.Email()},
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

	elem := doc.Find("p.text-error:contains('Password is required')")
	assert.Equal(t, 1, elem.Length())
}

func TestAccountRegister_Post_PasswordConfirmationEmpty(t *testing.T) {
	setup()

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}

	settings.SelfRegistrationEnabled = true
	err = database.UpdateSettings(nil, settings)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/account/register"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}

	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
		"email":              {gofakeit.Email()},
		"password":           {"asd123"},
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

	elem := doc.Find("p.text-error:contains('Password confirmation is required')")
	assert.Equal(t, 1, elem.Length())
}

func TestAccountRegister_Post_PasswordConfirmationDoesNotMatch(t *testing.T) {
	setup()

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}

	settings.SelfRegistrationEnabled = true
	err = database.UpdateSettings(nil, settings)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/account/register"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}

	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
		"email":                {gofakeit.Email()},
		"password":             {"asd123"},
		"passwordConfirmation": {"different"},
		"gorilla.csrf.Token":   {csrf},
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

	elem := doc.Find("p.text-error:contains('The password confirmation does not match the password')")
	assert.Equal(t, 1, elem.Length())
}

func TestAccountRegister_Post_InvalidPassword(t *testing.T) {
	setup()

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}

	settings.SelfRegistrationEnabled = true
	settings.PasswordPolicy = enums.PasswordPolicyMedium
	err = database.UpdateSettings(nil, settings)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/account/register"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}

	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
		"email":                {gofakeit.Email()},
		"password":             {"a"},
		"passwordConfirmation": {"a"},
		"gorilla.csrf.Token":   {csrf},
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

	elem := doc.Find("p.text-error:contains('The minimum length for the password is 8 characters')")
	assert.Equal(t, 1, elem.Length())
}

func TestAccountRegister_Post_SelfRegistrationNotEnabled(t *testing.T) {
	setup()

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}

	settings.SelfRegistrationEnabled = true
	settings.PasswordPolicy = enums.PasswordPolicyLow
	err = database.UpdateSettings(nil, settings)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/account/register"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}

	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	settings.SelfRegistrationEnabled = false
	err = database.UpdateSettings(nil, settings)
	if err != nil {
		t.Fatal(err)
	}

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
		"email":                {gofakeit.Email()},
		"password":             {"abc123"},
		"passwordConfirmation": {"abc123"},
		"gorilla.csrf.Token":   {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 500, resp.StatusCode)
}

func TestAccountRegister_Post_RequiresEmailVerification(t *testing.T) {
	setup()

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}

	settings.SelfRegistrationEnabled = true
	settings.SelfRegistrationRequiresEmailVerification = true
	settings.PasswordPolicy = enums.PasswordPolicyLow
	err = database.UpdateSettings(nil, settings)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/account/register"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}

	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
		"email":                {gofakeit.Email()},
		"password":             {"abc123"},
		"passwordConfirmation": {"abc123"},
		"gorilla.csrf.Token":   {csrf},
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

	elem := doc.Find("p:contains('Before you can access your account, please complete')")
	assert.Equal(t, 1, elem.Length())

	// check if the pre-registration was created

	preRegistration, err := database.GetPreRegistrationByEmail(nil, formData.Get("email"))
	if err != nil {
		t.Fatal(err)
	}

	assert.NotNil(t, preRegistration)

	assertEmailSent(t, formData.Get("email"), "To activate your account, please verify your email")
}

func TestAccountRegister_Post_NoEmailVerification(t *testing.T) {
	setup()

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}

	settings.SelfRegistrationEnabled = true
	settings.SelfRegistrationRequiresEmailVerification = false
	settings.PasswordPolicy = enums.PasswordPolicyLow
	err = database.UpdateSettings(nil, settings)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/account/register"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}

	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
		"email":                {gofakeit.Email()},
		"password":             {"abc123"},
		"passwordConfirmation": {"abc123"},
		"gorilla.csrf.Token":   {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	user, err := database.GetUserByEmail(nil, formData.Get("email"))
	if err != nil {
		t.Fatal(err)
	}

	assert.NotNil(t, user)

	assertRedirect(t, resp, "/auth/pwd")
	assertEmailSent(t, formData.Get("email"), "Congratulations! Your account has been created")
}
