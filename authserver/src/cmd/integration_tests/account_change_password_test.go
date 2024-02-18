package integrationtests

import (
	"net/url"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/stretchr/testify/assert"
)

func TestAccountChangePassword_Get_NotLoggedIn(t *testing.T) {
	setup()

	url := lib.GetBaseUrl() + "/account/change-password"

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

func TestAccountChangePassword_Get(t *testing.T) {
	setup()
	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/change-password"

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
	assert.Equal(t, "Goiabada - Account - Change password", elem.Text())

	elem = doc.Find("input[name=currentPassword]")
	assert.Equal(t, 1, elem.Length())

	elem = doc.Find("input[name=newPassword]")
	assert.Equal(t, 1, elem.Length())

	elem = doc.Find("input[name=newPasswordConfirmation]")
	assert.Equal(t, 1, elem.Length())
}

func TestAccountChangePassword_Post_AuthFailed(t *testing.T) {
	setup()
	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/change-password"

	resp, err := httpClient.Get(destUrl)

	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)
	formData := url.Values{
		"currentPassword":         {"invalid"},
		"newPassword":             {"asd1234"},
		"newPasswordConfirmation": {"asd1234"},
		"gorilla.csrf.Token":      {csrf},
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
	assert.Contains(t, elem.Text(), "Authentication failed. Check your current password and try again")
}

func TestAccountChangePassword_Post_NewPasswordMissing(t *testing.T) {
	setup()
	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/change-password"

	resp, err := httpClient.Get(destUrl)

	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)
	formData := url.Values{
		"currentPassword":    {"asd123"},
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
	assert.Contains(t, elem.Text(), "New password is required")
}

func TestAccountChangePassword_Post_ConfirmationDoesNotMatch(t *testing.T) {
	setup()
	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/change-password"

	resp, err := httpClient.Get(destUrl)

	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)
	formData := url.Values{
		"currentPassword":    {"asd123"},
		"newPassword":        {"asd1234"},
		"newPasswordConfirm": {"asd12345"},
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
	assert.Contains(t, elem.Text(), "The new password confirmation does not match the password")
}

func TestAccountChangePassword_Post_ValidatePassword(t *testing.T) {
	setup()

	resetUserPassword(t, "viviane@gmail.com", "asd123")
	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/change-password"

	resp, err := httpClient.Get(destUrl)

	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	testCases := []struct {
		testCase    string
		policy      enums.PasswordPolicy
		password    string
		expectedErr string
	}{
		{
			testCase:    "1",
			policy:      enums.PasswordPolicyNone,
			password:    "",
			expectedErr: "New password is required",
		},
		{
			testCase:    "2",
			policy:      enums.PasswordPolicyNone,
			password:    "a",
			expectedErr: "",
		},
		{
			testCase:    "3",
			policy:      enums.PasswordPolicyLow,
			password:    "asd12",
			expectedErr: "The minimum length for the password is 6 characters",
		},
		{
			testCase:    "4",
			policy:      enums.PasswordPolicyLow,
			password:    "asd123",
			expectedErr: "",
		},
		{
			testCase:    "5",
			policy:      enums.PasswordPolicyMedium,
			password:    "asd1234",
			expectedErr: "The minimum length for the password is 8 characters",
		},
		{
			testCase:    "6",
			policy:      enums.PasswordPolicyMedium,
			password:    "abcdefgh",
			expectedErr: "As per our policy, an uppercase character is required in the password",
		},
		{
			testCase:    "7",
			policy:      enums.PasswordPolicyMedium,
			password:    "ABCDEFGH",
			expectedErr: "As per our policy, a lowercase character is required in the password",
		},
		{
			testCase:    "8",
			policy:      enums.PasswordPolicyMedium,
			password:    "abcdEFGH",
			expectedErr: "As per our policy, your password must contain a numerical digit",
		},
		{
			testCase:    "9",
			policy:      enums.PasswordPolicyMedium,
			password:    "abcdEFG9",
			expectedErr: "",
		},
		{
			testCase:    "10",
			policy:      enums.PasswordPolicyHigh,
			password:    "asd123456",
			expectedErr: "The minimum length for the password is 10 characters",
		},
		{
			testCase:    "11",
			policy:      enums.PasswordPolicyHigh,
			password:    "abcdefghij",
			expectedErr: "As per our policy, an uppercase character is required in the password",
		},
		{
			testCase:    "12",
			policy:      enums.PasswordPolicyHigh,
			password:    "ABCDEFGHIJ",
			expectedErr: "As per our policy, a lowercase character is required in the password",
		},
		{
			testCase:    "13",
			policy:      enums.PasswordPolicyHigh,
			password:    "abcdEFGHij",
			expectedErr: "As per our policy, your password must contain a numerical digit",
		},
		{
			testCase:    "14",
			policy:      enums.PasswordPolicyHigh,
			password:    "abcdEFGHi9",
			expectedErr: "As per our policy, a special character/symbol is required in the password",
		},
		{
			testCase:    "15",
			policy:      enums.PasswordPolicyHigh,
			password:    "abcdEFGHi9$",
			expectedErr: "",
		},
		{
			testCase:    "16",
			policy:      enums.PasswordPolicyNone,
			password:    "1234567890123456789012345678901234567890123456789012345678901254a",
			expectedErr: "The maximum length for the password is 64 characters",
		},
		{
			testCase:    "17",
			policy:      enums.PasswordPolicyLow,
			password:    "1234567890123456789012345678901234567890123456789012345678901254a",
			expectedErr: "The maximum length for the password is 64 characters",
		},
		{
			testCase:    "18",
			policy:      enums.PasswordPolicyMedium,
			password:    "1234567890123456789012345678901234567890123456789012345678901254a",
			expectedErr: "The maximum length for the password is 64 characters",
		},
		{
			testCase:    "19",
			policy:      enums.PasswordPolicyHigh,
			password:    "1234567890123456789012345678901234567890123456789012345678901254a",
			expectedErr: "The maximum length for the password is 64 characters",
		},
	}

	csrf := getCsrfValue(t, resp)

	for _, tc := range testCases {

		resetUserPassword(t, "viviane@gmail.com", "asd123")

		formData := url.Values{
			"currentPassword":         {"asd123"},
			"newPassword":             {tc.password},
			"newPasswordConfirmation": {tc.password},
			"gorilla.csrf.Token":      {csrf},
		}

		settings, err := database.GetSettings()
		if err != nil {
			t.Fatal(err)
		}
		settings.PasswordPolicy = tc.policy
		_, err = database.SaveSettings(settings)
		if err != nil {
			t.Fatal(err)
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

		if len(tc.expectedErr) > 0 {
			elem := doc.Find("div.text-error p")
			assert.Contains(t, elem.Text(), tc.expectedErr, "Test case: "+tc.testCase)
		} else {
			elem := doc.Find("div.text-success p")
			assert.Contains(t, elem.Text(), "Password changed successfully", "Test case: "+tc.testCase)

			user, err := database.GetUserByEmail("viviane@gmail.com")
			if err != nil {
				t.Fatal(err)
			}

			isValid := lib.VerifyPasswordHash(user.PasswordHash, tc.password)
			assert.True(t, isValid, "Test case: "+tc.testCase)
		}
	}

	resetUserPassword(t, "viviane@gmail.com", "asd123")
}
