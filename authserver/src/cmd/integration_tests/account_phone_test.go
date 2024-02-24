package integrationtests

import (
	"bufio"
	"database/sql"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/stretchr/testify/assert"
)

func TestAccountPhone_Get_NotLoggedIn(t *testing.T) {
	setup()

	url := lib.GetBaseUrl() + "/account/phone"

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

func TestAccountPhone_Get_SMSEnabled_PhoneNumberVerified(t *testing.T) {
	setup()

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	settings.SMSProvider = "test"
	err = database.UpdateSettings(nil, settings)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/phone"

	user, err := database.GetUserByEmail(nil, "viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}

	user.PhoneNumber = "+55 47 99133 4598"
	user.PhoneNumberVerified = true
	err = database.UpdateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	elem := doc.Find("span.bg-success:contains(\"Your phone is verified\")")
	assert.Equal(t, 1, elem.Length())

	elem = doc.Find("option.country-flags[value=\"+55\"]")
	assert.Equal(t, 1, elem.Length())
	_, exists := elem.Attr("selected")
	assert.True(t, exists)

	elem = doc.Find("input[name=\"phoneNumber\"]")
	assert.Equal(t, 1, elem.Length())
	assert.Equal(t, "47 99133 4598", elem.AttrOr("value", ""))

	// countries
	elem = doc.Find("select option")
	assert.Greater(t, elem.Length(), 250)
}

func TestAccountPhone_Get_SMSEnabled_PhoneNumberNotVerified(t *testing.T) {
	setup()

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	settings.SMSProvider = "test"
	err = database.UpdateSettings(nil, settings)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/phone"

	user, err := database.GetUserByEmail(nil, "viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}

	user.PhoneNumber = "+55 47 99133 4598"
	user.PhoneNumberVerified = false
	err = database.UpdateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	elem := doc.Find("span.bg-warning:contains(\"Phone verification pending\")")
	assert.Equal(t, 1, elem.Length())

	elem = doc.Find("span:contains(\"Verify your phone\")")
	assert.Equal(t, 1, elem.Length())

	elem = doc.Find("option.country-flags[value=\"+55\"]")
	assert.Equal(t, 1, elem.Length())
	_, exists := elem.Attr("selected")
	assert.True(t, exists)

	elem = doc.Find("input[name=\"phoneNumber\"]")
	assert.Equal(t, 1, elem.Length())
	assert.Equal(t, "47 99133 4598", elem.AttrOr("value", ""))

	// countries
	elem = doc.Find("select option")
	assert.Greater(t, elem.Length(), 250)
}

func TestAccountPhone_Get_SMSDisabled(t *testing.T) {
	setup()

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	settings.SMSProvider = ""
	err = database.UpdateSettings(nil, settings)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/phone"

	user, err := database.GetUserByEmail(nil, "viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}

	user.PhoneNumber = "+55 47 99133 4598"
	user.PhoneNumberVerified = true
	err = database.UpdateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	elem := doc.Find("span.bg-success:contains(\"Your phone is verified\")")
	assert.Equal(t, 0, elem.Length())

	elem = doc.Find("span.bg-warning:contains(\"Phone verification pending\")")
	assert.Equal(t, 0, elem.Length())

	elem = doc.Find("span:contains(\"Verify your phone\")")
	assert.Equal(t, 0, elem.Length())

	elem = doc.Find("option.country-flags[value=\"+55\"]")
	assert.Equal(t, 1, elem.Length())
	_, exists := elem.Attr("selected")
	assert.True(t, exists)

	elem = doc.Find("input[name=\"phoneNumber\"]")
	assert.Equal(t, 1, elem.Length())
	assert.Equal(t, "47 99133 4598", elem.AttrOr("value", ""))

	// countries
	elem = doc.Find("select option")
	assert.Greater(t, elem.Length(), 250)
}

func TestAccountPhone_VerifyGet_PhoneIsAlreadyVerified(t *testing.T) {
	setup()

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	settings.SMSProvider = "test"
	err = database.UpdateSettings(nil, settings)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/phone-verify"

	user, err := database.GetUserByEmail(nil, "viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}

	user.PhoneNumber = "+55 47 99133 4598"
	user.PhoneNumberVerified = true
	err = database.UpdateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 500, resp.StatusCode)
}

func TestAccountPhone_VerifyGet_PhoneVerificationInfoNotPresent(t *testing.T) {
	setup()

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	settings.SMSProvider = "test"
	err = database.UpdateSettings(nil, settings)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/phone-verify"

	user, err := database.GetUserByEmail(nil, "viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}

	user.PhoneNumber = "+55 47 99133 4598"
	user.PhoneNumberVerified = false
	user.PhoneNumberVerificationCodeEncrypted = nil
	user.PhoneNumberVerificationCodeIssuedAt = sql.NullTime{Valid: false}
	err = database.UpdateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 500, resp.StatusCode)
}

func TestAccountPhone_VerifyGet(t *testing.T) {
	setup()

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	settings.SMSProvider = "test"
	err = database.UpdateSettings(nil, settings)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/phone-verify"

	user, err := database.GetUserByEmail(nil, "viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}

	user.PhoneNumber = "+55 47 99133 4598"
	user.PhoneNumberVerified = false

	// set verification code
	user.PhoneNumberVerificationCodeEncrypted, err = lib.EncryptText("123456", settings.AESEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	user.PhoneNumberVerificationCodeIssuedAt = sql.NullTime{Time: now, Valid: true}
	err = database.UpdateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	elem := doc.Find("p:contains(\"Kindly check your mobile phone for an SMS message containing a code\")")
	assert.Equal(t, 1, elem.Length())
}

func TestAccountPhone_VerifyPost_InvalidCode(t *testing.T) {
	setup()

	setup()

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	settings.SMSProvider = "test"
	err = database.UpdateSettings(nil, settings)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/phone-verify"

	user, err := database.GetUserByEmail(nil, "viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}

	user.PhoneNumber = "+55 47 99133 4598"
	user.PhoneNumberVerified = false

	// set verification code
	user.PhoneNumberVerificationCodeEncrypted, err = lib.EncryptText("123456", settings.AESEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	user.PhoneNumberVerificationCodeIssuedAt = sql.NullTime{Time: now, Valid: true}
	err = database.UpdateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
		"code":               {"000000"},
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
	elem := doc.Find("p:contains(\"The verification code provided is either invalid or has expired\")")
	assert.Equal(t, 1, elem.Length())
}

func TestAccountPhone_VerifyPost_ExpiredCode(t *testing.T) {
	setup()

	setup()

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	settings.SMSProvider = "test"
	err = database.UpdateSettings(nil, settings)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/phone-verify"

	user, err := database.GetUserByEmail(nil, "viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}

	user.PhoneNumber = "+55 47 99133 4598"
	user.PhoneNumberVerified = false

	// set verification code
	user.PhoneNumberVerificationCodeEncrypted, err = lib.EncryptText("123456", settings.AESEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}

	// set code issued 10 minutes ago
	date := time.Now().UTC().Add(-10 * time.Minute)
	user.PhoneNumberVerificationCodeIssuedAt = sql.NullTime{Time: date, Valid: true}
	err = database.UpdateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
		"code":               {"123456"},
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
	elem := doc.Find("p:contains(\"The verification code provided is either invalid or has expired\")")
	assert.Equal(t, 1, elem.Length())
}

func TestAccountPhone_VerifyPost(t *testing.T) {
	setup()

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	settings.SMSProvider = "test"
	err = database.UpdateSettings(nil, settings)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/phone-verify"

	user, err := database.GetUserByEmail(nil, "viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}

	user.PhoneNumber = "+55 47 99133 4598"
	user.PhoneNumberVerified = false

	// set verification code
	user.PhoneNumberVerificationCodeEncrypted, err = lib.EncryptText("123456", settings.AESEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}

	date := time.Now().UTC()
	user.PhoneNumberVerificationCodeIssuedAt = sql.NullTime{Time: date, Valid: true}
	err = database.UpdateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
		"code":               {"123456"},
		"gorilla.csrf.Token": {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/account/phone")

	// reload user
	user, err = database.GetUserByEmail(nil, "viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}

	assert.True(t, user.PhoneNumberVerified)
	assert.Nil(t, user.PhoneNumberVerificationCodeEncrypted)
	assert.False(t, user.PhoneNumberVerificationCodeIssuedAt.Valid)
}

func TestAccountPhone_SendVerificationPost_TooManyRequests(t *testing.T) {
	setup()

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	settings.SMSProvider = "test"
	err = database.UpdateSettings(nil, settings)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/phone"

	user, err := database.GetUserByEmail(nil, "viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}

	user.PhoneNumber = "+55 47 99133 4598"
	user.PhoneNumberVerified = false

	// set verification code
	user.PhoneNumberVerificationCodeEncrypted, err = lib.EncryptText("123456", settings.AESEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}

	date := time.Now().UTC().Add(-1 * time.Minute)
	user.PhoneNumberVerificationCodeIssuedAt = sql.NullTime{Time: date, Valid: true}
	err = database.UpdateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	destUrl = lib.GetBaseUrl() + "/account/phone-send-verification"

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
	assert.False(t, result["PhoneVerified"].(bool))
	assert.False(t, result["PhoneVerificationSent"].(bool))
	assert.True(t, result["TooManyRequests"].(bool))
	assert.Greater(t, result["WaitInSeconds"].(float64), 20.0)
}

func TestAccountPhone_SendVerificationPost_PhoneAlreadyVerified(t *testing.T) {
	setup()

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	settings.SMSProvider = "test"
	err = database.UpdateSettings(nil, settings)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/phone"

	user, err := database.GetUserByEmail(nil, "viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}

	user.PhoneNumber = "+55 47 99133 4598"
	user.PhoneNumberVerified = true

	user.PhoneNumberVerificationCodeEncrypted = nil
	user.PhoneNumberVerificationCodeIssuedAt = sql.NullTime{Valid: false}
	err = database.UpdateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	destUrl = lib.GetBaseUrl() + "/account/phone-send-verification"

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
	assert.True(t, result["PhoneVerified"].(bool))
	assert.False(t, result["PhoneVerificationSent"].(bool))
	assert.False(t, result["TooManyRequests"].(bool))
	assert.Equal(t, result["WaitInSeconds"].(float64), 0.0)
}

func TestAccountPhone_SendVerificationPost(t *testing.T) {
	setup()

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	settings.SMSProvider = "test"
	err = database.UpdateSettings(nil, settings)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/phone"

	user, err := database.GetUserByEmail(nil, "viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}

	randomNumber := fmt.Sprintf("%04d", rand.Intn(10000))
	user.PhoneNumber = "+55 47 99133 " + randomNumber
	user.PhoneNumberVerified = false

	user.PhoneNumberVerificationCodeEncrypted = nil
	user.PhoneNumberVerificationCodeIssuedAt = sql.NullTime{Valid: false}
	err = database.UpdateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	destUrl = lib.GetBaseUrl() + "/account/phone-send-verification"

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
	assert.False(t, result["PhoneVerified"].(bool))
	assert.True(t, result["PhoneVerificationSent"].(bool))
	assert.False(t, result["TooManyRequests"].(bool))
	assert.Equal(t, result["WaitInSeconds"].(float64), 0.0)

	filePath := filepath.Join(os.TempDir(), "sms_messages.txt")
	file, err := os.Open(filePath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	found := false
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, "|")
		if len(parts) == 2 && parts[0] == user.PhoneNumber && strings.Contains(parts[1], "Your verification code is") {
			found = true
			break
		}
	}

	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	assert.True(t, found, "Expected SMS message not found in sms_messages.txt")
}
