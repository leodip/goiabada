package integrationtests

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/initialization"
	"github.com/leodip/goiabada/internal/lib"
	"golang.org/x/exp/slog"
)

var database *data.Database

func setup() {
	if database == nil {
		initialization.Viper()
		db, err := data.NewDatabase()
		if err != nil {
			slog.Error(err.Error())
			os.Exit(1)
		}
		database = db
		seedTestData(database)
	}
}

type createHttpClientInput struct {
	T               *testing.T
	FollowRedirects bool
	IgnoreTLSErrors bool
}

func createHttpClient(input *createHttpClientInput) *http.Client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		input.T.Fatal(err)
	}
	client := &http.Client{
		Jar: jar,
	}

	if !input.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	if input.IgnoreTLSErrors {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client.Transport = tr
	}
	return client
}

func clientSetEnabled(t *testing.T, clientIdentifier string, enabled bool) error {
	c, err := database.GetClientByClientIdentifier(clientIdentifier)
	if err != nil {
		t.Fatal(err)
	}
	if c == nil {
		t.Fatal(fmt.Errorf("can't update client %v because it does not exist", clientIdentifier))
	}
	c.Enabled = enabled
	result := database.DB.Save(c)

	if result.Error != nil {
		t.Fatal(result.Error, "unable to update client in database")
	}

	return nil
}

func clientSetConsentRequired(t *testing.T, clientIdentifier string, consentRequired bool) error {
	c, err := database.GetClientByClientIdentifier(clientIdentifier)
	if err != nil {
		t.Fatal(err)
	}
	if c == nil {
		t.Fatal(fmt.Errorf("can't update client %v because it does not exist", clientIdentifier))
	}
	c.ConsentRequired = consentRequired
	result := database.DB.Save(c)

	if result.Error != nil {
		t.Fatal(result.Error, "unable to update client in database")
	}
	return nil
}

//lint:ignore U1000 This function is used to debug tests
func dumpResponseBody(t *testing.T, response *http.Response) {
	t.Log("Response body:")
	byteArr, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	response.Body = io.NopCloser(bytes.NewReader(byteArr))
	content := string(byteArr)
	t.Log(content)
}

func getCsrfValue(t *testing.T, response *http.Response) string {
	byteArr, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	response.Body = io.NopCloser(bytes.NewReader(byteArr))
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(byteArr)))
	if err != nil {
		t.Fatal(err)
	}
	csrfNode := doc.Find("input[name='gorilla.csrf.Token']")
	if csrfNode.Length() != 1 {
		t.Fatal("expecting to find one input with name 'gorilla.csrf.Token'")
	}
	csrf, exists := csrfNode.Attr("value")
	if !exists {
		t.Fatal("input 'gorilla.csrf.Token' does not have a value")
	}
	return csrf
}

func getOtpSecret(t *testing.T, response *http.Response) string {
	byteArr, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	response.Body = io.NopCloser(bytes.NewReader(byteArr))
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(byteArr)))
	if err != nil {
		t.Fatal(err)
	}
	secret := doc.Find("pre.text-center")
	if secret.Length() != 1 {
		t.Fatal("expecting to find pre element with class 'text-center'")
	}
	return secret.Text()
}

func authenticateWithPassword(t *testing.T, client *http.Client, email string, password string, csrf string) *http.Response {
	destUrl := lib.GetBaseUrl() + "/auth/pwd"
	formData := url.Values{
		"email":              {email},
		"password":           {password},
		"gorilla.csrf.Token": {csrf},
	}

	formDataString := formData.Encode()
	requestBody := strings.NewReader(formDataString)
	request, err := http.NewRequest("POST", destUrl, requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func setOTPEnabled(t *testing.T, email string, enabled bool) *entities.User {
	user, err := database.GetUserByEmail(email)
	if err != nil {
		t.Fatal(err)
	}

	if enabled {
		user.OTPEnabled = true
		user.OTPSecret = "ILMGDC577J4A4HTR5POU4BU5H5W7VYM2"
	} else {
		user.OTPEnabled = false
		user.OTPSecret = ""
	}

	user, err = database.UpdateUser(user)
	if err != nil {
		t.Fatal(err)
	}
	return user
}

func deleteAllUserConsents(t *testing.T) {
	err := database.DB.Exec("DELETE FROM user_consents").Error
	if err != nil {
		t.Fatal(err)
	}
}

func postConsent(t *testing.T, client *http.Client, consents []int, csrf string) (resp *http.Response) {
	destUrl := lib.GetBaseUrl() + "/auth/consent"

	formData := url.Values{
		"gorilla.csrf.Token": {csrf},
	}
	for _, consent := range consents {
		formData.Add(fmt.Sprintf("consent%d", consent), "[on]")
	}
	if len(consents) > 0 {
		formData.Add("btnSubmit", "submit")
	} else {
		formData.Add("btnCancel", "cancel")
	}

	formDataString := formData.Encode()
	requestBody := strings.NewReader(formDataString)
	request, err := http.NewRequest("POST", destUrl, requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func loadConsentPage(t *testing.T, client *http.Client) (resp *http.Response) {
	destUrl := lib.GetBaseUrl() + "/auth/consent"

	request, err := http.NewRequest("GET", destUrl, nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func authenticateWithOtp(t *testing.T, client *http.Client, otp string, csrf string) *http.Response {
	destUrl := lib.GetBaseUrl() + "/auth/otp"
	formData := url.Values{
		"otp":                {otp},
		"gorilla.csrf.Token": {csrf},
	}

	formDataString := formData.Encode()
	requestBody := strings.NewReader(formDataString)
	request, err := http.NewRequest("POST", destUrl, requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func grantConsent(t *testing.T, clientIdentifier string, email string, scope string) {
	client, err := database.GetClientByClientIdentifier(clientIdentifier)
	if err != nil {
		t.Fatal(err)
	}
	if client == nil {
		t.Fatal(fmt.Errorf("can't grant consent because client %v does not exist", clientIdentifier))
	}

	user, err := database.GetUserByEmail(email)
	if err != nil {
		t.Fatal(err)
	}
	if user == nil {
		t.Fatal(fmt.Errorf("can't grant consent because user %v does not exist", email))
	}

	consent := entities.UserConsent{
		ClientID: client.ID,
		UserID:   user.ID,
		Scope:    scope,
	}
	err = database.DB.Create(&consent).Error
	if err != nil {
		t.Fatal(err)
	}
}

func settingsGetAcrLevel1MaxAgeInSeconds(t *testing.T) int {
	settings, err := database.GetSettings()
	if err != nil {
		t.Fatal(err)
	}
	return settings.AcrLevel1MaxAgeInSeconds
}

func settingsSetAcrLevel1MaxAgeInSeconds(t *testing.T, maxAge int) {
	settings, err := database.GetSettings()
	if err != nil {
		t.Fatal(err)
	}
	settings.AcrLevel1MaxAgeInSeconds = maxAge
	err = database.DB.Save(settings).Error
	if err != nil {
		t.Fatal(err)
	}
}

func settingsGetAcrLevel2MaxAgeInSeconds(t *testing.T) int {
	settings, err := database.GetSettings()
	if err != nil {
		t.Fatal(err)
	}
	return settings.AcrLevel2MaxAgeInSeconds
}

func settingsSetAcrLevel2MaxAgeInSeconds(t *testing.T, maxAge int) {
	settings, err := database.GetSettings()
	if err != nil {
		t.Fatal(err)
	}
	settings.AcrLevel2MaxAgeInSeconds = maxAge
	err = database.DB.Save(settings).Error
	if err != nil {
		t.Fatal(err)
	}
}

func settingsGetAcrLevel3MaxAgeInSeconds(t *testing.T) int {
	settings, err := database.GetSettings()
	if err != nil {
		t.Fatal(err)
	}
	return settings.AcrLevel3MaxAgeInSeconds
}

func settingsSetAcrLevel3MaxAgeInSeconds(t *testing.T, maxAge int) {
	settings, err := database.GetSettings()
	if err != nil {
		t.Fatal(err)
	}
	settings.AcrLevel3MaxAgeInSeconds = maxAge
	err = database.DB.Save(settings).Error
	if err != nil {
		t.Fatal(err)
	}
}

func postToTokenEndpoint(t *testing.T, client *http.Client, url string, urlValues url.Values) map[string]interface{} {

	formDataString := urlValues.Encode()
	requestBody := strings.NewReader(formDataString)
	request, err := http.NewRequest("POST", url, requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	var data interface{}
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Fatal(err)
	}

	return data.(map[string]interface{})
}
