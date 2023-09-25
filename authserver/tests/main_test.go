package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	b64 "encoding/base64"

	"github.com/PuerkitoBio/goquery"
	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

type errorResp struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type tokenResponse struct {
	AccessToken      string `json:"access_token,omitempty"`
	IdToken          string `json:"id_token,omitempty"`
	TokenType        string `json:"token_type,omitempty"`
	ExpiresIn        int    `json:"expires_in,omitempty"`
	RefreshToken     string `json:"refresh_token,omitempty"`
	RefreshExpiresIn int    `json:"refresh_expires_in,omitempty"`
	Scope            string `json:"scope,omitempty"`
}

func initViper() {
	viper.SetConfigName("config")
	viper.SetConfigType("json")

	viper.AddConfigPath(".")
	viper.AddConfigPath("./configs")

	viper.SetEnvPrefix("GOIABADA")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("unable to initialize configuration - make sure a config.json file exists and has content (%w)", err))
	}
}

var database *sql.DB

func Setup() {
	if database == nil {
		initViper()
		dsn := fmt.Sprintf("%v:%v@tcp(%v:%v)/%v?charset=utf8mb4&parseTime=True&loc=UTC",
			viper.GetString("DB.Username"),
			viper.GetString("DB.Password"),
			viper.GetString("DB.Host"),
			viper.GetInt("DB.Port"),
			viper.GetString("DB.DbName"))

		db, err := sql.Open("mysql", dsn)
		if err != nil {
			panic(err)
		}
		database = db
	}
}

func decryptText(encryptedText []byte, encryptionKey []byte) (string, error) {
	if len(encryptedText) == 0 {
		return "", errors.New("encrypted text is empty")
	}

	if len(encryptionKey) != 32 {
		return "", fmt.Errorf("encryption key must have 32 bytes, but it has %v bytes", len(encryptionKey))
	}

	// create a new AES cipher block
	c, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}

	// create a new GCM (Galois/Counter Mode) cipher
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return "", err
	}

	// nonce size
	nonceSize := gcm.NonceSize()
	if len(encryptedText) < nonceSize {
		return "", errors.New("encrypted text is too short")
	}

	// split the nonce and ciphertext
	nonce, ciphertext := encryptedText[:nonceSize], encryptedText[nonceSize:]

	// decrypt the text
	decryptedText, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(decryptedText), nil
}

func createHttpClient(t *testing.T, followRedirects bool, ignoreTLSErrors bool) *http.Client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Jar: jar,
	}

	if !followRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	if ignoreTLSErrors {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client.Transport = tr
	}
	return client
}

func TestClientIdIsMissing(t *testing.T) {
	Setup()
	url := viper.GetString("BaseUrl") + "/auth/authorize/"

	client := createHttpClient(t, true, true)

	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	title := doc.Find("p.text-red-500").Text()
	assert.Equal(t, "The client_id parameter is missing.", title)
}

func TestClientDoesNotExist(t *testing.T) {
	Setup()
	url := viper.GetString("BaseUrl") + "/auth/authorize/?client_id=does_not_exist"

	client := createHttpClient(t, true, true)

	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	title := doc.Find("p.text-red-500").Text()
	assert.Equal(t, "We couldn't find a client associated with the provided client_id.", title)
}

func TestClientIsDisabled(t *testing.T) {
	Setup()
	sqlCmd, err := database.Query("UPDATE clients SET enabled = 0 WHERE client_identifier = 'test-client-1'")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	url := viper.GetString("BaseUrl") + "/auth/authorize/?client_id=test-client-1"

	client := createHttpClient(t, true, true)

	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	title := doc.Find("p.text-red-500").Text()
	assert.Equal(t, "The client associated with the provided client_id is not enabled.", title)

	sqlCmd, err = database.Query("UPDATE clients SET enabled = 1 WHERE client_identifier = 'test-client-1'")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()
}

func TestRedirectUriIsMissing(t *testing.T) {
	Setup()
	url := viper.GetString("BaseUrl") + "/auth/authorize/?client_id=test-client-1"

	client := createHttpClient(t, true, true)

	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	title := doc.Find("p.text-red-500").Text()
	assert.Equal(t, "The redirect_uri parameter is missing.", title)
}

func TestClientDoesNotHaveRedirectUri(t *testing.T) {
	Setup()
	url := viper.GetString("BaseUrl") +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=http://something.com"

	client := createHttpClient(t, true, true)

	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	title := doc.Find("p.text-red-500").Text()
	assert.Equal(t, "Invalid redirect_uri parameter. The client does not have this redirect uri configured.", title)
}

func TestResponseTypeIsMissing(t *testing.T) {
	Setup()
	destUrl := viper.GetString("BaseUrl") +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://test-client.goiabada.local:3010/callback.html"

	client := createHttpClient(t, false, true)

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	error := redirectLocation.Query().Get("error")
	errorDescription := redirectLocation.Query().Get("error_description")

	assert.Equal(t, "invalid_request", error)
	assert.Equal(t, "Ensure response_type is set to 'code' as it's the only supported value.", errorDescription)
}

func TestResponseTypeIsInvalid(t *testing.T) {
	Setup()
	destUrl := viper.GetString("BaseUrl") +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://test-client.goiabada.local:3010/callback.html&response_type=invalid"

	client := createHttpClient(t, false, true)

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	error := redirectLocation.Query().Get("error")
	errorDescription := redirectLocation.Query().Get("error_description")

	assert.Equal(t, "invalid_request", error)
	assert.Equal(t, "Ensure response_type is set to 'code' as it's the only supported value.", errorDescription)
}

func TestCodeChallengeMethodMissing(t *testing.T) {
	Setup()
	destUrl := viper.GetString("BaseUrl") +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://test-client.goiabada.local:3010/callback.html&response_type=code"

	client := createHttpClient(t, false, true)

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	error := redirectLocation.Query().Get("error")
	errorDescription := redirectLocation.Query().Get("error_description")

	assert.Equal(t, "invalid_request", error)
	assert.Equal(t, "Ensure code_challenge_method is set to 'S256' as it's the only supported value.", errorDescription)
}

func TestCodeChallengeMethodInvalid(t *testing.T) {
	Setup()
	destUrl := viper.GetString("BaseUrl") +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://test-client.goiabada.local:3010/callback.html&response_type=code" +
		"&code_challenge_method=plain"

	client := createHttpClient(t, false, true)

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	error := redirectLocation.Query().Get("error")
	errorDescription := redirectLocation.Query().Get("error_description")

	assert.Equal(t, "invalid_request", error)
	assert.Equal(t, "Ensure code_challenge_method is set to 'S256' as it's the only supported value.", errorDescription)
}

func TestCodeChallengeMissing(t *testing.T) {
	Setup()
	destUrl := viper.GetString("BaseUrl") +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://test-client.goiabada.local:3010/callback.html&response_type=code" +
		"&code_challenge_method=S256"

	client := createHttpClient(t, false, true)

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	error := redirectLocation.Query().Get("error")
	errorDescription := redirectLocation.Query().Get("error_description")

	assert.Equal(t, "invalid_request", error)
	assert.Equal(t, "The code_challenge parameter is either missing or incorrect. It should be 43 to 128 characters long.", errorDescription)
}

func TestCodeChallengeLessThan43(t *testing.T) {
	Setup()
	destUrl := viper.GetString("BaseUrl") +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://test-client.goiabada.local:3010/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=abcabc"

	client := createHttpClient(t, false, true)

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	error := redirectLocation.Query().Get("error")
	errorDescription := redirectLocation.Query().Get("error_description")

	assert.Equal(t, "invalid_request", error)
	assert.Equal(t, "The code_challenge parameter is either missing or incorrect. It should be 43 to 128 characters long.", errorDescription)
}

func TestCodeChallengeMoreThan128(t *testing.T) {
	Setup()

	codeChallenge := ""
	for i := 0; i < 150; i++ {
		codeChallenge += "a"
	}

	destUrl := viper.GetString("BaseUrl") +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://test-client.goiabada.local:3010/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge

	client := createHttpClient(t, false, true)

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	error := redirectLocation.Query().Get("error")
	errorDescription := redirectLocation.Query().Get("error_description")

	assert.Equal(t, "invalid_request", error)
	assert.Equal(t, "The code_challenge parameter is either missing or incorrect. It should be 43 to 128 characters long.", errorDescription)
}

func TestInvalidResponseMode(t *testing.T) {
	Setup()

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := viper.GetString("BaseUrl") +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://test-client.goiabada.local:3010/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=invalid"

	client := createHttpClient(t, false, true)

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	error := redirectLocation.Query().Get("error")
	errorDescription := redirectLocation.Query().Get("error_description")

	assert.Equal(t, "invalid_request", error)
	assert.Equal(t, "Please use 'query,' 'fragment,' or 'form_post' as the response_mode value.", errorDescription)
}

func TestInvalidScope1(t *testing.T) {
	Setup()

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := viper.GetString("BaseUrl") +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://test-client.goiabada.local:3010/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=a:b:c"

	client := createHttpClient(t, false, true)

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	error := redirectLocation.Query().Get("error")
	errorDescription := redirectLocation.Query().Get("error_description")

	assert.Equal(t, "invalid_scope", error)
	assert.Equal(t, "Invalid scope format: 'a:b:c'. Scopes must adhere to the resource-identifier:permission-identifier format. For instance: backend-service:create-product.", errorDescription)
}

func TestInvalidScope2(t *testing.T) {
	Setup()

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := viper.GetString("BaseUrl") +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://test-client.goiabada.local:3010/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=aaa"

	client := createHttpClient(t, false, true)

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	error := redirectLocation.Query().Get("error")
	errorDescription := redirectLocation.Query().Get("error_description")

	assert.Equal(t, "invalid_scope", error)
	assert.Equal(t, "Invalid scope format: 'aaa'. Scopes must adhere to the resource-identifier:permission-identifier format. For instance: backend-service:create-product.", errorDescription)
}

func TestInvalidScope3(t *testing.T) {
	Setup()

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := viper.GetString("BaseUrl") +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://test-client.goiabada.local:3010/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=res:perm"

	client := createHttpClient(t, false, true)

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	error := redirectLocation.Query().Get("error")
	errorDescription := redirectLocation.Query().Get("error_description")

	assert.Equal(t, "invalid_scope", error)
	assert.Equal(t, "Invalid scope: 'res:perm'. Could not find a resource with identifier 'res'.", errorDescription)
}

func TestInvalidScope4(t *testing.T) {
	Setup()

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := viper.GetString("BaseUrl") +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://test-client.goiabada.local:3010/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=backend-svcA:perm"

	client := createHttpClient(t, false, true)

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	error := redirectLocation.Query().Get("error")
	errorDescription := redirectLocation.Query().Get("error_description")

	assert.Equal(t, "invalid_scope", error)
	assert.Equal(t, "Scope 'backend-svcA:perm' is not recognized. The resource identified by 'backend-svcA' doesn't grant the 'perm' permission.", errorDescription)
}

func TestPermissionNotGrantedToUser(t *testing.T) {
	Setup()

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := viper.GetString("BaseUrl") +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://test-client.goiabada.local:3010/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=backend-svcA:create-product"

	client := createHttpClient(t, true, true)

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	csrfNode := doc.Find("input[name='gorilla.csrf.Token']")
	csrf, _ := csrfNode.Attr("value")

	destUrl = viper.GetString("BaseUrl") + "/auth/pwd"

	formData := url.Values{
		"username":           {"mauro1"},
		"password":           {"abc123"},
		"gorilla.csrf.Token": {csrf},
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
	defer resp.Body.Close()

	doc, err = goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	title := doc.Find("p.text-red-500").Text()
	assert.Equal(t, "Permission to access scope 'backend-svcA:create-product' is not granted to the user.", title)
}

func TestOneLogin_Pwd_WithFullConsent(t *testing.T) {
	Setup()

	// make sure otp is disabled for the user
	sqlCmd, err := database.Query("UPDATE users SET acr_level2_include_otp = 0 WHERE username = 'mauro1'")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	// make sure there's no prior user consent
	sqlCmd, err = database.Query("DELETE FROM user_consents")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := viper.GetString("BaseUrl") +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://test-client.goiabada.local:3010/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email%20backend-svcA%3Aread-product&state=a1b2c3&nonce=m9n8b7"

	client := createHttpClient(t, true, true)

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	csrfNode := doc.Find("input[name='gorilla.csrf.Token']")
	csrf, _ := csrfNode.Attr("value")

	// ----------------------------------------------------------------

	destUrl = viper.GetString("BaseUrl") + "/auth/pwd"

	formData := url.Values{
		"username":           {"mauro1"},
		"password":           {"abc123"},
		"gorilla.csrf.Token": {csrf},
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
	defer resp.Body.Close()

	doc, err = goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	csrfNode = doc.Find("input[name='gorilla.csrf.Token']")
	csrf, _ = csrfNode.Attr("value")

	// ----------------------------------------------------------------

	destUrl = viper.GetString("BaseUrl") + "/auth/consent"

	formData = url.Values{
		"btnSubmit":          {"submit"},
		"consent0":           {"[on]"},
		"consent1":           {"[on]"},
		"consent2":           {"[on]"},
		"consent3":           {"[on]"},
		"gorilla.csrf.Token": {csrf},
	}

	formDataString = formData.Encode()
	requestBody = strings.NewReader(formDataString)
	request, err = http.NewRequest("POST", destUrl, requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	codeVal := redirectLocation.Query().Get("code")
	stateVal := redirectLocation.Query().Get("state")

	assert.Equal(t, 128, len(codeVal))
	assert.Equal(t, "a1b2c3", stateVal)

	sqlCmd, err = database.Query("SELECT scope, state, nonce, acr_level, auth_methods, used FROM codes WHERE code = ?", codeVal)
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	var scope, state, nonce, acr_level, auth_methods, used string
	for sqlCmd.Next() {
		err := sqlCmd.Scan(&scope, &state, &nonce, &acr_level, &auth_methods, &used)
		if err != nil {
			t.Fatal(err)
		}
	}
	assert.Equal(t, "openid profile email backend-svcA:read-product", scope)
	assert.Equal(t, "a1b2c3", state)
	assert.Equal(t, "m9n8b7", nonce)
	assert.Equal(t, "1", acr_level)
	assert.Equal(t, "pwd", auth_methods)
	assert.Equal(t, "0", used)
}

func TestOneLogin_PwdAndOtp_WithFullConsent(t *testing.T) {
	Setup()

	// make sure otp is enabled for the user
	sqlCmd, err := database.Query("UPDATE users SET acr_level2_include_otp = 1 WHERE username = 'mauro1'")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	// make sure there's no prior user consent
	sqlCmd, err = database.Query("DELETE FROM user_consents")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := viper.GetString("BaseUrl") +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://test-client.goiabada.local:3010/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email%20backend-svcA%3Aread-product&state=a1b2c3&nonce=m9n8b7"

	client := createHttpClient(t, true, true)

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	csrfNode := doc.Find("input[name='gorilla.csrf.Token']")
	csrf, _ := csrfNode.Attr("value")

	// ----------------------------------------------------------------

	destUrl = viper.GetString("BaseUrl") + "/auth/pwd"

	formData := url.Values{
		"username":           {"mauro1"},
		"password":           {"abc123"},
		"gorilla.csrf.Token": {csrf},
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
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err = goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	csrfNode = doc.Find("input[name='gorilla.csrf.Token']")
	csrf, _ = csrfNode.Attr("value")

	// ----------------------------------------------------------------

	destUrl = viper.GetString("BaseUrl") + "/auth/otp"

	totp, err := totp.GenerateCode("ILMGDC577J4A4HTR5POU4BU5H5W7VYM2", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	formData = url.Values{
		"otp":                {totp},
		"gorilla.csrf.Token": {csrf},
	}

	formDataString = formData.Encode()
	requestBody = strings.NewReader(formDataString)
	request, err = http.NewRequest("POST", destUrl, requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err = goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	csrfNode = doc.Find("input[name='gorilla.csrf.Token']")
	csrf, _ = csrfNode.Attr("value")

	// ----------------------------------------------------------------

	destUrl = viper.GetString("BaseUrl") + "/auth/consent"

	formData = url.Values{
		"btnSubmit":          {"submit"},
		"consent0":           {"[on]"},
		"consent1":           {"[on]"},
		"consent2":           {"[on]"},
		"consent3":           {"[on]"},
		"gorilla.csrf.Token": {csrf},
	}

	formDataString = formData.Encode()
	requestBody = strings.NewReader(formDataString)
	request, err = http.NewRequest("POST", destUrl, requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	codeVal := redirectLocation.Query().Get("code")
	stateVal := redirectLocation.Query().Get("state")

	assert.Equal(t, 128, len(codeVal))
	assert.Equal(t, "a1b2c3", stateVal)

	sqlCmd, err = database.Query("SELECT scope, state, nonce, acr_level, auth_methods, used FROM codes WHERE code = ?", codeVal)
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	var scope, state, nonce, acr_level, auth_methods, used string
	for sqlCmd.Next() {
		err := sqlCmd.Scan(&scope, &state, &nonce, &acr_level, &auth_methods, &used)
		if err != nil {
			t.Fatal(err)
		}
	}
	assert.Equal(t, "openid profile email backend-svcA:read-product", scope)
	assert.Equal(t, "a1b2c3", state)
	assert.Equal(t, "m9n8b7", nonce)
	assert.Equal(t, "2", acr_level)
	assert.Equal(t, "pwd otp", auth_methods)
	assert.Equal(t, "0", used)
}

func TestTwoLogins_Pwd_WithFullConsent(t *testing.T) {
	Setup()

	// make sure otp is disabled for the user
	sqlCmd, err := database.Query("UPDATE users SET acr_level2_include_otp = 0 WHERE username = 'mauro1'")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	// make sure there's no prior user consent
	sqlCmd, err = database.Query("DELETE FROM user_consents")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := viper.GetString("BaseUrl") +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://test-client.goiabada.local:3010/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email%20backend-svcA%3Aread-product&state=a1b2c3&nonce=m9n8b7"

	client := createHttpClient(t, true, true)

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	csrfNode := doc.Find("input[name='gorilla.csrf.Token']")
	csrf, _ := csrfNode.Attr("value")

	// ----------------------------------------------------------------

	destUrl = viper.GetString("BaseUrl") + "/auth/pwd"

	formData := url.Values{
		"username":           {"mauro1"},
		"password":           {"abc123"},
		"gorilla.csrf.Token": {csrf},
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
	defer resp.Body.Close()

	doc, err = goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	csrfNode = doc.Find("input[name='gorilla.csrf.Token']")
	csrf, _ = csrfNode.Attr("value")

	// ----------------------------------------------------------------

	destUrl = viper.GetString("BaseUrl") + "/auth/consent"

	formData = url.Values{
		"btnSubmit":          {"submit"},
		"consent0":           {"[on]"},
		"consent1":           {"[on]"},
		"consent2":           {"[on]"},
		"consent3":           {"[on]"},
		"gorilla.csrf.Token": {csrf},
	}

	formDataString = formData.Encode()
	requestBody = strings.NewReader(formDataString)
	request, err = http.NewRequest("POST", destUrl, requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	codeVal := redirectLocation.Query().Get("code")
	stateVal := redirectLocation.Query().Get("state")

	assert.Equal(t, 128, len(codeVal))
	assert.Equal(t, "a1b2c3", stateVal)

	sqlCmd, err = database.Query("SELECT scope, state, nonce, acr_level, auth_methods, used FROM codes WHERE code = ?", codeVal)
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	var scope, state, nonce, acr_level, auth_methods, used string
	for sqlCmd.Next() {
		err := sqlCmd.Scan(&scope, &state, &nonce, &acr_level, &auth_methods, &used)
		if err != nil {
			t.Fatal(err)
		}
	}
	assert.Equal(t, "openid profile email backend-svcA:read-product", scope)
	assert.Equal(t, "a1b2c3", state)
	assert.Equal(t, "m9n8b7", nonce)
	assert.Equal(t, "1", acr_level)
	assert.Equal(t, "pwd", auth_methods)
	assert.Equal(t, "0", used)

	// ----------------------------------------------------------------

	destUrl = viper.GetString("BaseUrl") +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://test-client.goiabada.local:3010/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email%20backend-svcA%3Aread-product&state=a1b2c3&nonce=m9n8b7"

	request, err = http.NewRequest("GET", destUrl, nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	// ----------------------------------------------------------------

	destUrl = viper.GetString("BaseUrl") + "/auth/consent"

	request, err = http.NewRequest("GET", destUrl, nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	redirectLocation, err = url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	codeVal = redirectLocation.Query().Get("code")
	stateVal = redirectLocation.Query().Get("state")

	assert.Equal(t, 128, len(codeVal))
	assert.Equal(t, "a1b2c3", stateVal)

	sqlCmd, err = database.Query("SELECT scope, state, nonce, acr_level, auth_methods, used, session_identifier FROM codes WHERE code = ?", codeVal)
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	var session_identifier string
	for sqlCmd.Next() {
		err := sqlCmd.Scan(&scope, &state, &nonce, &acr_level, &auth_methods, &used, &session_identifier)
		if err != nil {
			t.Fatal(err)
		}
	}
	assert.Equal(t, "openid profile email backend-svcA:read-product", scope)
	assert.Equal(t, "a1b2c3", state)
	assert.Equal(t, "m9n8b7", nonce)
	assert.Equal(t, "1", acr_level)
	assert.Equal(t, "pwd", auth_methods)
	assert.Equal(t, "0", used)
	assert.True(t, len(session_identifier) > 0)
}

func TestOneLogin_Pwd_WithPartialConsent(t *testing.T) {
	Setup()

	// make sure otp is disabled for the user
	sqlCmd, err := database.Query("UPDATE users SET acr_level2_include_otp = 0 WHERE username = 'mauro1'")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	// make sure there's no prior user consent
	sqlCmd, err = database.Query("DELETE FROM user_consents")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := viper.GetString("BaseUrl") +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://test-client.goiabada.local:3010/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email%20backend-svcA%3Aread-product&state=a1b2c3&nonce=m9n8b7"

	client := createHttpClient(t, true, true)

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	csrfNode := doc.Find("input[name='gorilla.csrf.Token']")
	csrf, _ := csrfNode.Attr("value")

	// ----------------------------------------------------------------

	destUrl = viper.GetString("BaseUrl") + "/auth/pwd"

	formData := url.Values{
		"username":           {"mauro1"},
		"password":           {"abc123"},
		"gorilla.csrf.Token": {csrf},
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
	defer resp.Body.Close()

	doc, err = goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	csrfNode = doc.Find("input[name='gorilla.csrf.Token']")
	csrf, _ = csrfNode.Attr("value")

	// ----------------------------------------------------------------

	destUrl = viper.GetString("BaseUrl") + "/auth/consent"

	formData = url.Values{
		"btnSubmit":          {"submit"},
		"consent0":           {"[on]"},
		"consent3":           {"[on]"},
		"gorilla.csrf.Token": {csrf},
	}

	formDataString = formData.Encode()
	requestBody = strings.NewReader(formDataString)
	request, err = http.NewRequest("POST", destUrl, requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	codeVal := redirectLocation.Query().Get("code")
	stateVal := redirectLocation.Query().Get("state")

	assert.Equal(t, 128, len(codeVal))
	assert.Equal(t, "a1b2c3", stateVal)

	sqlCmd, err = database.Query("SELECT scope, state, nonce, acr_level, auth_methods, used FROM codes WHERE code = ?", codeVal)
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	var scope, state, nonce, acr_level, auth_methods, used string
	for sqlCmd.Next() {
		err := sqlCmd.Scan(&scope, &state, &nonce, &acr_level, &auth_methods, &used)
		if err != nil {
			t.Fatal(err)
		}
	}
	assert.Equal(t, "openid backend-svcA:read-product", scope)
	assert.Equal(t, "a1b2c3", state)
	assert.Equal(t, "m9n8b7", nonce)
	assert.Equal(t, "1", acr_level)
	assert.Equal(t, "pwd", auth_methods)
	assert.Equal(t, "0", used)
}

func TestOneLogin_PwdAndOtp_WithPartialConsent(t *testing.T) {
	Setup()

	// make sure otp is enabled for the user
	sqlCmd, err := database.Query("UPDATE users SET acr_level2_include_otp = 1 WHERE username = 'mauro1'")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	// make sure there's no prior user consent
	sqlCmd, err = database.Query("DELETE FROM user_consents")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := viper.GetString("BaseUrl") +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://test-client.goiabada.local:3010/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email%20backend-svcA%3Aread-product&state=a1b2c3&nonce=m9n8b7"

	client := createHttpClient(t, true, true)

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	csrfNode := doc.Find("input[name='gorilla.csrf.Token']")
	csrf, _ := csrfNode.Attr("value")

	// ----------------------------------------------------------------

	destUrl = viper.GetString("BaseUrl") + "/auth/pwd"

	formData := url.Values{
		"username":           {"mauro1"},
		"password":           {"abc123"},
		"gorilla.csrf.Token": {csrf},
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
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err = goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	csrfNode = doc.Find("input[name='gorilla.csrf.Token']")
	csrf, _ = csrfNode.Attr("value")

	// ----------------------------------------------------------------

	destUrl = viper.GetString("BaseUrl") + "/auth/otp"

	totp, err := totp.GenerateCode("ILMGDC577J4A4HTR5POU4BU5H5W7VYM2", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	formData = url.Values{
		"otp":                {totp},
		"gorilla.csrf.Token": {csrf},
	}

	formDataString = formData.Encode()
	requestBody = strings.NewReader(formDataString)
	request, err = http.NewRequest("POST", destUrl, requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err = goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	csrfNode = doc.Find("input[name='gorilla.csrf.Token']")
	csrf, _ = csrfNode.Attr("value")

	// ----------------------------------------------------------------

	destUrl = viper.GetString("BaseUrl") + "/auth/consent"

	formData = url.Values{
		"btnSubmit":          {"submit"},
		"consent0":           {"[on]"},
		"consent3":           {"[on]"},
		"gorilla.csrf.Token": {csrf},
	}

	formDataString = formData.Encode()
	requestBody = strings.NewReader(formDataString)
	request, err = http.NewRequest("POST", destUrl, requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	codeVal := redirectLocation.Query().Get("code")
	stateVal := redirectLocation.Query().Get("state")

	assert.Equal(t, 128, len(codeVal))
	assert.Equal(t, "a1b2c3", stateVal)

	sqlCmd, err = database.Query("SELECT scope, state, nonce, acr_level, auth_methods, used FROM codes WHERE code = ?", codeVal)
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	var scope, state, nonce, acr_level, auth_methods, used string
	for sqlCmd.Next() {
		err := sqlCmd.Scan(&scope, &state, &nonce, &acr_level, &auth_methods, &used)
		if err != nil {
			t.Fatal(err)
		}
	}
	assert.Equal(t, "openid backend-svcA:read-product", scope)
	assert.Equal(t, "a1b2c3", state)
	assert.Equal(t, "m9n8b7", nonce)
	assert.Equal(t, "2", acr_level)
	assert.Equal(t, "pwd otp", auth_methods)
	assert.Equal(t, "0", used)
}

func TestTwoLogins_Pwd_WithPreviousConsentGiven(t *testing.T) {
	Setup()

	// make sure otp is disabled for the user
	sqlCmd, err := database.Query("UPDATE users SET acr_level2_include_otp = 0 WHERE username = 'mauro1'")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	// clear user consent
	sqlCmd, err = database.Query("DELETE FROM user_consents")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	// add user consent
	sqlCmd, err = database.Query("INSERT INTO user_consents (user_id, client_id, scope) values (2, 4, 'openid profile email backend-svcA:read-product')")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := viper.GetString("BaseUrl") +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://test-client.goiabada.local:3010/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email%20backend-svcA%3Aread-product&state=a1b2c3&nonce=m9n8b7"

	client := createHttpClient(t, true, true)

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	csrfNode := doc.Find("input[name='gorilla.csrf.Token']")
	csrf, _ := csrfNode.Attr("value")

	// ----------------------------------------------------------------

	destUrl = viper.GetString("BaseUrl") + "/auth/pwd"

	formData := url.Values{
		"username":           {"mauro1"},
		"password":           {"abc123"},
		"gorilla.csrf.Token": {csrf},
	}

	formDataString := formData.Encode()
	requestBody := strings.NewReader(formDataString)
	request, err := http.NewRequest("POST", destUrl, requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// ----------------------------------------------------------------

	destUrl = viper.GetString("BaseUrl") + "/auth/consent"

	request, err = http.NewRequest("GET", destUrl, nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	codeVal := redirectLocation.Query().Get("code")
	stateVal := redirectLocation.Query().Get("state")

	assert.Equal(t, 128, len(codeVal))
	assert.Equal(t, "a1b2c3", stateVal)

	sqlCmd, err = database.Query("SELECT scope, state, nonce, acr_level, auth_methods, used FROM codes WHERE code = ?", codeVal)
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	var scope, state, nonce, acr_level, auth_methods, used string
	for sqlCmd.Next() {
		err := sqlCmd.Scan(&scope, &state, &nonce, &acr_level, &auth_methods, &used)
		if err != nil {
			t.Fatal(err)
		}
	}
	assert.Equal(t, "openid profile email backend-svcA:read-product", scope)
	assert.Equal(t, "a1b2c3", state)
	assert.Equal(t, "m9n8b7", nonce)
	assert.Equal(t, "1", acr_level)
	assert.Equal(t, "pwd", auth_methods)
	assert.Equal(t, "0", used)
}

func TestTwoLogins_Pwd_WithFullConsent_WithAcrDowngrade(t *testing.T) {
	Setup()

	// make sure otp is disabled for the user
	sqlCmd, err := database.Query("UPDATE users SET acr_level2_include_otp = 0 WHERE username = 'mauro1'")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	// make sure there's no prior user consent
	sqlCmd, err = database.Query("DELETE FROM user_consents")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	// allow only 1 second of acr level 1
	sqlCmd, err = database.Query("UPDATE settings SET acr_level1_max_age_in_seconds = 1")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := viper.GetString("BaseUrl") +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://test-client.goiabada.local:3010/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email%20backend-svcA%3Aread-product&state=a1b2c3&nonce=m9n8b7"

	client := createHttpClient(t, true, true)

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	csrfNode := doc.Find("input[name='gorilla.csrf.Token']")
	csrf, _ := csrfNode.Attr("value")

	// ----------------------------------------------------------------

	destUrl = viper.GetString("BaseUrl") + "/auth/pwd"

	formData := url.Values{
		"username":           {"mauro1"},
		"password":           {"abc123"},
		"gorilla.csrf.Token": {csrf},
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
	defer resp.Body.Close()

	doc, err = goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	csrfNode = doc.Find("input[name='gorilla.csrf.Token']")
	csrf, _ = csrfNode.Attr("value")

	// ----------------------------------------------------------------

	destUrl = viper.GetString("BaseUrl") + "/auth/consent"

	formData = url.Values{
		"btnSubmit":          {"submit"},
		"consent0":           {"[on]"},
		"consent1":           {"[on]"},
		"consent2":           {"[on]"},
		"consent3":           {"[on]"},
		"gorilla.csrf.Token": {csrf},
	}

	formDataString = formData.Encode()
	requestBody = strings.NewReader(formDataString)
	request, err = http.NewRequest("POST", destUrl, requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	codeVal := redirectLocation.Query().Get("code")
	stateVal := redirectLocation.Query().Get("state")

	assert.Equal(t, 128, len(codeVal))
	assert.Equal(t, "a1b2c3", stateVal)

	sqlCmd, err = database.Query("SELECT scope, state, nonce, acr_level, auth_methods, used FROM codes WHERE code = ?", codeVal)
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	var scope, state, nonce, acr_level, auth_methods, used string
	for sqlCmd.Next() {
		err := sqlCmd.Scan(&scope, &state, &nonce, &acr_level, &auth_methods, &used)
		if err != nil {
			t.Fatal(err)
		}
	}
	assert.Equal(t, "openid profile email backend-svcA:read-product", scope)
	assert.Equal(t, "a1b2c3", state)
	assert.Equal(t, "m9n8b7", nonce)
	assert.Equal(t, "1", acr_level)
	assert.Equal(t, "pwd", auth_methods)
	assert.Equal(t, "0", used)

	// ----------------------------------------------------------------

	time.Sleep(2 * time.Second)

	destUrl = viper.GetString("BaseUrl") +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://test-client.goiabada.local:3010/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email%20backend-svcA%3Aread-product&state=a1b2c3&nonce=m9n8b7"

	request, err = http.NewRequest("GET", destUrl, nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	// ----------------------------------------------------------------

	destUrl = viper.GetString("BaseUrl") + "/auth/consent"

	request, err = http.NewRequest("GET", destUrl, nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	redirectLocation, err = url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	codeVal = redirectLocation.Query().Get("code")
	stateVal = redirectLocation.Query().Get("state")

	assert.Equal(t, 128, len(codeVal))
	assert.Equal(t, "a1b2c3", stateVal)

	sqlCmd, err = database.Query("SELECT scope, state, nonce, acr_level, auth_methods, used, session_identifier FROM codes WHERE code = ?", codeVal)
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	var session_identifier string
	for sqlCmd.Next() {
		err := sqlCmd.Scan(&scope, &state, &nonce, &acr_level, &auth_methods, &used, &session_identifier)
		if err != nil {
			t.Fatal(err)
		}
	}
	assert.Equal(t, "openid profile email backend-svcA:read-product", scope)
	assert.Equal(t, "a1b2c3", state)
	assert.Equal(t, "m9n8b7", nonce)
	assert.Equal(t, "0", acr_level) // acr downgraded because it's past the acr level 1 max age
	assert.Equal(t, "pwd", auth_methods)
	assert.Equal(t, "0", used)
	assert.True(t, len(session_identifier) > 0)

	// restore settings
	sqlCmd, err = database.Query("UPDATE settings SET acr_level1_max_age_in_seconds = 43200")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()
}

func TestTwoLogins_Pwd_WithFullConsent_WithAcrDowngrade_AndRequestedAcrValue1(t *testing.T) {
	Setup()

	// make sure otp is disabled for the user
	sqlCmd, err := database.Query("UPDATE users SET acr_level2_include_otp = 0 WHERE username = 'mauro1'")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	// make sure there's no prior user consent
	sqlCmd, err = database.Query("DELETE FROM user_consents")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	// allow only 1 second of acr level 1
	sqlCmd, err = database.Query("UPDATE settings SET acr_level1_max_age_in_seconds = 1")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := viper.GetString("BaseUrl") +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://test-client.goiabada.local:3010/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email%20backend-svcA%3Aread-product&state=a1b2c3&nonce=m9n8b7"

	client := createHttpClient(t, true, true)

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	csrfNode := doc.Find("input[name='gorilla.csrf.Token']")
	csrf, _ := csrfNode.Attr("value")

	// ----------------------------------------------------------------

	destUrl = viper.GetString("BaseUrl") + "/auth/pwd"

	formData := url.Values{
		"username":           {"mauro1"},
		"password":           {"abc123"},
		"gorilla.csrf.Token": {csrf},
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
	defer resp.Body.Close()

	doc, err = goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	csrfNode = doc.Find("input[name='gorilla.csrf.Token']")
	csrf, _ = csrfNode.Attr("value")

	// ----------------------------------------------------------------

	destUrl = viper.GetString("BaseUrl") + "/auth/consent"

	formData = url.Values{
		"btnSubmit":          {"submit"},
		"consent0":           {"[on]"},
		"consent1":           {"[on]"},
		"consent2":           {"[on]"},
		"consent3":           {"[on]"},
		"gorilla.csrf.Token": {csrf},
	}

	formDataString = formData.Encode()
	requestBody = strings.NewReader(formDataString)
	request, err = http.NewRequest("POST", destUrl, requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	codeVal := redirectLocation.Query().Get("code")
	stateVal := redirectLocation.Query().Get("state")

	assert.Equal(t, 128, len(codeVal))
	assert.Equal(t, "a1b2c3", stateVal)

	sqlCmd, err = database.Query("SELECT scope, state, nonce, acr_level, auth_methods, used FROM codes WHERE code = ?", codeVal)
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	var scope, state, nonce, acr_level, auth_methods, used string
	for sqlCmd.Next() {
		err := sqlCmd.Scan(&scope, &state, &nonce, &acr_level, &auth_methods, &used)
		if err != nil {
			t.Fatal(err)
		}
	}
	assert.Equal(t, "openid profile email backend-svcA:read-product", scope)
	assert.Equal(t, "a1b2c3", state)
	assert.Equal(t, "m9n8b7", nonce)
	assert.Equal(t, "1", acr_level)
	assert.Equal(t, "pwd", auth_methods)
	assert.Equal(t, "0", used)

	// ----------------------------------------------------------------

	time.Sleep(2 * time.Second)

	destUrl = viper.GetString("BaseUrl") +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://test-client.goiabada.local:3010/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email%20backend-svcA%3Aread-product&state=a1b2c3&nonce=m9n8b7" +
		"&acr_values=1"

	request, err = http.NewRequest("GET", destUrl, nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	// ----------------------------------------------------------------

	destUrl = viper.GetString("BaseUrl") + "/auth/pwd"

	formData = url.Values{
		"username":           {"mauro1"},
		"password":           {"abc123"},
		"gorilla.csrf.Token": {csrf},
	}

	formDataString = formData.Encode()
	requestBody = strings.NewReader(formDataString)
	request, err = http.NewRequest("POST", destUrl, requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// ----------------------------------------------------------------

	destUrl = viper.GetString("BaseUrl") + "/auth/consent"

	request, err = http.NewRequest("GET", destUrl, nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	redirectLocation, err = url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	codeVal = redirectLocation.Query().Get("code")
	stateVal = redirectLocation.Query().Get("state")

	assert.Equal(t, 128, len(codeVal))
	assert.Equal(t, "a1b2c3", stateVal)

	sqlCmd, err = database.Query("SELECT scope, state, nonce, acr_level, auth_methods, used, session_identifier FROM codes WHERE code = ?", codeVal)
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	var session_identifier string
	for sqlCmd.Next() {
		err := sqlCmd.Scan(&scope, &state, &nonce, &acr_level, &auth_methods, &used, &session_identifier)
		if err != nil {
			t.Fatal(err)
		}
	}
	assert.Equal(t, "openid profile email backend-svcA:read-product", scope)
	assert.Equal(t, "a1b2c3", state)
	assert.Equal(t, "m9n8b7", nonce)
	assert.Equal(t, "1", acr_level)
	assert.Equal(t, "pwd", auth_methods)
	assert.Equal(t, "0", used)
	assert.True(t, len(session_identifier) > 0)

	// restore settings
	sqlCmd, err = database.Query("UPDATE settings SET acr_level1_max_age_in_seconds = 43200")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()
}

func TestTwoLogins_Pwd_WithFullConsent_WithRequestedMaxAge(t *testing.T) {
	Setup()

	// make sure otp is disabled for the user
	sqlCmd, err := database.Query("UPDATE users SET acr_level2_include_otp = 0 WHERE username = 'mauro1'")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	// make sure there's no prior user consent
	sqlCmd, err = database.Query("DELETE FROM user_consents")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := viper.GetString("BaseUrl") +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://test-client.goiabada.local:3010/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email%20backend-svcA%3Aread-product&state=a1b2c3&nonce=m9n8b7"

	client := createHttpClient(t, true, true)

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	csrfNode := doc.Find("input[name='gorilla.csrf.Token']")
	csrf, _ := csrfNode.Attr("value")

	// ----------------------------------------------------------------

	destUrl = viper.GetString("BaseUrl") + "/auth/pwd"

	formData := url.Values{
		"username":           {"mauro1"},
		"password":           {"abc123"},
		"gorilla.csrf.Token": {csrf},
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
	defer resp.Body.Close()

	doc, err = goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	csrfNode = doc.Find("input[name='gorilla.csrf.Token']")
	csrf, _ = csrfNode.Attr("value")

	// ----------------------------------------------------------------

	destUrl = viper.GetString("BaseUrl") + "/auth/consent"

	formData = url.Values{
		"btnSubmit":          {"submit"},
		"consent0":           {"[on]"},
		"consent1":           {"[on]"},
		"consent2":           {"[on]"},
		"consent3":           {"[on]"},
		"gorilla.csrf.Token": {csrf},
	}

	formDataString = formData.Encode()
	requestBody = strings.NewReader(formDataString)
	request, err = http.NewRequest("POST", destUrl, requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	codeVal := redirectLocation.Query().Get("code")
	stateVal := redirectLocation.Query().Get("state")

	assert.Equal(t, 128, len(codeVal))
	assert.Equal(t, "a1b2c3", stateVal)

	sqlCmd, err = database.Query("SELECT scope, state, nonce, acr_level, auth_methods, used FROM codes WHERE code = ?", codeVal)
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	var scope, state, nonce, acr_level, auth_methods, used string
	for sqlCmd.Next() {
		err := sqlCmd.Scan(&scope, &state, &nonce, &acr_level, &auth_methods, &used)
		if err != nil {
			t.Fatal(err)
		}
	}
	assert.Equal(t, "openid profile email backend-svcA:read-product", scope)
	assert.Equal(t, "a1b2c3", state)
	assert.Equal(t, "m9n8b7", nonce)
	assert.Equal(t, "1", acr_level)
	assert.Equal(t, "pwd", auth_methods)
	assert.Equal(t, "0", used)

	// ----------------------------------------------------------------

	time.Sleep(2 * time.Second)

	destUrl = viper.GetString("BaseUrl") +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://test-client.goiabada.local:3010/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email%20backend-svcA%3Aread-product&state=a1b2c3&nonce=m9n8b7" +
		"&max_age=1"

	request, err = http.NewRequest("GET", destUrl, nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	// ----------------------------------------------------------------

	destUrl = viper.GetString("BaseUrl") + "/auth/pwd"

	formData = url.Values{
		"username":           {"mauro1"},
		"password":           {"abc123"},
		"gorilla.csrf.Token": {csrf},
	}

	formDataString = formData.Encode()
	requestBody = strings.NewReader(formDataString)
	request, err = http.NewRequest("POST", destUrl, requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// ----------------------------------------------------------------

	destUrl = viper.GetString("BaseUrl") + "/auth/consent"

	request, err = http.NewRequest("GET", destUrl, nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	redirectLocation, err = url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	codeVal = redirectLocation.Query().Get("code")
	stateVal = redirectLocation.Query().Get("state")

	assert.Equal(t, 128, len(codeVal))
	assert.Equal(t, "a1b2c3", stateVal)

	sqlCmd, err = database.Query("SELECT scope, state, nonce, acr_level, auth_methods, used, session_identifier FROM codes WHERE code = ?", codeVal)
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	var session_identifier string
	for sqlCmd.Next() {
		err := sqlCmd.Scan(&scope, &state, &nonce, &acr_level, &auth_methods, &used, &session_identifier)
		if err != nil {
			t.Fatal(err)
		}
	}
	assert.Equal(t, "openid profile email backend-svcA:read-product", scope)
	assert.Equal(t, "a1b2c3", state)
	assert.Equal(t, "m9n8b7", nonce)
	assert.Equal(t, "1", acr_level)
	assert.Equal(t, "pwd", auth_methods)
	assert.Equal(t, "0", used)
	assert.True(t, len(session_identifier) > 0)
}

func TestTwoLogins_Pwd_WithFullConsent_ForceAcrLevel2Enrollment(t *testing.T) {
	Setup()

	// make sure otp is disabled for the user
	sqlCmd, err := database.Query("UPDATE users SET acr_level2_include_otp = 0 WHERE username = 'mauro1'")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	// make sure there's no prior user consent
	sqlCmd, err = database.Query("DELETE FROM user_consents")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := viper.GetString("BaseUrl") +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://test-client.goiabada.local:3010/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email%20backend-svcA%3Aread-product&state=a1b2c3&nonce=m9n8b7"

	client := createHttpClient(t, true, true)

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	csrfNode := doc.Find("input[name='gorilla.csrf.Token']")
	csrf, _ := csrfNode.Attr("value")

	// ----------------------------------------------------------------

	destUrl = viper.GetString("BaseUrl") + "/auth/pwd"

	formData := url.Values{
		"username":           {"vivi1"},
		"password":           {"asd123"},
		"gorilla.csrf.Token": {csrf},
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
	defer resp.Body.Close()

	doc, err = goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	csrfNode = doc.Find("input[name='gorilla.csrf.Token']")
	csrf, _ = csrfNode.Attr("value")

	// ----------------------------------------------------------------

	destUrl = viper.GetString("BaseUrl") + "/auth/consent"

	formData = url.Values{
		"btnSubmit":          {"submit"},
		"consent0":           {"[on]"},
		"consent1":           {"[on]"},
		"consent2":           {"[on]"},
		"consent3":           {"[on]"},
		"gorilla.csrf.Token": {csrf},
	}

	formDataString = formData.Encode()
	requestBody = strings.NewReader(formDataString)
	request, err = http.NewRequest("POST", destUrl, requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	codeVal := redirectLocation.Query().Get("code")
	stateVal := redirectLocation.Query().Get("state")

	assert.Equal(t, 128, len(codeVal))
	assert.Equal(t, "a1b2c3", stateVal)

	sqlCmd, err = database.Query("SELECT scope, state, nonce, acr_level, auth_methods, used FROM codes WHERE code = ?", codeVal)
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	var scope, state, nonce, acr_level, auth_methods, used string
	for sqlCmd.Next() {
		err := sqlCmd.Scan(&scope, &state, &nonce, &acr_level, &auth_methods, &used)
		if err != nil {
			t.Fatal(err)
		}
	}
	assert.Equal(t, "openid profile email backend-svcA:read-product", scope)
	assert.Equal(t, "a1b2c3", state)
	assert.Equal(t, "m9n8b7", nonce)
	assert.Equal(t, "1", acr_level)
	assert.Equal(t, "pwd", auth_methods)
	assert.Equal(t, "0", used)

	// ----------------------------------------------------------------

	destUrl = viper.GetString("BaseUrl") +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://test-client.goiabada.local:3010/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email%20backend-svcA%3Aread-product&state=a1b2c3&nonce=m9n8b7" +
		"&acr_values=2"

	request, err = http.NewRequest("GET", destUrl, nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	// ----------------------------------------------------------------

	destUrl = viper.GetString("BaseUrl") + "/auth/otp"
	request, err = http.NewRequest("GET", destUrl, nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	html := string(bytes)

	// ----------------------------------------------------------------

	assert.Contains(t, html, "We require you to enroll in Two-Factor Authentication (2FA)")
}

func CreateAuthCode(t *testing.T, scope string) string {
	Setup()

	// make sure otp is disabled for the user
	sqlCmd, err := database.Query("UPDATE users SET acr_level2_include_otp = 0 WHERE username = 'mauro1'")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	// make sure there's no prior user consent
	sqlCmd, err = database.Query("DELETE FROM user_consents")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	//code verifier: DdazqdVNuDmRLGGRGQKKehEaoFeatACtNsM2UYGwuHkhBhDsTSzaCqWttcBc0kGx
	codeChallenge := "0BnoD4e6xPCPip8rqZ9Zc2RqWOFfvryu9vzXJN4egoY"

	if scope == "" {
		scope = "openid%20profile%20email%20backend-svcA%3Aread-product%20offline_access"
	}

	destUrl := viper.GetString("BaseUrl") +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://test-client.goiabada.local:3010/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=" + scope + "&state=a1b2c3&nonce=m9n8b7"

	client := createHttpClient(t, true, true)

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	csrfNode := doc.Find("input[name='gorilla.csrf.Token']")
	csrf, _ := csrfNode.Attr("value")

	// ----------------------------------------------------------------

	destUrl = viper.GetString("BaseUrl") + "/auth/pwd"

	formData := url.Values{
		"username":           {"mauro1"},
		"password":           {"abc123"},
		"gorilla.csrf.Token": {csrf},
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
	defer resp.Body.Close()

	doc, err = goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	csrfNode = doc.Find("input[name='gorilla.csrf.Token']")
	csrf, _ = csrfNode.Attr("value")

	// ----------------------------------------------------------------

	destUrl = viper.GetString("BaseUrl") + "/auth/consent"

	formData = url.Values{
		"btnSubmit":          {"submit"},
		"consent0":           {"[on]"},
		"consent1":           {"[on]"},
		"consent2":           {"[on]"},
		"consent3":           {"[on]"},
		"consent4":           {"[on]"},
		"consent5":           {"[on]"},
		"consent6":           {"[on]"},
		"consent7":           {"[on]"},
		"gorilla.csrf.Token": {csrf},
	}

	formDataString = formData.Encode()
	requestBody = strings.NewReader(formDataString)
	request, err = http.NewRequest("POST", destUrl, requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		html, _ := io.ReadAll(resp.Body)
		htmlStr := string(html)
		t.Log(htmlStr)
	}

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	codeVal := redirectLocation.Query().Get("code")
	stateVal := redirectLocation.Query().Get("state")

	assert.Equal(t, 128, len(codeVal))
	assert.Equal(t, "a1b2c3", stateVal)

	sqlCmd, err = database.Query("SELECT scope, state, nonce, acr_level, auth_methods, used FROM codes WHERE code = ?", codeVal)
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	var scopeDb, state, nonce, acr_level, auth_methods, used string
	for sqlCmd.Next() {
		err := sqlCmd.Scan(&scopeDb, &state, &nonce, &acr_level, &auth_methods, &used)
		if err != nil {
			t.Fatal(err)
		}
	}
	scope = strings.Replace(scope, "%20", " ", -1)
	scope = strings.Replace(scope, "%3A", ":", -1)
	assert.Equal(t, scope, scopeDb)
	assert.Equal(t, "a1b2c3", state)
	assert.Equal(t, "m9n8b7", nonce)
	assert.Equal(t, "1", acr_level)
	assert.Equal(t, "pwd", auth_methods)
	assert.Equal(t, "0", used)

	return codeVal
}

func TestToken_InvalidGrantType(t *testing.T) {
	Setup()

	destUrl := viper.GetString("BaseUrl") + "/auth/token"

	client := createHttpClient(t, true, true)

	formData := url.Values{
		"grant_type": {"invalid"},
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
	defer resp.Body.Close()

	jsonBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	jsonStr := string(jsonBytes)
	var errorResp errorResp
	if err := json.Unmarshal([]byte(jsonStr), &errorResp); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "unsupported_grant_type", errorResp.Error)
	assert.Equal(t, "Unsupported grant_type", errorResp.ErrorDescription)
}

func TestToken_MissingCode(t *testing.T) {
	Setup()

	destUrl := viper.GetString("BaseUrl") + "/auth/token"

	client := createHttpClient(t, true, true)

	formData := url.Values{
		"grant_type": {"authorization_code"},
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
	defer resp.Body.Close()

	jsonBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	jsonStr := string(jsonBytes)
	var errorResp errorResp
	if err := json.Unmarshal([]byte(jsonStr), &errorResp); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "invalid_request", errorResp.Error)
	assert.Equal(t, "Missing required code parameter", errorResp.ErrorDescription)
}

func TestToken_MissingRedirectUri(t *testing.T) {
	Setup()
	code := CreateAuthCode(t, "")

	destUrl := viper.GetString("BaseUrl") + "/auth/token"

	client := createHttpClient(t, true, true)

	formData := url.Values{
		"grant_type": {"authorization_code"},
		"code":       {code},
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
	defer resp.Body.Close()

	jsonBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	jsonStr := string(jsonBytes)
	var errorResp errorResp
	if err := json.Unmarshal([]byte(jsonStr), &errorResp); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "invalid_request", errorResp.Error)
	assert.Equal(t, "Missing required redirect_uri parameter", errorResp.ErrorDescription)
}

func TestToken_MissingCodeVerifier(t *testing.T) {
	Setup()

	destUrl := viper.GetString("BaseUrl") + "/auth/token"

	client := createHttpClient(t, true, true)

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"invalid"},
		"client_id":     {"test-client-2"},
		"redirect_uri":  {"https://test-client.goiabada.local:3010/callback.html"},
		"code_verifier": {"DdazqdVNuDmRLGGRGQKKehEaoFeatACtNsM2UYGwuHkhBhDsTSzaCqWttcBc0kGx"},
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
	defer resp.Body.Close()

	jsonBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	jsonStr := string(jsonBytes)
	var errorResp errorResp
	if err := json.Unmarshal([]byte(jsonStr), &errorResp); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "invalid_grant", errorResp.Error)
	assert.Equal(t, "Code is invalid", errorResp.ErrorDescription)
}

func TestToken_InvalidRedirectUri(t *testing.T) {
	Setup()
	code := CreateAuthCode(t, "")

	destUrl := viper.GetString("BaseUrl") + "/auth/token"

	client := createHttpClient(t, true, true)

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"test-client-2"},
		"redirect_uri":  {"http://localhost:3010/invalid.html"},
		"code_verifier": {"DdazqdVNuDmRLGGRGQKKehEaoFeatACtNsM2UYGwuHkhBhDsTSzaCqWttcBc0kGx"},
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
	defer resp.Body.Close()

	jsonBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	jsonStr := string(jsonBytes)
	var errorResp errorResp
	if err := json.Unmarshal([]byte(jsonStr), &errorResp); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "invalid_grant", errorResp.Error)
	assert.Equal(t, "Invalid redirect_uri", errorResp.ErrorDescription)
}

func TestToken_InvalidCodeVerifier(t *testing.T) {
	Setup()
	code := CreateAuthCode(t, "")

	destUrl := viper.GetString("BaseUrl") + "/auth/token"

	client := createHttpClient(t, true, true)

	sqlCmd, err := database.Query("SELECT aes_encryption_key FROM settings WHERE id = 1")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	var aes_encryption_key []byte
	for sqlCmd.Next() {
		err := sqlCmd.Scan(&aes_encryption_key)
		if err != nil {
			t.Fatal(err)
		}
	}

	sqlCmd, err = database.Query("SELECT client_secret_encrypted FROM clients WHERE client_identifier = ?", "test-client-1")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	var client_secret_encrypted []byte
	for sqlCmd.Next() {
		err := sqlCmd.Scan(&client_secret_encrypted)
		if err != nil {
			t.Fatal(err)
		}
	}

	clientSecret, err := decryptText(client_secret_encrypted, aes_encryption_key)
	if err != nil {
		t.Fatal(err)
	}

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"test-client-1"},
		"client_secret": {clientSecret},
		"redirect_uri":  {"https://test-client.goiabada.local:3010/callback.html"},
		"code_verifier": {"invalid"},
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
	defer resp.Body.Close()

	jsonBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	jsonStr := string(jsonBytes)
	var errorResp errorResp
	if err := json.Unmarshal([]byte(jsonStr), &errorResp); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "invalid_grant", errorResp.Error)
	assert.Equal(t, "Invalid code_verifier (PKCE)", errorResp.ErrorDescription)
}

func TestToken_Success(t *testing.T) {
	Setup()
	s := "openid%20profile%20email%20address%20phone%20roles%20offline_access%20backend-svcA%3Aread-product"
	code := CreateAuthCode(t, s)

	destUrl := viper.GetString("BaseUrl") + "/auth/token"

	client := createHttpClient(t, true, true)

	sqlCmd, err := database.Query("SELECT aes_encryption_key FROM settings WHERE id = 1")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	var aes_encryption_key []byte
	for sqlCmd.Next() {
		err := sqlCmd.Scan(&aes_encryption_key)
		if err != nil {
			t.Fatal(err)
		}
	}

	sqlCmd, err = database.Query("SELECT client_secret_encrypted FROM clients WHERE client_identifier = ?", "test-client-1")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	var client_secret_encrypted []byte
	for sqlCmd.Next() {
		err := sqlCmd.Scan(&client_secret_encrypted)
		if err != nil {
			t.Fatal(err)
		}
	}

	clientSecret, err := decryptText(client_secret_encrypted, aes_encryption_key)
	if err != nil {
		t.Fatal(err)
	}

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"test-client-1"},
		"client_secret": {clientSecret},
		"redirect_uri":  {"https://test-client.goiabada.local:3010/callback.html"},
		"code_verifier": {"DdazqdVNuDmRLGGRGQKKehEaoFeatACtNsM2UYGwuHkhBhDsTSzaCqWttcBc0kGx"},
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
	defer resp.Body.Close()

	jsonBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	jsonStr := string(jsonBytes)
	var tokenResponse tokenResponse
	if err := json.Unmarshal([]byte(jsonStr), &tokenResponse); err != nil {
		t.Fatal(err)
	}
	assert.NotEmpty(t, tokenResponse.AccessToken)
	assert.NotEmpty(t, tokenResponse.IdToken)
	assert.NotEmpty(t, tokenResponse.RefreshToken)
	assert.Equal(t, "openid profile email address phone roles offline_access backend-svcA:read-product", tokenResponse.Scope)

	sqlCmd, err = database.Query("SELECT public_key_pem FROM key_pairs WHERE id = 1")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	var public_key_pem string
	for sqlCmd.Next() {
		err := sqlCmd.Scan(&public_key_pem)
		if err != nil {
			t.Fatal(err)
		}
	}

	publicKeyPEMBytes, err := b64.StdEncoding.DecodeString(public_key_pem)
	if err != nil {
		t.Fatal(err)
	}
	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyPEMBytes)
	if err != nil {
		t.Fatal(err)
	}

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenResponse.AccessToken, claims, func(token *jwt.Token) (interface{}, error) {
		return pubKey, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, token.Valid)
	aud, err := claims.GetAudience()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 2, len(aud))
	assert.Equal(t, "account", aud[0])
	assert.Equal(t, "backend-svcA", aud[1])
	assert.Equal(t, "test-client-1", claims["azp"].(string))
	assert.Equal(t, "https://goiabada.dev", claims["iss"].(string))
	assert.Equal(t, "openid profile email address phone roles offline_access backend-svcA:read-product", claims["scope"].(string))

	sqlCmd, err = database.Query("SELECT subject FROM users WHERE username = 'mauro1'")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	var subject string
	for sqlCmd.Next() {
		err := sqlCmd.Scan(&subject)
		if err != nil {
			t.Fatal(err)
		}
	}

	assert.Equal(t, subject, claims["sub"].(string))
	assert.Equal(t, "Bearer", claims["typ"].(string))
	assert.Equal(t, "1", claims["acr"].(string))
	assert.Equal(t, "pwd", claims["amr"].(string))
	assert.Equal(t, "1979-12-22", claims["birthdate"].(string))
	assert.Equal(t, "mauro@outlook.com", claims["email"].(string))
	assert.Equal(t, true, claims["email_verified"].(bool))
	assert.Equal(t, "Golias", claims["family_name"].(string))
	assert.Equal(t, "male", claims["gender"].(string))
	assert.Equal(t, "Mauro", claims["given_name"].(string))
	assert.Equal(t, "pt-BR", claims["locale"].(string))
	assert.Equal(t, "Dantes", claims["middle_name"].(string))
	assert.Equal(t, "Mauro Dantes Golias", claims["name"].(string))
	assert.Equal(t, "maurogo", claims["nickname"].(string))
	assert.Equal(t, "mauro1", claims["preferred_username"].(string))
	assert.Equal(t, "https://goiabada.local:3000/account", claims["profile"].(string))
	assert.Equal(t, "m9n8b7", claims["nonce"].(string))
	assert.Equal(t, "https://www.maurogo.com", claims["website"].(string))
	assert.Equal(t, "America/Sao_Paulo", claims["zoneinfo"].(string))
	assert.Equal(t, "+351 912156387", claims["phone_number"].(string))
	assert.Equal(t, true, claims["phone_number_verified"].(bool))

	address := claims["address"].(map[string]interface{})
	assert.Equal(t, "Portugal", address["country"].(string))
	assert.Equal(t, "Rua de São Romão 138\r\nApto 5A\r\nVila Nova de Gaia\r\nPorto\r\n4400-089\r\nPortugal", address["formatted"].(string))
	assert.Equal(t, "Vila Nova de Gaia", address["locality"].(string))
	assert.Equal(t, "4400-089", address["postal_code"].(string))
	assert.Equal(t, "Porto", address["region"].(string))
	assert.Equal(t, "Rua de São Romão 138\r\nApto 5A", address["street_address"].(string))

	roles := claims["roles"].([]interface{})
	assert.Equal(t, 2, len(roles))
	assert.Equal(t, "site-admin", roles[0].(string))
	assert.Equal(t, "product-admin", roles[1].(string))

	claims = jwt.MapClaims{}
	token, err = jwt.ParseWithClaims(tokenResponse.IdToken, claims, func(token *jwt.Token) (interface{}, error) {
		return pubKey, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, token.Valid)
	aud, err = claims.GetAudience()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 1, len(aud))
	assert.Equal(t, "test-client-1", aud[0])
	assert.Equal(t, "test-client-1", claims["azp"].(string))
	assert.Equal(t, "https://goiabada.dev", claims["iss"].(string))

	assert.Equal(t, subject, claims["sub"].(string))
	assert.Equal(t, "ID", claims["typ"].(string))
	assert.Equal(t, "1", claims["acr"].(string))
	assert.Equal(t, "pwd", claims["amr"].(string))
	assert.Equal(t, "1979-12-22", claims["birthdate"].(string))
	assert.Equal(t, "mauro@outlook.com", claims["email"].(string))
	assert.Equal(t, true, claims["email_verified"].(bool))
	assert.Equal(t, "Golias", claims["family_name"].(string))
	assert.Equal(t, "male", claims["gender"].(string))
	assert.Equal(t, "Mauro", claims["given_name"].(string))
	assert.Equal(t, "pt-BR", claims["locale"].(string))
	assert.Equal(t, "Dantes", claims["middle_name"].(string))
	assert.Equal(t, "Mauro Dantes Golias", claims["name"].(string))
	assert.Equal(t, "maurogo", claims["nickname"].(string))
	assert.Equal(t, "mauro1", claims["preferred_username"].(string))
	assert.Equal(t, "https://goiabada.local:3000/account", claims["profile"].(string))
	assert.Equal(t, "m9n8b7", claims["nonce"].(string))
	assert.Equal(t, "https://www.maurogo.com", claims["website"].(string))
	assert.Equal(t, "America/Sao_Paulo", claims["zoneinfo"].(string))
	assert.Equal(t, "+351 912156387", claims["phone_number"].(string))
	assert.Equal(t, true, claims["phone_number_verified"].(bool))

	address = claims["address"].(map[string]interface{})
	assert.Equal(t, "Portugal", address["country"].(string))
	assert.Equal(t, "Rua de São Romão 138\r\nApto 5A\r\nVila Nova de Gaia\r\nPorto\r\n4400-089\r\nPortugal", address["formatted"].(string))
	assert.Equal(t, "Vila Nova de Gaia", address["locality"].(string))
	assert.Equal(t, "4400-089", address["postal_code"].(string))
	assert.Equal(t, "Porto", address["region"].(string))
	assert.Equal(t, "Rua de São Romão 138\r\nApto 5A", address["street_address"].(string))

	claims = jwt.MapClaims{}
	token, err = jwt.ParseWithClaims(tokenResponse.RefreshToken, claims, func(token *jwt.Token) (interface{}, error) {
		return pubKey, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, token.Valid)
	aud, err = claims.GetAudience()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 1, len(aud))
	assert.Equal(t, "https://goiabada.dev", aud[0])
	assert.Equal(t, "https://goiabada.dev", claims["iss"].(string))
	assert.Equal(t, "m9n8b7", claims["nonce"].(string))
	assert.Equal(t, "Refresh", claims["typ"].(string))
}

func TestClientCred_ClientDoesNotExist(t *testing.T) {
	Setup()

	destUrl := viper.GetString("BaseUrl") + "/auth/token"

	client := createHttpClient(t, true, true)

	formData := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"invalid"},
		"client_secret": {"invalid"},
		"scope":         {""},
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
	defer resp.Body.Close()

	jsonBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	jsonStr := string(jsonBytes)
	var errorResp errorResp
	if err := json.Unmarshal([]byte(jsonStr), &errorResp); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "invalid_client", errorResp.Error)
	assert.Equal(t, "The client with this identifier could not be found", errorResp.ErrorDescription)
}

func TestClientCred_PublicClientIsNotEligible(t *testing.T) {
	Setup()

	destUrl := viper.GetString("BaseUrl") + "/auth/token"

	client := createHttpClient(t, true, true)

	formData := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"test-client-2"},
		"client_secret": {"invalid"},
		"scope":         {""},
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
	defer resp.Body.Close()

	jsonBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	jsonStr := string(jsonBytes)
	var errorResp errorResp
	if err := json.Unmarshal([]byte(jsonStr), &errorResp); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "unauthorized_client", errorResp.Error)
	assert.Equal(t, "A public client is not eligible for the client credentials flow. Kindly review the client configuration", errorResp.ErrorDescription)
}

func TestClientCred_ClientAuthFailed(t *testing.T) {
	Setup()

	destUrl := viper.GetString("BaseUrl") + "/auth/token"

	client := createHttpClient(t, true, true)

	sqlCmd, err := database.Query("SELECT client_secret_encrypted FROM clients WHERE client_identifier = ?", "test-client-1")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	formData := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"test-client-1"},
		"client_secret": {"invalid"},
		"scope":         {""},
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
	defer resp.Body.Close()

	jsonBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	jsonStr := string(jsonBytes)
	var errorResp errorResp
	if err := json.Unmarshal([]byte(jsonStr), &errorResp); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "invalid_client", errorResp.Error)
	assert.Equal(t, "Client authentication failed", errorResp.ErrorDescription)
}

func TestClientCred_NoScopesGiven(t *testing.T) {
	Setup()

	destUrl := viper.GetString("BaseUrl") + "/auth/token"

	client := createHttpClient(t, true, true)

	sqlCmd, err := database.Query("SELECT client_secret_encrypted FROM clients WHERE client_identifier = ?", "test-client-1")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	var client_secret_encrypted []byte
	for sqlCmd.Next() {
		err := sqlCmd.Scan(&client_secret_encrypted)
		if err != nil {
			t.Fatal(err)
		}
	}

	sqlCmd, err = database.Query("SELECT aes_encryption_key FROM settings WHERE id = 1")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	var aes_encryption_key []byte
	for sqlCmd.Next() {
		err := sqlCmd.Scan(&aes_encryption_key)
		if err != nil {
			t.Fatal(err)
		}
	}

	clientSecret, err := decryptText(client_secret_encrypted, aes_encryption_key)
	if err != nil {
		t.Fatal(err)
	}

	formData := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"test-client-1"},
		"client_secret": {clientSecret},
		"scope":         {""},
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
	defer resp.Body.Close()

	jsonBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	jsonStr := string(jsonBytes)
	var tokenResponse tokenResponse
	if err := json.Unmarshal([]byte(jsonStr), &tokenResponse); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "backend-svcA:create-product backend-svcB:read-info", tokenResponse.Scope)
	assert.Equal(t, "Bearer", tokenResponse.TokenType)
	assert.True(t, len(tokenResponse.AccessToken) > 0)

	sqlCmd, err = database.Query("SELECT public_key_pem FROM key_pairs WHERE id = 1")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	var public_key_pem string
	for sqlCmd.Next() {
		err := sqlCmd.Scan(&public_key_pem)
		if err != nil {
			t.Fatal(err)
		}
	}

	publicKeyPEMBytes, err := b64.StdEncoding.DecodeString(public_key_pem)
	if err != nil {
		t.Fatal(err)
	}
	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyPEMBytes)
	if err != nil {
		t.Fatal(err)
	}

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenResponse.AccessToken, claims, func(token *jwt.Token) (interface{}, error) {
		return pubKey, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, token.Valid)
	aud, err := claims.GetAudience()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 2, len(aud))
	assert.Equal(t, "backend-svcA", aud[0])
	assert.Equal(t, "backend-svcB", aud[1])
	assert.Equal(t, "test-client-1", claims["azp"].(string))
	assert.Equal(t, "https://goiabada.dev", claims["iss"].(string))
	assert.Equal(t, "backend-svcA:create-product backend-svcB:read-info", claims["scope"].(string))
	assert.Equal(t, "test-client-1", claims["sub"].(string))
	assert.Equal(t, "Bearer", claims["typ"].(string))
}

func TestClientCred_SpecificScope(t *testing.T) {
	Setup()

	destUrl := viper.GetString("BaseUrl") + "/auth/token"

	client := createHttpClient(t, true, true)

	sqlCmd, err := database.Query("SELECT client_secret_encrypted FROM clients WHERE client_identifier = ?", "test-client-1")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	var client_secret_encrypted []byte
	for sqlCmd.Next() {
		err := sqlCmd.Scan(&client_secret_encrypted)
		if err != nil {
			t.Fatal(err)
		}
	}

	sqlCmd, err = database.Query("SELECT aes_encryption_key FROM settings WHERE id = 1")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	var aes_encryption_key []byte
	for sqlCmd.Next() {
		err := sqlCmd.Scan(&aes_encryption_key)
		if err != nil {
			t.Fatal(err)
		}
	}

	clientSecret, err := decryptText(client_secret_encrypted, aes_encryption_key)
	if err != nil {
		t.Fatal(err)
	}

	formData := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"test-client-1"},
		"client_secret": {clientSecret},
		"scope":         {"backend-svcB:read-info"},
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
	defer resp.Body.Close()

	jsonBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	jsonStr := string(jsonBytes)
	var tokenResponse tokenResponse
	if err := json.Unmarshal([]byte(jsonStr), &tokenResponse); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "backend-svcB:read-info", tokenResponse.Scope)
	assert.Equal(t, "Bearer", tokenResponse.TokenType)
	assert.True(t, len(tokenResponse.AccessToken) > 0)

	sqlCmd, err = database.Query("SELECT public_key_pem FROM key_pairs WHERE id = 1")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlCmd.Close()

	var public_key_pem string
	for sqlCmd.Next() {
		err := sqlCmd.Scan(&public_key_pem)
		if err != nil {
			t.Fatal(err)
		}
	}

	publicKeyPEMBytes, err := b64.StdEncoding.DecodeString(public_key_pem)
	if err != nil {
		t.Fatal(err)
	}
	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyPEMBytes)
	if err != nil {
		t.Fatal(err)
	}

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenResponse.AccessToken, claims, func(token *jwt.Token) (interface{}, error) {
		return pubKey, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, token.Valid)
	aud, err := claims.GetAudience()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 1, len(aud))
	assert.Equal(t, "backend-svcB", aud[0])
	assert.Equal(t, "test-client-1", claims["azp"].(string))
	assert.Equal(t, "https://goiabada.dev", claims["iss"].(string))
	assert.Equal(t, "backend-svcB:read-info", claims["scope"].(string))
	assert.Equal(t, "test-client-1", claims["sub"].(string))
	assert.Equal(t, "Bearer", claims["typ"].(string))
}

func DumpResponseBody(t *testing.T, resp *http.Response) {
	body, _ := io.ReadAll(resp.Body)
	t.Log(string(body))
}
