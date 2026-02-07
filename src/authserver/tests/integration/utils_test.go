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
	"strings"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/oidc"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
)

func createHttpClient(t *testing.T) *http.Client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Jar: jar,
	}

	// disable follow redirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client.Transport = tr
	return client
}

func assertRedirect(t *testing.T, response *http.Response, location string) string {
	if response.StatusCode != http.StatusFound {
		t.Fatalf("Expected status code %d, got %d", http.StatusFound, response.StatusCode)
	}

	redirectLocation, err := url.Parse(response.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, location, redirectLocation.Path)

	return redirectLocation.String()
}

func loadPage(t *testing.T, client *http.Client, url string) *http.Response {
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return resp
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
		t.Fatal("expecting to find 'gorilla.csrf.Token' but it was not found")
		dumpResponseBody(t, response)
	}
	csrf, exists := csrfNode.Attr("value")
	if !exists {
		t.Fatal("input 'gorilla.csrf.Token' does not have a value")
		dumpResponseBody(t, response)
	}
	return csrf
}

func authenticateWithPassword(t *testing.T, client *http.Client, destUrl string,
	email string, password string, csrf string) *http.Response {

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
	request.Header.Set("Referer", destUrl)
	request.Header.Set("Origin", config.GetAuthServer().BaseURL)

	resp, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func authenticateWithOtp(t *testing.T, client *http.Client, destUrl string, otp string, csrf string) *http.Response {
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
	request.Header.Set("Referer", destUrl)
	request.Header.Set("Origin", config.GetAuthServer().BaseURL)

	resp, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func getOtpSecretFromEnrollmentPage(t *testing.T, response *http.Response) string {
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
		t.Fatal("expecting to find pre element with class 'text-center' but it was not found")
	}
	return secret.Text()
}

func getCodeAndStateFromUrl(t *testing.T, resp *http.Response) (code string, state string) {
	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	code = redirectLocation.Query().Get("code")
	state = redirectLocation.Query().Get("state")

	assert.NotEmpty(t, code, "code should not be empty")
	assert.NotEmpty(t, state, "state should not be empty")

	assert.Equal(t, 128, len(code))

	return code, state
}

func loadCodeFromDatabase(t *testing.T, codeVal string) *models.Code {
	codeHash, err := hashutil.HashString(codeVal)
	if err != nil {
		t.Fatal(err)
	}
	code, err := database.GetCodeByCodeHash(nil, codeHash, false)
	if err != nil {
		t.Fatal(err)
	}

	err = database.CodeLoadClient(nil, code)
	if err != nil {
		t.Fatal(err)
	}

	err = database.CodeLoadUser(nil, code)
	if err != nil {
		t.Fatal(err)
	}

	return code
}

func assertWithinLastXSeconds(t *testing.T, timeToCheck time.Time, seconds float64) {
	now := time.Now().UTC()
	xSecondsAgo := now.Add(-time.Duration(seconds * float64(time.Second)))

	assert.True(t, timeToCheck.After(xSecondsAgo) && timeToCheck.Before(now),
		"Expected time to be within the last %.2f seconds", seconds)
}

func createResource(t *testing.T) *models.Resource {
	resource := &models.Resource{
		ResourceIdentifier: "res-" + gofakeit.LetterN(8),
	}
	err := database.CreateResource(nil, resource)
	if err != nil {
		t.Fatal(err)
	}
	return resource
}

func createResourceWithId(t *testing.T, resourceIdentifier string) *models.Resource {
	resource := &models.Resource{
		ResourceIdentifier: resourceIdentifier,
	}
	err := database.CreateResource(nil, resource)
	if err != nil {
		t.Fatal(err)
	}
	return resource
}

func createPermission(t *testing.T, resourceId int64) *models.Permission {
	permission := &models.Permission{
		PermissionIdentifier: "perm-" + gofakeit.LetterN(8),
		ResourceId:           resourceId,
	}
	err := database.CreatePermission(nil, permission)
	if err != nil {
		t.Fatal(err)
	}
	return permission
}

func createPermissionWithId(t *testing.T, resourceId int64, permissionIdentifier string) *models.Permission {
	permission := &models.Permission{
		PermissionIdentifier: permissionIdentifier,
		ResourceId:           resourceId,
	}
	err := database.CreatePermission(nil, permission)
	if err != nil {
		t.Fatal(err)
	}
	return permission
}

func assignPermissionToUser(t *testing.T, userId int64, permissionId int64) {
	userPermission := &models.UserPermission{
		UserId:       userId,
		PermissionId: permissionId,
	}
	err := database.CreateUserPermission(nil, userPermission)
	if err != nil {
		t.Fatal(err)
	}
}

func postConsent(t *testing.T, client *http.Client, destUrl string, consents []int, csrf string) (resp *http.Response) {

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
	request.Header.Set("Referer", destUrl)
	request.Header.Set("Origin", config.GetAuthServer().BaseURL)

	resp, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func createSessionWithAcrLevel1(t *testing.T) (*http.Client, *models.Client, *models.RedirectURI, *models.User) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          false,
		DefaultAcrLevel:          enums.AcrLevel1,
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

	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email"

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)

	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, requestCodeChallenge, code.CodeChallenge.String)
	assert.Equal(t, "S256", code.CodeChallengeMethod.String)
	assert.Equal(t, requestScope, code.Scope)
	assert.Equal(t, requestState, code.State)
	assert.Equal(t, requestNonce, code.Nonce)
	assert.Equal(t, redirectUri.URI, code.RedirectURI)
	assert.Equal(t, user.Id, code.User.Id)
	assert.Equal(t, "query", code.ResponseMode)
	assertWithinLastXSeconds(t, code.AuthenticatedAt, 3)
	assert.Equal(t, enums.AcrLevel1.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)

	return httpClient, client, redirectUri, user
}

func createSessionWithAcrLevel2Optional(t *testing.T) (*http.Client, *models.Client, *models.RedirectURI, *models.User) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          false,
		DefaultAcrLevel:          enums.AcrLevel2Optional,
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

	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email"

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)

	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, requestCodeChallenge, code.CodeChallenge.String)
	assert.Equal(t, "S256", code.CodeChallengeMethod.String)
	assert.Equal(t, requestScope, code.Scope)
	assert.Equal(t, requestState, code.State)
	assert.Equal(t, requestNonce, code.Nonce)
	assert.Equal(t, redirectUri.URI, code.RedirectURI)
	assert.Equal(t, user.Id, code.User.Id)
	assert.Equal(t, "query", code.ResponseMode)
	assertWithinLastXSeconds(t, code.AuthenticatedAt, 3)
	assert.Equal(t, enums.AcrLevel2Optional.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)

	return httpClient, client, redirectUri, user
}

func createSessionWithAcrLevel2Mandatory(t *testing.T) (*http.Client, *models.Client, *models.RedirectURI, *models.User) {
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

	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	userEmail := gofakeit.Email()
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Goiabada",
		AccountName: userEmail,
	})
	if err != nil {
		t.Fatal(err)
	}

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
		OTPSecret:    key.Secret(),
		OTPEnabled:   true,
	}

	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email"

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/otp")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf = getCsrfValue(t, resp)

	otpCode, err := totp.GenerateCode(user.OTPSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp = authenticateWithOtp(t, httpClient, redirectLocation, otpCode, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)

	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, requestCodeChallenge, code.CodeChallenge.String)
	assert.Equal(t, "S256", code.CodeChallengeMethod.String)
	assert.Equal(t, requestScope, code.Scope)
	assert.Equal(t, requestState, code.State)
	assert.Equal(t, requestNonce, code.Nonce)
	assert.Equal(t, redirectUri.URI, code.RedirectURI)
	assert.Equal(t, user.Id, code.User.Id)
	assert.Equal(t, "query", code.ResponseMode)
	assertWithinLastXSeconds(t, code.AuthenticatedAt, 3)
	assert.Equal(t, enums.AcrLevel2Mandatory.String(), code.AcrLevel)
	assert.Equal(t, fmt.Sprintf("%s %s", enums.AuthMethodPassword.String(), enums.AuthMethodOTP.String()), code.AuthMethods)
	assert.Equal(t, false, code.Used)

	return httpClient, client, redirectUri, user
}

func createAuthCode(t *testing.T, clientSecret string, scope string) (*http.Client, *models.Code) {

	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)

	clientSecretEncrypted, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
	assert.NoError(t, err)

	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		IsPublic:                 false,
		ConsentRequired:          false,
		DefaultAcrLevel:          enums.AcrLevel2Optional,
		ClientSecretEncrypted:    clientSecretEncrypted,
	}

	err = database.CreateClient(nil, client)
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

	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	codeVerifier := "code-verifier"
	requestCodeChallenge := oauth.GeneratePKCECodeChallenge(codeVerifier)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(scope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)
	code.Code = codeVal
	return httpClient, code
}

// createAuthCodeEnsuringUserScope creates a confidential client and a user, grants the user
// all custom resource:permission scopes contained in the provided scope string, then runs the
// authorization code flow to issue a code for that user and returns (httpClient, code).
// It guarantees custom scopes survive filtering and end up in the token if requested.
func createAuthCodeEnsuringUserScope(t *testing.T, clientSecret string, scope string) (*http.Client, *models.Code) {

	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)

	clientSecretEncrypted, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
	assert.NoError(t, err)

	client := &models.Client{
		ClientIdentifier:         "acctscope-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		IsPublic:                 false,
		ConsentRequired:          false,
		DefaultAcrLevel:          enums.AcrLevel2Optional,
		ClientSecretEncrypted:    clientSecretEncrypted,
	}

	err = database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{ClientId: client.Id, URI: gofakeit.URL()}
	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	// Create a user and pre-grant all custom resource scopes requested
	password := gofakeit.Password(true, true, true, true, false, 10)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	user := &models.User{Subject: uuid.New(), Enabled: true, Email: gofakeit.Email(), PasswordHash: passwordHashed}
	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	scopes := strings.Split(scope, " ")
	for _, s := range scopes {
		if s == "" || oidc.IsIdTokenScope(s) || oidc.IsOfflineAccessScope(s) {
			continue
		}
		parts := strings.Split(s, ":")
		if len(parts) != 2 {
			t.Fatalf("invalid scope format in helper: %s", s)
		}
		resourceIdentifier := parts[0]
		permissionIdentifier := parts[1]

		resource, err := database.GetResourceByResourceIdentifier(nil, resourceIdentifier)
		if err != nil {
			t.Fatal(err)
		}
		if resource == nil {
			t.Fatalf("resource not found: %s", resourceIdentifier)
		}

		perms, err := database.GetPermissionsByResourceId(nil, resource.Id)
		if err != nil {
			t.Fatal(err)
		}
		var sel *models.Permission
		for i := range perms {
			if perms[i].PermissionIdentifier == permissionIdentifier {
				sel = &perms[i]
				break
			}
		}
		if sel == nil {
			t.Fatalf("permission not found: %s:%s", resourceIdentifier, permissionIdentifier)
		}
		err = database.CreateUserPermission(nil, &models.UserPermission{UserId: user.Id, PermissionId: sel.Id})
		if err != nil {
			t.Fatal(err)
		}
	}

	codeVerifier := "code-verifier"
	requestCodeChallenge := oauth.GeneratePKCECodeChallenge(codeVerifier)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(scope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)
	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)
	code := loadCodeFromDatabase(t, codeVal)
	code.Code = codeVal
	return httpClient, code
}

// createUserAccessTokenWithScope issues an access token for a user making sure requested
// custom scopes are granted to that user before the flow. Returns (accessToken, *user).
func createUserAccessTokenWithScope(t *testing.T, scope string) (string, *models.User) {
	clientSecret := gofakeit.LetterN(32)
	httpClient, code := createAuthCodeEnsuringUserScope(t, clientSecret, scope)

	// Exchange code for tokens
	tokenEndpoint := config.GetAuthServer().BaseURL + "/auth/token/"
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"client_secret": {clientSecret},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {"code-verifier"},
	}
	data := postToTokenEndpoint(t, httpClient, tokenEndpoint, form)
	accessToken, ok := data["access_token"].(string)
	assert.True(t, ok)
	assert.NotEmpty(t, accessToken)
	return accessToken, &code.User
}

func postToTokenEndpoint(t *testing.T, client *http.Client, url string, formData url.Values) map[string]interface{} {
	formDataString := formData.Encode()
	requestBody := strings.NewReader(formDataString)
	request, err := http.NewRequest("POST", url, requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Referer", url)
	request.Header.Set("Origin", config.GetAuthServer().BaseURL)

	resp, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

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

// postToTokenEndpointWithBasicAuth sends a POST request to the token endpoint using HTTP Basic authentication
func postToTokenEndpointWithBasicAuth(t *testing.T, client *http.Client, url string, formData url.Values, clientId, clientSecret string) map[string]interface{} {
	formDataString := formData.Encode()
	requestBody := strings.NewReader(formDataString)
	request, err := http.NewRequest("POST", url, requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Referer", url)
	request.Header.Set("Origin", config.GetAuthServer().BaseURL)
	request.SetBasicAuth(clientId, clientSecret)

	resp, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

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

// createAdminClientWithToken creates a client with admin permissions and returns an access token
func createAdminClientWithToken(t *testing.T) (string, *models.Client) {
	// Generate client secret
	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)

	clientSecretEncrypted, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
	assert.NoError(t, err)

	// Create client with admin permissions
	client := &models.Client{
		ClientIdentifier:         "admin-test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		ClientCredentialsEnabled: true,
		IsPublic:                 false,
		ClientSecretEncrypted:    clientSecretEncrypted,
	}
	err = database.CreateClient(nil, client)
	assert.NoError(t, err)

	// Get authserver resource and permission
	authServerResource, err := database.GetResourceByResourceIdentifier(nil, constants.AuthServerResourceIdentifier)
	assert.NoError(t, err)

	permissions, err := database.GetPermissionsByResourceId(nil, authServerResource.Id)
	assert.NoError(t, err)

	var adminPermission *models.Permission
	for idx, permission := range permissions {
		if permission.PermissionIdentifier == constants.ManagePermissionIdentifier {
			adminPermission = &permissions[idx]
			break
		}
	}
	assert.NotNil(t, adminPermission, "Should find manage permission")

	// Assign admin permission to client
	err = database.CreateClientPermission(nil, &models.ClientPermission{
		ClientId:     client.Id,
		PermissionId: adminPermission.Id,
	})
	assert.NoError(t, err)

	// Get access token using client credentials flow
	httpClient := createHttpClient(t)
	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"scope":         {constants.AuthServerResourceIdentifier + ":" + constants.ManagePermissionIdentifier},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)
	accessToken, ok := data["access_token"].(string)
	assert.True(t, ok, "access_token should be a string")
	assert.NotEmpty(t, accessToken, "access_token should not be empty")

	return accessToken, client
}

// makeAPIRequest makes an authenticated API request
func makeAPIRequest(t *testing.T, method, url, accessToken string, body interface{}) *http.Response {
	var reqBody *bytes.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		assert.NoError(t, err)
		reqBody = bytes.NewReader(jsonBody)
	} else {
		reqBody = bytes.NewReader([]byte{})
	}

	req, err := http.NewRequest(method, url, reqBody)
	assert.NoError(t, err)

	req.Header.Set("Authorization", "Bearer "+accessToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)

	return resp
}

// Helper function to create a test resource
func createTestResource(t *testing.T, identifier, description string) *models.Resource {
	resource := &models.Resource{
		ResourceIdentifier: identifier,
		Description:        description,
	}
	err := database.CreateResource(nil, resource)
	assert.NoError(t, err)
	return resource
}

// Helper function to create a test group
func createTestGroup(t *testing.T) *models.Group {
	group := &models.Group{
		GroupIdentifier:      "test-group-" + uuid.New().String()[:8],
		Description:          "Test Group",
		IncludeInIdToken:     true,
		IncludeInAccessToken: false,
	}
	err := database.CreateGroup(nil, group)
	assert.NoError(t, err)
	return group
}

// Helper function to create a test permission
func createTestPermission(t *testing.T, resourceId int64, identifier, description string) *models.Permission {
	permission := &models.Permission{
		ResourceId:           resourceId,
		PermissionIdentifier: identifier,
		Description:          description,
	}
	err := database.CreatePermission(nil, permission)
	assert.NoError(t, err)
	return permission
}

// ============================================================================
// Client Display Testing Helpers
// ============================================================================

// parseHTMLResponse reads the response body and returns a goquery document
// while preserving the response body for potential re-reading
func parseHTMLResponse(t *testing.T, response *http.Response) *goquery.Document {
	byteArr, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	response.Body = io.NopCloser(bytes.NewReader(byteArr))

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(byteArr)))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// assertClientNameInHTML verifies the client name is displayed correctly
// Supports both auth layout and consent layout patterns
func assertClientNameInHTML(t *testing.T, doc *goquery.Document, expectedName string) {
	var found bool
	var actualName string

	// Auth layout pattern: <span class="mt-1 text-sm text-base-content/80">CLIENT_NAME</span>
	doc.Find("span.text-sm").Each(func(i int, s *goquery.Selection) {
		class, _ := s.Attr("class")
		if strings.Contains(class, "text-base-content") && strings.Contains(class, "mt-1") {
			actualName = strings.TrimSpace(s.Text())
			if actualName == expectedName {
				found = true
			}
		}
	})

	// Consent layout pattern: <h4 class="text-lg font-bold">CLIENT_NAME</h4>
	if !found {
		doc.Find("h4.text-lg").Each(func(i int, s *goquery.Selection) {
			actualName = strings.TrimSpace(s.Text())
			if actualName == expectedName {
				found = true
			}
		})
	}

	if !found {
		t.Logf("Expected client name: %s", expectedName)
		t.Logf("Actual client name found: %s", actualName)

		// Debug: Show all h4 tags found
		var h4Count int
		doc.Find("h4").Each(func(i int, s *goquery.Selection) {
			h4Count++
			t.Logf("Found h4 #%d: class='%s', text='%s'", i, s.AttrOr("class", ""), strings.TrimSpace(s.Text()))
		})
		t.Logf("Total h4 tags found: %d", h4Count)

		dumpResponseBody(t, &http.Response{Body: io.NopCloser(strings.NewReader(doc.Text()))})
	}

	assert.True(t, found, "Client name '%s' should be displayed in HTML", expectedName)
}

// assertClientLogoInHTML verifies logo image is present/absent as expected
func assertClientLogoInHTML(t *testing.T, doc *goquery.Document, clientIdentifier string, expectLogo bool) {
	expectedSrc := "/client/logo/" + clientIdentifier
	var logoFound bool

	doc.Find("img").Each(func(i int, s *goquery.Selection) {
		src, exists := s.Attr("src")
		if exists && src == expectedSrc {
			logoFound = true
		}
	})

	if expectLogo {
		assert.True(t, logoFound,
			"Logo image with src '%s' should be present when ShowLogo=true and logo exists", expectedSrc)
	} else {
		assert.False(t, logoFound,
			"Logo image with src '%s' should not be present when ShowLogo=false or no logo uploaded", expectedSrc)
	}
}

// assertClientDescriptionInHTML verifies description is present/absent and matches expected
func assertClientDescriptionInHTML(t *testing.T, doc *goquery.Document, expectedDescription string, expectPresent bool) {
	if !expectPresent {
		// When not expecting description, verify it's not in either layout pattern
		if expectedDescription != "" {
			var foundInAuthLayout bool
			doc.Find("span.text-xs").Each(func(i int, s *goquery.Selection) {
				class, _ := s.Attr("class")
				if strings.Contains(class, "text-base-content") {
					if strings.Contains(s.Text(), expectedDescription) {
						foundInAuthLayout = true
					}
				}
			})

			var foundInConsentLayout bool
			doc.Find("p.text-sm").Each(func(i int, s *goquery.Selection) {
				class, _ := s.Attr("class")
				if strings.Contains(class, "opacity-70") {
					if strings.Contains(s.Text(), expectedDescription) {
						foundInConsentLayout = true
					}
				}
			})

			assert.False(t, foundInAuthLayout || foundInConsentLayout,
				"Description should not be visible when ShowDescription=false or description empty")
		}
		return
	}

	// When expecting description, check both layout patterns
	var found bool

	// Auth layout pattern: <span class="text-xs text-base-content/80">
	doc.Find("span.text-xs").Each(func(i int, s *goquery.Selection) {
		class, _ := s.Attr("class")
		if strings.Contains(class, "text-base-content") {
			text := strings.TrimSpace(s.Text())
			if text == expectedDescription {
				found = true
			}
		}
	})

	// Consent layout pattern: <p class="text-sm opacity-70">
	if !found {
		doc.Find("p.opacity-70").Each(func(i int, s *goquery.Selection) {
			text := strings.TrimSpace(s.Text())
			if text == expectedDescription {
				found = true
			}
		})
	}

	if !found {
		// Debug: Show all p tags with opacity-70 found
		t.Logf("Expected description: '%s'", expectedDescription)
		doc.Find("p").Each(func(i int, s *goquery.Selection) {
			class := s.AttrOr("class", "")
			if strings.Contains(class, "opacity") || strings.Contains(class, "text-sm") {
				t.Logf("Found p: class='%s', text='%s'", class, strings.TrimSpace(s.Text()))
			}
		})
	}

	assert.True(t, found,
		"Description '%s' should be visible when ShowDescription=true and description not empty", expectedDescription)
}

// assertClientWebsiteUrlInHTML verifies website URL link is present/absent as expected
func assertClientWebsiteUrlInHTML(t *testing.T, doc *goquery.Document, expectedURL string, expectPresent bool) {
	if expectedURL == "" && !expectPresent {
		return
	}

	var linkFound bool
	doc.Find("a").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if exists && href == expectedURL {
			linkFound = true

			if expectPresent {
				// Verify link attributes
				target, _ := s.Attr("target")
				assert.Equal(t, "_blank", target, "Website link should open in new tab")

				rel, _ := s.Attr("rel")
				assert.Equal(t, "noopener noreferrer", rel, "Website link should have security attributes")
			}
		}
	})

	if expectPresent {
		assert.True(t, linkFound,
			"Website URL link with href '%s' should be present when ShowWebsiteURL=true and URL not empty", expectedURL)
	} else {
		assert.False(t, linkFound,
			"Website URL link with href '%s' should not be present when ShowWebsiteURL=false or URL empty", expectedURL)
	}
}

// ClientDisplaySettings holds configuration for test client creation
type ClientDisplaySettings struct {
	ClientIdentifier string
	DisplayName      string
	Description      string
	WebsiteURL       string
	ShowLogo         bool
	ShowDisplayName  bool
	ShowDescription  bool
	ShowWebsiteURL   bool
	UploadLogo       bool // Whether to actually upload a logo
	ConsentRequired  bool
	DefaultAcrLevel  enums.AcrLevel
}

// createClientWithDisplaySettings creates a client with specified display settings
// and optional logo upload. Returns the created client.
func createClientWithDisplaySettings(t *testing.T, settings ClientDisplaySettings) *models.Client {
	client := &models.Client{
		ClientIdentifier:         settings.ClientIdentifier,
		DisplayName:              settings.DisplayName,
		Description:              settings.Description,
		WebsiteURL:               settings.WebsiteURL,
		ShowLogo:                 settings.ShowLogo,
		ShowDisplayName:          settings.ShowDisplayName,
		ShowDescription:          settings.ShowDescription,
		ShowWebsiteURL:           settings.ShowWebsiteURL,
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          settings.ConsentRequired,
		DefaultAcrLevel:          settings.DefaultAcrLevel,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	// Upload logo if requested
	if settings.UploadLogo {
		// Create a simple 1x1 PNG image
		logoData := []byte{
			0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
			0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR chunk
			0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
			0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,
			0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41,
			0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
			0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00,
			0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE,
			0x42, 0x60, 0x82,
		}

		clientLogo := &models.ClientLogo{
			ClientId: client.Id,
			Logo:     logoData,
		}

		err = database.CreateClientLogo(nil, clientLogo)
		if err != nil {
			t.Fatal(err)
		}
	}

	return client
}

// navigateToPasswordScreen starts an auth flow and navigates to the password screen
// Returns the HTTP response for the password page
func navigateToPasswordScreen(t *testing.T, httpClient *http.Client, client *models.Client, redirectUri string) *http.Response {
	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email"

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

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
	// Note: caller is responsible for closing this response

	return resp
}

// navigateToOtpScreen starts an auth flow, authenticates with password, and navigates to OTP screen
// Returns the HTTP response for the OTP page
func navigateToOtpScreen(t *testing.T, httpClient *http.Client, client *models.Client, user *models.User,
	password string, redirectUri string) *http.Response {

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email"

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

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

	csrf := getCsrfValue(t, resp)
	_ = resp.Body.Close()
	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, redirectLocation)

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, redirectLocation)

	redirectLocation = assertRedirect(t, resp, "/auth/otp")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, redirectLocation)
	// Note: caller is responsible for closing this response

	return resp
}

// navigateToConsentScreen completes auth flow and navigates to consent screen
// Returns the HTTP response for the consent page
func navigateToConsentScreen(t *testing.T, httpClient *http.Client, client *models.Client,
	user *models.User, password string, redirectUri string) *http.Response {

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email"

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

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

	csrf := getCsrfValue(t, resp)
	_ = resp.Body.Close()
	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, redirectLocation)

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, redirectLocation)

	redirectLocation = assertRedirect(t, resp, "/auth/consent")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, redirectLocation)
	// Note: caller is responsible for closing this response

	return resp
}
