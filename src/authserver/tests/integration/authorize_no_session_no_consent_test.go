package integrationtests

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/testutil/fake"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
)

func TestAuthorize_NoExistingSession_AcrLevel1_Pwd_ConsentIsNotRequired(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + fake.LetterN(8),
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
		URI:      fake.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	password := fake.Password(8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	user := &models.User{
		Subject:      fake.UUID(),
		Enabled:      true,
		Email:        fake.Email(),
		PasswordHash: passwordHashed,
	}

	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	requestCodeChallenge := fake.LetterN(43)
	requestState := fake.LetterN(8)
	requestNonce := fake.LetterN(8)
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

	resp = authenticateWithPassword(t, httpClient, redirectLocation, resp, user.Email, password)
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
}

func TestAuthorize_NoExistingSession_AcrLevel2Optional_Pwd_OtpDisabled_ConsentIsNotRequired(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + fake.LetterN(8),
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
		URI:      fake.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	password := fake.Password(8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	user := &models.User{
		Subject:      fake.UUID(),
		Enabled:      true,
		Email:        fake.Email(),
		PasswordHash: passwordHashed,
		OTPEnabled:   false,
	}

	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	requestCodeChallenge := fake.LetterN(43)
	requestState := fake.LetterN(8)
	requestNonce := fake.LetterN(8)
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

	resp = authenticateWithPassword(t, httpClient, redirectLocation, resp, user.Email, password)
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
}

func TestAuthorize_NoExistingSession_AcrLevel2Optional_Pwd_OtpEnabled_ConsentIsNotRequired(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + fake.LetterN(8),
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
		URI:      fake.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	password := fake.Password(8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	userEmail := fake.Email()
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Goiabada",
		AccountName: userEmail,
	})
	if err != nil {
		t.Fatal(err)
	}

	user := &models.User{
		Subject:            fake.UUID(),
		Enabled:            true,
		Email:              userEmail,
		PasswordHash:       passwordHashed,
		OTPSecret:          key.Secret(),
		OTPSecretEncrypted: encryptOTPSecretForTest(t, key.Secret()),
		OTPEnabled:         true,
	}

	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	requestCodeChallenge := fake.LetterN(43)
	requestState := fake.LetterN(8)
	requestNonce := fake.LetterN(8)
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

	resp = authenticateWithPassword(t, httpClient, redirectLocation, resp, user.Email, password)
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

	otpCode, err := totp.GenerateCode(user.OTPSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp = authenticateWithOtp(t, httpClient, redirectLocation, resp, otpCode)
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
	assert.Equal(t, fmt.Sprintf("%s %s", enums.AuthMethodPassword.String(), enums.AuthMethodOTP.String()), code.AuthMethods)
	assert.Equal(t, false, code.Used)
}

func TestAuthorize_NoExistingSession_AcrLevel2Mandatory_Pwd_OtpDisabled_ConsentIsNotRequired(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + fake.LetterN(8),
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
		URI:      fake.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	password := fake.Password(8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	userEmail := fake.Email()
	user := &models.User{
		Subject:      fake.UUID(),
		Enabled:      true,
		Email:        userEmail,
		PasswordHash: passwordHashed,
		OTPEnabled:   false,
	}

	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	requestCodeChallenge := fake.LetterN(43)
	requestState := fake.LetterN(8)
	requestNonce := fake.LetterN(8)
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

	resp = authenticateWithPassword(t, httpClient, redirectLocation, resp, user.Email, password)
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

	otpSecret := getOtpSecretFromEnrollmentPage(t, resp)
	otpCode, err := totp.GenerateCode(otpSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp = authenticateWithOtp(t, httpClient, redirectLocation, resp, otpCode)
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
}

func TestAuthorize_NoExistingSession_AcrLevel2Mandatory_Pwd_OtpEnabled_ConsentIsNotRequired(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + fake.LetterN(8),
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
		URI:      fake.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	password := fake.Password(8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	userEmail := fake.Email()
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Goiabada",
		AccountName: userEmail,
	})
	if err != nil {
		t.Fatal(err)
	}

	user := &models.User{
		Subject:            fake.UUID(),
		Enabled:            true,
		Email:              userEmail,
		PasswordHash:       passwordHashed,
		OTPSecret:          key.Secret(),
		OTPSecretEncrypted: encryptOTPSecretForTest(t, key.Secret()),
		OTPEnabled:         true,
	}

	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	requestCodeChallenge := fake.LetterN(43)
	requestState := fake.LetterN(8)
	requestNonce := fake.LetterN(8)
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

	resp = authenticateWithPassword(t, httpClient, redirectLocation, resp, user.Email, password)
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

	otpCode, err := totp.GenerateCode(user.OTPSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp = authenticateWithOtp(t, httpClient, redirectLocation, resp, otpCode)
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
}

func TestAuthorize_NoExistingSession_AcrLevel1_Pwd_ConsentIsNotRequired_PasswordIsIncorrect(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + fake.LetterN(8),
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
		URI:      fake.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	password := fake.Password(8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	user := &models.User{
		Subject:      fake.UUID(),
		Enabled:      true,
		Email:        fake.Email(),
		PasswordHash: passwordHashed,
	}

	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	requestCodeChallenge := fake.LetterN(43)
	requestState := fake.LetterN(8)
	requestNonce := fake.LetterN(8)
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

	resp = authenticateWithPassword(t, httpClient, redirectLocation, resp, user.Email, "incorrect-password")
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	errorMsg := doc.Find("p.text-error").Text()
	assert.Equal(t, "Authentication failed.", errorMsg)

	resp = loadPage(t, httpClient, config.GetAuthServer().BaseURL+"/auth/level1completed")
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestAuthorize_NoExistingSession_AcrLevel2Mandatory_Pwd_OtpDisabled_ConsentIsNotRequired_OtpCodeIsIncorrect(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + fake.LetterN(8),
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
		URI:      fake.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	password := fake.Password(8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	userEmail := fake.Email()
	user := &models.User{
		Subject:      fake.UUID(),
		Enabled:      true,
		Email:        userEmail,
		PasswordHash: passwordHashed,
		OTPEnabled:   false,
	}

	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	requestCodeChallenge := fake.LetterN(43)
	requestState := fake.LetterN(8)
	requestNonce := fake.LetterN(8)
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

	resp = authenticateWithPassword(t, httpClient, redirectLocation, resp, user.Email, password)
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

	incorrectOtpCode := "123456" // Incorrect OTP code
	resp = authenticateWithOtp(t, httpClient, redirectLocation, resp, incorrectOtpCode)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	errorMsg := doc.Find("p.text-error").Text()
	assert.Contains(t, errorMsg, "Incorrect OTP Code")

	// Verify that the user can't proceed to the next step.
	//
	// 400 and not 500: the ceremony is on level2_otp and this asks for the step after it, which
	// is a request the server will not process rather than a server fault. Before #279 decision
	// 21 every one of these answered a 500 page with a stack and a request id, and the ordinary
	// way to reach one is the browser's Back button.
	resp = loadPage(t, httpClient, config.GetAuthServer().BaseURL+"/auth/completed")
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assertStateMismatchPage(t, resp)
}

func TestAuthorize_NoExistingSession_AcrLevel2Mandatory_Pwd_OtpEnabled_ConsentIsNotRequired_OtpIsIncorrect(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + fake.LetterN(8),
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
		URI:      fake.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	password := fake.Password(8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	userEmail := fake.Email()
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Goiabada",
		AccountName: userEmail,
	})
	if err != nil {
		t.Fatal(err)
	}

	user := &models.User{
		Subject:            fake.UUID(),
		Enabled:            true,
		Email:              userEmail,
		PasswordHash:       passwordHashed,
		OTPSecret:          key.Secret(),
		OTPSecretEncrypted: encryptOTPSecretForTest(t, key.Secret()),
		OTPEnabled:         true,
	}

	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	requestCodeChallenge := fake.LetterN(43)
	requestState := fake.LetterN(8)
	requestNonce := fake.LetterN(8)
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

	resp = authenticateWithPassword(t, httpClient, redirectLocation, resp, user.Email, password)
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

	incorrectOtpCode := "123456" // Incorrect OTP code
	resp = authenticateWithOtp(t, httpClient, redirectLocation, resp, incorrectOtpCode)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	errorMsg := doc.Find("p.text-error").Text()
	assert.Contains(t, errorMsg, "Incorrect OTP Code")

	// Verify that the user can't proceed to the next step.
	//
	// 400 and not 500: the ceremony is on level2_otp and this asks for the step after it, which
	// is a request the server will not process rather than a server fault. Before #279 decision
	// 21 every one of these answered a 500 page with a stack and a request id, and the ordinary
	// way to reach one is the browser's Back button.
	resp = loadPage(t, httpClient, config.GetAuthServer().BaseURL+"/auth/completed")
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assertStateMismatchPage(t, resp)
}
