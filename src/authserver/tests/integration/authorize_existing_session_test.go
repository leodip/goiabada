package integrationtests

import (
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/enums"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
)

func TestAuthorize_ExistingAcrLevel1Session_AcrLevel1Request(t *testing.T) {
	httpClient, client, redirectUri, user := createSessionWithAcrLevel1(t)

	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession1 := userSessions[0]

	time.Sleep(200 * time.Millisecond)

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
		"&nonce=" + requestNonce +
		"&acr_values=" + enums.AcrLevel1.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	userSessions, err = database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession2 := userSessions[0]

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

	assert.Equal(t, userSession1.Id, userSession2.Id)
	assert.Equal(t, userSession1.SessionIdentifier, userSession2.SessionIdentifier)
	assert.Equal(t, userSession1.Started, userSession2.Started)
	assert.Greater(t, userSession2.LastAccessed, userSession1.LastAccessed)
}

func TestAuthorize_ExistingAcrLevel1Session_AcrLevel2OptionalRequest_OtpDisabled(t *testing.T) {
	httpClient, client, redirectUri, user := createSessionWithAcrLevel1(t)

	user.OTPEnabled = false
	err := database.UpdateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession1 := userSessions[0]

	time.Sleep(200 * time.Millisecond)

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
		"&nonce=" + requestNonce +
		"&acr_values=" + enums.AcrLevel2Optional.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1completed")
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

	userSessions, err = database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession2 := userSessions[0]

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

	assert.Equal(t, userSession1.Id, userSession2.Id)
	assert.Equal(t, userSession1.SessionIdentifier, userSession2.SessionIdentifier)
	assert.Equal(t, userSession1.Started, userSession2.Started)
	assert.Greater(t, userSession2.LastAccessed, userSession1.LastAccessed)
}

func TestAuthorize_ExistingAcrLevel1Session_AcrLevel2OptionalRequest_OtpEnabled(t *testing.T) {
	httpClient, client, redirectUri, user := createSessionWithAcrLevel1(t)

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Goiabada",
		AccountName: user.Email,
	})
	if err != nil {
		t.Fatal(err)
	}

	user.OTPEnabled = true
	user.OTPSecret = key.Secret()
	err = database.UpdateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession1 := userSessions[0]

	time.Sleep(200 * time.Millisecond)

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
		"&nonce=" + requestNonce +
		"&acr_values=" + enums.AcrLevel2Optional.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/otp")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)

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

	userSessions, err = database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession2 := userSessions[0]

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

	assert.Equal(t, userSession1.Id, userSession2.Id)
	assert.Equal(t, userSession1.SessionIdentifier, userSession2.SessionIdentifier)
	assert.Equal(t, userSession1.Started, userSession2.Started)
	assert.Greater(t, userSession2.LastAccessed, userSession1.LastAccessed)
}

func TestAuthorize_ExistingAcrLevel1Session_AcrLevel2MandatoryRequest_OtpDisabled(t *testing.T) {
	httpClient, client, redirectUri, user := createSessionWithAcrLevel1(t)

	user.OTPEnabled = false
	err := database.UpdateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession1 := userSessions[0]

	time.Sleep(200 * time.Millisecond)

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
		"&nonce=" + requestNonce +
		"&acr_values=" + enums.AcrLevel2Mandatory.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/otp")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)
	otpSecret := getOtpSecretFromEnrollmentPage(t, resp)
	otpCode, err := totp.GenerateCode(otpSecret, time.Now())
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

	userSessions, err = database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession2 := userSessions[0]

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

	assert.Equal(t, userSession1.Id, userSession2.Id)
	assert.Equal(t, userSession1.SessionIdentifier, userSession2.SessionIdentifier)
	assert.Equal(t, userSession1.Started, userSession2.Started)
	assert.Greater(t, userSession2.LastAccessed, userSession1.LastAccessed)
}

func TestAuthorize_ExistingAcrLevel1Session_AcrLevel2MandatoryRequest_OtpEnabled(t *testing.T) {
	httpClient, client, redirectUri, user := createSessionWithAcrLevel1(t)

	// Enable OTP for the user
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Goiabada",
		AccountName: user.Email,
	})
	if err != nil {
		t.Fatal(err)
	}

	user.OTPEnabled = true
	user.OTPSecret = key.Secret()
	err = database.UpdateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession1 := userSessions[0]

	time.Sleep(200 * time.Millisecond)

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
		"&nonce=" + requestNonce +
		"&acr_values=" + enums.AcrLevel2Mandatory.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/otp")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)

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

	userSessions, err = database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession2 := userSessions[0]

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

	assert.Equal(t, userSession1.Id, userSession2.Id)
	assert.Equal(t, userSession1.SessionIdentifier, userSession2.SessionIdentifier)
	assert.Equal(t, userSession1.Started, userSession2.Started)
	assert.Greater(t, userSession2.LastAccessed, userSession1.LastAccessed)
}

func TestAuthorize_ExistingAcrLevel2OptionalSession_AcrLevel1Request(t *testing.T) {
	httpClient, client, redirectUri, user := createSessionWithAcrLevel2Optional(t)

	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession1 := userSessions[0]

	time.Sleep(200 * time.Millisecond)

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
		"&nonce=" + requestNonce +
		"&acr_values=" + enums.AcrLevel1.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	userSessions, err = database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession2 := userSessions[0]

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

	assert.Equal(t, userSession1.Id, userSession2.Id)
	assert.Equal(t, userSession1.SessionIdentifier, userSession2.SessionIdentifier)
	assert.Equal(t, userSession1.Started, userSession2.Started)
	assert.Greater(t, userSession2.LastAccessed, userSession1.LastAccessed)
}

func TestAuthorize_ExistingAcrLevel2OptionalSession_AcrLevel2OptionalRequest_OtpDisabled(t *testing.T) {
	httpClient, client, redirectUri, user := createSessionWithAcrLevel2Optional(t)

	// Ensure OTP is disabled for the user
	user.OTPEnabled = false
	err := database.UpdateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession1 := userSessions[0]

	time.Sleep(200 * time.Millisecond)

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
		"&nonce=" + requestNonce +
		"&acr_values=" + enums.AcrLevel2Optional.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	userSessions, err = database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession2 := userSessions[0]

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

	assert.Equal(t, userSession1.Id, userSession2.Id)
	assert.Equal(t, userSession1.SessionIdentifier, userSession2.SessionIdentifier)
	assert.Equal(t, userSession1.Started, userSession2.Started)
	assert.Greater(t, userSession2.LastAccessed, userSession1.LastAccessed)
}

func TestAuthorize_ExistingAcrLevel2OptionalSession_AcrLevel2OptionalRequest_OtpEnabled(t *testing.T) {
	httpClient, client, redirectUri, user := createSessionWithAcrLevel2Optional(t)

	// in this test we simulate an existing session where OTP was disabled,
	// then OTP gets enabled, the user logs in again, and is prompted for OTP

	// Ensure OTP is enabled for the user
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Goiabada",
		AccountName: user.Email,
	})
	if err != nil {
		t.Fatal(err)
	}

	user.OTPEnabled = true
	user.OTPSecret = key.Secret()
	err = database.UpdateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession1 := userSessions[0]

	userSession1.Level2AuthConfigHasChanged = true
	err = database.UpdateUserSession(nil, &userSession1)
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(200 * time.Millisecond)

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
		"&nonce=" + requestNonce +
		"&acr_values=" + enums.AcrLevel2Optional.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/otp")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)

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

	userSessions, err = database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession2 := userSessions[0]

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

	assert.Equal(t, userSession1.Id, userSession2.Id)
	assert.Equal(t, userSession1.SessionIdentifier, userSession2.SessionIdentifier)
	assert.Equal(t, userSession1.Started, userSession2.Started)
	assert.Greater(t, userSession2.LastAccessed, userSession1.LastAccessed)

	assert.Equal(t, false, userSession2.Level2AuthConfigHasChanged)
}

func TestAuthorize_ExistingAcrLevel2OptionalSession_AcrLevel2MandatoryRequest_OtpDisabled(t *testing.T) {
	httpClient, client, redirectUri, user := createSessionWithAcrLevel2Optional(t)

	// Ensure OTP is disabled for the user
	user.OTPEnabled = false
	err := database.UpdateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession1 := userSessions[0]

	time.Sleep(200 * time.Millisecond)

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
		"&nonce=" + requestNonce +
		"&acr_values=" + enums.AcrLevel2Mandatory.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/otp")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)
	otpSecret := getOtpSecretFromEnrollmentPage(t, resp)
	otpCode, err := totp.GenerateCode(otpSecret, time.Now())
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

	userSessions, err = database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession2 := userSessions[0]

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

	assert.Equal(t, userSession1.Id, userSession2.Id)
	assert.Equal(t, userSession1.SessionIdentifier, userSession2.SessionIdentifier)
	assert.Equal(t, userSession1.Started, userSession2.Started)
	assert.Greater(t, userSession2.LastAccessed, userSession1.LastAccessed)

	// Verify that OTP is now enabled for the user
	updatedUser, err := database.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, updatedUser.OTPEnabled)
	assert.NotEmpty(t, updatedUser.OTPSecret)
}

func TestAuthorize_ExistingAcrLevel2OptionalSession_AcrLevel2MandatoryRequest_OtpEnabled(t *testing.T) {
	httpClient, client, redirectUri, user := createSessionWithAcrLevel2Optional(t)

	// Ensure OTP is enabled for the user
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Goiabada",
		AccountName: user.Email,
	})
	if err != nil {
		t.Fatal(err)
	}

	user.OTPEnabled = true
	user.OTPSecret = key.Secret()
	err = database.UpdateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession1 := userSessions[0]

	time.Sleep(200 * time.Millisecond)

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
		"&nonce=" + requestNonce +
		"&acr_values=" + enums.AcrLevel2Mandatory.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/otp")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)
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

	userSessions, err = database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession2 := userSessions[0]

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

	assert.Equal(t, userSession1.Id, userSession2.Id)
	assert.Equal(t, userSession1.SessionIdentifier, userSession2.SessionIdentifier)
	assert.Equal(t, userSession1.Started, userSession2.Started)
	assert.Greater(t, userSession2.LastAccessed, userSession1.LastAccessed)

	// Verify that OTP is still enabled for the user
	updatedUser, err := database.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, updatedUser.OTPEnabled)
	assert.Equal(t, user.OTPSecret, updatedUser.OTPSecret)
}

func TestAuthorize_ExistingAcrLevel2MandatorySession_AcrLevel1Request(t *testing.T) {
	httpClient, client, redirectUri, user := createSessionWithAcrLevel2Mandatory(t)

	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession1 := userSessions[0]

	time.Sleep(200 * time.Millisecond)

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
		"&nonce=" + requestNonce +
		"&acr_values=" + enums.AcrLevel1.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	userSessions, err = database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession2 := userSessions[0]

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

	assert.Equal(t, userSession1.Id, userSession2.Id)
	assert.Equal(t, userSession1.SessionIdentifier, userSession2.SessionIdentifier)
	assert.Equal(t, userSession1.Started, userSession2.Started)
	assert.Greater(t, userSession2.LastAccessed, userSession1.LastAccessed)
}

func TestAuthorize_ExistingAcrLevel2MandatorySession_AcrLevel2OptionalRequest_OtpDisabled(t *testing.T) {
	httpClient, client, redirectUri, user := createSessionWithAcrLevel2Mandatory(t)

	// Disable OTP for the user
	user.OTPEnabled = false
	user.OTPSecret = ""
	err := database.UpdateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession1 := userSessions[0]

	time.Sleep(200 * time.Millisecond)

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
		"&nonce=" + requestNonce +
		"&acr_values=" + enums.AcrLevel2Optional.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	userSessions, err = database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession2 := userSessions[0]

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

	assert.Equal(t, userSession1.Id, userSession2.Id)
	assert.Equal(t, userSession1.SessionIdentifier, userSession2.SessionIdentifier)
	assert.Equal(t, userSession1.Started, userSession2.Started)
	assert.Greater(t, userSession2.LastAccessed, userSession1.LastAccessed)

	// Verify that the user's OTP settings haven't changed
	updatedUser, err := database.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	assert.False(t, updatedUser.OTPEnabled)
	assert.Empty(t, updatedUser.OTPSecret)
}

func TestAuthorize_ExistingAcrLevel2MandatorySession_AcrLevel2OptionalRequest_OtpEnabled(t *testing.T) {
	httpClient, client, redirectUri, user := createSessionWithAcrLevel2Mandatory(t)

	// Ensure OTP is enabled for the user
	if !user.OTPEnabled {
		t.Fatal("Expected user to have OTP enabled")
	}

	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession1 := userSessions[0]

	time.Sleep(200 * time.Millisecond)

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
		"&nonce=" + requestNonce +
		"&acr_values=" + enums.AcrLevel2Optional.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	userSessions, err = database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession2 := userSessions[0]

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

	assert.Equal(t, userSession1.Id, userSession2.Id)
	assert.Equal(t, userSession1.SessionIdentifier, userSession2.SessionIdentifier)
	assert.Equal(t, userSession1.Started, userSession2.Started)
	assert.Greater(t, userSession2.LastAccessed, userSession1.LastAccessed)

	// Verify that the user's OTP settings haven't changed
	updatedUser, err := database.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, updatedUser.OTPEnabled)
	assert.NotEmpty(t, updatedUser.OTPSecret)
}

func TestAuthorize_ExistingAcrLevel2MandatorySession_AcrLevel2MandatoryRequest_OtpDisabled(t *testing.T) {
	httpClient, client, redirectUri, user := createSessionWithAcrLevel2Mandatory(t)

	// Disable OTP for the user
	user.OTPEnabled = false
	user.OTPSecret = ""
	err := database.UpdateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession1 := userSessions[0]

	userSession1.Level2AuthConfigHasChanged = true
	err = database.UpdateUserSession(nil, &userSession1)
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(200 * time.Millisecond)

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
		"&nonce=" + requestNonce +
		"&acr_values=" + enums.AcrLevel2Mandatory.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/otp")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)
	otpSecret := getOtpSecretFromEnrollmentPage(t, resp)
	otpCode, err := totp.GenerateCode(otpSecret, time.Now())
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

	userSessions, err = database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession2 := userSessions[0]

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

	assert.Equal(t, userSession1.Id, userSession2.Id)
	assert.Equal(t, userSession1.SessionIdentifier, userSession2.SessionIdentifier)
	assert.Equal(t, userSession1.Started, userSession2.Started)
	assert.Greater(t, userSession2.LastAccessed, userSession1.LastAccessed)

	// Verify that the user's OTP settings have been updated
	updatedUser, err := database.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, updatedUser.OTPEnabled)
	assert.NotEmpty(t, updatedUser.OTPSecret)
}

func TestAuthorize_ExistingAcrLevel2MandatorySession_AcrLevel2MandatoryRequest_OtpEnabled(t *testing.T) {
	httpClient, client, redirectUri, user := createSessionWithAcrLevel2Mandatory(t)

	// Ensure OTP is enabled for the user
	if !user.OTPEnabled {
		t.Fatal("Expected user to have OTP enabled")
	}

	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession1 := userSessions[0]

	time.Sleep(200 * time.Millisecond)

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
		"&nonce=" + requestNonce +
		"&acr_values=" + enums.AcrLevel2Mandatory.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	userSessions, err = database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession2 := userSessions[0]

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

	assert.Equal(t, userSession1.Id, userSession2.Id)
	assert.Equal(t, userSession1.SessionIdentifier, userSession2.SessionIdentifier)
	assert.Equal(t, userSession1.Started, userSession2.Started)
	assert.Greater(t, userSession2.LastAccessed, userSession1.LastAccessed)

	// Check that the user's OTP settings remain unchanged
	updatedUser, err := database.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, updatedUser.OTPEnabled)
	assert.Equal(t, user.OTPSecret, updatedUser.OTPSecret)
}
