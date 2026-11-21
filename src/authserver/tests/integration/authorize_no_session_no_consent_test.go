package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/otp/otptest"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
)

func TestAuthorize_NoExistingSession_ACRLevel1_Pwd_ConsentIsNotRequired(t *testing.T) {
	started := time.Now().UTC()
	client := &record.Client{
		ClientIdentifier:         "test-client-" + fake.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          false,
		DefaultACRLevel:          record.ACRLevel1,
	}

	err := database.CreateClient(context.Background(), nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectURI := &record.RedirectURI{
		ClientID: client.ID,
		URI:      fake.URL(),
	}

	err = database.CreateRedirectURI(context.Background(), nil, redirectURI)
	if err != nil {
		t.Fatal(err)
	}

	password := fake.Password(8)
	passwordHashed, err := passwordhash.Hash(password)
	if err != nil {
		t.Fatal(err)
	}

	user := &record.User{
		Subject:      fake.UUID(),
		Enabled:      true,
		Email:        fake.Email(),
		PasswordHash: passwordHashed,
	}

	err = database.CreateUser(context.Background(), nil, user)
	if err != nil {
		t.Fatal(err)
	}

	requestCodeChallenge := randomCodeChallenge()
	requestState := fake.LetterN(8)
	requestNonce := fake.LetterN(8)
	requestScope := "openid profile email"

	destURL := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectURI.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHTTPClient(t)

	resp, err := httpClient.Get(destURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, resp, user.Email, password)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	codeVal, stateVal := getCodeAndStateFromURL(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)

	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, requestCodeChallenge, code.CodeChallenge.String)
	assert.Equal(t, "S256", code.CodeChallengeMethod.String)
	assert.Equal(t, requestScope, code.Scope)
	assert.Equal(t, requestState, code.State)
	assert.Equal(t, requestNonce, code.Nonce)
	assert.Equal(t, redirectURI.URI, code.RedirectURI)
	assert.Equal(t, user.ID, code.User.ID)
	assert.Equal(t, "query", code.ResponseMode)
	assertStampedSince(t, code.AuthenticatedAt, started)
	assert.Equal(t, record.ACRLevel1, code.ACRLevel)
	assert.Equal(t, oidc.AuthMethodPassword.String(), code.AuthMethods)
	assert.False(t, code.Used)
}

func TestAuthorize_NoExistingSession_ACRLevel2Optional_Pwd_OTPDisabled_ConsentIsNotRequired(t *testing.T) {
	started := time.Now().UTC()
	client := &record.Client{
		ClientIdentifier:         "test-client-" + fake.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          false,
		DefaultACRLevel:          record.ACRLevel2Optional,
	}

	err := database.CreateClient(context.Background(), nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectURI := &record.RedirectURI{
		ClientID: client.ID,
		URI:      fake.URL(),
	}

	err = database.CreateRedirectURI(context.Background(), nil, redirectURI)
	if err != nil {
		t.Fatal(err)
	}

	password := fake.Password(8)
	passwordHashed, err := passwordhash.Hash(password)
	if err != nil {
		t.Fatal(err)
	}

	user := &record.User{
		Subject:      fake.UUID(),
		Enabled:      true,
		Email:        fake.Email(),
		PasswordHash: passwordHashed,
		OTPEnabled:   false,
	}

	err = database.CreateUser(context.Background(), nil, user)
	if err != nil {
		t.Fatal(err)
	}

	requestCodeChallenge := randomCodeChallenge()
	requestState := fake.LetterN(8)
	requestNonce := fake.LetterN(8)
	requestScope := "openid profile email"

	destURL := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectURI.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHTTPClient(t)

	resp, err := httpClient.Get(destURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, resp, user.Email, password)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	codeVal, stateVal := getCodeAndStateFromURL(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)

	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, requestCodeChallenge, code.CodeChallenge.String)
	assert.Equal(t, "S256", code.CodeChallengeMethod.String)
	assert.Equal(t, requestScope, code.Scope)
	assert.Equal(t, requestState, code.State)
	assert.Equal(t, requestNonce, code.Nonce)
	assert.Equal(t, redirectURI.URI, code.RedirectURI)
	assert.Equal(t, user.ID, code.User.ID)
	assert.Equal(t, "query", code.ResponseMode)
	assertStampedSince(t, code.AuthenticatedAt, started)
	assert.Equal(t, record.ACRLevel2Optional, code.ACRLevel)
	assert.Equal(t, oidc.AuthMethodPassword.String(), code.AuthMethods)
	assert.False(t, code.Used)
}

func TestAuthorize_NoExistingSession_ACRLevel2Optional_Pwd_OTPEnabled_ConsentIsNotRequired(t *testing.T) {
	started := time.Now().UTC()
	client := &record.Client{
		ClientIdentifier:         "test-client-" + fake.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          false,
		DefaultACRLevel:          record.ACRLevel2Optional,
	}

	err := database.CreateClient(context.Background(), nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectURI := &record.RedirectURI{
		ClientID: client.ID,
		URI:      fake.URL(),
	}

	err = database.CreateRedirectURI(context.Background(), nil, redirectURI)
	if err != nil {
		t.Fatal(err)
	}

	password := fake.Password(8)
	passwordHashed, err := passwordhash.Hash(password)
	if err != nil {
		t.Fatal(err)
	}

	userEmail := fake.Email()
	otpSecret := newOTPSecretForTest(t, userEmail)

	user := &record.User{
		Subject:            fake.UUID(),
		Enabled:            true,
		Email:              userEmail,
		PasswordHash:       passwordHashed,
		OTPSecretEncrypted: encryptOTPSecretForTest(t, otpSecret),
		OTPEnabled:         true,
	}

	err = database.CreateUser(context.Background(), nil, user)
	if err != nil {
		t.Fatal(err)
	}

	requestCodeChallenge := randomCodeChallenge()
	requestState := fake.LetterN(8)
	requestNonce := fake.LetterN(8)
	requestScope := "openid profile email"

	destURL := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectURI.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHTTPClient(t)

	resp, err := httpClient.Get(destURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, resp, user.Email, password)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/otp")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	otpCode := otptest.Code(t, otpSecret, time.Now())
	resp = authenticateWithOTP(t, httpClient, redirectLocation, resp, otpCode)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	codeVal, stateVal := getCodeAndStateFromURL(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)

	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, requestCodeChallenge, code.CodeChallenge.String)
	assert.Equal(t, "S256", code.CodeChallengeMethod.String)
	assert.Equal(t, requestScope, code.Scope)
	assert.Equal(t, requestState, code.State)
	assert.Equal(t, requestNonce, code.Nonce)
	assert.Equal(t, redirectURI.URI, code.RedirectURI)
	assert.Equal(t, user.ID, code.User.ID)
	assert.Equal(t, "query", code.ResponseMode)
	assertStampedSince(t, code.AuthenticatedAt, started)
	assert.Equal(t, record.ACRLevel2Optional, code.ACRLevel)
	assert.Equal(t, fmt.Sprintf("%s %s", oidc.AuthMethodPassword.String(), oidc.AuthMethodOTP.String()), code.AuthMethods)
	assert.False(t, code.Used)
}

func TestAuthorize_NoExistingSession_ACRLevel2Mandatory_Pwd_OTPDisabled_ConsentIsNotRequired(t *testing.T) {
	started := time.Now().UTC()
	client := &record.Client{
		ClientIdentifier:         "test-client-" + fake.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          false,
		DefaultACRLevel:          record.ACRLevel2Mandatory,
	}

	err := database.CreateClient(context.Background(), nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectURI := &record.RedirectURI{
		ClientID: client.ID,
		URI:      fake.URL(),
	}

	err = database.CreateRedirectURI(context.Background(), nil, redirectURI)
	if err != nil {
		t.Fatal(err)
	}

	password := fake.Password(8)
	passwordHashed, err := passwordhash.Hash(password)
	if err != nil {
		t.Fatal(err)
	}

	userEmail := fake.Email()
	user := &record.User{
		Subject:      fake.UUID(),
		Enabled:      true,
		Email:        userEmail,
		PasswordHash: passwordHashed,
		OTPEnabled:   false,
	}

	err = database.CreateUser(context.Background(), nil, user)
	if err != nil {
		t.Fatal(err)
	}

	requestCodeChallenge := randomCodeChallenge()
	requestState := fake.LetterN(8)
	requestNonce := fake.LetterN(8)
	requestScope := "openid profile email"

	destURL := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectURI.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHTTPClient(t)

	resp, err := httpClient.Get(destURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, resp, user.Email, password)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/otp")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	otpSecret := getOTPSecretFromEnrollmentPage(t, resp)
	otpCode := otptest.Code(t, otpSecret, time.Now())
	resp = passSetupRecoveryCodes(t, httpClient, authenticateWithOTP(t, httpClient, redirectLocation, resp, otpCode))
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	codeVal, stateVal := getCodeAndStateFromURL(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)

	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, requestCodeChallenge, code.CodeChallenge.String)
	assert.Equal(t, "S256", code.CodeChallengeMethod.String)
	assert.Equal(t, requestScope, code.Scope)
	assert.Equal(t, requestState, code.State)
	assert.Equal(t, requestNonce, code.Nonce)
	assert.Equal(t, redirectURI.URI, code.RedirectURI)
	assert.Equal(t, user.ID, code.User.ID)
	assert.Equal(t, "query", code.ResponseMode)
	assertStampedSince(t, code.AuthenticatedAt, started)
	assert.Equal(t, record.ACRLevel2Mandatory, code.ACRLevel)
	assert.Equal(t, fmt.Sprintf("%s %s", oidc.AuthMethodPassword.String(), oidc.AuthMethodOTP.String()), code.AuthMethods)
	assert.False(t, code.Used)
}

func TestAuthorize_NoExistingSession_ACRLevel2Mandatory_Pwd_OTPEnabled_ConsentIsNotRequired(t *testing.T) {
	started := time.Now().UTC()
	client := &record.Client{
		ClientIdentifier:         "test-client-" + fake.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          false,
		DefaultACRLevel:          record.ACRLevel2Mandatory,
	}

	err := database.CreateClient(context.Background(), nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectURI := &record.RedirectURI{
		ClientID: client.ID,
		URI:      fake.URL(),
	}

	err = database.CreateRedirectURI(context.Background(), nil, redirectURI)
	if err != nil {
		t.Fatal(err)
	}

	password := fake.Password(8)
	passwordHashed, err := passwordhash.Hash(password)
	if err != nil {
		t.Fatal(err)
	}

	userEmail := fake.Email()
	otpSecret := newOTPSecretForTest(t, userEmail)

	user := &record.User{
		Subject:            fake.UUID(),
		Enabled:            true,
		Email:              userEmail,
		PasswordHash:       passwordHashed,
		OTPSecretEncrypted: encryptOTPSecretForTest(t, otpSecret),
		OTPEnabled:         true,
	}

	err = database.CreateUser(context.Background(), nil, user)
	if err != nil {
		t.Fatal(err)
	}

	requestCodeChallenge := randomCodeChallenge()
	requestState := fake.LetterN(8)
	requestNonce := fake.LetterN(8)
	requestScope := "openid profile email"

	destURL := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectURI.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHTTPClient(t)

	resp, err := httpClient.Get(destURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, resp, user.Email, password)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/otp")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	otpCode := otptest.Code(t, otpSecret, time.Now())
	resp = authenticateWithOTP(t, httpClient, redirectLocation, resp, otpCode)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	codeVal, stateVal := getCodeAndStateFromURL(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)

	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, requestCodeChallenge, code.CodeChallenge.String)
	assert.Equal(t, "S256", code.CodeChallengeMethod.String)
	assert.Equal(t, requestScope, code.Scope)
	assert.Equal(t, requestState, code.State)
	assert.Equal(t, requestNonce, code.Nonce)
	assert.Equal(t, redirectURI.URI, code.RedirectURI)
	assert.Equal(t, user.ID, code.User.ID)
	assert.Equal(t, "query", code.ResponseMode)
	assertStampedSince(t, code.AuthenticatedAt, started)
	assert.Equal(t, record.ACRLevel2Mandatory, code.ACRLevel)
	assert.Equal(t, fmt.Sprintf("%s %s", oidc.AuthMethodPassword.String(), oidc.AuthMethodOTP.String()), code.AuthMethods)
	assert.False(t, code.Used)
}

func TestAuthorize_NoExistingSession_ACRLevel1_Pwd_ConsentIsNotRequired_PasswordIsIncorrect(t *testing.T) {
	client := &record.Client{
		ClientIdentifier:         "test-client-" + fake.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          false,
		DefaultACRLevel:          record.ACRLevel1,
	}

	err := database.CreateClient(context.Background(), nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectURI := &record.RedirectURI{
		ClientID: client.ID,
		URI:      fake.URL(),
	}

	err = database.CreateRedirectURI(context.Background(), nil, redirectURI)
	if err != nil {
		t.Fatal(err)
	}

	password := fake.Password(8)
	passwordHashed, err := passwordhash.Hash(password)
	if err != nil {
		t.Fatal(err)
	}

	user := &record.User{
		Subject:      fake.UUID(),
		Enabled:      true,
		Email:        fake.Email(),
		PasswordHash: passwordHashed,
	}

	err = database.CreateUser(context.Background(), nil, user)
	if err != nil {
		t.Fatal(err)
	}

	requestCodeChallenge := randomCodeChallenge()
	requestState := fake.LetterN(8)
	requestNonce := fake.LetterN(8)
	requestScope := "openid profile email"

	destURL := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectURI.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHTTPClient(t)

	resp, err := httpClient.Get(destURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, resp, user.Email, "incorrect-password")
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	errorMsg := strings.TrimSpace(doc.Find(`[role="alert"]`).Text())
	assert.Equal(t, "Authentication failed.", errorMsg)

	// Verify that the user can't proceed to the next step. 400 like every other gated step; this
	// one answered 500 until #436 put it behind the same gate (#248 part 1).
	resp = loadPage(t, httpClient, stepURLOfTheSameCeremony(t, redirectLocation, "/auth/level1completed"))
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assertStateMismatchPage(t, resp)
}

func TestAuthorize_NoExistingSession_ACRLevel2Mandatory_Pwd_OTPDisabled_ConsentIsNotRequired_OTPCodeIsIncorrect(t *testing.T) {
	client := &record.Client{
		ClientIdentifier:         "test-client-" + fake.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          false,
		DefaultACRLevel:          record.ACRLevel2Mandatory,
	}

	err := database.CreateClient(context.Background(), nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectURI := &record.RedirectURI{
		ClientID: client.ID,
		URI:      fake.URL(),
	}

	err = database.CreateRedirectURI(context.Background(), nil, redirectURI)
	if err != nil {
		t.Fatal(err)
	}

	password := fake.Password(8)
	passwordHashed, err := passwordhash.Hash(password)
	if err != nil {
		t.Fatal(err)
	}

	userEmail := fake.Email()
	user := &record.User{
		Subject:      fake.UUID(),
		Enabled:      true,
		Email:        userEmail,
		PasswordHash: passwordHashed,
		OTPEnabled:   false,
	}

	err = database.CreateUser(context.Background(), nil, user)
	if err != nil {
		t.Fatal(err)
	}

	requestCodeChallenge := randomCodeChallenge()
	requestState := fake.LetterN(8)
	requestNonce := fake.LetterN(8)
	requestScope := "openid profile email"

	destURL := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectURI.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHTTPClient(t)

	resp, err := httpClient.Get(destURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, resp, user.Email, password)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/otp")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	incorrectOTPCode := "123456" // Incorrect OTP code
	resp = authenticateWithOTP(t, httpClient, redirectLocation, resp, incorrectOTPCode)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	errorMsg := strings.TrimSpace(doc.Find(`[role="alert"]`).Text())
	assert.Contains(t, errorMsg, "That code isn't right")

	// Verify that the user can't proceed to the next step.
	//
	// 400 and not 500: the ceremony is on level2_otp and this asks for the step after it, which
	// is a request the server will not process rather than a server fault. Before #279 decision
	// 21 every one of these answered a 500 page with a stack and a request id, and the ordinary
	// way to reach one is the browser's Back button.
	resp = loadPage(t, httpClient, stepURLOfTheSameCeremony(t, redirectLocation, "/auth/completed"))
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assertStateMismatchPage(t, resp)
}

func TestAuthorize_NoExistingSession_ACRLevel2Mandatory_Pwd_OTPEnabled_ConsentIsNotRequired_OTPIsIncorrect(t *testing.T) {
	client := &record.Client{
		ClientIdentifier:         "test-client-" + fake.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          false,
		DefaultACRLevel:          record.ACRLevel2Mandatory,
	}

	err := database.CreateClient(context.Background(), nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectURI := &record.RedirectURI{
		ClientID: client.ID,
		URI:      fake.URL(),
	}

	err = database.CreateRedirectURI(context.Background(), nil, redirectURI)
	if err != nil {
		t.Fatal(err)
	}

	password := fake.Password(8)
	passwordHashed, err := passwordhash.Hash(password)
	if err != nil {
		t.Fatal(err)
	}

	userEmail := fake.Email()
	otpSecret := newOTPSecretForTest(t, userEmail)

	user := &record.User{
		Subject:            fake.UUID(),
		Enabled:            true,
		Email:              userEmail,
		PasswordHash:       passwordHashed,
		OTPSecretEncrypted: encryptOTPSecretForTest(t, otpSecret),
		OTPEnabled:         true,
	}

	err = database.CreateUser(context.Background(), nil, user)
	if err != nil {
		t.Fatal(err)
	}

	requestCodeChallenge := randomCodeChallenge()
	requestState := fake.LetterN(8)
	requestNonce := fake.LetterN(8)
	requestScope := "openid profile email"

	destURL := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectURI.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHTTPClient(t)

	resp, err := httpClient.Get(destURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, resp, user.Email, password)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/otp")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	incorrectOTPCode := "123456" // Incorrect OTP code
	resp = authenticateWithOTP(t, httpClient, redirectLocation, resp, incorrectOTPCode)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	errorMsg := strings.TrimSpace(doc.Find(`[role="alert"]`).Text())
	assert.Contains(t, errorMsg, "That code isn't right")

	// Verify that the user can't proceed to the next step.
	//
	// 400 and not 500: the ceremony is on level2_otp and this asks for the step after it, which
	// is a request the server will not process rather than a server fault. Before #279 decision
	// 21 every one of these answered a 500 page with a stack and a request id, and the ordinary
	// way to reach one is the browser's Back button.
	resp = loadPage(t, httpClient, stepURLOfTheSameCeremony(t, redirectLocation, "/auth/completed"))
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assertStateMismatchPage(t, resp)
}
