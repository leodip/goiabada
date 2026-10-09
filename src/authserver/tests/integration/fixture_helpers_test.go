package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/permissions"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadCodeFromDatabase(t *testing.T, codeVal string) *record.Code {
	codeHash := hashutil.HashString(codeVal)
	code, err := database.GetCodeByCodeHash(context.Background(), nil, codeHash, false)
	if err != nil {
		t.Fatal(err)
	}

	err = database.CodeLoadClient(context.Background(), nil, code)
	if err != nil {
		t.Fatal(err)
	}

	err = database.CodeLoadUser(context.Background(), nil, code)
	if err != nil {
		t.Fatal(err)
	}

	return code
}

func createResource(t *testing.T) *record.Resource {
	resource := &record.Resource{
		ResourceIdentifier: "res-" + fake.LetterN(8),
	}
	err := database.CreateResource(context.Background(), nil, resource)
	if err != nil {
		t.Fatal(err)
	}
	return resource
}

func createResourceWithId(t *testing.T, resourceIdentifier string) *record.Resource {
	resource := &record.Resource{
		ResourceIdentifier: resourceIdentifier,
	}
	err := database.CreateResource(context.Background(), nil, resource)
	if err != nil {
		t.Fatal(err)
	}
	return resource
}

func createPermission(t *testing.T, resourceId int64) *record.Permission {
	permission := &record.Permission{
		PermissionIdentifier: "perm-" + fake.LetterN(8),
		ResourceId:           resourceId,
	}
	err := database.CreatePermission(context.Background(), nil, permission)
	if err != nil {
		t.Fatal(err)
	}
	return permission
}

func createPermissionWithId(t *testing.T, resourceId int64, permissionIdentifier string) *record.Permission {
	permission := &record.Permission{
		PermissionIdentifier: permissionIdentifier,
		ResourceId:           resourceId,
	}
	err := database.CreatePermission(context.Background(), nil, permission)
	if err != nil {
		t.Fatal(err)
	}
	return permission
}

func assignPermissionToUser(t *testing.T, userId int64, permissionId int64) {
	userPermission := &record.UserPermission{
		UserId:       userId,
		PermissionId: permissionId,
	}
	err := database.CreateUserPermission(context.Background(), nil, userPermission)
	if err != nil {
		t.Fatal(err)
	}
}

func createSessionWithAcrLevel1(t *testing.T) (*http.Client, *record.Client, *record.RedirectURI, *record.User) {
	client := &record.Client{
		ClientIdentifier:         "test-client-" + fake.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          false,
		DefaultAcrLevel:          record.AcrLevel1,
	}

	err := database.CreateClient(context.Background(), nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &record.RedirectURI{
		ClientId: client.Id,
		URI:      fake.URL(),
	}

	err = database.CreateRedirectURI(context.Background(), nil, redirectUri)
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

	requestCodeChallenge := fake.LetterN(43)
	requestState := fake.LetterN(8)
	requestNonce := fake.LetterN(8)
	requestScope := "openid profile email"

	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
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
	assert.Equal(t, record.AcrLevel1, code.AcrLevel)
	assert.Equal(t, oidc.AuthMethodPassword.String(), code.AuthMethods)
	assert.False(t, code.Used)

	return httpClient, client, redirectUri, user
}

func createSessionWithAcrLevel2Optional(t *testing.T) (*http.Client, *record.Client, *record.RedirectURI, *record.User) {
	client := &record.Client{
		ClientIdentifier:         "test-client-" + fake.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          false,
		DefaultAcrLevel:          record.AcrLevel2Optional,
	}

	err := database.CreateClient(context.Background(), nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &record.RedirectURI{
		ClientId: client.Id,
		URI:      fake.URL(),
	}

	err = database.CreateRedirectURI(context.Background(), nil, redirectUri)
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

	requestCodeChallenge := fake.LetterN(43)
	requestState := fake.LetterN(8)
	requestNonce := fake.LetterN(8)
	requestScope := "openid profile email"

	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
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
	assert.Equal(t, record.AcrLevel2Optional, code.AcrLevel)
	assert.Equal(t, oidc.AuthMethodPassword.String(), code.AuthMethods)
	assert.False(t, code.Used)

	return httpClient, client, redirectUri, user
}

func createSessionWithAcrLevel2Mandatory(t *testing.T) (*http.Client, *record.Client, *record.RedirectURI, *record.User) {
	client := &record.Client{
		ClientIdentifier:         "test-client-" + fake.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          false,
		DefaultAcrLevel:          record.AcrLevel2Mandatory,
	}

	err := database.CreateClient(context.Background(), nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &record.RedirectURI{
		ClientId: client.Id,
		URI:      fake.URL(),
	}

	err = database.CreateRedirectURI(context.Background(), nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	password := fake.Password(8)
	passwordHashed, err := passwordhash.Hash(password)
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

	user := &record.User{
		Subject:            fake.UUID(),
		Enabled:            true,
		Email:              fake.Email(),
		PasswordHash:       passwordHashed,
		OTPSecretEncrypted: encryptOTPSecretForTest(t, key.Secret()),
		OTPEnabled:         true,
	}

	err = database.CreateUser(context.Background(), nil, user)
	if err != nil {
		t.Fatal(err)
	}

	requestCodeChallenge := fake.LetterN(43)
	requestState := fake.LetterN(8)
	requestNonce := fake.LetterN(8)
	requestScope := "openid profile email"

	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
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

	otpCode, err := totp.GenerateCode(key.Secret(), time.Now())
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
	assert.Equal(t, record.AcrLevel2Mandatory, code.AcrLevel)
	assert.Equal(t, fmt.Sprintf("%s %s", oidc.AuthMethodPassword.String(), oidc.AuthMethodOTP.String()), code.AuthMethods)
	assert.False(t, code.Used)

	return httpClient, client, redirectUri, user
}

// encryptOTPSecretForTest encrypts a TOTP secret with the server's AES key, so a
// test can persist a user whose OTP secret is stored the way production stores
// it (issue #82: encrypted at rest). Set the result on user.OTPSecretEncrypted,
// which is the only column a seed lives in since migration 000048 dropped
// users.otp_secret (#98), and keep the plaintext in a local for generating codes.
func encryptOTPSecretForTest(t *testing.T, plain string) []byte {
	enc, err := dataCipher.Encrypt(plain)
	assert.NoError(t, err)
	return enc
}

// authCodeOptions varies the client and the ceremony createAuthCode runs. Its ZERO VALUE is
// createAuthCode's original behaviour, a confidential client running a PKCE ceremony, so the
// existing call sites pass nothing and are unaffected (#245).
//
// noPKCE has a precondition the caller owns: the seeded Settings.PKCERequired is true, so a
// challenge-less ceremony is refused at /auth/authorize unless pkceRequired is also set to
// false. That is deliberate rather than inferred here, because the two together are exactly
// the misconfiguration the tests are about.
type authCodeOptions struct {
	isPublic     bool
	noPKCE       bool
	pkceRequired *bool
	// user and userPassword run the ceremony as an EXISTING user instead of a freshly created
	// one. Both are required together, because the ceremony goes through the real password form.
	// Their purpose is a fixture no single call can build: one user holding grants on two
	// different clients, which is what proves a client-scoped revocation leaves the user's other
	// clients alone (#245, D2).
	user         *record.User
	userPassword string
	// userAgent runs the ceremony as a different DEVICE. Two ceremonies for one user from the
	// default client replace each other's session, because the server treats the same user on
	// the same device as one session, so a fixture wanting two live sessions has to say which
	// is which. This is the same trick secondSessionFor uses.
	userAgent string
}

func createAuthCode(t *testing.T, clientSecret string, scope string, opts ...authCodeOptions) (*http.Client, *record.Code) {

	var opt authCodeOptions
	if len(opts) > 0 {
		opt = opts[0]
	}

	clientSecretEncrypted, err := dataCipher.Encrypt(clientSecret)
	require.NoError(t, err)

	client := &record.Client{
		ClientIdentifier:         "test-client-" + fake.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		IsPublic:                 opt.isPublic,
		ConsentRequired:          false,
		DefaultAcrLevel:          record.AcrLevel2Optional,
		ClientSecretEncrypted:    clientSecretEncrypted,
		PKCERequired:             opt.pkceRequired,
	}
	if opt.isPublic {
		// A public client holds no secret. Leaving the encrypted one on the row would be a
		// fixture that cannot occur in production, and the flip deletes it for that reason.
		client.ClientSecretEncrypted = nil
	}

	err = database.CreateClient(context.Background(), nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &record.RedirectURI{
		ClientId: client.Id,
		URI:      fake.URL(),
	}

	err = database.CreateRedirectURI(context.Background(), nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	password := opt.userPassword
	user := opt.user
	if user == nil {
		password = fake.Password(8)
		passwordHashed, createErr := passwordhash.Hash(password)
		if createErr != nil {
			t.Fatal(createErr)
		}

		user = &record.User{
			Subject:      fake.UUID(),
			Enabled:      true,
			Email:        fake.Email(),
			PasswordHash: passwordHashed,
		}

		createErr = database.CreateUser(context.Background(), nil, user)
		if createErr != nil {
			t.Fatal(createErr)
		}
	}

	codeVerifier := testCodeVerifier
	requestCodeChallenge := oauth.GeneratePKCECodeChallenge(codeVerifier)
	requestState := fake.LetterN(8)
	requestNonce := fake.LetterN(8)

	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code"
	if !opt.noPKCE {
		destUrl += "&code_challenge_method=S256" +
			"&code_challenge=" + requestCodeChallenge
	}
	destUrl += "&scope=" + url.QueryEscape(scope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHttpClient(t)
	if opt.userAgent != "" {
		httpClient = createHttpClientWithUserAgent(t, opt.userAgent)
	}

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
	code.Code = codeVal
	return httpClient, code
}

// createAuthCodeEnsuringUserScope creates a confidential client and a user, grants the user
// all custom resource:permission scopes contained in the provided scope string, then runs the
// authorization code flow to issue a code for that user and returns (httpClient, code).
// It guarantees custom scopes survive filtering and end up in the token if requested.
func createAuthCodeEnsuringUserScope(t *testing.T, clientSecret string, scope string) (*http.Client, *record.Code) {

	clientSecretEncrypted, err := dataCipher.Encrypt(clientSecret)
	require.NoError(t, err)

	// Allowed to request the administrative scopes when the scope names one, as an operator allows a
	// client that legitimately needs them: the tests minting an administrative user token through
	// this fixture are about what the token does, not about which client may obtain one (#499).
	administrative := slices.ContainsFunc(strings.Split(scope, " "), permissions.IsAdministrativeScope)
	client := &record.Client{
		ClientIdentifier:            "acctscope-client-" + fake.LetterN(8),
		Enabled:                     true,
		AuthorizationCodeEnabled:    true,
		IsPublic:                    false,
		ConsentRequired:             false,
		DefaultAcrLevel:             record.AcrLevel2Optional,
		ClientSecretEncrypted:       clientSecretEncrypted,
		AdministrativeScopesAllowed: administrative,
	}

	err = database.CreateClient(context.Background(), nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &record.RedirectURI{ClientId: client.Id, URI: fake.URL()}
	err = database.CreateRedirectURI(context.Background(), nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	// Create a user and pre-grant all custom resource scopes requested
	password := fake.Password(10)
	passwordHashed, err := passwordhash.Hash(password)
	if err != nil {
		t.Fatal(err)
	}

	user := &record.User{Subject: fake.UUID(), Enabled: true, Email: fake.Email(), PasswordHash: passwordHashed}
	err = database.CreateUser(context.Background(), nil, user)
	if err != nil {
		t.Fatal(err)
	}

	scopes := strings.Split(scope, " ")
	for _, s := range scopes {
		if s == "" || oidc.IsClaimScope(s) || oidc.IsOfflineAccessScope(s) {
			continue
		}
		parts := strings.Split(s, ":")
		if len(parts) != 2 {
			t.Fatalf("invalid scope format in helper: %s", s)
		}
		resourceIdentifier := parts[0]
		permissionIdentifier := parts[1]

		resource, grantErr := database.GetResourceByResourceIdentifier(context.Background(), nil, resourceIdentifier)
		if grantErr != nil {
			t.Fatal(grantErr)
		}
		if resource == nil {
			t.Fatalf("resource not found: %s", resourceIdentifier)
		}

		perms, grantErr := database.GetPermissionsByResourceId(context.Background(), nil, resource.Id)
		if grantErr != nil {
			t.Fatal(grantErr)
		}
		var sel *record.Permission
		for i := range perms {
			if perms[i].PermissionIdentifier == permissionIdentifier {
				sel = &perms[i]
				break
			}
		}
		if sel == nil {
			t.Fatalf("permission not found: %s:%s", resourceIdentifier, permissionIdentifier)
		}
		grantErr = database.CreateUserPermission(context.Background(), nil, &record.UserPermission{UserId: user.Id, PermissionId: sel.Id})
		if grantErr != nil {
			t.Fatal(grantErr)
		}
	}

	codeVerifier := testCodeVerifier
	requestCodeChallenge := oauth.GeneratePKCECodeChallenge(codeVerifier)
	requestState := fake.LetterN(8)
	requestNonce := fake.LetterN(8)

	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
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
	code.Code = codeVal
	return httpClient, code
}

// Helper function to create a test resource
func createTestResource(t *testing.T, identifier, description string) *record.Resource {
	resource := &record.Resource{
		ResourceIdentifier: identifier,
		Description:        description,
	}
	err := database.CreateResource(context.Background(), nil, resource)
	assert.NoError(t, err)
	return resource
}

// deleteTestUsers removes fixture users and reports a delete that did nothing.
//
// The tier's older idiom was `_ = database.DeleteUser(context.Background(), nil, user.Id)`, which
// hides the two ways a cleanup silently fails to clean up: an insert that never
// happened leaves Id == 0, so the delete matches no row, and an engine that
// refuses the delete says so only in the error. Either way the rows stay, and
// with them every later fixture that reuses an address.
func deleteTestUsers(t *testing.T, users []*record.User) {
	t.Helper()
	for _, user := range users {
		if user == nil {
			continue
		}
		assert.NotZero(t, user.Id, "fixture user %q was never created, so cleanup cannot delete it", user.Email)
		assert.NoError(t, database.DeleteUser(context.Background(), nil, user.Id), "unable to delete fixture user %q", user.Email)
	}
}

// uniqueEmail inserts a random run into addr's local part, so a fixture address
// stays readable in a leftover row while no two calls of it can collide.
//
// It exists because this tier's fixtures spell their addresses as descriptive
// literals, and a literal is only safe while every row carrying it is deleted
// again. run-tests.sh drops the sqlite file on exit, but goiabada_integration on
// mysql, postgres and mssql is never dropped, so one leaked row there fails the
// same test on every run after it, with a UNIQUE violation raised from a fixture
// rather than from the behaviour under test.
func uniqueEmail(addr string) string {
	local, domain, found := strings.Cut(addr, "@")
	if !found {
		panic("uniqueEmail: " + addr + " is not an address")
	}
	// The API rejects an address over 60 bytes (accountvalidation.EmailValidator), and
	// fixtures reach that endpoint, so the run added here is short and the
	// longest address in the tier stays well inside the limit.
	return local + "-" + strings.ToLower(fake.LetterN(8)) + "@" + domain
}

// Helper function to create a test group
func createTestGroup(t *testing.T) *record.Group {
	group := &record.Group{
		GroupIdentifier:      "test-group-" + fake.UUID()[:8],
		Description:          "Test Group",
		IncludeInIdToken:     true,
		IncludeInAccessToken: false,
	}
	err := database.CreateGroup(context.Background(), nil, group)
	assert.NoError(t, err)
	return group
}

// Helper function to create a test permission
func createTestPermission(t *testing.T, resourceId int64, identifier, description string) *record.Permission {
	permission := &record.Permission{
		ResourceId:           resourceId,
		PermissionIdentifier: identifier,
		Description:          description,
	}
	err := database.CreatePermission(context.Background(), nil, permission)
	assert.NoError(t, err)
	return permission
}

// ============================================================================
// Client Display Testing Helpers
// ============================================================================

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
	DefaultAcrLevel  record.AcrLevel
}

// createClientWithDisplaySettings creates a client with specified display settings
// and optional logo upload. Returns the created client.
func createClientWithDisplaySettings(t *testing.T, settings ClientDisplaySettings) *record.Client {
	client := &record.Client{
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

	err := database.CreateClient(context.Background(), nil, client)
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

		clientLogo := &record.ClientLogo{
			ClientId: client.Id,
			Logo:     logoData,
		}

		err = database.CreateClientLogo(context.Background(), nil, clientLogo)
		if err != nil {
			t.Fatal(err)
		}
	}

	return client
}
