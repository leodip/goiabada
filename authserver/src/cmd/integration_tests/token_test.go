package integrationtests

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	core_token "github.com/leodip/goiabada/internal/core/token"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/stretchr/testify/assert"
)

func TestToken_MissingClientId(t *testing.T) {
	setup()

	destUrl := lib.GetBaseUrl() + "/auth/token"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	formData := url.Values{}
	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_request", data["error"])
	assert.Equal(t, "Missing required client_id parameter.", data["error_description"])
}

func TestToken_ClientDoesNotExist(t *testing.T) {
	setup()

	destUrl := lib.GetBaseUrl() + "/auth/token"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	formData := url.Values{
		"client_id": {"invalid"},
	}
	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_request", data["error"])
	assert.Equal(t, "Client does not exist.", data["error_description"])
}

func TestToken_InvalidGrantType(t *testing.T) {
	setup()

	destUrl := lib.GetBaseUrl() + "/auth/token"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	formData := url.Values{
		"client_id":  {"test-client-1"},
		"grant_type": {"invalid"},
	}
	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "unsupported_grant_type", data["error"])
	assert.Equal(t, "Unsupported grant_type.", data["error_description"])
}

func TestToken_AuthCode_MissingCode(t *testing.T) {
	setup()

	destUrl := lib.GetBaseUrl() + "/auth/token"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	formData := url.Values{
		"client_id":  {"test-client-1"},
		"grant_type": {"authorization_code"},
	}
	respData := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_request", respData["error"])
	assert.Equal(t, "Missing required code parameter.", respData["error_description"])
}

func TestToken_AuthCode_MissingRedirectURI(t *testing.T) {
	setup()
	code, httpClient := createAuthCode(t, "openid profile email backend-svcA:read-product offline_access")

	destUrl := lib.GetBaseUrl() + "/auth/token"

	formData := url.Values{
		"client_id":  {"test-client-1"},
		"grant_type": {"authorization_code"},
		"code":       {code.Code},
	}
	respData := postToTokenEndpoint(t, httpClient, destUrl, formData)
	assert.Equal(t, "invalid_request", respData["error"])
	assert.Equal(t, "Missing required redirect_uri parameter.", respData["error_description"])
}

func TestToken_AuthCode_MissingCodeVerifier(t *testing.T) {
	setup()
	code, httpClient := createAuthCode(t, "openid profile email backend-svcA:read-product offline_access")

	destUrl := lib.GetBaseUrl() + "/auth/token"

	formData := url.Values{
		"client_id":    {"test-client-1"},
		"grant_type":   {"authorization_code"},
		"redirect_uri": {code.RedirectURI},
		"code":         {code.Code},
	}
	respData := postToTokenEndpoint(t, httpClient, destUrl, formData)
	assert.Equal(t, "invalid_request", respData["error"])
	assert.Equal(t, "Missing required code_verifier parameter.", respData["error_description"])
}

func TestToken_AuthCode_InvalidClient(t *testing.T) {
	setup()
	code, httpClient := createAuthCode(t, "openid profile email backend-svcA:read-product offline_access")

	destUrl := lib.GetBaseUrl() + "/auth/token"

	formData := url.Values{
		"client_id":     {"invalid"},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {code.RedirectURI},
		"code":          {code.Code},
		"code_verifier": {"DdazqdVNuDmRLGGRGQKKehEaoFeatACtNsM2UYGwuHkhBhDsTSzaCqWttcBc0kGx"},
	}
	respData := postToTokenEndpoint(t, httpClient, destUrl, formData)
	assert.Equal(t, "invalid_request", respData["error"])
	assert.Equal(t, "Client does not exist.", respData["error_description"])
}

func TestToken_AuthCode_CodeIsInvalid(t *testing.T) {
	setup()
	code, httpClient := createAuthCode(t, "openid profile email backend-svcA:read-product offline_access")

	destUrl := lib.GetBaseUrl() + "/auth/token"

	formData := url.Values{
		"client_id":     {"test-client-1"},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {code.RedirectURI},
		"code":          {"invalid"},
		"code_verifier": {"DdazqdVNuDmRLGGRGQKKehEaoFeatACtNsM2UYGwuHkhBhDsTSzaCqWttcBc0kGx"},
	}
	respData := postToTokenEndpoint(t, httpClient, destUrl, formData)
	assert.Equal(t, "invalid_grant", respData["error"])
	assert.Equal(t, "Code is invalid.", respData["error_description"])
}

func TestToken_AuthCode_RedirectURIIsInvalid(t *testing.T) {
	setup()
	code, httpClient := createAuthCode(t, "openid profile email backend-svcA:read-product offline_access")

	destUrl := lib.GetBaseUrl() + "/auth/token"

	formData := url.Values{
		"client_id":     {"test-client-1"},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {"invalid"},
		"code":          {code.Code},
		"code_verifier": {"DdazqdVNuDmRLGGRGQKKehEaoFeatACtNsM2UYGwuHkhBhDsTSzaCqWttcBc0kGx"},
	}
	respData := postToTokenEndpoint(t, httpClient, destUrl, formData)
	assert.Equal(t, "invalid_grant", respData["error"])
	assert.Equal(t, "Invalid redirect_uri.", respData["error_description"])
}

func TestToken_AuthCode_WrongClient(t *testing.T) {
	setup()
	code, httpClient := createAuthCode(t, "openid profile email backend-svcA:read-product offline_access")

	destUrl := lib.GetBaseUrl() + "/auth/token"

	formData := url.Values{
		"client_id":     {"test-client-2"},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {code.RedirectURI},
		"code":          {code.Code},
		"code_verifier": {"DdazqdVNuDmRLGGRGQKKehEaoFeatACtNsM2UYGwuHkhBhDsTSzaCqWttcBc0kGx"},
	}
	respData := postToTokenEndpoint(t, httpClient, destUrl, formData)
	assert.Equal(t, "invalid_grant", respData["error"])
	assert.Equal(t, "The client_id provided does not match the client_id from code.", respData["error_description"])
}

func TestToken_AuthCode_ConfidentialClient_NoClientSecret(t *testing.T) {
	setup()
	code, httpClient := createAuthCode(t, "openid profile email backend-svcA:read-product offline_access")

	destUrl := lib.GetBaseUrl() + "/auth/token"

	formData := url.Values{
		"client_id":     {"test-client-1"},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {code.RedirectURI},
		"code":          {code.Code},
		"code_verifier": {"DdazqdVNuDmRLGGRGQKKehEaoFeatACtNsM2UYGwuHkhBhDsTSzaCqWttcBc0kGx"},
	}
	respData := postToTokenEndpoint(t, httpClient, destUrl, formData)
	assert.Equal(t, "invalid_request", respData["error"])
	assert.Equal(t, "This client is configured as confidential (not public), which means a client_secret is required for authentication. Please provide a valid client_secret to proceed.", respData["error_description"])
}

func TestToken_AuthCode_ConfidentialClient_ClientAuthFailed(t *testing.T) {
	setup()
	code, httpClient := createAuthCode(t, "openid profile email backend-svcA:read-product offline_access")

	destUrl := lib.GetBaseUrl() + "/auth/token"

	formData := url.Values{
		"client_id":     {"test-client-1"},
		"client_secret": {"invalid"},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {code.RedirectURI},
		"code":          {code.Code},
		"code_verifier": {"DdazqdVNuDmRLGGRGQKKehEaoFeatACtNsM2UYGwuHkhBhDsTSzaCqWttcBc0kGx"},
	}
	respData := postToTokenEndpoint(t, httpClient, destUrl, formData)
	assert.Equal(t, "invalid_grant", respData["error"])
	assert.Equal(t, "Client authentication failed. Please review your client_secret.", respData["error_description"])
}

func TestToken_AuthCode_InvalidCodeVerifier(t *testing.T) {
	setup()
	code, httpClient := createAuthCode(t, "openid profile email backend-svcA:read-product offline_access")

	destUrl := lib.GetBaseUrl() + "/auth/token"

	clientSecret := getClientSecret(t, "test-client-1")

	formData := url.Values{
		"client_id":     {"test-client-1"},
		"client_secret": {clientSecret},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {code.RedirectURI},
		"code":          {code.Code},
		"code_verifier": {"invalid"},
	}
	respData := postToTokenEndpoint(t, httpClient, destUrl, formData)
	assert.Equal(t, "invalid_grant", respData["error"])
	assert.Equal(t, "Invalid code_verifier (PKCE).", respData["error_description"])
}

func TestToken_AuthCode_SuccessPath(t *testing.T) {
	setup()
	scope := "openid profile email phone address offline_access groups backend-svcA:read-product backend-svcB:write-info"
	code, httpClient := createAuthCode(t, scope)

	destUrl := lib.GetBaseUrl() + "/auth/token"

	clientSecret := getClientSecret(t, "test-client-1")

	formData := url.Values{
		"client_id":     {"test-client-1"},
		"client_secret": {clientSecret},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {code.RedirectURI},
		"code":          {code.Code},
		"code_verifier": {"DdazqdVNuDmRLGGRGQKKehEaoFeatACtNsM2UYGwuHkhBhDsTSzaCqWttcBc0kGx"},
	}
	respData := postToTokenEndpoint(t, httpClient, destUrl, formData)

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "Bearer", respData["token_type"])
	assert.Equal(t, float64(settings.TokenExpirationInSeconds), respData["expires_in"])
	assert.Equal(t, float64(settings.RefreshTokenOfflineIdleTimeoutInSeconds), respData["refresh_expires_in"])
	assert.Equal(t, scope+" authserver:userinfo", respData["scope"])
	assert.NotEmpty(t, respData["access_token"])
	assert.NotEmpty(t, respData["id_token"])
	assert.NotEmpty(t, respData["refresh_token"])

	tokenResponse := &dtos.TokenResponse{
		AccessToken:      respData["access_token"].(string),
		IdToken:          respData["id_token"].(string),
		TokenType:        respData["token_type"].(string),
		ExpiresIn:        int64(respData["expires_in"].(float64)),
		RefreshToken:     respData["refresh_token"].(string),
		RefreshExpiresIn: int64(respData["refresh_expires_in"].(float64)),
		Scope:            respData["scope"].(string),
	}

	tokenParser := core_token.NewTokenParser(database)

	// validate signature
	jwt, err := tokenParser.ParseTokenResponse(context.Background(), tokenResponse)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, jwt.AccessToken != nil && jwt.AccessToken.SignatureIsValid)
	assert.True(t, jwt.IdToken != nil && jwt.IdToken.SignatureIsValid)
	assert.True(t, jwt.RefreshToken != nil && jwt.RefreshToken.SignatureIsValid)

	// validate claims (access token)
	assert.Equal(t, settings.Issuer, jwt.AccessToken.GetStringClaim("iss"))
	assert.Equal(t, code.User.Subject.String(), jwt.AccessToken.GetStringClaim("sub"))

	issuedAt := jwt.AccessToken.GetTimeClaim("iat")
	assert.False(t, issuedAt.IsZero())
	assert.True(t, issuedAt.Add(time.Second*10).After(time.Now().UTC()))

	authTime := jwt.AccessToken.GetTimeClaim("auth_time")
	assert.False(t, authTime.IsZero())
	assertTimeWithinRange(t, time.Now().UTC(), authTime, 10)

	assert.True(t, len(jwt.AccessToken.GetStringClaim("jti")) > 0)
	assert.Equal(t, code.AcrLevel, jwt.AccessToken.GetStringClaim("acr"))
	assert.Equal(t, code.AuthMethods, jwt.AccessToken.GetStringClaim("amr"))
	assert.Equal(t, code.SessionIdentifier, jwt.AccessToken.GetStringClaim("sid"))

	aud := jwt.AccessToken.GetAudience()
	assert.Len(t, aud, 3)
	assert.Equal(t, "authserver", aud[0])
	assert.Equal(t, "backend-svcA", aud[1])
	assert.Equal(t, "backend-svcB", aud[2])

	assert.Equal(t, "Bearer", jwt.AccessToken.GetStringClaim("typ"))

	utcNow := time.Now().UTC()
	expectedExp := utcNow.Add(time.Duration(time.Second * time.Duration(settings.TokenExpirationInSeconds)))
	assertTimeWithinRange(t, expectedExp, jwt.AccessToken.GetTimeClaim("exp").UTC(), 10)

	assert.Equal(t, scope+" authserver:userinfo", jwt.AccessToken.GetStringClaim("scope"))

	// validate claims (id token)
	assert.Equal(t, settings.Issuer, jwt.IdToken.GetStringClaim("iss"))
	assert.Equal(t, code.User.Subject.String(), jwt.IdToken.GetStringClaim("sub"))

	issuedAt = jwt.IdToken.GetTimeClaim("iat")
	assert.False(t, issuedAt.IsZero())
	assert.True(t, issuedAt.Add(time.Second*10).After(time.Now().UTC()))

	authTime = jwt.IdToken.GetTimeClaim("auth_time")
	assert.False(t, authTime.IsZero())
	assertTimeWithinRange(t, time.Now().UTC(), authTime, 10)

	assert.True(t, len(jwt.IdToken.GetStringClaim("jti")) > 0)
	assert.Equal(t, code.AcrLevel, jwt.IdToken.GetStringClaim("acr"))
	assert.Equal(t, code.AuthMethods, jwt.IdToken.GetStringClaim("amr"))
	assert.Equal(t, code.SessionIdentifier, jwt.IdToken.GetStringClaim("sid"))

	aud = jwt.IdToken.GetAudience()
	assert.Len(t, aud, 1)
	assert.Equal(t, "test-client-1", aud[0])

	assert.Equal(t, "ID", jwt.IdToken.GetStringClaim("typ"))

	expectedExp = utcNow.Add(time.Duration(time.Second * time.Duration(settings.TokenExpirationInSeconds)))
	assertTimeWithinRange(t, expectedExp, jwt.IdToken.GetTimeClaim("exp").UTC(), 10)
	jwt.IdToken.IsNonceValid(code.Nonce)

	assert.Equal(t, code.User.GetFullName(), jwt.IdToken.GetStringClaim("name"))
	assert.Equal(t, code.User.GivenName, jwt.IdToken.GetStringClaim("given_name"))
	assert.Equal(t, code.User.FamilyName, jwt.IdToken.GetStringClaim("family_name"))
	assert.Equal(t, code.User.MiddleName, jwt.IdToken.GetStringClaim("middle_name"))
	assert.Equal(t, code.User.Nickname, jwt.IdToken.GetStringClaim("nickname"))
	assert.Equal(t, code.User.Username, jwt.IdToken.GetStringClaim("preferred_username"))
	assert.Equal(t, lib.GetBaseUrl()+"/account/profile", jwt.IdToken.GetStringClaim("profile"))
	assert.Equal(t, code.User.Website, jwt.IdToken.GetStringClaim("website"))
	assert.Equal(t, code.User.Gender, jwt.IdToken.GetStringClaim("gender"))
	assert.Equal(t, code.User.BirthDate.Time.Format("2006-01-02"), jwt.IdToken.GetStringClaim("birthdate"))
	assert.Equal(t, code.User.ZoneInfo, jwt.IdToken.GetStringClaim("zoneinfo"))
	assert.Equal(t, code.User.Locale, jwt.IdToken.GetStringClaim("locale"))
	assertTimeWithinRange(t, code.User.UpdatedAt.Time, jwt.IdToken.GetTimeClaim("updated_at"), 10)

	assert.Equal(t, code.User.Email, jwt.IdToken.GetStringClaim("email"))
	emailVerified := jwt.IdToken.GetBoolClaim("email_verified")
	assert.NotNil(t, emailVerified)
	assert.True(t, *emailVerified)

	addressFromClaim := jwt.IdToken.GetAddressClaim()
	assert.Len(t, addressFromClaim, 6)

	addressFromUser := code.User.GetAddressClaim()
	assert.Equal(t, addressFromUser["street_address"], addressFromClaim["street_address"])
	assert.Equal(t, addressFromUser["locality"], addressFromClaim["locality"])
	assert.Equal(t, addressFromUser["region"], addressFromClaim["region"])
	assert.Equal(t, addressFromUser["postal_code"], addressFromClaim["postal_code"])
	assert.Equal(t, addressFromUser["country"], addressFromClaim["country"])
	assert.Equal(t, addressFromUser["formatted"], addressFromClaim["formatted"])

	assert.Equal(t, code.User.PhoneNumber, jwt.IdToken.GetStringClaim("phone_number"))
	phoneVerified := jwt.IdToken.GetBoolClaim("phone_number_verified")
	assert.NotNil(t, phoneVerified)
	assert.True(t, *phoneVerified)
}

func TestToken_ClientCred_FlowIsNotEnabled(t *testing.T) {
	setup()

	destUrl := lib.GetBaseUrl() + "/auth/token"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	formData := url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {"test-client-2"},
	}
	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "unauthorized_client", data["error"])
	assert.Equal(t, "The client associated with the provided client_id does not support client credentials flow.", data["error_description"])
}

func TestToken_ClientCred_NoClientSecret(t *testing.T) {
	setup()
	destUrl := lib.GetBaseUrl() + "/auth/token"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	formData := url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {"test-client-1"},
	}
	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_request", data["error"])
	assert.Equal(t, "This client is configured as confidential (not public), which means a client_secret is required for authentication. Please provide a valid client_secret to proceed.", data["error_description"])
}

func TestToken_ClientCred_ClientAuthFailed(t *testing.T) {
	setup()
	destUrl := lib.GetBaseUrl() + "/auth/token"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	formData := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"test-client-1"},
		"client_secret": {"invalid"},
	}
	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_client", data["error"])
	assert.Equal(t, "Client authentication failed.", data["error_description"])
}

func TestToken_ClientCred_InvalidScope(t *testing.T) {

	testCases := []struct {
		scope            string
		errorCode        string
		errorDescription string
	}{
		{
			scope:            "openid",
			errorCode:        "invalid_request",
			errorDescription: "Id token scopes (such as 'openid') are not supported in the client credentials flow. Please use scopes in the format 'resource:permission' (e.g., 'backendA:read'). Multiple scopes can be specified, separated by spaces.",
		},
		{
			scope:            "groups",
			errorCode:        "invalid_request",
			errorDescription: "Id token scopes (such as 'groups') are not supported in the client credentials flow. Please use scopes in the format 'resource:permission' (e.g., 'backendA:read'). Multiple scopes can be specified, separated by spaces.",
		},
		{
			scope:            "aaa",
			errorCode:        "invalid_scope",
			errorDescription: "Invalid scope format: 'aaa'. Scopes must adhere to the resource-identifier:permission-identifier format. For instance: backend-service:create-product.",
		},
		{
			scope:            "invalid:perm",
			errorCode:        "invalid_scope",
			errorDescription: "Invalid scope: 'invalid:perm'. Could not find a resource with identifier 'invalid'.",
		},
		{
			scope:            "backend-svcA:perm",
			errorCode:        "invalid_scope",
			errorDescription: "Scope 'backend-svcA:perm' is not recognized. The resource identified by 'backend-svcA' doesn't grant the 'perm' permission.",
		},
		{
			scope:            "backend-svcA:read-product",
			errorCode:        "invalid_scope",
			errorDescription: "Permission to access scope 'backend-svcA:read-product' is not granted to the client.",
		},
	}

	setup()
	destUrl := lib.GetBaseUrl() + "/auth/token"

	for _, testCase := range testCases {
		httpClient := createHttpClient(&createHttpClientInput{
			T: t,
		})

		clientSecret := getClientSecret(t, "test-client-1")
		formData := url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {"test-client-1"},
			"client_secret": {clientSecret},
			"scope":         {testCase.scope},
		}
		data := postToTokenEndpoint(t, httpClient, destUrl, formData)

		assert.Equal(t, testCase.errorCode, data["error"])
		assert.Equal(t, testCase.errorDescription, data["error_description"])
	}
}

func TestToken_ClientCred_NoScopesGiven(t *testing.T) {
	setup()
	destUrl := lib.GetBaseUrl() + "/auth/token"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	clientSecret := getClientSecret(t, "test-client-1")
	formData := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"test-client-1"},
		"client_secret": {clientSecret},
	}
	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	// when no scopes are requried, it will include all scopes that the client has access to

	scope := data["scope"].(string)
	parts := strings.Split(scope, " ")
	assert.Equal(t, 2, len(parts))
	assert.Equal(t, "backend-svcA:create-product", parts[0])
	assert.Equal(t, "backend-svcB:read-info", parts[1])
}

func TestToken_ClientCred_SpecificScope(t *testing.T) {
	setup()
	destUrl := lib.GetBaseUrl() + "/auth/token"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	clientSecret := getClientSecret(t, "test-client-1")
	formData := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"test-client-1"},
		"client_secret": {clientSecret},
		"scope":         {"backend-svcA:create-product"},
	}
	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	scope := data["scope"].(string)
	parts := strings.Split(scope, " ")
	assert.Equal(t, 1, len(parts))
	assert.Equal(t, "backend-svcA:create-product", parts[0])
}

func TestToken_Refresh_ConfidentialClient_NoClientSecret(t *testing.T) {
	setup()
	destUrl := lib.GetBaseUrl() + "/auth/token"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	formData := url.Values{
		"grant_type": {"refresh_token"},
		"client_id":  {"test-client-1"},
	}
	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_request", data["error"])
	assert.Equal(t, "This client is configured as confidential (not public), which means a client_secret is required for authentication. Please provide a valid client_secret to proceed.", data["error_description"])
}

func TestToken_Refresh_ConfidentialClient_ClientAuthFailed(t *testing.T) {
	setup()

	destUrl := lib.GetBaseUrl() + "/auth/token"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	formData := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {"test-client-1"},
		"client_secret": {"invalid"},
	}
	respData := postToTokenEndpoint(t, httpClient, destUrl, formData)
	assert.Equal(t, "invalid_grant", respData["error"])
	assert.Equal(t, "Client authentication failed. Please review your client_secret.", respData["error_description"])
}

func TestToken_Refresh_MissingRefreshToken(t *testing.T) {
	setup()

	destUrl := lib.GetBaseUrl() + "/auth/token"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	clientSecret := getClientSecret(t, "test-client-1")

	formData := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {"test-client-1"},
		"client_secret": {clientSecret},
	}
	respData := postToTokenEndpoint(t, httpClient, destUrl, formData)
	assert.Equal(t, "invalid_request", respData["error"])
	assert.Equal(t, "Missing required refresh_token parameter.", respData["error_description"])
}

func TestToken_Refresh_TokenWithBadSignature(t *testing.T) {
	setup()

	destUrl := lib.GetBaseUrl() + "/auth/token"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	clientSecret := getClientSecret(t, "test-client-1")

	claims := make(jwt.MapClaims)

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	refreshTokenExpirationInSeconds := settings.UserSessionIdleTimeoutInSeconds

	jti := uuid.New().String()
	exp := now.Add(time.Duration(time.Second * time.Duration(refreshTokenExpirationInSeconds)))
	claims["iss"] = settings.Issuer
	claims["iat"] = now.Unix()
	claims["jti"] = jti
	claims["aud"] = settings.Issuer
	claims["typ"] = enums.TokenTypeRefresh.String()
	claims["exp"] = exp.Unix()
	keyPair := createNewKeyPair(t)
	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyPair.PrivateKeyPEM)
	if err != nil {
		t.Fatal("unable to parse private key from PEM")
	}
	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(privKey)
	if err != nil {
		t.Fatal("unable to sign refresh_token")
	}

	formData := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {"test-client-1"},
		"client_secret": {clientSecret},
		"refresh_token": {refreshToken},
	}
	respData := postToTokenEndpoint(t, httpClient, destUrl, formData)
	assert.Equal(t, "invalid_grant", respData["error"])
	assert.Contains(t, respData["error_description"], "token signature is invalid")
}

func TestToken_Refresh_TokenExpired(t *testing.T) {
	setup()

	destUrl := lib.GetBaseUrl() + "/auth/token"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	clientSecret := getClientSecret(t, "test-client-1")

	claims := make(jwt.MapClaims)

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()

	jti := uuid.New().String()
	exp := now.AddDate(-5, 0, 0)
	claims["iss"] = settings.Issuer
	claims["iat"] = now.Unix()
	claims["jti"] = jti
	claims["aud"] = settings.Issuer
	claims["typ"] = enums.TokenTypeRefresh.String()
	claims["exp"] = exp.Unix()
	keyPair, err := database.GetCurrentSigningKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyPair.PrivateKeyPEM)
	if err != nil {
		t.Fatal("unable to parse private key from PEM")
	}
	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(privKey)
	if err != nil {
		t.Fatal("unable to sign refresh_token")
	}

	formData := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {"test-client-1"},
		"client_secret": {clientSecret},
		"refresh_token": {refreshToken},
	}
	respData := postToTokenEndpoint(t, httpClient, destUrl, formData)
	assert.Equal(t, "invalid_grant", respData["error"])
	assert.Contains(t, respData["error_description"], "token is expired")
}

func TestToken_Refresh_WrongClient(t *testing.T) {
	setup()
	scope := "openid profile email phone address offline_access groups backend-svcA:read-product backend-svcB:write-info"
	code, httpClient := createAuthCode(t, scope)

	destUrl := lib.GetBaseUrl() + "/auth/token"

	clientSecret := getClientSecret(t, "test-client-1")

	formData := url.Values{
		"client_id":     {"test-client-1"},
		"client_secret": {clientSecret},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {code.RedirectURI},
		"code":          {code.Code},
		"code_verifier": {"DdazqdVNuDmRLGGRGQKKehEaoFeatACtNsM2UYGwuHkhBhDsTSzaCqWttcBc0kGx"},
	}
	respData := postToTokenEndpoint(t, httpClient, destUrl, formData)

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "Bearer", respData["token_type"])
	assert.Equal(t, float64(settings.TokenExpirationInSeconds), respData["expires_in"])
	assert.Equal(t, float64(settings.RefreshTokenOfflineIdleTimeoutInSeconds), respData["refresh_expires_in"])
	assert.Equal(t, scope+" authserver:userinfo", respData["scope"])
	assert.NotEmpty(t, respData["access_token"])
	assert.NotEmpty(t, respData["id_token"])
	assert.NotEmpty(t, respData["refresh_token"])

	formData = url.Values{
		"client_id":     {"test-client-2"},
		"grant_type":    {"refresh_token"},
		"refresh_token": {respData["refresh_token"].(string)},
	}
	respData = postToTokenEndpoint(t, httpClient, destUrl, formData)
	assert.Equal(t, "invalid_request", respData["error"])
	assert.Equal(t, "The refresh token is invalid because it does not belong to the client.", respData["error_description"])
}

func TestToken_Refresh_WithAdditionalScope(t *testing.T) {
	setup()
	scope := "openid profile email phone address groups backend-svcA:read-product"
	code, httpClient := createAuthCode(t, scope)

	destUrl := lib.GetBaseUrl() + "/auth/token"

	clientSecret := getClientSecret(t, "test-client-1")

	formData := url.Values{
		"client_id":     {"test-client-1"},
		"client_secret": {clientSecret},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {code.RedirectURI},
		"code":          {code.Code},
		"code_verifier": {"DdazqdVNuDmRLGGRGQKKehEaoFeatACtNsM2UYGwuHkhBhDsTSzaCqWttcBc0kGx"},
	}
	respData := postToTokenEndpoint(t, httpClient, destUrl, formData)

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "Bearer", respData["token_type"])
	assert.Equal(t, float64(settings.TokenExpirationInSeconds), respData["expires_in"])
	assert.Equal(t, float64(settings.UserSessionIdleTimeoutInSeconds), respData["refresh_expires_in"])
	assert.Equal(t, scope+" authserver:userinfo", respData["scope"])
	assert.NotEmpty(t, respData["access_token"])
	assert.NotEmpty(t, respData["id_token"])
	assert.NotEmpty(t, respData["refresh_token"])

	formData = url.Values{
		"client_id":     {"test-client-1"},
		"client_secret": {clientSecret},
		"grant_type":    {"refresh_token"},
		"refresh_token": {respData["refresh_token"].(string)},
		"scope":         {"openid profile email phone address groups backend-svcA:read-product backend-svcB:write-info"},
	}
	respData = postToTokenEndpoint(t, httpClient, destUrl, formData)
	assert.Equal(t, "invalid_grant", respData["error"])
	assert.Equal(t, "Scope 'backend-svcB:write-info' is not recognized. The original access token does not grant the 'backend-svcB:write-info' permission.", respData["error_description"])
}

func TestToken_Refresh_ConsentRemoved(t *testing.T) {
	setup()
	scope := "openid profile email phone address groups backend-svcA:read-product backend-svcB:write-info"
	code, httpClient := createAuthCode(t, scope)

	destUrl := lib.GetBaseUrl() + "/auth/token"

	clientSecret := getClientSecret(t, "test-client-1")

	formData := url.Values{
		"client_id":     {"test-client-1"},
		"client_secret": {clientSecret},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {code.RedirectURI},
		"code":          {code.Code},
		"code_verifier": {"DdazqdVNuDmRLGGRGQKKehEaoFeatACtNsM2UYGwuHkhBhDsTSzaCqWttcBc0kGx"},
	}
	respData := postToTokenEndpoint(t, httpClient, destUrl, formData)

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "Bearer", respData["token_type"])
	assert.Equal(t, float64(settings.TokenExpirationInSeconds), respData["expires_in"])
	assert.Equal(t, float64(settings.UserSessionIdleTimeoutInSeconds), respData["refresh_expires_in"])
	assert.Equal(t, scope+" authserver:userinfo", respData["scope"])
	assert.NotEmpty(t, respData["access_token"])
	assert.NotEmpty(t, respData["id_token"])
	assert.NotEmpty(t, respData["refresh_token"])

	deleteAllUserConsents(t)

	formData = url.Values{
		"client_id":     {"test-client-1"},
		"client_secret": {clientSecret},
		"grant_type":    {"refresh_token"},
		"refresh_token": {respData["refresh_token"].(string)},
		"scope":         {"openid profile email phone address groups backend-svcA:read-product"},
	}
	respData = postToTokenEndpoint(t, httpClient, destUrl, formData)
	assert.Equal(t, "invalid_grant", respData["error"])
	assert.Equal(t, "The user has either not given consent to this client or the previously granted consent has been revoked.", respData["error_description"])
}

func TestToken_Refresh_ConsentDoesNotIncludeScope(t *testing.T) {
	setup()
	scope := "openid profile email phone address offline_access groups backend-svcA:read-product backend-svcB:write-info"
	code, httpClient := createAuthCode(t, scope)

	destUrl := lib.GetBaseUrl() + "/auth/token"

	clientSecret := getClientSecret(t, "test-client-1")

	formData := url.Values{
		"client_id":     {"test-client-1"},
		"client_secret": {clientSecret},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {code.RedirectURI},
		"code":          {code.Code},
		"code_verifier": {"DdazqdVNuDmRLGGRGQKKehEaoFeatACtNsM2UYGwuHkhBhDsTSzaCqWttcBc0kGx"},
	}
	respData := postToTokenEndpoint(t, httpClient, destUrl, formData)

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "Bearer", respData["token_type"])
	assert.Equal(t, float64(settings.TokenExpirationInSeconds), respData["expires_in"])
	assert.Equal(t, float64(settings.RefreshTokenOfflineIdleTimeoutInSeconds), respData["refresh_expires_in"])
	assert.Equal(t, scope+" authserver:userinfo", respData["scope"])
	assert.NotEmpty(t, respData["access_token"])
	assert.NotEmpty(t, respData["id_token"])
	assert.NotEmpty(t, respData["refresh_token"])

	userConsent, err := database.GetConsentByUserIdAndClientId(nil, code.UserId, code.ClientId)
	if err != nil {
		t.Fatal(err)
	}
	userConsent.Scope = "openid profile email phone address offline_access groups backend-svcB:write-info"
	err = database.UpdateUserConsent(nil, userConsent)
	if err != nil {
		t.Fatal(err)
	}

	formData = url.Values{
		"client_id":     {"test-client-1"},
		"client_secret": {clientSecret},
		"grant_type":    {"refresh_token"},
		"refresh_token": {respData["refresh_token"].(string)},
	}
	respData = postToTokenEndpoint(t, httpClient, destUrl, formData)
	assert.Equal(t, "invalid_grant", respData["error"])
	assert.Equal(t, "Scope 'backend-svcA:read-product' is not recognized. The user has not consented to the 'backend-svcA:read-product' permission.", respData["error_description"])
}

func TestToken_Refresh_TokenMarkedAsUsed(t *testing.T) {
	setup()
	scope := "openid profile email phone address groups backend-svcA:read-product backend-svcB:write-info"
	code, httpClient := createAuthCode(t, scope)

	destUrl := lib.GetBaseUrl() + "/auth/token"

	clientSecret := getClientSecret(t, "test-client-1")

	formData := url.Values{
		"client_id":     {"test-client-1"},
		"client_secret": {clientSecret},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {code.RedirectURI},
		"code":          {code.Code},
		"code_verifier": {"DdazqdVNuDmRLGGRGQKKehEaoFeatACtNsM2UYGwuHkhBhDsTSzaCqWttcBc0kGx"},
	}
	respData := postToTokenEndpoint(t, httpClient, destUrl, formData)

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "Bearer", respData["token_type"])
	assert.Equal(t, float64(settings.TokenExpirationInSeconds), respData["expires_in"])
	assert.Equal(t, float64(settings.UserSessionIdleTimeoutInSeconds), respData["refresh_expires_in"])
	assert.Equal(t, scope+" authserver:userinfo", respData["scope"])
	assert.NotEmpty(t, respData["access_token"])
	assert.NotEmpty(t, respData["id_token"])
	assert.NotEmpty(t, respData["refresh_token"])

	tokenParser := core_token.NewTokenParser(database)
	refreshTokenJwt, err := tokenParser.ParseToken(context.Background(), respData["refresh_token"].(string), true)
	if err != nil {
		t.Fatal(err)
	}
	jti := refreshTokenJwt.GetStringClaim("jti")
	assert.NotEmpty(t, jti)

	refreshToken, err := database.GetRefreshTokenByJti(nil, jti)
	if err != nil {
		t.Fatal(err)
	}
	assert.False(t, refreshToken.Revoked)

	formData = url.Values{
		"client_id":     {"test-client-1"},
		"client_secret": {clientSecret},
		"grant_type":    {"refresh_token"},
		"refresh_token": {respData["refresh_token"].(string)},
	}
	_ = postToTokenEndpoint(t, httpClient, destUrl, formData)

	refreshToken, err = database.GetRefreshTokenByJti(nil, jti)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, refreshToken.Revoked)
}

func TestToken_Refresh_UseTokenTwice(t *testing.T) {
	setup()
	scope := "openid profile email phone address groups backend-svcA:read-product backend-svcB:write-info"
	code, httpClient := createAuthCode(t, scope)

	destUrl := lib.GetBaseUrl() + "/auth/token"

	clientSecret := getClientSecret(t, "test-client-1")

	formData := url.Values{
		"client_id":     {"test-client-1"},
		"client_secret": {clientSecret},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {code.RedirectURI},
		"code":          {code.Code},
		"code_verifier": {"DdazqdVNuDmRLGGRGQKKehEaoFeatACtNsM2UYGwuHkhBhDsTSzaCqWttcBc0kGx"},
	}
	respData := postToTokenEndpoint(t, httpClient, destUrl, formData)

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "Bearer", respData["token_type"])
	assert.Equal(t, float64(settings.TokenExpirationInSeconds), respData["expires_in"])
	assert.Equal(t, float64(settings.UserSessionIdleTimeoutInSeconds), respData["refresh_expires_in"])
	assert.Equal(t, scope+" authserver:userinfo", respData["scope"])
	assert.NotEmpty(t, respData["access_token"])
	assert.NotEmpty(t, respData["id_token"])
	assert.NotEmpty(t, respData["refresh_token"])

	formData = url.Values{
		"client_id":     {"test-client-1"},
		"client_secret": {clientSecret},
		"grant_type":    {"refresh_token"},
		"refresh_token": {respData["refresh_token"].(string)},
	}
	respData2 := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "Bearer", respData2["token_type"])
	assert.Equal(t, float64(settings.TokenExpirationInSeconds), respData2["expires_in"])
	assert.Equal(t, float64(settings.UserSessionIdleTimeoutInSeconds), respData2["refresh_expires_in"])
	assert.Equal(t, scope+" authserver:userinfo", respData2["scope"])
	assert.NotEmpty(t, respData2["access_token"])
	assert.NotEmpty(t, respData2["id_token"])
	assert.NotEmpty(t, respData2["refresh_token"])

	formData = url.Values{
		"client_id":     {"test-client-1"},
		"client_secret": {clientSecret},
		"grant_type":    {"refresh_token"},
		"refresh_token": {respData["refresh_token"].(string)},
	}
	respData3 := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_grant", respData3["error"])
	assert.Equal(t, "This refresh token has been revoked.", respData3["error_description"])
}
