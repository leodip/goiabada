package integrationtests

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	core "github.com/leodip/goiabada/internal/core/validators"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/stretchr/testify/assert"
)

func TestToken_MissingClientId(t *testing.T) {
	setup()

	destUrl := lib.GetBaseUrl() + "/auth/token"

	client := createHttpClient(&createHttpClientInput{
		T: t,
	})

	formData := url.Values{}
	data := postToTokenEndpoint(t, client, destUrl, formData)

	assert.Equal(t, "invalid_request", data["error"])
	assert.Equal(t, "Missing required client_id parameter.", data["error_description"])
}

func TestToken_ClientDoesNotExist(t *testing.T) {
	setup()

	destUrl := lib.GetBaseUrl() + "/auth/token"

	client := createHttpClient(&createHttpClientInput{
		T: t,
	})

	formData := url.Values{
		"client_id": {"invalid"},
	}
	data := postToTokenEndpoint(t, client, destUrl, formData)

	assert.Equal(t, "invalid_request", data["error"])
	assert.Equal(t, "Client does not exist.", data["error_description"])
}

func TestToken_InvalidGrantType(t *testing.T) {
	setup()

	destUrl := lib.GetBaseUrl() + "/auth/token"

	client := createHttpClient(&createHttpClientInput{
		T: t,
	})

	formData := url.Values{
		"client_id":  {"test-client-1"},
		"grant_type": {"invalid"},
	}
	data := postToTokenEndpoint(t, client, destUrl, formData)

	assert.Equal(t, "unsupported_grant_type", data["error"])
	assert.Equal(t, "Unsupported grant_type.", data["error_description"])
}

func TestToken_AuthCode_MissingCode(t *testing.T) {
	setup()

	destUrl := lib.GetBaseUrl() + "/auth/token"

	client := createHttpClient(&createHttpClientInput{
		T: t,
	})

	formData := url.Values{
		"client_id":  {"test-client-1"},
		"grant_type": {"authorization_code"},
	}
	respData := postToTokenEndpoint(t, client, destUrl, formData)

	assert.Equal(t, "invalid_request", respData["error"])
	assert.Equal(t, "Missing required code parameter.", respData["error_description"])
}

func TestToken_AuthCode_MissingRedirectURI(t *testing.T) {
	setup()
	code := createAuthCode(t, "openid profile email backend-svcA:read-product offline_access")

	destUrl := lib.GetBaseUrl() + "/auth/token"

	client := createHttpClient(&createHttpClientInput{
		T: t,
	})

	formData := url.Values{
		"client_id":  {"test-client-1"},
		"grant_type": {"authorization_code"},
		"code":       {code.Code},
	}
	respData := postToTokenEndpoint(t, client, destUrl, formData)
	assert.Equal(t, "invalid_request", respData["error"])
	assert.Equal(t, "Missing required redirect_uri parameter.", respData["error_description"])
}

func TestToken_AuthCode_MissingCodeVerifier(t *testing.T) {
	setup()
	code := createAuthCode(t, "openid profile email backend-svcA:read-product offline_access")

	destUrl := lib.GetBaseUrl() + "/auth/token"

	client := createHttpClient(&createHttpClientInput{
		T: t,
	})

	formData := url.Values{
		"client_id":    {"test-client-1"},
		"grant_type":   {"authorization_code"},
		"redirect_uri": {code.RedirectURI},
		"code":         {code.Code},
	}
	respData := postToTokenEndpoint(t, client, destUrl, formData)
	assert.Equal(t, "invalid_request", respData["error"])
	assert.Equal(t, "Missing required code_verifier parameter.", respData["error_description"])
}

func TestToken_AuthCode_InvalidClient(t *testing.T) {
	setup()
	code := createAuthCode(t, "openid profile email backend-svcA:read-product offline_access")

	destUrl := lib.GetBaseUrl() + "/auth/token"

	client := createHttpClient(&createHttpClientInput{
		T: t,
	})

	formData := url.Values{
		"client_id":     {"invalid"},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {code.RedirectURI},
		"code":          {code.Code},
		"code_verifier": {"DdazqdVNuDmRLGGRGQKKehEaoFeatACtNsM2UYGwuHkhBhDsTSzaCqWttcBc0kGx"},
	}
	respData := postToTokenEndpoint(t, client, destUrl, formData)
	assert.Equal(t, "invalid_request", respData["error"])
	assert.Equal(t, "Client does not exist.", respData["error_description"])
}

func TestToken_AuthCode_CodeIsInvalid(t *testing.T) {
	setup()
	code := createAuthCode(t, "openid profile email backend-svcA:read-product offline_access")

	destUrl := lib.GetBaseUrl() + "/auth/token"

	client := createHttpClient(&createHttpClientInput{
		T: t,
	})

	formData := url.Values{
		"client_id":     {"test-client-1"},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {code.RedirectURI},
		"code":          {"invalid"},
		"code_verifier": {"DdazqdVNuDmRLGGRGQKKehEaoFeatACtNsM2UYGwuHkhBhDsTSzaCqWttcBc0kGx"},
	}
	respData := postToTokenEndpoint(t, client, destUrl, formData)
	assert.Equal(t, "invalid_grant", respData["error"])
	assert.Equal(t, "Code is invalid.", respData["error_description"])
}

func TestToken_AuthCode_RedirectURIIsInvalid(t *testing.T) {
	setup()
	code := createAuthCode(t, "openid profile email backend-svcA:read-product offline_access")

	destUrl := lib.GetBaseUrl() + "/auth/token"

	client := createHttpClient(&createHttpClientInput{
		T: t,
	})

	formData := url.Values{
		"client_id":     {"test-client-1"},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {"invalid"},
		"code":          {code.Code},
		"code_verifier": {"DdazqdVNuDmRLGGRGQKKehEaoFeatACtNsM2UYGwuHkhBhDsTSzaCqWttcBc0kGx"},
	}
	respData := postToTokenEndpoint(t, client, destUrl, formData)
	assert.Equal(t, "invalid_grant", respData["error"])
	assert.Equal(t, "Invalid redirect_uri.", respData["error_description"])
}

func TestToken_AuthCode_WrongClient(t *testing.T) {
	setup()
	code := createAuthCode(t, "openid profile email backend-svcA:read-product offline_access")

	destUrl := lib.GetBaseUrl() + "/auth/token"

	client := createHttpClient(&createHttpClientInput{
		T: t,
	})

	formData := url.Values{
		"client_id":     {"test-client-2"},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {code.RedirectURI},
		"code":          {code.Code},
		"code_verifier": {"DdazqdVNuDmRLGGRGQKKehEaoFeatACtNsM2UYGwuHkhBhDsTSzaCqWttcBc0kGx"},
	}
	respData := postToTokenEndpoint(t, client, destUrl, formData)
	assert.Equal(t, "invalid_grant", respData["error"])
	assert.Equal(t, "The client_id provided does not match the client_id from code.", respData["error_description"])
}

func TestToken_AuthCode_ConfidentialClient_NoClientSecret(t *testing.T) {
	setup()
	code := createAuthCode(t, "openid profile email backend-svcA:read-product offline_access")

	destUrl := lib.GetBaseUrl() + "/auth/token"

	client := createHttpClient(&createHttpClientInput{
		T: t,
	})

	formData := url.Values{
		"client_id":     {"test-client-1"},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {code.RedirectURI},
		"code":          {code.Code},
		"code_verifier": {"DdazqdVNuDmRLGGRGQKKehEaoFeatACtNsM2UYGwuHkhBhDsTSzaCqWttcBc0kGx"},
	}
	respData := postToTokenEndpoint(t, client, destUrl, formData)
	assert.Equal(t, "invalid_request", respData["error"])
	assert.Equal(t, "This client is configured as confidential (not public), which means a client_secret is required for authentication. Please provide a valid client_secret to proceed.", respData["error_description"])
}

func TestToken_AuthCode_ConfidentialClient_ClientAuthFailed(t *testing.T) {
	setup()
	code := createAuthCode(t, "openid profile email backend-svcA:read-product offline_access")

	destUrl := lib.GetBaseUrl() + "/auth/token"

	client := createHttpClient(&createHttpClientInput{
		T: t,
	})

	formData := url.Values{
		"client_id":     {"test-client-1"},
		"client_secret": {"invalid"},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {code.RedirectURI},
		"code":          {code.Code},
		"code_verifier": {"DdazqdVNuDmRLGGRGQKKehEaoFeatACtNsM2UYGwuHkhBhDsTSzaCqWttcBc0kGx"},
	}
	respData := postToTokenEndpoint(t, client, destUrl, formData)
	assert.Equal(t, "invalid_grant", respData["error"])
	assert.Equal(t, "Client authentication failed. Please review your client_secret.", respData["error_description"])
}

func TestToken_AuthCode_InvalidCodeVerifier(t *testing.T) {
	setup()
	code := createAuthCode(t, "openid profile email backend-svcA:read-product offline_access")

	destUrl := lib.GetBaseUrl() + "/auth/token"

	client := createHttpClient(&createHttpClientInput{
		T: t,
	})

	clientSecret := getClientSecret(t, "test-client-1")

	formData := url.Values{
		"client_id":     {"test-client-1"},
		"client_secret": {clientSecret},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {code.RedirectURI},
		"code":          {code.Code},
		"code_verifier": {"invalid"},
	}
	respData := postToTokenEndpoint(t, client, destUrl, formData)
	assert.Equal(t, "invalid_grant", respData["error"])
	assert.Equal(t, "Invalid code_verifier (PKCE).", respData["error_description"])
}

func TestToken_AuthCode_SuccessPath(t *testing.T) {
	setup()
	scope := "openid profile email phone address offline_access groups backend-svcA:read-product backend-svcB:write-info"
	code := createAuthCode(t, scope)

	destUrl := lib.GetBaseUrl() + "/auth/token"

	client := createHttpClient(&createHttpClientInput{
		T: t,
	})

	clientSecret := getClientSecret(t, "test-client-1")

	formData := url.Values{
		"client_id":     {"test-client-1"},
		"client_secret": {clientSecret},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {code.RedirectURI},
		"code":          {code.Code},
		"code_verifier": {"DdazqdVNuDmRLGGRGQKKehEaoFeatACtNsM2UYGwuHkhBhDsTSzaCqWttcBc0kGx"},
	}
	respData := postToTokenEndpoint(t, client, destUrl, formData)

	settings, err := database.GetSettings()
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "Bearer", respData["token_type"])
	assert.Equal(t, float64(settings.TokenExpirationInSeconds), respData["expires_in"])
	assert.Equal(t, float64(30), respData["refresh_expires_in"])
	assert.Equal(t, scope, respData["scope"])
	assert.NotEmpty(t, respData["access_token"])
	assert.NotEmpty(t, respData["id_token"])
	assert.NotEmpty(t, respData["refresh_token"])

	tokenResponse := &dtos.TokenResponse{
		AccessToken:      respData["access_token"].(string),
		IdToken:          respData["id_token"].(string),
		TokenType:        respData["token_type"].(string),
		ExpiresIn:        int(respData["expires_in"].(float64)),
		RefreshToken:     respData["refresh_token"].(string),
		RefreshExpiresIn: int(respData["refresh_expires_in"].(float64)),
		Scope:            respData["scope"].(string),
	}

	tokenValidator := core.NewTokenValidator(database)

	// validate signature
	jwt, err := tokenValidator.ValidateJwtSignature(context.Background(), tokenResponse)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, jwt.IsAccessTokenPresentAndValid())
	assert.True(t, jwt.IsIdTokenPresentAndValid())
	assert.True(t, jwt.IsRefreshTokenPresentAndValid())

	// validate claims (access token)
	assert.Equal(t, settings.Issuer, jwt.GetAccessTokenStringClaim("iss"))
	assert.Equal(t, code.User.Subject.String(), jwt.GetAccessTokenStringClaim("sub"))

	issuedAt := jwt.GetAccessTokenTimeClaim("iat")
	assert.False(t, issuedAt.IsZero())
	assert.True(t, issuedAt.Add(time.Second*10).After(time.Now().UTC()))

	authTime := jwt.GetAccessTokenTimeClaim("auth_time")
	assert.False(t, authTime.IsZero())
	assertTimeWithinRange(t, time.Now().UTC(), authTime, 10)

	assert.True(t, len(jwt.GetAccessTokenStringClaim("jti")) > 0)
	assert.Equal(t, code.Client.ClientIdentifier, jwt.GetAccessTokenStringClaim("azp"))
	assert.Equal(t, code.AcrLevel, jwt.GetAccessTokenStringClaim("acr"))
	assert.Equal(t, code.AuthMethods, jwt.GetAccessTokenStringClaim("amr"))
	assert.Equal(t, code.SessionIdentifier, jwt.GetAccessTokenStringClaim("sid"))

	aud := jwt.GetAccessTokenAudience()
	assert.Len(t, aud, 3)
	assert.Equal(t, "account", aud[0])
	assert.Equal(t, "backend-svcA", aud[1])
	assert.Equal(t, "backend-svcB", aud[2])

	assert.Equal(t, "Bearer", jwt.GetAccessTokenStringClaim("typ"))

	utcNow := time.Now().UTC()
	expectedExp := utcNow.Add(time.Duration(time.Second * time.Duration(settings.TokenExpirationInSeconds)))
	assertTimeWithinRange(t, expectedExp, jwt.GetAccessTokenTimeClaim("exp").UTC(), 10)

	assert.Equal(t, scope, jwt.GetAccessTokenStringClaim("scope"))

	// TODO
	// groups := jwt.GetAccessTokenGroups()
	// assert.Len(t, groups, 2)
	// assert.Equal(t, "site-admin", groups[0])
	// assert.Equal(t, "product-admin", groups[1])

	assert.Equal(t, code.User.GetFullName(), jwt.GetAccessTokenStringClaim("name"))
	assert.Equal(t, code.User.GivenName, jwt.GetAccessTokenStringClaim("given_name"))
	assert.Equal(t, code.User.FamilyName, jwt.GetAccessTokenStringClaim("family_name"))
	assert.Equal(t, code.User.MiddleName, jwt.GetAccessTokenStringClaim("middle_name"))
	assert.Equal(t, code.User.Nickname, jwt.GetAccessTokenStringClaim("nickname"))
	assert.Equal(t, code.User.Username, jwt.GetAccessTokenStringClaim("preferred_username"))
	assert.Equal(t, lib.GetBaseUrl()+"/account/profile", jwt.GetAccessTokenStringClaim("profile"))
	assert.Equal(t, code.User.Website, jwt.GetAccessTokenStringClaim("website"))
	assert.Equal(t, code.User.Gender, jwt.GetAccessTokenStringClaim("gender"))
	assert.Equal(t, code.User.BirthDate.Format("2006-01-02"), jwt.GetAccessTokenStringClaim("birthdate"))
	assert.Equal(t, code.User.ZoneInfo, jwt.GetAccessTokenStringClaim("zoneinfo"))
	assert.Equal(t, code.User.Locale, jwt.GetAccessTokenStringClaim("locale"))
	assertTimeWithinRange(t, code.User.UpdatedAt, jwt.GetAccessTokenTimeClaim("updated_at"), 10)

	assert.Equal(t, code.User.Email, jwt.GetAccessTokenStringClaim("email"))
	emailVerified := jwt.GetAccessTokenBoolClaim("email_verified")
	assert.NotNil(t, emailVerified)
	assert.True(t, *emailVerified)

	addressFromClaim := jwt.GetAccessTokenAddressClaim()
	assert.Len(t, addressFromClaim, 6)

	addressFromUser := code.User.GetAddressClaim()
	assert.Equal(t, addressFromUser["street_address"], addressFromClaim["street_address"])
	assert.Equal(t, addressFromUser["locality"], addressFromClaim["locality"])
	assert.Equal(t, addressFromUser["region"], addressFromClaim["region"])
	assert.Equal(t, addressFromUser["postal_code"], addressFromClaim["postal_code"])
	assert.Equal(t, addressFromUser["country"], addressFromClaim["country"])
	assert.Equal(t, addressFromUser["formatted"], addressFromClaim["formatted"])

	assert.Equal(t, code.User.PhoneNumber, jwt.GetAccessTokenStringClaim("phone_number"))
	phoneVerified := jwt.GetAccessTokenBoolClaim("phone_number_verified")
	assert.NotNil(t, phoneVerified)
	assert.True(t, *phoneVerified)

	// validate claims (id token)
	assert.Equal(t, settings.Issuer, jwt.GetIdTokenStringClaim("iss"))
	assert.Equal(t, code.User.Subject.String(), jwt.GetIdTokenStringClaim("sub"))

	issuedAt = jwt.GetIdTokenTimeClaim("iat")
	assert.False(t, issuedAt.IsZero())
	assert.True(t, issuedAt.Add(time.Second*10).After(time.Now().UTC()))

	authTime = jwt.GetIdTokenTimeClaim("auth_time")
	assert.False(t, authTime.IsZero())
	assertTimeWithinRange(t, time.Now().UTC(), authTime, 10)

	assert.True(t, len(jwt.GetIdTokenStringClaim("jti")) > 0)
	assert.Equal(t, code.Client.ClientIdentifier, jwt.GetIdTokenStringClaim("azp"))
	assert.Equal(t, code.AcrLevel, jwt.GetIdTokenStringClaim("acr"))
	assert.Equal(t, code.AuthMethods, jwt.GetIdTokenStringClaim("amr"))
	assert.Equal(t, code.SessionIdentifier, jwt.GetIdTokenStringClaim("sid"))

	aud = jwt.GetIdTokenAudience()
	assert.Len(t, aud, 1)
	assert.Equal(t, "test-client-1", aud[0])

	assert.Equal(t, "ID", jwt.GetIdTokenStringClaim("typ"))

	expectedExp = utcNow.Add(time.Duration(time.Second * time.Duration(settings.TokenExpirationInSeconds)))
	assertTimeWithinRange(t, expectedExp, jwt.GetIdTokenTimeClaim("exp").UTC(), 10)
	jwt.IsIdTokenNonceValid(code.Nonce)

	assert.Equal(t, code.User.GetFullName(), jwt.GetIdTokenStringClaim("name"))
	assert.Equal(t, code.User.GivenName, jwt.GetIdTokenStringClaim("given_name"))
	assert.Equal(t, code.User.FamilyName, jwt.GetIdTokenStringClaim("family_name"))
	assert.Equal(t, code.User.MiddleName, jwt.GetIdTokenStringClaim("middle_name"))
	assert.Equal(t, code.User.Nickname, jwt.GetIdTokenStringClaim("nickname"))
	assert.Equal(t, code.User.Username, jwt.GetIdTokenStringClaim("preferred_username"))
	assert.Equal(t, lib.GetBaseUrl()+"/account/profile", jwt.GetIdTokenStringClaim("profile"))
	assert.Equal(t, code.User.Website, jwt.GetIdTokenStringClaim("website"))
	assert.Equal(t, code.User.Gender, jwt.GetIdTokenStringClaim("gender"))
	assert.Equal(t, code.User.BirthDate.Format("2006-01-02"), jwt.GetIdTokenStringClaim("birthdate"))
	assert.Equal(t, code.User.ZoneInfo, jwt.GetIdTokenStringClaim("zoneinfo"))
	assert.Equal(t, code.User.Locale, jwt.GetIdTokenStringClaim("locale"))
	assertTimeWithinRange(t, code.User.UpdatedAt, jwt.GetIdTokenTimeClaim("updated_at"), 10)

	assert.Equal(t, code.User.Email, jwt.GetIdTokenStringClaim("email"))
	emailVerified = jwt.GetIdTokenBoolClaim("email_verified")
	assert.NotNil(t, emailVerified)
	assert.True(t, *emailVerified)

	addressFromClaim = jwt.GetIdTokenAddressClaim()
	assert.Len(t, addressFromClaim, 6)

	addressFromUser = code.User.GetAddressClaim()
	assert.Equal(t, addressFromUser["street_address"], addressFromClaim["street_address"])
	assert.Equal(t, addressFromUser["locality"], addressFromClaim["locality"])
	assert.Equal(t, addressFromUser["region"], addressFromClaim["region"])
	assert.Equal(t, addressFromUser["postal_code"], addressFromClaim["postal_code"])
	assert.Equal(t, addressFromUser["country"], addressFromClaim["country"])
	assert.Equal(t, addressFromUser["formatted"], addressFromClaim["formatted"])

	assert.Equal(t, code.User.PhoneNumber, jwt.GetIdTokenStringClaim("phone_number"))
	phoneVerified = jwt.GetIdTokenBoolClaim("phone_number_verified")
	assert.NotNil(t, phoneVerified)
	assert.True(t, *phoneVerified)

	// validate claims (refresh token)
	assert.Equal(t, settings.Issuer, jwt.GetRefreshTokenStringClaim("iss"))

	issuedAt = jwt.GetRefreshTokenTimeClaim("iat")
	assert.False(t, issuedAt.IsZero())
	assert.True(t, issuedAt.Add(time.Second*10).After(time.Now().UTC()))

	assert.True(t, len(jwt.GetRefreshTokenStringClaim("jti")) > 0)

	aud = jwt.GetRefreshTokenAudience()
	assert.Len(t, aud, 1)
	assert.Equal(t, settings.Issuer, aud[0])

	assert.Equal(t, "Refresh", jwt.GetRefreshTokenStringClaim("typ"))

	expectedExp = utcNow.Add(time.Duration(time.Second * time.Duration(30)))
	assertTimeWithinRange(t, expectedExp, jwt.GetRefreshTokenTimeClaim("exp").UTC(), 10)
}

func TestToken_ClientCred_PublicClient(t *testing.T) {
	setup()

	destUrl := lib.GetBaseUrl() + "/auth/token"

	client := createHttpClient(&createHttpClientInput{
		T: t,
	})

	formData := url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {"test-client-2"},
	}
	data := postToTokenEndpoint(t, client, destUrl, formData)

	assert.Equal(t, "unauthorized_client", data["error"])
	assert.Equal(t, "A public client is not eligible for the client credentials flow. Please review the client configuration.", data["error_description"])
}

func TestToken_ClientCred_NoClientSecret(t *testing.T) {
	setup()
	destUrl := lib.GetBaseUrl() + "/auth/token"

	client := createHttpClient(&createHttpClientInput{
		T: t,
	})

	formData := url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {"test-client-1"},
	}
	data := postToTokenEndpoint(t, client, destUrl, formData)

	assert.Equal(t, "invalid_request", data["error"])
	assert.Equal(t, "This client is configured as confidential (not public), which means a client_secret is required for authentication. Please provide a valid client_secret to proceed.", data["error_description"])
}

func TestToken_ClientCred_ClientAuthFailed(t *testing.T) {
	setup()
	destUrl := lib.GetBaseUrl() + "/auth/token"

	client := createHttpClient(&createHttpClientInput{
		T: t,
	})

	formData := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"test-client-1"},
		"client_secret": {"invalid"},
	}
	data := postToTokenEndpoint(t, client, destUrl, formData)

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
		client := createHttpClient(&createHttpClientInput{
			T: t,
		})

		clientSecret := getClientSecret(t, "test-client-1")
		formData := url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {"test-client-1"},
			"client_secret": {clientSecret},
			"scope":         {testCase.scope},
		}
		data := postToTokenEndpoint(t, client, destUrl, formData)

		assert.Equal(t, testCase.errorCode, data["error"])
		assert.Equal(t, testCase.errorDescription, data["error_description"])
	}
}

func TestToken_ClientCred_NoScopesGiven(t *testing.T) {
	setup()
	destUrl := lib.GetBaseUrl() + "/auth/token"

	client := createHttpClient(&createHttpClientInput{
		T: t,
	})

	clientSecret := getClientSecret(t, "test-client-1")
	formData := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"test-client-1"},
		"client_secret": {clientSecret},
	}
	data := postToTokenEndpoint(t, client, destUrl, formData)

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

	client := createHttpClient(&createHttpClientInput{
		T: t,
	})

	clientSecret := getClientSecret(t, "test-client-1")
	formData := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"test-client-1"},
		"client_secret": {clientSecret},
		"scope":         {"backend-svcA:create-product"},
	}
	data := postToTokenEndpoint(t, client, destUrl, formData)

	scope := data["scope"].(string)
	parts := strings.Split(scope, " ")
	assert.Equal(t, 1, len(parts))
	assert.Equal(t, "backend-svcA:create-product", parts[0])
}
