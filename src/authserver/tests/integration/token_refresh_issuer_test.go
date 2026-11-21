package integration

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A refresh token is live only while its iss and its aud are each exactly the current issuer
// (#710 decisions 1 to 3). Once the issuer changes, a refresh token issued under the earlier one is
// refused with invalid_grant and the message that says nothing about why, nothing is rotated or
// revoked, introspection answers it inactive and revocation answers 200 and revokes nothing.
// Changing the issuer back lets it work again. A rotated token of an earlier issuer is still a
// replay, and contains its family.

const invalidRefreshTokenDescription = "The refresh token is invalid."

// anotherIssuer is an issuer no test has published.
func anotherIssuer() string {
	return "https://issuer-" + strings.ToLower(fake.LetterN(6)) + ".example.org"
}

// assertRefusedForItsIssuer asserts the token endpoint refuses refreshToken with invalid_grant and
// the message that says nothing about why.
func assertRefusedForItsIssuer(t *testing.T, httpClient *http.Client, clientIdentifier, clientSecret, refreshToken string) {
	t.Helper()
	status, body := replayRefreshToken(t, httpClient, clientIdentifier, clientSecret, refreshToken)
	assertRefusedAsInvalidGrant(t, status, body, "a refresh token of an earlier issuer")
	assert.Equal(t, invalidRefreshTokenDescription, body["error_description"])
	assert.Nil(t, body["id_token"], "no ID token is issued")
}

// A code-descended refresh token issued before the issuer changed is refused at the token endpoint,
// inactive at introspection, and not revoked by revocation. Its row stays live and no token is
// minted, so changing the issuer back lets it refresh.
func TestToken_Refresh_ATokenOfAnEarlierIssuerIsRefused(t *testing.T) {
	data, code, httpClient, clientSecret := userTokenResponseWithScope(t, "openid", nil)
	refreshToken := data["refresh_token"].(string)
	original := restoreSettings(t).Issuer
	require.Equal(t, original, decodeJWTPayload(t, refreshToken)["iss"], "the token names the issuer it was issued under")

	changeSettings(t, func(settings *record.Settings) { settings.Issuer = anotherIssuer() })

	assertRefusedForItsIssuer(t, httpClient, code.Client.ClientIdentifier, clientSecret, refreshToken)
	assert.False(t, refreshTokenRowByJTI(t, refreshToken).Revoked, "the refusal revokes nothing")
	rows, err := database.GetRefreshTokensByCodeID(context.Background(), nil, code.ID)
	require.NoError(t, err)
	assert.Len(t, rows, 1, "the refusal minted no refresh token")

	assertInactive(t, introspectAs(t, code.Client.ClientIdentifier, clientSecret, refreshToken))
	revokeAs(t, code.Client.ClientIdentifier, clientSecret, refreshToken)
	assert.False(t, refreshTokenRowByJTI(t, refreshToken).Revoked, "revocation revoked nothing: the token is not live")
	recorded, err := database.IsRefreshTokenFamilyRevoked(context.Background(), nil, refreshTokenRowByJTI(t, refreshToken).FirstRefreshTokenJTI)
	require.NoError(t, err)
	assert.False(t, recorded, "nor recorded its family")

	// The issuer changed back: the token is the current issuer's again.
	changeSettings(t, func(settings *record.Settings) { settings.Issuer = original })

	assertActive(t, introspectAs(t, code.Client.ClientIdentifier, clientSecret, refreshToken))
	status, rotated := refreshAuthCodeGrant(t, httpClient, code, clientSecret, refreshToken, "")
	require.Equal(t, http.StatusOK, status, "%v", rotated)
	assert.Equal(t, original, decodeJWTPayload(t, rotated["id_token"].(string))["iss"],
		"the refreshed ID token names the issuer of the sign-in")
}

// The password grant's refresh tokens are refused the same way.
func TestToken_Refresh_APasswordGrantTokenOfAnEarlierIssuerIsRefused(t *testing.T) {
	changeSettings(t, func(settings *record.Settings) { settings.ResourceOwnerPasswordCredentialsEnabled = true })

	clientSecret := fake.Password(32)
	password := fake.Password(12)
	client := createROPCClient(t, clientSecret, false)
	user := createROPCUser(t, password)
	httpClient := createHTTPClient(t)
	data := postToTokenEndpoint(t, httpClient, appConfig.AuthServer.BaseURL+"/auth/token/", url.Values{
		"grant_type":    {"password"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"username":      {user.Email},
		"password":      {password},
		"scope":         {"openid"},
	})
	require.NotNil(t, data["refresh_token"], "the password grant must return a refresh token")
	refreshToken := data["refresh_token"].(string)

	changeSettings(t, func(settings *record.Settings) { settings.Issuer = anotherIssuer() })

	assertRefusedForItsIssuer(t, httpClient, client.ClientIdentifier, clientSecret, refreshToken)
	assert.False(t, refreshTokenRowByJTI(t, refreshToken).Revoked, "the refusal revokes nothing")
	assertInactive(t, introspectAs(t, client.ClientIdentifier, clientSecret, refreshToken))
}

// A refresh token whose aud is not exactly the issuer, as a string, is not one the server gives
// refresh tokens, and is refused, under the issuer that is still current. The tokens are signed with
// the server's own key, as nothing else could make the server read them.
func TestToken_Refresh_ATokenWhoseAudIsNotTheIssuerIsRefused(t *testing.T) {
	issuer := restoreSettings(t).Issuer
	audiences := map[string]interface{}{
		"another issuer":                   anotherIssuer(),
		"an array holding the issuer":      []interface{}{issuer},
		"the issuer with a trailing slash": issuer + "/",
	}
	for name, aud := range audiences {
		t.Run(name, func(t *testing.T) {
			data, code, httpClient, clientSecret := userTokenResponseWithScope(t, "openid", nil)
			refreshToken := data["refresh_token"].(string)
			claims := jwt.MapClaims(decodeJWTPayload(t, refreshToken))
			require.Equal(t, issuer, claims["aud"], "the server gives a refresh token the issuer as its aud")
			claims["aud"] = aud
			forged := resignWithCurrentKey(t, claims, "")

			assertRefusedForItsIssuer(t, httpClient, code.Client.ClientIdentifier, clientSecret, forged)
			assertInactive(t, introspectAs(t, code.Client.ClientIdentifier, clientSecret, forged))
			assert.False(t, refreshTokenRowByJTI(t, refreshToken).Revoked, "the refusal revokes nothing")

			// The control: the token as the server signed it still refreshes.
			status, rotated := refreshAuthCodeGrant(t, httpClient, code, clientSecret, refreshToken, "")
			assert.Equal(t, http.StatusOK, status, "%v", rotated)
		})
	}
}

// A family rotated across an issuer change before the upgrade has a rotated token naming the earlier
// issuer and a live one naming the current issuer. Presenting the rotated one is a replay: it is
// answered as a revoked token, and the family is contained, its live member revoked and the family
// recorded, so a thief's live token stops working (#710 decision 3). The rotated token naming the
// earlier issuer is the server's own, re-signed with its key under that issuer.
func TestToken_Refresh_ARotatedTokenOfAnEarlierIssuerContainsItsFamily(t *testing.T) {
	clientSecret := fake.Password(32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")

	rt1 := exchangeAuthCode(t, httpClient, code.Client.ClientIdentifier, clientSecret,
		code.Code, code.RedirectURI, testCodeVerifier)
	rt2 := rotateRefreshToken(t, httpClient, code.Client.ClientIdentifier, clientSecret, rt1)
	require.True(t, refreshTokenRowByJTI(t, rt1).Revoked, "the rotation retired rt1")

	claims := jwt.MapClaims(decodeJWTPayload(t, rt1))
	earlier := anotherIssuer()
	claims["iss"] = earlier
	claims["aud"] = earlier
	rotatedOfEarlierIssuer := resignWithCurrentKey(t, claims, "")

	status, body := replayRefreshToken(t, httpClient, code.Client.ClientIdentifier, clientSecret, rotatedOfEarlierIssuer)
	assertRefusedAsInvalidGrant(t, status, body, "a rotated token of an earlier issuer")
	assert.Equal(t, "This refresh token has been revoked.", body["error_description"])

	assert.True(t, refreshTokenRowByJTI(t, rt2).Revoked, "the family's live member is revoked")
	recorded, err := database.IsRefreshTokenFamilyRevoked(context.Background(), nil, refreshTokenRowByJTI(t, rt1).FirstRefreshTokenJTI)
	require.NoError(t, err)
	assert.True(t, recorded, "the family is recorded as revoked")
	status, body = replayRefreshToken(t, httpClient, code.Client.ClientIdentifier, clientSecret, rt2)
	assertRefusedAsInvalidGrant(t, status, body, "the contained live member")
}
