package oauth

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"

	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func getTestPrivateKey(t *testing.T) []byte {
	privateKeyBase64 := "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlKSndJQkFBS0NBZ0VBb2Q3dFRUeVlCUjI0aDg1WEZaUkdxSDhBc25FMFdUeWJEVkQvNFhqN1ZIdjdFYStyClU1S2cyVFdKNjhkL09BcCtNK1lMYnVMYXdIVk1mWWtQM0lhWlNHV3pwd0JVeHFzSWZZOUtsR1paM3doYkhaL0QKZWRCU2I1UjNkdnJjUEIvQmcrMkFucUVnRkV2N3Y4djZFT1psUk1TRHFHS3ZURTRrTzdRQVRHQlltQmhMNmY3KwpPUnlRRmNLdUFZZ29DZmlKOG1hb3FkK1dIREk5TWMyTlBncnczOE5pbWZDdkUzdVZteWN0UXIwM3dNMDJPUDQzCkIyS3pCdUREc2ZKdUZWSVFWTUVtU2IyQ2ZqMjloWkpGMCtJWlVlZi9UeFdBNnJValMrWlhIa251eVg0MFVvWlgKYUFJVU5zbUVEeVUxWHRKRTh5Ym1xSHdNK3BjT2dCSzh3TElXTktWRUVINW0yMGxpK2oyN2dJOG9xWU1qYkJiNwpyYlI1L2JnSmdjL05qU2c4bTZrZDJzVC9TSmltMlI2eENFOEh5V1NsR29CTEhlOVJBQlhxRHhRODlEK2JMZFFvClV5R1N2RVJVWXBBNzZYNGViY2tqdnR0UFl3cTFSWEZuS0Vzb2hRNDRJUXJIQUxNNGZxNDJFcXZaRm9NTFBWaG8KT0xOSWd2NUlhU1lHZm9IMW1uQlZPZkJzZ3B4ejk0czRCNTJyMU1wTkZoTWpobVJJcEJxZi9Ic09qU20zTmZQbQppYkVVQ0c2OEo3aSthU3ZvVTdwSnVZQzgyQW1TWmwxeWxLOTdGNFRQbVFoYlQ0bnIyVnExL2gwanBBQjM1bkNRCi9tM09Sckl6RXYzL0F0UEdnbktlWENML3M0ZUQzd2hzbkNaTDBWZUw2ZUVhaGhQVjJ1bTlWVnN5WjBVQ0F3RUEKQVFLQ0FnQWZKS1hoWTFRWVArU2Q5RndhNGNGS2I4enhpQWc3VndhNTVDaW05OERiTzFOTnpzK1dyN0pVdUJGRwpGTWJzUUZDUnFhUHZmS1A3dlZXdkhXeTQwQWl6dmlWM2J2L2dqVTEvNHM3RmlIK29BcEtOTzR5L1pnNUdPM2xVCm9lVTNpQ0NTUW1LcG9uUnFrMGZuV2RaTjVCWDl5aFZPazFZSXgwdi9WSjF1RkdkWE0rMS9JcmxFd2JNVERMYXYKd3NONVQ2RXl5ditPVjE4cEk1MVVkS2pGRkJQTjZXaVNGNVdIbVJKcW5Ibi95aW5zNVU2V1hvcTEyQTU3dDBqUApkc1lwUWZXMGFNajJEUWtMUXRPdzNEaWxFRzR3clFNWTh4a3ZqeFF3YVN1L3Z4ZTdHcFgwZnJaWVkzWUNLSGxJCjlLNjFCSjJSYnAyWU11M0lWTUhNY0U1eWdKRDIxN0pLbzZKa3RRcTRoT09KRElhclhkSjIzT3N3OEdteEJyN1EKcSswQXhuVjd3NnRWRDVGOTg4SUpvc05OZW05cmgrUUN6YnhtN3BQc2JXT1hvdUlmQ2dyT0szZkJaZzg4QUs5UQpVRVZFSHlJUk5qMzBJSmw5MDh1d0JoWm9JVzJERk5xdERCQ1BJT09iZDFkblNLT2xlbjdRd3p0ajE1ak1QNm9oCnp3UU1pT0FHK051RmphY0FIRzRIWEx5NTZYK056RmJ6ZEZiWWZqTkZ5aElUd1Q5eC8vY3phSzVTcm8xY3ZFR0wKanJacFpXU1ZHOEJucVA4cGR3d3lwaml5KzM1alVGVnhkOWhVS3hBcjlHTkE3TFNsMG5qUHBRSTJiNnNSck92Tgp6KzlOR0h2UHI0N0F2WHJZazEvb01idHZLaHdmT0NqNjNZVDhOV1Z0YWxPRGtGNWdBUUtDQVFFQXlLc1RzUE4wCit4T0JYWDlDVW5kS25oemFIM1BaVnVxUmZrblJLbGZHVDFRYmQ2b1FLSWIwWWp6WUlDRWdTVGJNbTNMVWFOeEwKcUNqaktLbmRzL1ZWL0lSTjJYN1FaZHBtczFwU04zdnFSdnJxQzB4amp6RzhlZGhib1lKcGtZSHpoeENuc055eQpFNzZUTWpQSTdqTDNyQ0ROUDc3dkhJY0J1dUIrTUpyZVZXczN4RVFrR2ZaSldHTXNTNVRLY2pGQUpPV2JCaXhFCmY5WmJNNnRnc3lBUUdmU05sRXJXQll2c1kxemZtTVpWRmJIUTV1SmZkamUxN2l6TnNkNWI3c2dhbFR2L1ZXNW4KWXZKSHNaRzlKYldRdG9QTTQ3SFlmb21JMDhIMzV6K1M0YVZhdXVOWVpLT1RkYXB2ejRnOXE0dVhSS1plUFVlMgpLMHg0MXhUSzZQQ3ZSUUtDQVFFQXpvRXZoVldCdWZLeVVpZDBReExlSDVBQjNubkRNbndnUTJxTkh4VFdFS3pZCm5BVkVneDduZHY5OGorNjhqelZpNGhqY1Zxd2tvSTIxZWhKWktRVWdxaVo3ekg2bllrWE4wb2RVOVhUdHpzSGsKRjlkRWxsOFpSWkd4elFCMFFkN1dnb3pqcWF4YjN5YlZPOEN5WWFNbllsbTd3N1hxRllPNTVpLzBCL1c4UzQxVgpITEtSRXJya29ta2R0Q0pjNWhnYTg4eU5qNkV0SHhzL0J5aWcxRzhrc2RycGdmeVBWSTJMZnIrS3RwNGRKVmJOCmlLMnNQVmVMTU4wcXFRaTNSdCs0SjdMcFhLUllBM3A0M0FRLy9paXdmZ1NLOTEwVUVnbUlBVitjTGl6VU9mdkwKVk8xcnV3bmdlZlAvM2lwcWx0MWEyM3hnS1VIdmpZdlN3bUhFVlJwWUFRS0NBUUI3WHRLSVkrVnp4NVl0U1dRWgpGMFpFMXpBelRpSTlFWkhKdHRCbDIva01KSVdPbUh1K3J0bm8yOGQwV1dsa0dkREpjVnV0N0dLSFREdjhjQkxoCjVOK3NsQnJZc09LbS9CTlFDU09yQVFBVUM0ZUEwc0lTODEwUS9EZTVvRmdQSVhuN2UvM2MrcEp4R1NXZUk4QlEKMGZ6N1VsOWQ1YUZVUkp5SHJDVm85STNrcmpwbTdBM1YrRmszZ2lGbGhtREF2QTdYb0dJaTlXeFh2QTN1UWxyOQpSYVVnai8zTFFnYzYrYituaHgzZzYyNjhHOHAzYUkyUVBNZ1pXbXBNQkkwNHpNV3JJbXZrdGkvUjRXcTZmUU53Ci82T3Mwbk5ST2JJRWVjSXBqb00vSlJMRXI4aU1SZUcrWGVMMjRJWkZiVm1jOGdGYUwzNlk1bEhWWlBxV0lTNXUKOENxUkFvSUJBR3dBbkwzN2JwRzJJUlZlbFN2UFhtVGJpRjYzQ0NRTFQwUnpJY096dmhHU2xPZGt5ZVJaOFcwSApTanBzL2lsWUhwTnB0VE9QYk1pYjFPSTNYbkpad0MrOVdOb25FNXdPTGd1QnhDbHNNa1FFbkNycjUyOU41WVhCCklXQzZjQk5UWEpXQzRqOEhhalZYdGdZK1RnMUtxM3FBdS9jcjJYWFBJeGNFMVhpa1NRcXFyRzBKNTE0SWFUT1kKRG5UNzArSnprUVVaWXFCUUI2MVJMckdyeWhIUTN6dzE1aEtaNk15c0N0MExpSnppTFJRdVJlaktERjg0dmcrYwpYSWR6aTRlQjBtclE0OFFVSUFRUnRjdzhYTXVzdEVIMFZrbnhZR0hlb2tjMW5oVjRWTGJPdmhWNDV2TTN3ek9GCkxia2dMZ2NoVmplYzRSNHk0ZnNCdWdUMzVSc3RZQUVDZ2dFQUV5VTZkblRHZzFHZjM0Y0FRM1B0a09qMDRTblMKV0dVQTZPWTd4bHQ5WHBzclF0ekpNS0NaOEZiVWZBeVp2UkNvclhpN01BZzdwNTRUdWk5cmhvRlFMYW1ZRnJEZgpncEk3WjNCUVF3dkZCNUE3eWdQQmVRdzJHd2xkYVBuKzJrZTduZDZKdGIvZ1RJSjdFbmtLY041SXlmNHdqQ09TCjlWRmw3c2dldHMzMFFIYjlhZVBKTUJ4emlDM3N0K0x5azdEdmZMT2tOT0RvbHgyTE5aNW1hYkRiZ3BzLzlzdlIKU0ZYZEg5dGJRYWp5SEZnQnZCMVF6b3pSdTBnbGEvc0RHT0Z0MWtnQTE0OUlnM2ZSN3FhNGRIWDFoU012MmZPaQpNT1RFRDZxa1JwSHdGU3FsaVZPdzNPVkdOcnh5MGphWlhRSVZINUlqZmVFTUQwYnZzSS9uZ0lrTmFnPT0KLS0tLS1FTkQgUlNBIFBSSVZBVEUgS0VZLS0tLS0K"

	privateKeyBytes, err := base64.StdEncoding.DecodeString(privateKeyBase64)
	assert.NoError(t, err)

	return privateKeyBytes
}

func getTestPublicKey(t *testing.T) []byte {
	publicKeyBase64 := "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUNJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBZzhBTUlJQ0NnS0NBZ0VBb2Q3dFRUeVlCUjI0aDg1WEZaUkcKcUg4QXNuRTBXVHliRFZELzRYajdWSHY3RWErclU1S2cyVFdKNjhkL09BcCtNK1lMYnVMYXdIVk1mWWtQM0lhWgpTR1d6cHdCVXhxc0lmWTlLbEdaWjN3aGJIWi9EZWRCU2I1UjNkdnJjUEIvQmcrMkFucUVnRkV2N3Y4djZFT1psClJNU0RxR0t2VEU0a083UUFUR0JZbUJoTDZmNytPUnlRRmNLdUFZZ29DZmlKOG1hb3FkK1dIREk5TWMyTlBncncKMzhOaW1mQ3ZFM3VWbXljdFFyMDN3TTAyT1A0M0IyS3pCdUREc2ZKdUZWSVFWTUVtU2IyQ2ZqMjloWkpGMCtJWgpVZWYvVHhXQTZyVWpTK1pYSGtudXlYNDBVb1pYYUFJVU5zbUVEeVUxWHRKRTh5Ym1xSHdNK3BjT2dCSzh3TElXCk5LVkVFSDVtMjBsaStqMjdnSThvcVlNamJCYjdyYlI1L2JnSmdjL05qU2c4bTZrZDJzVC9TSmltMlI2eENFOEgKeVdTbEdvQkxIZTlSQUJYcUR4UTg5RCtiTGRRb1V5R1N2RVJVWXBBNzZYNGViY2tqdnR0UFl3cTFSWEZuS0VzbwpoUTQ0SVFySEFMTTRmcTQyRXF2WkZvTUxQVmhvT0xOSWd2NUlhU1lHZm9IMW1uQlZPZkJzZ3B4ejk0czRCNTJyCjFNcE5GaE1qaG1SSXBCcWYvSHNPalNtM05mUG1pYkVVQ0c2OEo3aSthU3ZvVTdwSnVZQzgyQW1TWmwxeWxLOTcKRjRUUG1RaGJUNG5yMlZxMS9oMGpwQUIzNW5DUS9tM09Sckl6RXYzL0F0UEdnbktlWENML3M0ZUQzd2hzbkNaTAowVmVMNmVFYWhoUFYydW05VlZzeVowVUNBd0VBQVE9PQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCg=="

	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyBase64)
	assert.NoError(t, err)

	return publicKeyBytes
}

func TestGenerateTokenResponseForAuthCode_FullOpenIDConnect(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	settings := &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		UserSessionIdleTimeoutInSeconds:         1200,
		UserSessionMaxLifetimeInSeconds:         2400,
		IncludeOpenIDConnectClaimsInAccessToken: true,
		RefreshTokenOfflineIdleTimeoutInSeconds: 1800,
		RefreshTokenOfflineMaxLifetimeInSeconds: 3600,
	}

	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

	now := time.Now().UTC()
	sub := uuid.New()
	sessionIdentifier := "test-session-123"

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	code := &models.Code{
		Id:                1,
		ClientId:          1,
		UserId:            1,
		Scope:             "openid profile email address phone groups attributes offline_access",
		Nonce:             "test-nonce",
		AuthenticatedAt:   now.Add(-5 * time.Minute),
		SessionIdentifier: sessionIdentifier,
		AcrLevel:          "urn:goiabada:pwd:otp_mandatory",
		AuthMethods:       "pwd otp",
	}
	client := &models.Client{
		Id:                                      1,
		ClientIdentifier:                        "test-client",
		TokenExpirationInSeconds:                900,
		RefreshTokenOfflineIdleTimeoutInSeconds: 3600,
		RefreshTokenOfflineMaxLifetimeInSeconds: 7200,
	}
	user := &models.User{
		Id:                  1,
		UpdatedAt:           sql.NullTime{Time: time.Now().Add(-1 * time.Minute), Valid: true},
		Subject:             sub,
		Email:               "test@example.com",
		EmailVerified:       true,
		Username:            "testuser",
		GivenName:           "Test",
		MiddleName:          "Middle",
		FamilyName:          "User",
		Nickname:            "Testy",
		Website:             "https://test.com",
		Gender:              "male",
		BirthDate:           sql.NullTime{Time: time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC), Valid: true},
		ZoneInfo:            "Europe/London",
		Locale:              "en-GB",
		PhoneNumber:         "+1234567890",
		PhoneNumberVerified: true,
		AddressLine1:        "123 Test St",
		AddressLine2:        "apartment 1",
		AddressLocality:     "Test City",
		AddressRegion:       "Test Region",
		AddressPostalCode:   "12345",
		AddressCountry:      "Test Country",
		Groups: []models.Group{
			{GroupIdentifier: "group1", IncludeInIdToken: true, IncludeInAccessToken: true},
			{GroupIdentifier: "group2", IncludeInIdToken: true, IncludeInAccessToken: false},
			{GroupIdentifier: "group3", IncludeInIdToken: false, IncludeInAccessToken: true},
			{GroupIdentifier: "group4", IncludeInIdToken: true, IncludeInAccessToken: true},
		},
		Attributes: []models.UserAttribute{
			{Key: "attr1", Value: "value1", IncludeInIdToken: true, IncludeInAccessToken: true},
			{Key: "attr2", Value: "value2", IncludeInIdToken: true, IncludeInAccessToken: false},
			{Key: "attr3", Value: "value3", IncludeInIdToken: false, IncludeInAccessToken: true},
			{Key: "attr4", Value: "value4", IncludeInIdToken: true, IncludeInAccessToken: true},
		},
	}

	mockDB.On("CodeLoadClient", mock.Anything, code).Return(nil)
	code.Client = *client
	mockDB.On("CodeLoadUser", mock.Anything, code).Return(nil)
	code.User = *user
	mockDB.On("UserLoadGroups", mock.Anything, &code.User).Return(nil)
	mockDB.On("GroupsLoadAttributes", mock.Anything, code.User.Groups).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, &code.User).Return(nil)
	mockDB.On("UserHasProfilePicture", mock.Anything, user.Id).Return(false, nil)
	mockDB.On("CreateRefreshToken", mock.Anything, mock.AnythingOfType("*models.RefreshToken")).Return(nil)
	mockDB.On("GetCurrentSigningKey", mock.Anything).Return(&models.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: privateKeyBytes,
	}, nil)

	response, err := tokenIssuer.GenerateTokenResponseForAuthCode(ctx, code)

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, "Bearer", response.TokenType)
	assert.Equal(t, int64(900), response.ExpiresIn)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.IdToken)
	assert.NotEmpty(t, response.RefreshToken)
	assert.Equal(t, "openid profile email address phone groups attributes offline_access authserver:userinfo", response.Scope)
	assert.Equal(t, int64(3600), response.RefreshExpiresIn)

	// validate Id token --------------------------------------------

	idClaims := verifyAndDecodeToken(t, response.IdToken, publicKeyBytes)
	assert.Equal(t, settings.Issuer, idClaims["iss"])
	assert.Equal(t, user.Subject.String(), idClaims["sub"])
	assert.Equal(t, client.ClientIdentifier, idClaims["aud"])
	assert.Equal(t, code.Nonce, idClaims["nonce"])
	assert.Equal(t, code.AcrLevel, idClaims["acr"])
	assert.Equal(t, code.AuthMethods, idClaims["amr"])
	assert.Equal(t, sessionIdentifier, idClaims["sid"])

	assertTimeClaimWithinRange(t, idClaims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, idClaims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, idClaims, "exp", 900*time.Second, "exp should be 900 seconds from now")
	assertTimeClaimWithinRange(t, idClaims, "updated_at", -60*time.Second, "updated_at should be 60 seconds ago")
	assertTimeClaimWithinRange(t, idClaims, "auth_time", -300*time.Second, "auth_time should be 300 seconds ago")

	assert.Contains(t, idClaims, "auth_time")
	authTimeUnix := idClaims["auth_time"].(float64)
	authTime := time.Unix(int64(authTimeUnix), 0)
	assert.Equal(t, now.Add(-300*time.Second).Unix(), authTime.Unix(), fmt.Sprintf("auth_time should be 300 seconds ago: %s", authTime))

	_, err = uuid.Parse(idClaims["jti"].(string))
	assert.NoError(t, err)

	assert.Equal(t, user.GetFullName(), idClaims["name"])
	assert.Equal(t, user.GivenName, idClaims["given_name"])
	assert.Equal(t, user.MiddleName, idClaims["middle_name"])
	assert.Equal(t, user.FamilyName, idClaims["family_name"])
	assert.Equal(t, user.Nickname, idClaims["nickname"])
	assert.Equal(t, user.Username, idClaims["preferred_username"])
	assert.Equal(t, "http://localhost:8081/account/profile", idClaims["profile"])
	assert.Equal(t, user.Website, idClaims["website"])
	assert.Equal(t, user.Gender, idClaims["gender"])
	assert.Equal(t, "1990-01-01", idClaims["birthdate"])
	assert.Equal(t, user.ZoneInfo, idClaims["zoneinfo"])
	assert.Equal(t, user.Locale, idClaims["locale"])
	assert.NotEmpty(t, idClaims["updated_at"])
	assert.Equal(t, user.Email, idClaims["email"])
	assert.Equal(t, user.EmailVerified, idClaims["email_verified"])
	assert.Equal(t, user.PhoneNumber, idClaims["phone_number"])
	assert.Equal(t, user.PhoneNumberVerified, idClaims["phone_number_verified"])
	address, ok := idClaims["address"].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, user.AddressLine1+"\r\n"+user.AddressLine2, address["street_address"])
	assert.Equal(t, user.AddressLocality, address["locality"])
	assert.Equal(t, user.AddressRegion, address["region"])
	assert.Equal(t, user.AddressPostalCode, address["postal_code"])
	assert.Equal(t, user.AddressCountry, address["country"])
	assert.Equal(t, "123 Test St\r\napartment 1\r\nTest City\r\nTest Region\r\n12345\r\nTest Country", address["formatted"])
	groups, ok := idClaims["groups"].([]interface{})
	assert.True(t, ok)
	assert.ElementsMatch(t, []string{"group1", "group2", "group4"}, groups)
	assert.Equal(t, 3, len(groups))
	attributes, ok := idClaims["attributes"].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "value1", attributes["attr1"])
	assert.Equal(t, "value2", attributes["attr2"])
	assert.Equal(t, "value4", attributes["attr4"])
	assert.Equal(t, 3, len(attributes))

	// validate Access token --------------------------------------------

	accessClaims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)
	assert.Equal(t, settings.Issuer, accessClaims["iss"])
	assert.Equal(t, user.Subject.String(), accessClaims["sub"])
	assert.Equal(t, "authserver", accessClaims["aud"])
	assert.Equal(t, code.Nonce, accessClaims["nonce"])
	assert.Equal(t, code.AcrLevel, accessClaims["acr"])
	assert.Equal(t, code.AuthMethods, accessClaims["amr"])
	assert.Equal(t, sessionIdentifier, accessClaims["sid"])
	assert.Equal(t, "Bearer", accessClaims["typ"])

	assertTimeClaimWithinRange(t, accessClaims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, accessClaims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, accessClaims, "exp", 900*time.Second, "exp should be 900 seconds from now")
	assertTimeClaimWithinRange(t, accessClaims, "updated_at", -60*time.Second, "updated_at should be 60 seconds ago")
	assertTimeClaimWithinRange(t, accessClaims, "auth_time", -300*time.Second, "auth_time should be 300 seconds ago")

	_, err = uuid.Parse(accessClaims["jti"].(string))
	assert.NoError(t, err)

	assert.Equal(t, user.GetFullName(), accessClaims["name"])
	assert.Equal(t, user.GivenName, accessClaims["given_name"])
	assert.Equal(t, user.MiddleName, accessClaims["middle_name"])
	assert.Equal(t, user.FamilyName, accessClaims["family_name"])
	assert.Equal(t, user.Nickname, accessClaims["nickname"])
	assert.Equal(t, user.Username, accessClaims["preferred_username"])
	assert.Equal(t, "http://localhost:8081/account/profile", accessClaims["profile"])
	assert.Equal(t, user.Website, accessClaims["website"])
	assert.Equal(t, user.Gender, accessClaims["gender"])
	assert.Equal(t, "1990-01-01", accessClaims["birthdate"])
	assert.Equal(t, user.ZoneInfo, accessClaims["zoneinfo"])
	assert.Equal(t, user.Locale, accessClaims["locale"])
	assert.NotEmpty(t, accessClaims["updated_at"])
	assert.Equal(t, user.Email, accessClaims["email"])
	assert.Equal(t, user.EmailVerified, accessClaims["email_verified"])
	assert.Equal(t, user.PhoneNumber, accessClaims["phone_number"])
	assert.Equal(t, user.PhoneNumberVerified, accessClaims["phone_number_verified"])
	address, ok = accessClaims["address"].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, user.AddressLine1+"\r\n"+user.AddressLine2, address["street_address"])
	assert.Equal(t, user.AddressLocality, address["locality"])
	assert.Equal(t, user.AddressRegion, address["region"])
	assert.Equal(t, user.AddressPostalCode, address["postal_code"])
	assert.Equal(t, user.AddressCountry, address["country"])
	assert.Equal(t, "123 Test St\r\napartment 1\r\nTest City\r\nTest Region\r\n12345\r\nTest Country", address["formatted"])
	groups, ok = accessClaims["groups"].([]interface{})
	assert.True(t, ok)
	assert.ElementsMatch(t, []string{"group1", "group3", "group4"}, groups)
	assert.Equal(t, 3, len(groups))
	attributes, ok = accessClaims["attributes"].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "value1", attributes["attr1"])
	assert.Equal(t, "value3", attributes["attr3"])
	assert.Equal(t, "value4", attributes["attr4"])
	assert.Equal(t, 3, len(attributes))
	assert.Equal(t, "openid profile email address phone groups attributes offline_access authserver:userinfo", accessClaims["scope"])

	// validate Refresh token --------------------------------------------

	refreshClaims := verifyAndDecodeToken(t, response.RefreshToken, publicKeyBytes)
	assert.Equal(t, user.Subject.String(), refreshClaims["sub"])
	assert.Equal(t, "https://test-issuer.com", refreshClaims["aud"])
	assert.Equal(t, "https://test-issuer.com", refreshClaims["iss"])
	assert.Equal(t, "Offline", refreshClaims["typ"])
	assert.Equal(t, "openid profile email address phone groups attributes offline_access authserver:userinfo", refreshClaims["scope"])

	assertTimeClaimWithinRange(t, refreshClaims, "exp", 3600*time.Second, "exp should be 3600 seconds from now")
	assertTimeClaimWithinRange(t, refreshClaims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, refreshClaims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, refreshClaims, "offline_access_max_lifetime", 7200*time.Second, "offline_access_max_lifetime should be 7200 seconds from now")

	_, err = uuid.Parse(refreshClaims["jti"].(string))
	assert.NoError(t, err)

	mockDB.AssertExpectations(t)
}

func TestGenerateTokenResponseForAuthCode_MinimalScope(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	settings := &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		UserSessionIdleTimeoutInSeconds:         1200,
		UserSessionMaxLifetimeInSeconds:         2400,
		IncludeOpenIDConnectClaimsInAccessToken: false,
		RefreshTokenOfflineIdleTimeoutInSeconds: 1800,
		RefreshTokenOfflineMaxLifetimeInSeconds: 3600,
	}

	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

	now := time.Now().UTC()
	sub := uuid.New()
	sessionIdentifier := "test-session-123"

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	code := &models.Code{
		Id:                2,
		ClientId:          2,
		UserId:            2,
		Scope:             "openid",
		Nonce:             "minimal-nonce",
		AuthenticatedAt:   now.Add(-120 * time.Second), // Authenticated 2 minutes ago
		SessionIdentifier: sessionIdentifier,
		AcrLevel:          "urn:goiabada:pwd",
		AuthMethods:       "pwd",
	}
	client := &models.Client{
		Id:               2,
		ClientIdentifier: "minimal-client",
	}
	user := &models.User{
		Id:      2,
		Subject: sub,
		Email:   "minimal@example.com",
	}

	mockDB.On("CodeLoadClient", mock.Anything, code).Return(nil)
	code.Client = *client
	mockDB.On("CodeLoadUser", mock.Anything, code).Return(nil)
	code.User = *user
	mockDB.On("UserLoadGroups", mock.Anything, &code.User).Return(nil)
	mockDB.On("GroupsLoadAttributes", mock.Anything, code.User.Groups).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, &code.User).Return(nil)
	mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(&models.UserSession{
		Id:           1,
		UserId:       1,
		Started:      now.Add(-30 * time.Minute),
		LastAccessed: now.Add(-5 * time.Minute),
	}, nil)
	mockDB.On("CreateRefreshToken", mock.Anything, mock.AnythingOfType("*models.RefreshToken")).Return(nil)
	mockDB.On("GetCurrentSigningKey", mock.Anything).Return(&models.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: privateKeyBytes,
	}, nil)

	response, err := tokenIssuer.GenerateTokenResponseForAuthCode(ctx, code)

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, "Bearer", response.TokenType)
	assert.Equal(t, int64(600), response.ExpiresIn)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.IdToken)
	assert.NotEmpty(t, response.RefreshToken)
	assert.Equal(t, "openid authserver:userinfo", response.Scope)
	assert.InDelta(t, int64(600), response.RefreshExpiresIn, 1)

	// validate Id token --------------------------------------------

	idClaims := verifyAndDecodeToken(t, response.IdToken, publicKeyBytes)
	assert.Equal(t, "https://test-issuer.com", idClaims["iss"])
	assert.Equal(t, user.Subject.String(), idClaims["sub"])
	assert.Equal(t, client.ClientIdentifier, idClaims["aud"])
	assert.Equal(t, code.Nonce, idClaims["nonce"])
	assert.Equal(t, code.AcrLevel, idClaims["acr"])
	assert.Equal(t, code.AuthMethods, idClaims["amr"])
	assert.Equal(t, sessionIdentifier, idClaims["sid"])

	assertTimeClaimWithinRange(t, idClaims, "auth_time", -120*time.Second, "auth_time should be 2 minutes ago")
	assertTimeClaimWithinRange(t, idClaims, "exp", 600*time.Second, "exp should be 10 minutes in the future")
	assertTimeClaimWithinRange(t, idClaims, "iat", 0, "iat should be now")
	assertTimeClaimWithinRange(t, idClaims, "nbf", 0, "nbf should be now")

	_, err = uuid.Parse(idClaims["jti"].(string))
	assert.NoError(t, err)

	// validate Access token --------------------------------------------

	accessClaims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)
	assert.Equal(t, "https://test-issuer.com", accessClaims["iss"])
	assert.Equal(t, user.Subject.String(), accessClaims["sub"])
	assert.Equal(t, code.Nonce, accessClaims["nonce"])
	assert.Equal(t, code.AcrLevel, accessClaims["acr"])
	assert.Equal(t, code.AuthMethods, accessClaims["amr"])
	assert.Equal(t, sessionIdentifier, accessClaims["sid"])
	assert.Equal(t, "Bearer", accessClaims["typ"])
	assert.Equal(t, "openid authserver:userinfo", accessClaims["scope"])

	assertTimeClaimWithinRange(t, accessClaims, "auth_time", -120*time.Second, "auth_time should be 2 minutes ago")
	assertTimeClaimWithinRange(t, accessClaims, "exp", 600*time.Second, "exp should be 10 minutes in the future")
	assertTimeClaimWithinRange(t, accessClaims, "iat", 0, "iat should be now")
	assertTimeClaimWithinRange(t, accessClaims, "nbf", 0, "nbf should be now")

	_, err = uuid.Parse(accessClaims["jti"].(string))
	assert.NoError(t, err)

	// validate Refresh token --------------------------------------------

	refreshClaims := verifyAndDecodeToken(t, response.RefreshToken, publicKeyBytes)
	assert.Equal(t, user.Subject.String(), refreshClaims["sub"])
	assert.Equal(t, "https://test-issuer.com", refreshClaims["aud"])
	assert.Equal(t, "Refresh", refreshClaims["typ"])
	assert.Equal(t, sessionIdentifier, refreshClaims["sid"])
	assert.Equal(t, "openid authserver:userinfo", refreshClaims["scope"])

	assertTimeClaimWithinRange(t, refreshClaims, "exp", 600*time.Second, "exp should be 10 minutes in the future")
	assertTimeClaimWithinRange(t, refreshClaims, "iat", 0, "iat should be now")
	assertTimeClaimWithinRange(t, refreshClaims, "nbf", 0, "nbf should be now")

	_, err = uuid.Parse(refreshClaims["jti"].(string))
	assert.NoError(t, err)

	mockDB.AssertExpectations(t)
}

func TestGenerateTokenResponseForAuthCode_ClientOverrideAndMixedScopes(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	settings := &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		UserSessionIdleTimeoutInSeconds:         1200,
		UserSessionMaxLifetimeInSeconds:         2400,
		IncludeOpenIDConnectClaimsInAccessToken: false,
		RefreshTokenOfflineIdleTimeoutInSeconds: 1800,
		RefreshTokenOfflineMaxLifetimeInSeconds: 3600,
	}

	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

	now := time.Now().UTC()
	sub := uuid.New()
	sessionIdentifier := "test-session-123"

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	code := &models.Code{
		Id:                3,
		ClientId:          3,
		UserId:            3,
		Scope:             "openid profile email authserver:userinfo resource1:read resource2:write",
		Nonce:             "mixed-nonce",
		AuthenticatedAt:   now.Add(-60 * time.Second),
		SessionIdentifier: sessionIdentifier,
		AcrLevel:          "urn:goiabada:pwd:otp_ifpossible",
		AuthMethods:       "pwd otp",
	}
	client := &models.Client{
		Id:                                      3,
		ClientIdentifier:                        "mixed-client",
		TokenExpirationInSeconds:                1500,
		RefreshTokenOfflineIdleTimeoutInSeconds: 2400,
		RefreshTokenOfflineMaxLifetimeInSeconds: 4800,
		IncludeOpenIDConnectClaimsInAccessToken: "on",
	}
	user := &models.User{
		Id:            3,
		Subject:       sub,
		Email:         "mixed@example.com",
		EmailVerified: true,
		Username:      "mixeduser",
		GivenName:     "Mixed",
		FamilyName:    "User",
		UpdatedAt:     sql.NullTime{Time: now.Add(-24 * time.Hour), Valid: true},
		Groups: []models.Group{
			{GroupIdentifier: "group1", IncludeInIdToken: true, IncludeInAccessToken: true},
			{GroupIdentifier: "group2", IncludeInIdToken: false, IncludeInAccessToken: true},
		},
		Attributes: []models.UserAttribute{
			{Key: "attr1", Value: "value1", IncludeInIdToken: true, IncludeInAccessToken: true},
			{Key: "attr2", Value: "value2", IncludeInIdToken: true, IncludeInAccessToken: false},
		},
	}

	mockDB.On("CodeLoadClient", mock.Anything, code).Return(nil)
	code.Client = *client
	mockDB.On("CodeLoadUser", mock.Anything, code).Return(nil)
	code.User = *user
	mockDB.On("UserLoadGroups", mock.Anything, &code.User).Return(nil)
	mockDB.On("GroupsLoadAttributes", mock.Anything, code.User.Groups).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, &code.User).Return(nil)
	mockDB.On("UserHasProfilePicture", mock.Anything, user.Id).Return(false, nil)
	mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(&models.UserSession{
		Id:           1,
		UserId:       3,
		Started:      now.Add(-30 * time.Minute),
		LastAccessed: now.Add(-5 * time.Minute),
	}, nil)
	mockDB.On("CreateRefreshToken", mock.Anything, mock.AnythingOfType("*models.RefreshToken")).Return(nil)
	mockDB.On("GetCurrentSigningKey", mock.Anything).Return(&models.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: privateKeyBytes,
	}, nil)

	response, err := tokenIssuer.GenerateTokenResponseForAuthCode(ctx, code)

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, "Bearer", response.TokenType)
	assert.Equal(t, int64(1500), response.ExpiresIn)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.IdToken)
	assert.NotEmpty(t, response.RefreshToken)
	assert.Equal(t, "openid profile email authserver:userinfo resource1:read resource2:write", response.Scope)
	assert.InDelta(t, int64(600), response.RefreshExpiresIn, 1)

	// validate Id token --------------------------------------------

	idClaims := verifyAndDecodeToken(t, response.IdToken, publicKeyBytes)
	assert.Equal(t, settings.Issuer, idClaims["iss"])
	assert.Equal(t, user.Subject.String(), idClaims["sub"])
	assert.Equal(t, client.ClientIdentifier, idClaims["aud"])
	assert.Equal(t, code.Nonce, idClaims["nonce"])
	assert.Equal(t, code.AcrLevel, idClaims["acr"])
	assert.Equal(t, code.AuthMethods, idClaims["amr"])
	assert.Equal(t, sessionIdentifier, idClaims["sid"])

	assertTimeClaimWithinRange(t, idClaims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, idClaims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, idClaims, "exp", 1500*time.Second, "exp should be 1500 seconds from now")
	assertTimeClaimWithinRange(t, idClaims, "auth_time", -60*time.Second, "auth_time should be 60 seconds ago")
	assertTimeClaimWithinRange(t, idClaims, "updated_at", -24*time.Hour, "updated_at should be 24 hours ago")

	_, err = uuid.Parse(idClaims["jti"].(string))
	assert.NoError(t, err)

	assert.Equal(t, user.Email, idClaims["email"])
	assert.Equal(t, user.EmailVerified, idClaims["email_verified"])
	assert.Equal(t, user.Username, idClaims["preferred_username"])
	assert.Equal(t, user.GivenName, idClaims["given_name"])
	assert.Equal(t, user.FamilyName, idClaims["family_name"])
	assert.Equal(t, user.GetFullName(), idClaims["name"])
	assert.Equal(t, "http://localhost:8081/account/profile", idClaims["profile"])

	assert.NotContains(t, idClaims, "groups")
	assert.NotContains(t, idClaims, "attributes")

	// validate Access token --------------------------------------------

	accessClaims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)
	assert.Equal(t, settings.Issuer, accessClaims["iss"])
	assert.Equal(t, user.Subject.String(), accessClaims["sub"])
	assert.Equal(t, []interface{}{"authserver", "resource1", "resource2"}, accessClaims["aud"])
	assert.Equal(t, code.Nonce, accessClaims["nonce"])
	assert.Equal(t, code.AcrLevel, accessClaims["acr"])
	assert.Equal(t, code.AuthMethods, accessClaims["amr"])
	assert.Equal(t, sessionIdentifier, accessClaims["sid"])
	assert.Equal(t, "Bearer", accessClaims["typ"])

	assertTimeClaimWithinRange(t, accessClaims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, accessClaims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, accessClaims, "exp", 1500*time.Second, "exp should be 1500 seconds from now")
	assertTimeClaimWithinRange(t, accessClaims, "auth_time", -60*time.Second, "auth_time should be 60 seconds ago")
	assertTimeClaimWithinRange(t, accessClaims, "updated_at", -24*time.Hour, "updated_at should be 24 hours ago")

	_, err = uuid.Parse(accessClaims["jti"].(string))
	assert.NoError(t, err)

	assert.Equal(t, user.Email, accessClaims["email"])
	assert.Equal(t, user.EmailVerified, accessClaims["email_verified"])
	assert.Equal(t, user.Username, accessClaims["preferred_username"])
	assert.Equal(t, user.GivenName, accessClaims["given_name"])
	assert.Equal(t, user.FamilyName, accessClaims["family_name"])
	assert.Equal(t, user.GetFullName(), accessClaims["name"])
	assert.Equal(t, "http://localhost:8081/account/profile", accessClaims["profile"])

	assert.NotContains(t, accessClaims, "groups")
	assert.NotContains(t, accessClaims, "attributes")
	assert.Equal(t, "openid profile email authserver:userinfo resource1:read resource2:write", accessClaims["scope"])

	// validate Refresh token --------------------------------------------

	refreshClaims := verifyAndDecodeToken(t, response.RefreshToken, publicKeyBytes)
	assert.Equal(t, user.Subject.String(), refreshClaims["sub"])
	assert.Equal(t, settings.Issuer, refreshClaims["aud"])
	assert.Equal(t, settings.Issuer, refreshClaims["iss"])
	assert.Equal(t, "Refresh", refreshClaims["typ"])
	assert.Equal(t, sessionIdentifier, refreshClaims["sid"])
	assert.Equal(t, "openid profile email authserver:userinfo resource1:read resource2:write", refreshClaims["scope"])

	assertTimeClaimWithinRange(t, refreshClaims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, refreshClaims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, refreshClaims, "exp", 600*time.Second, "exp should be 600 seconds from now")

	_, err = uuid.Parse(refreshClaims["jti"].(string))
	assert.NoError(t, err)

	mockDB.AssertExpectations(t)
}

func TestGenerateTokenResponseForAuthCode_ClientOverrideAndCustomScope(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	settings := &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		UserSessionIdleTimeoutInSeconds:         1200,
		UserSessionMaxLifetimeInSeconds:         2400,
		IncludeOpenIDConnectClaimsInAccessToken: false,
		RefreshTokenOfflineIdleTimeoutInSeconds: 1800,
		RefreshTokenOfflineMaxLifetimeInSeconds: 3600,
	}

	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

	now := time.Now().UTC()
	sub := uuid.New()
	sessionIdentifier := "test-session-123"

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	code := &models.Code{
		Id:                4,
		ClientId:          4,
		UserId:            4,
		Scope:             "resource1:read resource2:write offline_access",
		Nonce:             "custom-nonce",
		AuthenticatedAt:   now.Add(-30 * time.Second),
		SessionIdentifier: sessionIdentifier,
		AcrLevel:          "urn:goiabada:pwd",
		AuthMethods:       "pwd",
	}
	client := &models.Client{
		Id:                                      4,
		ClientIdentifier:                        "custom-client",
		TokenExpirationInSeconds:                1200,
		RefreshTokenOfflineIdleTimeoutInSeconds: 3000,
		RefreshTokenOfflineMaxLifetimeInSeconds: 6000,
		IncludeOpenIDConnectClaimsInAccessToken: "off",
	}
	user := &models.User{
		Id:      4,
		Subject: sub,
		Email:   "custom@example.com",
	}

	mockDB.On("CodeLoadClient", mock.Anything, code).Return(nil)
	code.Client = *client
	mockDB.On("CodeLoadUser", mock.Anything, code).Return(nil)
	code.User = *user
	mockDB.On("UserLoadGroups", mock.Anything, &code.User).Return(nil)
	mockDB.On("GroupsLoadAttributes", mock.Anything, code.User.Groups).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, &code.User).Return(nil)
	mockDB.On("CreateRefreshToken", mock.Anything, mock.AnythingOfType("*models.RefreshToken")).Return(nil)
	mockDB.On("GetCurrentSigningKey", mock.Anything).Return(&models.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: privateKeyBytes,
	}, nil)

	response, err := tokenIssuer.GenerateTokenResponseForAuthCode(ctx, code)

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, "Bearer", response.TokenType)
	assert.Equal(t, int64(1200), response.ExpiresIn)
	assert.NotEmpty(t, response.AccessToken)
	assert.Empty(t, response.IdToken)
	assert.NotEmpty(t, response.RefreshToken)
	assert.Equal(t, "resource1:read resource2:write offline_access", response.Scope)
	assert.Equal(t, int64(3000), response.RefreshExpiresIn)

	accessClaims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)
	assert.Equal(t, settings.Issuer, accessClaims["iss"])
	assert.Equal(t, user.Subject.String(), accessClaims["sub"])
	assert.Equal(t, []interface{}{"resource1", "resource2"}, accessClaims["aud"])
	assert.Equal(t, code.Nonce, accessClaims["nonce"])
	assert.Equal(t, code.AcrLevel, accessClaims["acr"])
	assert.Equal(t, code.AuthMethods, accessClaims["amr"])
	assert.Equal(t, sessionIdentifier, accessClaims["sid"])
	assert.Equal(t, "Bearer", accessClaims["typ"])

	assertTimeClaimWithinRange(t, accessClaims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, accessClaims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, accessClaims, "exp", 1200*time.Second, "exp should be 1200 seconds from now")
	assertTimeClaimWithinRange(t, accessClaims, "auth_time", -30*time.Second, "auth_time should be 30 seconds ago")

	_, err = uuid.Parse(accessClaims["jti"].(string))
	assert.NoError(t, err)

	assert.Equal(t, "resource1:read resource2:write offline_access", accessClaims["scope"])
	assert.NotContains(t, accessClaims, "email")
	assert.NotContains(t, accessClaims, "name")

	refreshClaims := verifyAndDecodeToken(t, response.RefreshToken, publicKeyBytes)
	assert.Equal(t, user.Subject.String(), refreshClaims["sub"])
	assert.Equal(t, settings.Issuer, refreshClaims["aud"])
	assert.Equal(t, settings.Issuer, refreshClaims["iss"])
	assert.Equal(t, "Offline", refreshClaims["typ"])
	assert.Equal(t, "resource1:read resource2:write offline_access", refreshClaims["scope"])

	assertTimeClaimWithinRange(t, refreshClaims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, refreshClaims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, refreshClaims, "exp", 3000*time.Second, "exp should be 3000 seconds from now")
	assertTimeClaimWithinRange(t, refreshClaims, "offline_access_max_lifetime", 6000*time.Second, "offline_access_max_lifetime should be 6000 seconds from now")

	_, err = uuid.Parse(refreshClaims["jti"].(string))
	assert.NoError(t, err)

	mockDB.AssertExpectations(t)
}

func TestGenerateTokenResponseForAuthCode_CustomScope(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	settings := &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		UserSessionIdleTimeoutInSeconds:         1200,
		UserSessionMaxLifetimeInSeconds:         2400,
		IncludeOpenIDConnectClaimsInAccessToken: false,
		RefreshTokenOfflineIdleTimeoutInSeconds: 1800,
		RefreshTokenOfflineMaxLifetimeInSeconds: 3600,
	}

	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

	now := time.Now().UTC()
	sub := uuid.New()
	sessionIdentifier := "test-session-123"

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	code := &models.Code{
		Id:                5,
		ClientId:          5,
		UserId:            5,
		Scope:             "resource1:read",
		Nonce:             "custom-nonce",
		AuthenticatedAt:   now.Add(-30 * time.Second),
		SessionIdentifier: sessionIdentifier,
		AcrLevel:          "urn:goiabada:pwd",
		AuthMethods:       "pwd",
	}
	client := &models.Client{
		Id:               5,
		ClientIdentifier: "custom-scope-client",
	}
	user := &models.User{
		Id:      5,
		Subject: sub,
		Email:   "custom@example.com",
	}

	mockDB.On("CodeLoadClient", mock.Anything, code).Return(nil)
	code.Client = *client
	mockDB.On("CodeLoadUser", mock.Anything, code).Return(nil)
	code.User = *user
	mockDB.On("UserLoadGroups", mock.Anything, &code.User).Return(nil)
	mockDB.On("GroupsLoadAttributes", mock.Anything, code.User.Groups).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, &code.User).Return(nil)
	mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(&models.UserSession{
		Id:           1,
		UserId:       5,
		Started:      now.Add(-30 * time.Minute),
		LastAccessed: now.Add(-5 * time.Minute),
	}, nil)
	mockDB.On("CreateRefreshToken", mock.Anything, mock.AnythingOfType("*models.RefreshToken")).Return(nil)
	mockDB.On("GetCurrentSigningKey", mock.Anything).Return(&models.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: privateKeyBytes,
	}, nil)

	response, err := tokenIssuer.GenerateTokenResponseForAuthCode(ctx, code)

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, "Bearer", response.TokenType)
	assert.Equal(t, int64(600), response.ExpiresIn)
	assert.NotEmpty(t, response.AccessToken)
	assert.Empty(t, response.IdToken)
	assert.NotEmpty(t, response.RefreshToken)
	assert.Equal(t, "resource1:read", response.Scope)
	assert.InDelta(t, int64(600), response.RefreshExpiresIn, 1)

	accessClaims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)
	assert.Equal(t, settings.Issuer, accessClaims["iss"])
	assert.Equal(t, user.Subject.String(), accessClaims["sub"])
	assert.Equal(t, "resource1", accessClaims["aud"])
	assert.Equal(t, code.Nonce, accessClaims["nonce"])
	assert.Equal(t, code.AcrLevel, accessClaims["acr"])
	assert.Equal(t, code.AuthMethods, accessClaims["amr"])
	assert.Equal(t, sessionIdentifier, accessClaims["sid"])
	assert.Equal(t, "Bearer", accessClaims["typ"])

	assertTimeClaimWithinRange(t, accessClaims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, accessClaims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, accessClaims, "exp", 600*time.Second, "exp should be 600 seconds from now")
	assertTimeClaimWithinRange(t, accessClaims, "auth_time", -30*time.Second, "auth_time should be 30 seconds ago")

	_, err = uuid.Parse(accessClaims["jti"].(string))
	assert.NoError(t, err)

	assert.Equal(t, "resource1:read", accessClaims["scope"])
	assert.NotContains(t, accessClaims, "email")
	assert.NotContains(t, accessClaims, "name")

	refreshClaims := verifyAndDecodeToken(t, response.RefreshToken, publicKeyBytes)
	assert.Equal(t, user.Subject.String(), refreshClaims["sub"])
	assert.Equal(t, settings.Issuer, refreshClaims["aud"])
	assert.Equal(t, settings.Issuer, refreshClaims["iss"])
	assert.Equal(t, "Refresh", refreshClaims["typ"])
	assert.Equal(t, "resource1:read", refreshClaims["scope"])

	assertTimeClaimWithinRange(t, refreshClaims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, refreshClaims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, refreshClaims, "exp", 600*time.Second, "exp should be 600 seconds from now")

	_, err = uuid.Parse(refreshClaims["jti"].(string))
	assert.NoError(t, err)

	mockDB.AssertExpectations(t)
}

func TestGenerateAccessToken(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	settings := &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		IncludeOpenIDConnectClaimsInAccessToken: true,
	}

	now := time.Now().UTC()
	sub := uuid.New()
	sessionIdentifier := "test-session-123"

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	assert.NoError(t, err)

	code := &models.Code{
		Id:                1,
		ClientId:          1,
		UserId:            1,
		Scope:             "openid profile email",
		Nonce:             "test-nonce",
		AuthenticatedAt:   now.Add(-5 * time.Minute),
		SessionIdentifier: sessionIdentifier,
		AcrLevel:          "urn:goiabada:pwd",
		AuthMethods:       "pwd",
	}
	client := &models.Client{
		Id:                                      1,
		ClientIdentifier:                        "test-client",
		TokenExpirationInSeconds:                900,
		IncludeOpenIDConnectClaimsInAccessToken: "on",
	}
	user := &models.User{
		Id:            1,
		Subject:       sub,
		Email:         "test@example.com",
		EmailVerified: true,
		Username:      "testuser",
		GivenName:     "Test",
		FamilyName:    "User",
		UpdatedAt:     sql.NullTime{Time: now.Add(-1 * time.Hour), Valid: true},
	}

	code.Client = *client
	code.User = *user

	mockDB.On("UserHasProfilePicture", mock.Anything, user.Id).Return(false, nil)

	accessToken, scope, err := tokenIssuer.generateAccessToken(settings, code, code.Scope, now, privKey, "test-key-id")
	assert.NoError(t, err)
	assert.NotEmpty(t, accessToken)
	assert.Equal(t, "openid profile email authserver:userinfo", scope)

	claims := verifyAndDecodeToken(t, accessToken, publicKeyBytes)

	assert.Equal(t, settings.Issuer, claims["iss"])
	assert.Equal(t, user.Subject.String(), claims["sub"])
	assert.Equal(t, constants.AuthServerResourceIdentifier, claims["aud"])
	assert.Equal(t, code.Nonce, claims["nonce"])
	assert.Equal(t, code.AcrLevel, claims["acr"])
	assert.Equal(t, code.AuthMethods, claims["amr"])
	assert.Equal(t, sessionIdentifier, claims["sid"])
	assert.Equal(t, "Bearer", claims["typ"])

	assertTimeClaimWithinRange(t, claims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, claims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, claims, "exp", 900*time.Second, "exp should be 900 seconds from now")
	assertTimeClaimWithinRange(t, claims, "auth_time", -300*time.Second, "auth_time should be 300 seconds ago")

	_, err = uuid.Parse(claims["jti"].(string))
	assert.NoError(t, err)

	assert.Equal(t, user.GetFullName(), claims["name"])
	assert.Equal(t, user.GivenName, claims["given_name"])
	assert.Equal(t, user.FamilyName, claims["family_name"])
	assert.Equal(t, user.Username, claims["preferred_username"])
	assert.Equal(t, "http://localhost:8081/account/profile", claims["profile"])
	assert.Equal(t, user.Email, claims["email"])
	assert.Equal(t, user.EmailVerified, claims["email_verified"])
	assert.Equal(t, "openid profile email authserver:userinfo", claims["scope"])

	assertTimeClaimWithinRange(t, claims, "updated_at", -1*time.Hour, "updated_at should be 1 hour ago")
}

func TestGenerateAccessToken_CustomScope(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	settings := &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		IncludeOpenIDConnectClaimsInAccessToken: false,
	}

	now := time.Now().UTC()
	sub := uuid.New()
	sessionIdentifier := "test-session-456"

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	assert.NoError(t, err)

	code := &models.Code{
		Id:                2,
		ClientId:          2,
		UserId:            2,
		Scope:             "resource1:read resource2:write",
		Nonce:             "custom-nonce",
		AuthenticatedAt:   now.Add(-10 * time.Minute),
		SessionIdentifier: sessionIdentifier,
		AcrLevel:          "urn:goiabada:pwd:otp_mandatory",
		AuthMethods:       "pwd otp",
	}
	client := &models.Client{
		Id:               2,
		ClientIdentifier: "custom-client",
	}
	user := &models.User{
		Id:      2,
		Subject: sub,
	}

	code.Client = *client
	code.User = *user

	accessToken, scope, err := tokenIssuer.generateAccessToken(settings, code, code.Scope, now, privKey, "test-key-id")
	assert.NoError(t, err)
	assert.NotEmpty(t, accessToken)
	assert.Equal(t, "resource1:read resource2:write", scope)

	claims := verifyAndDecodeToken(t, accessToken, publicKeyBytes)

	assert.Equal(t, settings.Issuer, claims["iss"])
	assert.Equal(t, user.Subject.String(), claims["sub"])
	assert.Equal(t, []interface{}{"resource1", "resource2"}, claims["aud"])
	assert.Equal(t, code.Nonce, claims["nonce"])
	assert.Equal(t, code.AcrLevel, claims["acr"])
	assert.Equal(t, code.AuthMethods, claims["amr"])
	assert.Equal(t, sessionIdentifier, claims["sid"])
	assert.Equal(t, "Bearer", claims["typ"])

	assertTimeClaimWithinRange(t, claims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, claims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, claims, "exp", 600*time.Second, "exp should be 600 seconds from now")
	assertTimeClaimWithinRange(t, claims, "auth_time", -600*time.Second, "auth_time should be 600 seconds ago")

	_, err = uuid.Parse(claims["jti"].(string))
	assert.NoError(t, err)

	assert.Equal(t, "resource1:read resource2:write", claims["scope"])

	// Verify that no OpenID Connect claims are included
	assert.NotContains(t, claims, "name")
	assert.NotContains(t, claims, "email")
	assert.NotContains(t, claims, "profile")
}

func TestGenerateAccessToken_WithGroupsAndAttributes(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	settings := &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		IncludeOpenIDConnectClaimsInAccessToken: true,
	}

	now := time.Now().UTC()
	sub := uuid.New()
	sessionIdentifier := "test-session-789"

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	assert.NoError(t, err)

	code := &models.Code{
		Id:                3,
		ClientId:          3,
		UserId:            3,
		Scope:             "openid profile email groups attributes",
		Nonce:             "groups-attributes-nonce",
		AuthenticatedAt:   now.Add(-15 * time.Minute),
		SessionIdentifier: sessionIdentifier,
		AcrLevel:          "urn:goiabada:pwd",
		AuthMethods:       "pwd",
	}
	client := &models.Client{
		Id:                                      3,
		ClientIdentifier:                        "groups-attributes-client",
		TokenExpirationInSeconds:                1200,
		IncludeOpenIDConnectClaimsInAccessToken: "on",
	}
	user := &models.User{
		Id:            3,
		Subject:       sub,
		Email:         "groups.attributes@example.com",
		EmailVerified: true,
		Username:      "groupsuser",
		GivenName:     "Groups",
		FamilyName:    "User",
		UpdatedAt:     sql.NullTime{Time: now.Add(-2 * time.Hour), Valid: true},
		Groups: []models.Group{
			{GroupIdentifier: "group1", IncludeInAccessToken: true},
			{GroupIdentifier: "group2", IncludeInAccessToken: false},
			{GroupIdentifier: "group3", IncludeInAccessToken: true},
		},
		Attributes: []models.UserAttribute{
			{Key: "attr1", Value: "value1", IncludeInAccessToken: true},
			{Key: "attr2", Value: "value2", IncludeInAccessToken: false},
			{Key: "attr3", Value: "value3", IncludeInAccessToken: true},
		},
	}

	code.Client = *client
	code.User = *user

	mockDB.On("UserHasProfilePicture", mock.Anything, user.Id).Return(false, nil)

	accessToken, scope, err := tokenIssuer.generateAccessToken(settings, code, code.Scope, now, privKey, "test-key-id")
	assert.NoError(t, err)
	assert.NotEmpty(t, accessToken)
	assert.Equal(t, "openid profile email groups attributes authserver:userinfo", scope)

	claims := verifyAndDecodeToken(t, accessToken, publicKeyBytes)

	assert.Equal(t, settings.Issuer, claims["iss"])
	assert.Equal(t, user.Subject.String(), claims["sub"])
	assert.Equal(t, constants.AuthServerResourceIdentifier, claims["aud"])
	assert.Equal(t, code.Nonce, claims["nonce"])
	assert.Equal(t, code.AcrLevel, claims["acr"])
	assert.Equal(t, code.AuthMethods, claims["amr"])
	assert.Equal(t, sessionIdentifier, claims["sid"])
	assert.Equal(t, "Bearer", claims["typ"])

	assertTimeClaimWithinRange(t, claims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, claims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, claims, "exp", 1200*time.Second, "exp should be 1200 seconds from now")
	assertTimeClaimWithinRange(t, claims, "auth_time", -900*time.Second, "auth_time should be 900 seconds ago")

	_, err = uuid.Parse(claims["jti"].(string))
	assert.NoError(t, err)

	assert.Equal(t, user.GetFullName(), claims["name"])
	assert.Equal(t, user.GivenName, claims["given_name"])
	assert.Equal(t, user.FamilyName, claims["family_name"])
	assert.Equal(t, user.Username, claims["preferred_username"])
	assert.Equal(t, "http://localhost:8081/account/profile", claims["profile"])
	assert.Equal(t, user.Email, claims["email"])
	assert.Equal(t, user.EmailVerified, claims["email_verified"])

	assert.Equal(t, "openid profile email groups attributes authserver:userinfo", claims["scope"])

	assertTimeClaimWithinRange(t, claims, "updated_at", -2*time.Hour, "updated_at should be 2 hours ago")

	// Check groups claim
	groups, ok := claims["groups"].([]interface{})
	assert.True(t, ok)
	assert.ElementsMatch(t, []string{"group1", "group3"}, groups)

	// Check attributes claim
	attributes, ok := claims["attributes"].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "value1", attributes["attr1"])
	assert.Equal(t, "value3", attributes["attr3"])
	assert.NotContains(t, attributes, "attr2")
}

func TestGenerateAccessToken_InvalidScope(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	settings := &models.Settings{
		Issuer:                   "https://test-issuer.com",
		TokenExpirationInSeconds: 600,
	}

	now := time.Now().UTC()
	sub := uuid.New()
	sessionIdentifier := "test-session-invalid"

	privateKeyBytes := getTestPrivateKey(t)

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	assert.NoError(t, err)

	code := &models.Code{
		Id:                4,
		ClientId:          4,
		UserId:            4,
		Scope:             "invalid-scope",
		Nonce:             "invalid-nonce",
		AuthenticatedAt:   now.Add(-5 * time.Minute),
		SessionIdentifier: sessionIdentifier,
		AcrLevel:          "urn:goiabada:pwd",
		AuthMethods:       "pwd",
	}
	client := &models.Client{
		Id:               4,
		ClientIdentifier: "invalid-client",
	}
	user := &models.User{
		Id:      4,
		Subject: sub,
	}

	code.Client = *client
	code.User = *user

	_, _, err = tokenIssuer.generateAccessToken(settings, code, code.Scope, now, privKey, "test-key-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid scope")
}

func TestGenerateIdToken_FullScope(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	settings := &models.Settings{
		Issuer:                   "https://test-issuer.com",
		TokenExpirationInSeconds: 600,
	}

	now := time.Now().UTC()
	sub := uuid.New()
	sessionIdentifier := "test-session-123"

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	assert.NoError(t, err)

	code := &models.Code{
		Id:                1,
		ClientId:          1,
		UserId:            1,
		Scope:             "openid profile email address phone groups attributes",
		Nonce:             "test-nonce",
		AuthenticatedAt:   now.Add(-5 * time.Minute),
		SessionIdentifier: sessionIdentifier,
		AcrLevel:          "urn:goiabada:pwd:otp_mandatory",
		AuthMethods:       "pwd otp",
	}
	client := &models.Client{
		Id:               1,
		ClientIdentifier: "test-client",
	}
	user := &models.User{
		Id:                  1,
		Subject:             sub,
		Email:               "test@example.com",
		EmailVerified:       true,
		Username:            "testuser",
		GivenName:           "Test",
		MiddleName:          "Middle",
		FamilyName:          "User",
		Nickname:            "Testy",
		Website:             "https://test.com",
		Gender:              "male",
		BirthDate:           sql.NullTime{Time: time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC), Valid: true},
		ZoneInfo:            "Europe/London",
		Locale:              "en-GB",
		PhoneNumber:         "+1234567890",
		PhoneNumberVerified: true,
		AddressLine1:        "123 Test St",
		AddressLine2:        "Apt 4",
		AddressLocality:     "Testville",
		AddressRegion:       "Testshire",
		AddressPostalCode:   "TE1 2ST",
		AddressCountry:      "Testland",
		UpdatedAt:           sql.NullTime{Time: now.Add(-1 * time.Hour), Valid: true},
		Groups: []models.Group{
			{GroupIdentifier: "group1", IncludeInIdToken: true},
			{GroupIdentifier: "group2", IncludeInIdToken: false},
		},
		Attributes: []models.UserAttribute{
			{Key: "attr1", Value: "value1", IncludeInIdToken: true},
			{Key: "attr2", Value: "value2", IncludeInIdToken: false},
		},
	}

	code.Client = *client
	code.User = *user

	mockDB.On("UserHasProfilePicture", mock.Anything, user.Id).Return(false, nil)

	idToken, err := tokenIssuer.generateIdToken(settings, code, code.Scope, now, privKey, "test-key-id")
	assert.NoError(t, err)
	assert.NotEmpty(t, idToken)

	claims := verifyAndDecodeToken(t, idToken, publicKeyBytes)

	assert.Equal(t, settings.Issuer, claims["iss"])
	assert.Equal(t, user.Subject.String(), claims["sub"])
	assert.Equal(t, client.ClientIdentifier, claims["aud"])
	assert.Equal(t, code.Nonce, claims["nonce"])
	assert.Equal(t, code.AcrLevel, claims["acr"])
	assert.Equal(t, code.AuthMethods, claims["amr"])
	assert.Equal(t, sessionIdentifier, claims["sid"])

	assertTimeClaimWithinRange(t, claims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, claims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, claims, "exp", 600*time.Second, "exp should be 600 seconds from now")
	assertTimeClaimWithinRange(t, claims, "auth_time", -300*time.Second, "auth_time should be 300 seconds ago")

	_, err = uuid.Parse(claims["jti"].(string))
	assert.NoError(t, err)

	assert.Equal(t, user.GetFullName(), claims["name"])
	assert.Equal(t, user.GivenName, claims["given_name"])
	assert.Equal(t, user.MiddleName, claims["middle_name"])
	assert.Equal(t, user.FamilyName, claims["family_name"])
	assert.Equal(t, user.Nickname, claims["nickname"])
	assert.Equal(t, user.Username, claims["preferred_username"])
	assert.Equal(t, "http://localhost:8081/account/profile", claims["profile"])
	assert.Equal(t, user.Website, claims["website"])
	assert.Equal(t, user.Gender, claims["gender"])
	assert.Equal(t, "1990-01-01", claims["birthdate"])
	assert.Equal(t, user.ZoneInfo, claims["zoneinfo"])
	assert.Equal(t, user.Locale, claims["locale"])
	assert.Equal(t, user.Email, claims["email"])
	assert.Equal(t, user.EmailVerified, claims["email_verified"])
	assert.Equal(t, user.PhoneNumber, claims["phone_number"])
	assert.Equal(t, user.PhoneNumberVerified, claims["phone_number_verified"])

	address := claims["address"].(map[string]interface{})
	assert.Equal(t, user.AddressLine1+"\r\n"+user.AddressLine2, address["street_address"])
	assert.Equal(t, user.AddressLocality, address["locality"])
	assert.Equal(t, user.AddressRegion, address["region"])
	assert.Equal(t, user.AddressPostalCode, address["postal_code"])
	assert.Equal(t, user.AddressCountry, address["country"])

	groups := claims["groups"].([]interface{})
	assert.Contains(t, groups, "group1")
	assert.NotContains(t, groups, "group2")

	attributes := claims["attributes"].(map[string]interface{})
	assert.Equal(t, "value1", attributes["attr1"])
	assert.NotContains(t, attributes, "attr2")

	assertTimeClaimWithinRange(t, claims, "updated_at", -1*time.Hour, "updated_at should be 1 hour ago")
}

func TestGenerateIdToken_MinimalScope(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	settings := &models.Settings{
		Issuer:                   "https://test-issuer.com",
		TokenExpirationInSeconds: 300,
	}

	now := time.Now().UTC()
	sub := uuid.New()
	sessionIdentifier := "test-session-456"

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	assert.NoError(t, err)

	code := &models.Code{
		Id:                2,
		ClientId:          2,
		UserId:            2,
		Scope:             "openid",
		Nonce:             "minimal-nonce",
		AuthenticatedAt:   now.Add(-1 * time.Minute),
		SessionIdentifier: sessionIdentifier,
		AcrLevel:          "urn:goiabada:pwd",
		AuthMethods:       "pwd",
	}
	client := &models.Client{
		Id:               2,
		ClientIdentifier: "minimal-client",
	}
	user := &models.User{
		Id:      2,
		Subject: sub,
	}

	code.Client = *client
	code.User = *user

	idToken, err := tokenIssuer.generateIdToken(settings, code, code.Scope, now, privKey, "test-key-id")
	assert.NoError(t, err)
	assert.NotEmpty(t, idToken)

	claims := verifyAndDecodeToken(t, idToken, publicKeyBytes)

	assert.Equal(t, settings.Issuer, claims["iss"])
	assert.Equal(t, user.Subject.String(), claims["sub"])
	assert.Equal(t, client.ClientIdentifier, claims["aud"])
	assert.Equal(t, code.Nonce, claims["nonce"])
	assert.Equal(t, code.AcrLevel, claims["acr"])
	assert.Equal(t, code.AuthMethods, claims["amr"])
	assert.Equal(t, sessionIdentifier, claims["sid"])

	assertTimeClaimWithinRange(t, claims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, claims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, claims, "exp", 300*time.Second, "exp should be 300 seconds from now")
	assertTimeClaimWithinRange(t, claims, "auth_time", -60*time.Second, "auth_time should be 60 seconds ago")

	_, err = uuid.Parse(claims["jti"].(string))
	assert.NoError(t, err)

	assert.NotContains(t, claims, "name")
	assert.NotContains(t, claims, "email")
	assert.NotContains(t, claims, "address")
	assert.NotContains(t, claims, "phone_number")
	assert.NotContains(t, claims, "groups")
	assert.NotContains(t, claims, "attributes")
}

func TestGenerateIdToken_ClientOverride(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	settings := &models.Settings{
		Issuer:                   "https://test-issuer.com",
		TokenExpirationInSeconds: 600,
	}

	now := time.Now().UTC()
	sub := uuid.New()
	sessionIdentifier := "test-session-789"

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	assert.NoError(t, err)

	code := &models.Code{
		Id:                3,
		ClientId:          3,
		UserId:            3,
		Scope:             "openid profile email",
		Nonce:             "override-nonce",
		AuthenticatedAt:   now.Add(-2 * time.Minute),
		SessionIdentifier: sessionIdentifier,
		AcrLevel:          "urn:goiabada:pwd:otp_ifpossible",
		AuthMethods:       "pwd otp",
	}
	client := &models.Client{
		Id:                       3,
		ClientIdentifier:         "override-client",
		TokenExpirationInSeconds: 1200,
	}
	user := &models.User{
		Id:            3,
		Subject:       sub,
		Email:         "override@example.com",
		EmailVerified: true,
		Username:      "overrideuser",
		GivenName:     "Override",
		FamilyName:    "User",
		UpdatedAt:     sql.NullTime{Time: now.Add(-30 * time.Minute), Valid: true},
	}

	code.Client = *client
	code.User = *user

	mockDB.On("UserHasProfilePicture", mock.Anything, user.Id).Return(false, nil)

	idToken, err := tokenIssuer.generateIdToken(settings, code, code.Scope, now, privKey, "test-key-id")
	assert.NoError(t, err)
	assert.NotEmpty(t, idToken)

	claims := verifyAndDecodeToken(t, idToken, publicKeyBytes)

	assert.Equal(t, settings.Issuer, claims["iss"])
	assert.Equal(t, user.Subject.String(), claims["sub"])
	assert.Equal(t, client.ClientIdentifier, claims["aud"])
	assert.Equal(t, code.Nonce, claims["nonce"])
	assert.Equal(t, code.AcrLevel, claims["acr"])
	assert.Equal(t, code.AuthMethods, claims["amr"])
	assert.Equal(t, sessionIdentifier, claims["sid"])

	assertTimeClaimWithinRange(t, claims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, claims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, claims, "exp", 1200*time.Second, "exp should be 1200 seconds from now (client override)")
	assertTimeClaimWithinRange(t, claims, "auth_time", -120*time.Second, "auth_time should be 120 seconds ago")

	_, err = uuid.Parse(claims["jti"].(string))
	assert.NoError(t, err)

	assert.Equal(t, user.GetFullName(), claims["name"])
	assert.Equal(t, user.GivenName, claims["given_name"])
	assert.Equal(t, user.FamilyName, claims["family_name"])
	assert.Equal(t, user.Username, claims["preferred_username"])
	assert.Equal(t, "http://localhost:8081/account/profile", claims["profile"])
	assert.Equal(t, user.Email, claims["email"])
	assert.Equal(t, user.EmailVerified, claims["email_verified"])

	assertTimeClaimWithinRange(t, claims, "updated_at", -30*time.Minute, "updated_at should be 30 minutes ago")
}

func TestGenerateRefreshToken_Offline(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	settings := &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		RefreshTokenOfflineIdleTimeoutInSeconds: 3600,
		RefreshTokenOfflineMaxLifetimeInSeconds: 86400,
	}

	now := time.Now().UTC()
	sub := uuid.New()
	sessionIdentifier := "test-session-123"

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	assert.NoError(t, err)

	code := &models.Code{
		Id:                1,
		ClientId:          1,
		UserId:            1,
		Scope:             "openid offline_access",
		Nonce:             "test-nonce",
		AuthenticatedAt:   now.Add(-5 * time.Minute),
		SessionIdentifier: sessionIdentifier,
	}
	client := &models.Client{
		Id:                                      1,
		ClientIdentifier:                        "test-client",
		RefreshTokenOfflineIdleTimeoutInSeconds: 7200,
		RefreshTokenOfflineMaxLifetimeInSeconds: 172800,
	}
	user := &models.User{
		Id:      1,
		Subject: sub,
	}

	code.Client = *client
	code.User = *user

	mockDB.On("CreateRefreshToken", mock.Anything, mock.AnythingOfType("*models.RefreshToken")).Return(nil)

	refreshToken, refreshExpiresIn, err := tokenIssuer.generateRefreshToken(settings, code, code.Scope, now, privKey, "test-key-id", nil)

	assert.NoError(t, err)
	assert.NotEmpty(t, refreshToken)
	assert.Equal(t, int64(7200), refreshExpiresIn)

	claims := verifyAndDecodeToken(t, refreshToken, publicKeyBytes)

	assert.Equal(t, settings.Issuer, claims["iss"])
	assert.Equal(t, settings.Issuer, claims["aud"])
	assert.Equal(t, user.Subject.String(), claims["sub"])
	assert.Equal(t, "Offline", claims["typ"])
	assert.Equal(t, code.Scope, claims["scope"])

	assertTimeClaimWithinRange(t, claims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, claims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, claims, "exp", 7200*time.Second, "exp should be 7200 seconds from now")
	assertTimeClaimWithinRange(t, claims, "offline_access_max_lifetime", 172800*time.Second, "offline_access_max_lifetime should be 172800 seconds from now")

	_, err = uuid.Parse(claims["jti"].(string))
	assert.NoError(t, err)

	mockDB.AssertExpectations(t)
}

func TestGenerateRefreshToken_Refresh(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	settings := &models.Settings{
		Issuer:                          "https://test-issuer.com",
		UserSessionIdleTimeoutInSeconds: 1800,
		UserSessionMaxLifetimeInSeconds: 43200,
	}

	now := time.Now().UTC()
	sub := uuid.New()
	sessionIdentifier := "test-session-456"

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	assert.NoError(t, err)

	code := &models.Code{
		Id:                2,
		ClientId:          2,
		UserId:            2,
		Scope:             "openid",
		Nonce:             "refresh-nonce",
		AuthenticatedAt:   now.Add(-10 * time.Minute),
		SessionIdentifier: sessionIdentifier,
	}
	client := &models.Client{
		Id:               2,
		ClientIdentifier: "refresh-client",
	}
	user := &models.User{
		Id:      2,
		Subject: sub,
	}

	code.Client = *client
	code.User = *user

	mockDB.On("CreateRefreshToken", mock.Anything, mock.AnythingOfType("*models.RefreshToken")).Return(nil)
	mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(&models.UserSession{
		Id:           1,
		UserId:       2,
		Started:      now.Add(-30 * time.Minute),
		LastAccessed: now.Add(-5 * time.Minute),
	}, nil)

	refreshToken, refreshExpiresIn, err := tokenIssuer.generateRefreshToken(settings, code, code.Scope, now, privKey, "test-key-id", nil)

	assert.NoError(t, err)
	assert.NotEmpty(t, refreshToken)
	assert.Equal(t, int64(1800), refreshExpiresIn)

	claims := verifyAndDecodeToken(t, refreshToken, publicKeyBytes)

	assert.Equal(t, settings.Issuer, claims["iss"])
	assert.Equal(t, settings.Issuer, claims["aud"])
	assert.Equal(t, user.Subject.String(), claims["sub"])
	assert.Equal(t, "Refresh", claims["typ"])
	assert.Equal(t, code.Scope, claims["scope"])
	assert.Equal(t, sessionIdentifier, claims["sid"])

	assertTimeClaimWithinRange(t, claims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, claims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, claims, "exp", 1800*time.Second, "exp should be 1800 seconds from now")

	_, err = uuid.Parse(claims["jti"].(string))
	assert.NoError(t, err)

	mockDB.AssertExpectations(t)
}

func TestGenerateRefreshToken_WithExistingRefreshToken(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	settings := &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		RefreshTokenOfflineIdleTimeoutInSeconds: 3600,
		RefreshTokenOfflineMaxLifetimeInSeconds: 86400,
	}

	now := time.Now().UTC()
	sub := uuid.New()
	sessionIdentifier := "test-session-789"

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	assert.NoError(t, err)

	code := &models.Code{
		Id:                3,
		ClientId:          3,
		UserId:            3,
		Scope:             "openid offline_access",
		Nonce:             "existing-nonce",
		AuthenticatedAt:   now.Add(-15 * time.Minute),
		SessionIdentifier: sessionIdentifier,
	}
	client := &models.Client{
		Id:               3,
		ClientIdentifier: "existing-client",
	}
	user := &models.User{
		Id:      3,
		Subject: sub,
	}

	code.Client = *client
	code.User = *user

	existingRefreshToken := &models.RefreshToken{
		Id:                   1,
		RefreshTokenJti:      "existing-jti",
		FirstRefreshTokenJti: "first-jti",
		MaxLifetime:          sql.NullTime{Time: now.Add(24 * time.Hour), Valid: true},
	}

	mockDB.On("CreateRefreshToken", mock.Anything, mock.AnythingOfType("*models.RefreshToken")).Return(nil)

	refreshToken, refreshExpiresIn, err := tokenIssuer.generateRefreshToken(settings, code, code.Scope, now, privKey, "test-key-id", existingRefreshToken)

	assert.NoError(t, err)
	assert.NotEmpty(t, refreshToken)
	assert.Equal(t, int64(3600), refreshExpiresIn)

	claims := verifyAndDecodeToken(t, refreshToken, publicKeyBytes)

	assert.Equal(t, settings.Issuer, claims["iss"])
	assert.Equal(t, settings.Issuer, claims["aud"])
	assert.Equal(t, user.Subject.String(), claims["sub"])
	assert.Equal(t, "Offline", claims["typ"])
	assert.Equal(t, code.Scope, claims["scope"])

	assertTimeClaimWithinRange(t, claims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, claims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, claims, "exp", 3600*time.Second, "exp should be 3600 seconds from now")
	assertTimeClaimWithinRange(t, claims, "offline_access_max_lifetime", 24*time.Hour, "offline_access_max_lifetime should match existing refresh token")

	_, err = uuid.Parse(claims["jti"].(string))
	assert.NoError(t, err)

	mockDB.AssertExpectations(t)

	mockDB.AssertCalled(t, "CreateRefreshToken", mock.Anything, mock.MatchedBy(func(rt *models.RefreshToken) bool {
		return rt.PreviousRefreshTokenJti == "existing-jti" &&
			rt.FirstRefreshTokenJti == "first-jti"
	}))
}

func TestGenerateRefreshToken_OfflineMaxLifetimeLimit(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	settings := &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		RefreshTokenOfflineIdleTimeoutInSeconds: 3600,  // 1 hour
		RefreshTokenOfflineMaxLifetimeInSeconds: 86400, // 24 hours
	}

	initialTime := time.Now().UTC()
	sub := uuid.New()
	sessionIdentifier := "test-session-max-lifetime"

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	assert.NoError(t, err)

	code := &models.Code{
		Id:                4,
		ClientId:          4,
		UserId:            4,
		Scope:             "openid offline_access",
		Nonce:             "max-lifetime-nonce",
		AuthenticatedAt:   initialTime.Add(-22 * time.Hour), // 22 hours ago
		SessionIdentifier: sessionIdentifier,
	}
	client := &models.Client{
		Id:                                      4,
		ClientIdentifier:                        "max-lifetime-client",
		RefreshTokenOfflineIdleTimeoutInSeconds: 7200,   // 2 hours
		RefreshTokenOfflineMaxLifetimeInSeconds: 172800, // 48 hours (client setting)
	}
	user := &models.User{
		Id:      4,
		Subject: sub,
	}

	code.Client = *client
	code.User = *user

	mockDB.On("CreateRefreshToken", mock.Anything, mock.AnythingOfType("*models.RefreshToken")).Return(nil)

	// Simulate two previous refresh token generations
	secondRefreshTime := initialTime.Add(-1 * time.Hour)

	secondRefreshToken := &models.RefreshToken{
		Id:                      2,
		RefreshTokenJti:         "second-jti",
		FirstRefreshTokenJti:    "first-jti",
		PreviousRefreshTokenJti: "first-jti",
		MaxLifetime:             sql.NullTime{Time: initialTime.Add(1 * time.Hour), Valid: true},
		IssuedAt:                sql.NullTime{Time: secondRefreshTime, Valid: true},
	}

	// Now generate the third refresh token
	thirdRefreshTime := initialTime
	refreshToken, refreshExpiresIn, err := tokenIssuer.generateRefreshToken(settings, code, code.Scope, thirdRefreshTime, privKey, "test-key-id", secondRefreshToken)

	assert.NoError(t, err)
	assert.NotEmpty(t, refreshToken)

	// The remaining time should be close to 1 hour (3600 seconds)
	expectedRemainingTime := int64(3600)
	assert.InDelta(t, expectedRemainingTime, refreshExpiresIn, 5, "refreshExpiresIn should be close to the remaining time in the max lifetime")

	claims := verifyAndDecodeToken(t, refreshToken, publicKeyBytes)

	assert.Equal(t, settings.Issuer, claims["iss"])
	assert.Equal(t, settings.Issuer, claims["aud"])
	assert.Equal(t, user.Subject.String(), claims["sub"])
	assert.Equal(t, "Offline", claims["typ"])
	assert.Equal(t, code.Scope, claims["scope"])

	assertTimeClaimWithinRange(t, claims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, claims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, claims, "exp", time.Duration(expectedRemainingTime)*time.Second, "exp should be close to the remaining time in the max lifetime")
	assertTimeClaimWithinRange(t, claims, "offline_access_max_lifetime", time.Duration(expectedRemainingTime)*time.Second, "offline_access_max_lifetime is not correct")

	_, err = uuid.Parse(claims["jti"].(string))
	assert.NoError(t, err)

	mockDB.AssertExpectations(t)

	// Verify that the refresh token's expiration doesn't exceed the max lifetime
	expUnix := int64(claims["exp"].(float64))
	maxLifetimeUnix := int64(claims["offline_access_max_lifetime"].(float64))
	assert.LessOrEqual(t, expUnix, maxLifetimeUnix, "Refresh token expiration should not exceed the max lifetime")

	// Verify that the correct previous and first refresh token JTIs are used
	mockDB.AssertCalled(t, "CreateRefreshToken", mock.Anything, mock.MatchedBy(func(rt *models.RefreshToken) bool {
		return rt.PreviousRefreshTokenJti == "second-jti" &&
			rt.FirstRefreshTokenJti == "first-jti"
	}))
}

func TestGetRefreshTokenExpiration(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	now := time.Now().UTC()
	settings := &models.Settings{
		RefreshTokenOfflineIdleTimeoutInSeconds: 3600,
		UserSessionIdleTimeoutInSeconds:         1800,
	}
	client := &models.Client{
		RefreshTokenOfflineIdleTimeoutInSeconds: 7200,
	}

	tests := []struct {
		name               string
		refreshTokenType   string
		expectedExpiration int64
		expectedError      bool
	}{
		{
			name:               "Offline token with client override",
			refreshTokenType:   "Offline",
			expectedExpiration: now.Add(7200 * time.Second).Unix(),
			expectedError:      false,
		},
		{
			name:               "Offline token without client override",
			refreshTokenType:   "Offline",
			expectedExpiration: now.Add(3600 * time.Second).Unix(),
			expectedError:      false,
		},
		{
			name:               "Refresh token",
			refreshTokenType:   "Refresh",
			expectedExpiration: now.Add(1800 * time.Second).Unix(),
			expectedError:      false,
		},
		{
			name:               "Invalid token type",
			refreshTokenType:   "Invalid",
			expectedExpiration: 0,
			expectedError:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "Offline token without client override" {
				client.RefreshTokenOfflineIdleTimeoutInSeconds = 0
			}

			exp, err := tokenIssuer.getRefreshTokenExpiration(tt.refreshTokenType, now, settings, client)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedExpiration, exp)
			}
		})
	}
}

func TestGetRefreshTokenMaxLifetime(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	now := time.Now().UTC()
	settings := &models.Settings{
		RefreshTokenOfflineMaxLifetimeInSeconds: 86400,
		UserSessionMaxLifetimeInSeconds:         43200,
	}
	client := &models.Client{
		RefreshTokenOfflineMaxLifetimeInSeconds: 172800,
	}
	sessionIdentifier := "test-session-123"

	tests := []struct {
		name             string
		refreshTokenType string
		expectedLifetime int64
		expectedError    bool
		mockUserSession  *models.UserSession
	}{
		{
			name:             "Offline token with client override",
			refreshTokenType: "Offline",
			expectedLifetime: now.Add(172800 * time.Second).Unix(),
			expectedError:    false,
		},
		{
			name:             "Offline token without client override",
			refreshTokenType: "Offline",
			expectedLifetime: now.Add(86400 * time.Second).Unix(),
			expectedError:    false,
		},
		{
			name:             "Refresh token",
			refreshTokenType: "Refresh",
			expectedLifetime: now.Add(43200 * time.Second).Unix(),
			expectedError:    false,
			mockUserSession: &models.UserSession{
				Started: now,
			},
		},
		{
			name:             "Invalid token type",
			refreshTokenType: "Invalid",
			expectedLifetime: 0,
			expectedError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "Offline token without client override" {
				client.RefreshTokenOfflineMaxLifetimeInSeconds = 0
			}

			if tt.mockUserSession != nil {
				mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(tt.mockUserSession, nil)
			}

			maxLifetime, err := tokenIssuer.getRefreshTokenMaxLifetime(tt.refreshTokenType, now, settings, client, sessionIdentifier)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedLifetime, maxLifetime)
			}

			mockDB.AssertExpectations(t)
		})
	}
}

func TestGenerateTokenResponseForClientCred(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	settings := &models.Settings{
		Issuer:                   "https://test-issuer.com",
		TokenExpirationInSeconds: 3600,
	}

	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	tests := []struct {
		name           string
		client         *models.Client
		scope          string
		expectedScopes []string
		expectedAud    interface{}
	}{
		{
			name: "Single custom scope",
			client: &models.Client{
				Id:               1,
				ClientIdentifier: "test-client-1",
			},
			scope:          "resource1:read",
			expectedScopes: []string{"resource1:read"},
			expectedAud:    "resource1",
		},
		{
			name: "Multiple custom scopes",
			client: &models.Client{
				Id:               2,
				ClientIdentifier: "test-client-2",
			},
			scope:          "resource1:read resource2:write",
			expectedScopes: []string{"resource1:read", "resource2:write"},
			expectedAud:    []interface{}{"resource1", "resource2"},
		},
		{
			name: "Custom scopes with OIDC scopes (should be ignored)",
			client: &models.Client{
				Id:               3,
				ClientIdentifier: "test-client-3",
			},
			scope:          "resource1:read openid profile",
			expectedScopes: []string{"resource1:read"},
			expectedAud:    "resource1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDB.On("GetCurrentSigningKey", mock.Anything).Return(&models.KeyPair{
				KeyIdentifier: "test-key-id",
				PrivateKeyPEM: privateKeyBytes,
			}, nil)

			response, err := tokenIssuer.GenerateTokenResponseForClientCred(ctx, tt.client, tt.scope)

			assert.NoError(t, err)
			assert.NotNil(t, response)
			assert.Equal(t, "Bearer", response.TokenType)
			assert.Equal(t, int64(3600), response.ExpiresIn)
			assert.NotEmpty(t, response.AccessToken)
			assert.Empty(t, response.IdToken)
			assert.Empty(t, response.RefreshToken)
			assert.Equal(t, tt.scope, response.Scope)

			claims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)

			assert.Equal(t, settings.Issuer, claims["iss"])
			assert.Equal(t, tt.client.ClientIdentifier, claims["sub"])
			assert.Equal(t, tt.expectedAud, claims["aud"])
			assert.Equal(t, "Bearer", claims["typ"])
			assert.Equal(t, tt.scope, claims["scope"])

			assertTimeClaimWithinRange(t, claims, "iat", 0*time.Second, "iat should be now")
		assertTimeClaimWithinRange(t, claims, "nbf", 0*time.Second, "nbf should be now")
			assertTimeClaimWithinRange(t, claims, "exp", 3600*time.Second, "exp should be 3600 seconds from now")

			_, err = uuid.Parse(claims["jti"].(string))
			assert.NoError(t, err)

			mockDB.AssertExpectations(t)
		})
	}
}

func TestGenerateTokenResponseForClientCred_InvalidScope(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	settings := &models.Settings{
		Issuer:                   "https://test-issuer.com",
		TokenExpirationInSeconds: 3600,
	}

	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

	client := &models.Client{
		Id:               4,
		ClientIdentifier: "test-client-4",
	}

	privateKeyBytes := getTestPrivateKey(t)

	mockDB.On("GetCurrentSigningKey", mock.Anything).Return(&models.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: privateKeyBytes,
	}, nil)

	response, err := tokenIssuer.GenerateTokenResponseForClientCred(ctx, client, "invalid-scope")

	if err == nil {
		t.Error("Expected an error, but got nil")
		if response != nil {
			t.Errorf("Unexpected response: %+v", response)
		}
	} else {
		assert.Contains(t, err.Error(), "invalid scope: invalid-scope")
	}

	mockDB.AssertExpectations(t)
}

func TestGenerateTokenResponseForRefresh(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	settings := &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		UserSessionIdleTimeoutInSeconds:         1200, // 20 minutes
		UserSessionMaxLifetimeInSeconds:         2400, // 40 minutes
		IncludeOpenIDConnectClaimsInAccessToken: true,
	}

	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

	now := time.Now().UTC()
	sub := uuid.New()
	sessionIdentifier := "test-session-123"

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	code := &models.Code{
		Id:                1,
		ClientId:          1,
		UserId:            1,
		Scope:             "openid profile resource1:read",
		Nonce:             "test-nonce",
		AuthenticatedAt:   now.Add(-5 * time.Minute),
		SessionIdentifier: sessionIdentifier,
		AcrLevel:          "urn:goiabada:pwd",
		AuthMethods:       "pwd",
	}
	client := &models.Client{
		Id:                       1,
		ClientIdentifier:         "test-client",
		TokenExpirationInSeconds: 900,
	}
	user := &models.User{
		Id:            1,
		Subject:       sub,
		Email:         "test@example.com",
		EmailVerified: true,
		Username:      "testuser",
		GivenName:     "Test",
		FamilyName:    "User",
		UpdatedAt:     sql.NullTime{Time: now.Add(-1 * time.Hour), Valid: true},
	}

	refreshToken := &models.RefreshToken{
		Id:                   1,
		RefreshTokenJti:      "existing-jti",
		FirstRefreshTokenJti: "first-jti",
		MaxLifetime:          sql.NullTime{Time: now.Add(24 * time.Hour), Valid: true},
	}

	refreshTokenInfo := &JwtToken{
		Claims: jwt.MapClaims{
			"jti":    "existing-jti",
			"scope":  "openid profile resource1:read",
			"exp":    now.Add(1 * time.Hour).Unix(),
			"iat":    now.Add(-1 * time.Hour).Unix(),
			"iss":    "https://test-issuer.com",
			"aud":    "https://test-issuer.com",
			"sub":    sub.String(),
			"typ":    "Refresh",
			"sid":    sessionIdentifier,
			"client": client.ClientIdentifier,
		},
	}

	mockDB.On("CodeLoadClient", mock.Anything, code).Return(nil)
	code.Client = *client
	mockDB.On("CodeLoadUser", mock.Anything, code).Return(nil)
	code.User = *user
	mockDB.On("UserLoadGroups", mock.Anything, &code.User).Return(nil)
	mockDB.On("GroupsLoadAttributes", mock.Anything, code.User.Groups).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, &code.User).Return(nil)
	mockDB.On("UserHasProfilePicture", mock.Anything, user.Id).Return(false, nil)
	var capturedRefreshToken *models.RefreshToken
	mockDB.On("CreateRefreshToken", mock.Anything, mock.AnythingOfType("*models.RefreshToken")).
		Run(func(args mock.Arguments) {
			capturedRefreshToken = args.Get(1).(*models.RefreshToken)
		}).
		Return(nil)
	mockDB.On("GetCurrentSigningKey", mock.Anything).Return(&models.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: privateKeyBytes,
	}, nil)
	// Add the missing mock expectation
	mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(&models.UserSession{
		Id:           1,
		UserId:       1,
		Started:      now.Add(-30 * time.Minute),
		LastAccessed: now.Add(-5 * time.Minute),
	}, nil)

	input := &GenerateTokenForRefreshInput{
		Code:             code,
		ScopeRequested:   "openid profile resource1:read",
		RefreshToken:     refreshToken,
		RefreshTokenInfo: refreshTokenInfo,
	}

	response, err := tokenIssuer.GenerateTokenResponseForRefresh(ctx, input)

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, "Bearer", response.TokenType)
	assert.Equal(t, int64(900), response.ExpiresIn) // client override
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.IdToken)
	assert.NotEmpty(t, response.RefreshToken)
	assert.Equal(t, "openid profile resource1:read authserver:userinfo", response.Scope)
	assert.InDelta(t, int64(600), response.RefreshExpiresIn, 1) // remaining time based on session max lifetime

	// validate Id token --------------------------------------------

	idClaims := verifyAndDecodeToken(t, response.IdToken, publicKeyBytes)
	assert.Equal(t, settings.Issuer, idClaims["iss"])
	assert.Equal(t, user.Subject.String(), idClaims["sub"])
	assert.Equal(t, client.ClientIdentifier, idClaims["aud"])
	assert.Equal(t, code.Nonce, idClaims["nonce"])
	assert.Equal(t, code.AcrLevel, idClaims["acr"])
	assert.Equal(t, code.AuthMethods, idClaims["amr"])
	assert.Equal(t, sessionIdentifier, idClaims["sid"])
	assertTimeClaimWithinRange(t, idClaims, "auth_time", -300*time.Second, "auth_time should be 300 seconds ago")
	assertTimeClaimWithinRange(t, idClaims, "exp", 900*time.Second, "exp should be 900 seconds from now")
	assertTimeClaimWithinRange(t, idClaims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, idClaims, "nbf", 0*time.Second, "nbf should be now")
	assert.Equal(t, user.FamilyName, idClaims["family_name"])
	assert.Equal(t, user.GivenName, idClaims["given_name"])
	assert.Equal(t, user.GetFullName(), idClaims["name"])
	assert.Equal(t, user.Username, idClaims["preferred_username"])
	assert.Equal(t, fmt.Sprintf("%v/account/profile", "http://localhost:8081"), idClaims["profile"])
	_, err = uuid.Parse(idClaims["jti"].(string))
	assert.NoError(t, err)
	assertTimeClaimWithinRange(t, idClaims, "updated_at", -1*time.Hour, "updated_at should be 1 hour ago")

	// validate Access token --------------------------------------------

	accessClaims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)
	assert.Equal(t, settings.Issuer, accessClaims["iss"])
	assert.Equal(t, user.Subject.String(), accessClaims["sub"])
	assert.ElementsMatch(t, []string{constants.AuthServerResourceIdentifier, "resource1"}, accessClaims["aud"])
	assert.Equal(t, code.Nonce, accessClaims["nonce"])
	assert.Equal(t, code.AcrLevel, accessClaims["acr"])
	assert.Equal(t, code.AuthMethods, accessClaims["amr"])
	assert.Equal(t, sessionIdentifier, accessClaims["sid"])
	assert.Equal(t, "Bearer", accessClaims["typ"])
	assert.Equal(t, user.FamilyName, accessClaims["family_name"])
	assert.Equal(t, user.GivenName, accessClaims["given_name"])
	assert.Equal(t, user.GetFullName(), accessClaims["name"])
	assert.Equal(t, user.Username, accessClaims["preferred_username"])
	assert.Equal(t, fmt.Sprintf("%v/account/profile", "http://localhost:8081"), accessClaims["profile"])
	assert.Equal(t, "openid profile resource1:read authserver:userinfo", accessClaims["scope"])
	_, err = uuid.Parse(accessClaims["jti"].(string))
	assert.NoError(t, err)
	assertTimeClaimWithinRange(t, accessClaims, "updated_at", -1*time.Hour, "updated_at should be 1 hour ago")

	assertTimeClaimWithinRange(t, accessClaims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, accessClaims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, accessClaims, "exp", 900*time.Second, "exp should be 900 seconds from now")
	assertTimeClaimWithinRange(t, accessClaims, "auth_time", -300*time.Second, "auth_time should be 300 seconds ago")

	// validate Refresh token --------------------------------------------

	refreshClaims := verifyAndDecodeToken(t, response.RefreshToken, publicKeyBytes)
	assert.Equal(t, user.Subject.String(), refreshClaims["sub"])
	assert.Equal(t, "https://test-issuer.com", refreshClaims["aud"])
	assert.Equal(t, "https://test-issuer.com", refreshClaims["iss"])
	assert.Equal(t, "Refresh", refreshClaims["typ"])
	assert.Equal(t, "openid profile resource1:read authserver:userinfo", refreshClaims["scope"])
	_, err = uuid.Parse(refreshClaims["jti"].(string))
	assert.NoError(t, err)
	assert.Equal(t, sessionIdentifier, refreshClaims["sid"])

	assertTimeClaimWithinRange(t, refreshClaims, "exp", 600*time.Second, "exp should be 600 seconds from now")
	assertTimeClaimWithinRange(t, refreshClaims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, refreshClaims, "nbf", 0*time.Second, "nbf should be now")

	// validate Refresh token passed to CreateRefreshToken --------------------------------------------

	assert.NotNil(t, capturedRefreshToken)
	assert.Equal(t, code.Id, capturedRefreshToken.CodeId)
	assert.NotEmpty(t, capturedRefreshToken.RefreshTokenJti)
	assert.Equal(t, refreshToken.FirstRefreshTokenJti, capturedRefreshToken.FirstRefreshTokenJti)
	assert.Equal(t, refreshToken.RefreshTokenJti, capturedRefreshToken.PreviousRefreshTokenJti)
	assert.Equal(t, "Refresh", capturedRefreshToken.RefreshTokenType)
	assert.Equal(t, "openid profile resource1:read authserver:userinfo", capturedRefreshToken.Scope)
	assert.Equal(t, sessionIdentifier, capturedRefreshToken.SessionIdentifier)
	assert.False(t, capturedRefreshToken.Revoked)
	assert.True(t, capturedRefreshToken.IssuedAt.Valid)
	assert.WithinDuration(t, now, capturedRefreshToken.IssuedAt.Time, 1*time.Second)
	assert.True(t, capturedRefreshToken.ExpiresAt.Valid)
	assert.WithinDuration(t, now.Add(600*time.Second), capturedRefreshToken.ExpiresAt.Time, 1*time.Second)

	mockDB.AssertExpectations(t)
}

func TestGenerateTokenResponseForRefresh_Offline_NoIdToken(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	settings := &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		IncludeOpenIDConnectClaimsInAccessToken: true,
		RefreshTokenOfflineIdleTimeoutInSeconds: 3600,
		RefreshTokenOfflineMaxLifetimeInSeconds: 86400,
	}

	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

	now := time.Now().UTC()
	sub := uuid.New()
	sessionIdentifier := "test-session-offline"

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	code := &models.Code{
		Id:                1,
		ClientId:          1,
		UserId:            1,
		Scope:             "openid profile offline_access",
		Nonce:             "test-nonce-offline",
		AuthenticatedAt:   now.Add(-10 * time.Minute),
		SessionIdentifier: sessionIdentifier,
		AcrLevel:          "urn:goiabada:pwd",
		AuthMethods:       "pwd",
	}
	client := &models.Client{
		Id:                                      1,
		ClientIdentifier:                        "test-client-offline",
		TokenExpirationInSeconds:                1200,
		RefreshTokenOfflineIdleTimeoutInSeconds: 7200,
		RefreshTokenOfflineMaxLifetimeInSeconds: 172800,
	}
	user := &models.User{
		Id:            1,
		Subject:       sub,
		Email:         "test@example.com",
		EmailVerified: true,
		Username:      "testuser",
		GivenName:     "Test",
		FamilyName:    "User",
		UpdatedAt:     sql.NullTime{Time: now.Add(-2 * time.Hour), Valid: true},
	}

	refreshToken := &models.RefreshToken{
		Id:                   1,
		RefreshTokenJti:      "existing-jti-offline",
		FirstRefreshTokenJti: "first-jti-offline",
		MaxLifetime:          sql.NullTime{Time: now.Add(48 * time.Hour), Valid: true},
	}

	refreshTokenInfo := &JwtToken{
		Claims: jwt.MapClaims{
			"jti":    "existing-jti-offline",
			"scope":  "openid profile offline_access",
			"exp":    now.Add(2 * time.Hour).Unix(),
			"iat":    now.Add(-1 * time.Hour).Unix(),
			"iss":    "https://test-issuer.com",
			"aud":    "https://test-issuer.com",
			"sub":    sub.String(),
			"typ":    "Offline",
			"client": client.ClientIdentifier,
		},
	}

	mockDB.On("CodeLoadClient", mock.Anything, code).Return(nil)
	code.Client = *client
	mockDB.On("CodeLoadUser", mock.Anything, code).Return(nil)
	code.User = *user
	mockDB.On("UserLoadGroups", mock.Anything, &code.User).Return(nil)
	mockDB.On("GroupsLoadAttributes", mock.Anything, code.User.Groups).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, &code.User).Return(nil)
	var capturedRefreshToken *models.RefreshToken
	mockDB.On("CreateRefreshToken", mock.Anything, mock.AnythingOfType("*models.RefreshToken")).
		Run(func(args mock.Arguments) {
			capturedRefreshToken = args.Get(1).(*models.RefreshToken)
		}).
		Return(nil)
	mockDB.On("GetCurrentSigningKey", mock.Anything).Return(&models.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: privateKeyBytes,
	}, nil)

	input := &GenerateTokenForRefreshInput{
		Code:             code,
		ScopeRequested:   "resource1:write offline_access",
		RefreshToken:     refreshToken,
		RefreshTokenInfo: refreshTokenInfo,
	}

	response, err := tokenIssuer.GenerateTokenResponseForRefresh(ctx, input)

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, "Bearer", response.TokenType)
	assert.Equal(t, int64(1200), response.ExpiresIn)
	assert.NotEmpty(t, response.AccessToken)
	assert.Empty(t, response.IdToken)
	assert.NotEmpty(t, response.RefreshToken)
	assert.Equal(t, "resource1:write offline_access", response.Scope)
	assert.Equal(t, int64(7200), response.RefreshExpiresIn)

	// validate Access token --------------------------------------------

	accessClaims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)
	assert.Equal(t, settings.Issuer, accessClaims["iss"])
	assert.Equal(t, user.Subject.String(), accessClaims["sub"])
	assert.Equal(t, "resource1", accessClaims["aud"])
	assert.Equal(t, code.Nonce, accessClaims["nonce"])
	assert.Equal(t, code.AcrLevel, accessClaims["acr"])
	assert.Equal(t, code.AuthMethods, accessClaims["amr"])
	assert.Equal(t, sessionIdentifier, accessClaims["sid"])
	assert.Equal(t, "Bearer", accessClaims["typ"])
	assert.Equal(t, "resource1:write offline_access", accessClaims["scope"])
	assertTimeClaimWithinRange(t, accessClaims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, accessClaims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, accessClaims, "exp", 1200*time.Second, "exp should be 1200 seconds from now")
	assertTimeClaimWithinRange(t, accessClaims, "auth_time", -600*time.Second, "auth_time should be 600 seconds ago")
	_, err = uuid.Parse(accessClaims["jti"].(string))
	assert.NoError(t, err, "Access token jti should be a valid UUID")

	// validate Refresh token --------------------------------------------

	refreshClaims := verifyAndDecodeToken(t, response.RefreshToken, publicKeyBytes)
	assert.Equal(t, user.Subject.String(), refreshClaims["sub"])
	assert.Equal(t, settings.Issuer, refreshClaims["aud"])
	assert.Equal(t, settings.Issuer, refreshClaims["iss"])
	assert.Equal(t, "Offline", refreshClaims["typ"])
	assert.Equal(t, "resource1:write offline_access", refreshClaims["scope"])
	assertTimeClaimWithinRange(t, refreshClaims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, refreshClaims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, refreshClaims, "exp", 7200*time.Second, "exp should be 7200 seconds from now")
	assertTimeClaimWithinRange(t, refreshClaims, "offline_access_max_lifetime", 172800*time.Second, "offline_access_max_lifetime should be 172800 seconds from now")
	_, err = uuid.Parse(refreshClaims["jti"].(string))
	assert.NoError(t, err, "Refresh token jti should be a valid UUID")

	// validate Refresh token passed to CreateRefreshToken --------------------------------------------

	assert.NotNil(t, capturedRefreshToken)
	assert.Equal(t, code.Id, capturedRefreshToken.CodeId)
	assert.NotEmpty(t, capturedRefreshToken.RefreshTokenJti)
	assert.Equal(t, refreshToken.FirstRefreshTokenJti, capturedRefreshToken.FirstRefreshTokenJti)
	assert.Equal(t, refreshToken.RefreshTokenJti, capturedRefreshToken.PreviousRefreshTokenJti)
	assert.Equal(t, "Offline", capturedRefreshToken.RefreshTokenType)
	assert.Equal(t, "resource1:write offline_access", capturedRefreshToken.Scope)
	assert.Empty(t, capturedRefreshToken.SessionIdentifier)
	assert.False(t, capturedRefreshToken.Revoked)
	assert.True(t, capturedRefreshToken.IssuedAt.Valid)
	assert.WithinDuration(t, now, capturedRefreshToken.IssuedAt.Time, 1*time.Second)
	assert.True(t, capturedRefreshToken.ExpiresAt.Valid)
	assert.WithinDuration(t, now.Add(7200*time.Second), capturedRefreshToken.ExpiresAt.Time, 1*time.Second)
	assert.True(t, capturedRefreshToken.MaxLifetime.Valid)
	assert.WithinDuration(t, now.Add(172800*time.Second), capturedRefreshToken.MaxLifetime.Time, 1*time.Second)

	mockDB.AssertExpectations(t)
}

func TestAddOpenIdConnectClaims(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := &TokenIssuer{
		database: mockDB,
		baseURL:  "http://localhost:8081",
	}
	now := time.Now().UTC()

	// Set up mock for profile picture check - it will be called for tests with profile scope
	mockDB.On("UserHasProfilePicture", mock.Anything, mock.Anything).Return(false, nil).Maybe()

	testCases := []struct {
		name     string
		code     *models.Code
		expected jwt.MapClaims
	}{
		{
			name: "Full scope",
			code: &models.Code{
				Scope: "openid profile email address phone",
				User: models.User{
					Email:               "test@example.com",
					EmailVerified:       true,
					Username:            "testuser",
					GivenName:           "Test",
					MiddleName:          "Middle",
					FamilyName:          "User",
					Nickname:            "Testy",
					Website:             "https://test.com",
					Gender:              "male",
					BirthDate:           sql.NullTime{Time: time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC), Valid: true},
					ZoneInfo:            "Europe/London",
					Locale:              "en-GB",
					PhoneNumber:         "+1234567890",
					PhoneNumberVerified: true,
					AddressLine1:        "123 Test St",
					AddressLine2:        "Apt 4",
					AddressLocality:     "Testville",
					AddressRegion:       "Testshire",
					AddressPostalCode:   "TE1 2ST",
					AddressCountry:      "Testland",
					UpdatedAt:           sql.NullTime{Time: now.Add(-1 * time.Hour), Valid: true},
				},
			},
			expected: jwt.MapClaims{
				"name":                  "Test Middle User",
				"given_name":            "Test",
				"middle_name":           "Middle",
				"family_name":           "User",
				"nickname":              "Testy",
				"preferred_username":    "testuser",
				"profile":               "http://localhost:8081/account/profile",
				"website":               "https://test.com",
				"gender":                "male",
				"birthdate":             "1990-01-01",
				"zoneinfo":              "Europe/London",
				"locale":                "en-GB",
				"email":                 "test@example.com",
				"email_verified":        true,
				"phone_number":          "+1234567890",
				"phone_number_verified": true,
				"updated_at":            now.Add(-1 * time.Hour).Unix(),
			},
		},
		{
			name: "Minimal scope",
			code: &models.Code{
				Scope: "openid",
				User: models.User{
					Email:     "minimal@example.com",
					UpdatedAt: sql.NullTime{Time: now.Add(-1 * time.Hour), Valid: true},
				},
			},
			expected: jwt.MapClaims{},
		},
		{
			name: "Profile scope only",
			code: &models.Code{
				Scope: "openid profile",
				User: models.User{
					Username:   "profileuser",
					GivenName:  "Profile",
					FamilyName: "User",
					UpdatedAt:  sql.NullTime{Time: now.Add(-1 * time.Hour), Valid: true},
				},
			},
			expected: jwt.MapClaims{
				"name":               "Profile User",
				"given_name":         "Profile",
				"family_name":        "User",
				"preferred_username": "profileuser",
				"profile":            "http://localhost:8081/account/profile",
				"updated_at":         now.Add(-1 * time.Hour).Unix(),
			},
		},
		{
			name: "Email scope only",
			code: &models.Code{
				Scope: "openid email",
				User: models.User{
					Email:         "email@example.com",
					EmailVerified: true,
					UpdatedAt:     sql.NullTime{Time: now.Add(-1 * time.Hour), Valid: true},
				},
			},
			expected: jwt.MapClaims{
				"email":          "email@example.com",
				"email_verified": true,
				"updated_at":     now.Add(-1 * time.Hour).Unix(),
			},
		},
		{
			name: "Address scope only",
			code: &models.Code{
				Scope: "openid address",
				User: models.User{
					AddressLine1:      "456 Address St",
					AddressLocality:   "Addressville",
					AddressRegion:     "Addressshire",
					AddressPostalCode: "AD1 3SS",
					AddressCountry:    "Addressland",
					UpdatedAt:         sql.NullTime{Time: now.Add(-1 * time.Hour), Valid: true},
				},
			},
			expected: jwt.MapClaims{
				"updated_at": now.Add(-1 * time.Hour).Unix(),
			},
		},
		{
			name: "Phone scope only",
			code: &models.Code{
				Scope: "openid phone",
				User: models.User{
					PhoneNumber:         "+9876543210",
					PhoneNumberVerified: false,
					UpdatedAt:           sql.NullTime{Time: now.Add(-1 * time.Hour), Valid: true},
				},
			},
			expected: jwt.MapClaims{
				"phone_number":          "+9876543210",
				"phone_number_verified": false,
				"updated_at":            now.Add(-1 * time.Hour).Unix(),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			claims := make(jwt.MapClaims)

			tokenIssuer.addOpenIdConnectClaims(claims, tc.code)

			for key, expectedValue := range tc.expected {
				assert.Equal(t, expectedValue, claims[key], "Mismatch for claim: %s", key)
			}

			if tc.code.Scope != "openid" {
				assert.NotZero(t, claims["updated_at"], "updated_at should be set")
			}

			// Check for address claim separately
			if strings.Contains(tc.code.Scope, "address") {
				addressClaim, ok := claims["address"].(map[string]string)
				assert.True(t, ok, "Address claim should be of type map[string]string")
				if ok {
					assert.Equal(t, tc.code.User.AddressLine1+"\r\n"+tc.code.User.AddressLine2, addressClaim["street_address"])
					assert.Equal(t, tc.code.User.AddressLocality, addressClaim["locality"])
					assert.Equal(t, tc.code.User.AddressRegion, addressClaim["region"])
					assert.Equal(t, tc.code.User.AddressPostalCode, addressClaim["postal_code"])
					assert.Equal(t, tc.code.User.AddressCountry, addressClaim["country"])
					expectedFormatted := strings.TrimSpace(tc.code.User.AddressLine1 + "\r\n" + tc.code.User.AddressLine2 + "\r\n" +
						tc.code.User.AddressLocality + "\r\n" + tc.code.User.AddressRegion + "\r\n" +
						tc.code.User.AddressPostalCode + "\r\n" + tc.code.User.AddressCountry)
					assert.Equal(t, expectedFormatted, addressClaim["formatted"])
				}
			}

			for key := range claims {
				if key != "updated_at" && key != "address" {
					_, expected := tc.expected[key]
					assert.True(t, expected, "Unexpected claim: %s", key)
				}
			}
		})
	}
}

func TestAddClaimIfNotEmpty(t *testing.T) {
	tokenIssuer := &TokenIssuer{}

	testCases := []struct {
		name           string
		claims         jwt.MapClaims
		claimName      string
		claimValue     string
		expectedClaims jwt.MapClaims
	}{
		{
			name:           "Non-empty claim",
			claims:         jwt.MapClaims{},
			claimName:      "test_claim",
			claimValue:     "test_value",
			expectedClaims: jwt.MapClaims{"test_claim": "test_value"},
		},
		{
			name:           "Empty claim",
			claims:         jwt.MapClaims{},
			claimName:      "empty_claim",
			claimValue:     "",
			expectedClaims: jwt.MapClaims{},
		},
		{
			name:           "Whitespace-only claim",
			claims:         jwt.MapClaims{},
			claimName:      "whitespace_claim",
			claimValue:     "   ",
			expectedClaims: jwt.MapClaims{},
		},
		{
			name:           "Claim with leading/trailing whitespace",
			claims:         jwt.MapClaims{},
			claimName:      "trimmed_claim",
			claimValue:     "  trimmed_value  ",
			expectedClaims: jwt.MapClaims{"trimmed_claim": "  trimmed_value  "},
		},
		{
			name:           "Adding to existing claims",
			claims:         jwt.MapClaims{"existing_claim": "existing_value"},
			claimName:      "new_claim",
			claimValue:     "new_value",
			expectedClaims: jwt.MapClaims{"existing_claim": "existing_value", "new_claim": "new_value"},
		},
		{
			name:           "Overwriting existing claim",
			claims:         jwt.MapClaims{"overwrite_claim": "old_value"},
			claimName:      "overwrite_claim",
			claimValue:     "new_value",
			expectedClaims: jwt.MapClaims{"overwrite_claim": "new_value"},
		},
		{
			name:           "Unicode claim value",
			claims:         jwt.MapClaims{},
			claimName:      "unicode_claim",
			claimValue:     "こんにちは",
			expectedClaims: jwt.MapClaims{"unicode_claim": "こんにちは"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tokenIssuer.addClaimIfNotEmpty(tc.claims, tc.claimName, tc.claimValue)

			assert.Equal(t, tc.expectedClaims, tc.claims, "Claims do not match expected values")

			if len(strings.TrimSpace(tc.claimValue)) > 0 {
				assert.Contains(t, tc.claims, tc.claimName, "Claim should be added")
				assert.Equal(t, tc.claimValue, tc.claims[tc.claimName], "Claim value should match")
			} else {
				assert.NotContains(t, tc.claims, tc.claimName, "Claim should not be added")
			}
		})
	}
}

func assertTimeClaimWithinRange(t *testing.T, claims jwt.MapClaims, claimName string, expectedDuration time.Duration, message string) {
	assert.Contains(t, claims, claimName)
	claimUnix := claims[claimName].(float64)
	claimTime := time.Unix(int64(claimUnix), 0)

	expectedTime := time.Now().UTC().Add(expectedDuration)

	start := expectedTime.Add(-3 * time.Second)
	end := expectedTime.Add(3 * time.Second)
	assert.True(t, claimTime.After(start) && claimTime.Before(end), fmt.Sprintf("%s: %s", message, claimTime))
}

func verifyAndDecodeToken(t *testing.T, tokenString string, publicKeyBytes []byte) jwt.MapClaims {
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)
	}, jwt.WithExpirationRequired())
	assert.NoError(t, err)
	assert.True(t, token.Valid)
	return claims
}

// ============================================================================
// Implicit Flow Tests
// ============================================================================

func TestGenerateTokenResponseForImplicit_AccessTokenOnly(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	settings := &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		IncludeOpenIDConnectClaimsInAccessToken: false,
	}

	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

	sub := uuid.New()
	sessionIdentifier := "test-session-implicit"
	authenticatedAt := time.Now().UTC().Add(-5 * time.Minute)

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	client := &models.Client{
		Id:               1,
		ClientIdentifier: "implicit-test-client",
	}
	user := &models.User{
		Id:       1,
		Subject:  sub,
		Email:    "implicit@example.com",
		Username: "implicituser",
		Groups:   []models.Group{},
	}

	mockDB.On("GetCurrentSigningKey", mock.Anything).Return(&models.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: privateKeyBytes,
	}, nil)
	mockDB.On("UserLoadGroups", mock.Anything, user).Return(nil)
	mockDB.On("GroupsLoadAttributes", mock.Anything, user.Groups).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, user).Return(nil)

	input := &ImplicitGrantInput{
		Client:            client,
		User:              user,
		Scope:             "openid profile",
		AcrLevel:          "urn:goiabada:pwd",
		AuthMethods:       "pwd",
		SessionIdentifier: sessionIdentifier,
		Nonce:             "test-nonce-123",
		AuthenticatedAt:   authenticatedAt,
	}

	response, err := tokenIssuer.GenerateTokenResponseForImplicit(ctx, input, true, false)
	assert.NoError(t, err)
	assert.NotNil(t, response)

	// Verify access token is issued
	assert.NotEmpty(t, response.AccessToken)
	// Verify NO id_token is issued
	assert.Empty(t, response.IdToken)
	// Verify token type
	assert.Equal(t, "Bearer", response.TokenType)
	// Verify expiration
	assert.Equal(t, int64(600), response.ExpiresIn)
	// Verify scope
	assert.Contains(t, response.Scope, "openid")

	// Decode and verify access token claims
	accessClaims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)
	assert.Equal(t, settings.Issuer, accessClaims["iss"])
	assert.Equal(t, sub.String(), accessClaims["sub"])
	assert.Equal(t, input.AcrLevel, accessClaims["acr"])
	assert.Equal(t, input.AuthMethods, accessClaims["amr"])
	assert.Equal(t, sessionIdentifier, accessClaims["sid"])
	assert.Equal(t, "test-nonce-123", accessClaims["nonce"])
	assert.Equal(t, "Bearer", accessClaims["typ"])

	mockDB.AssertExpectations(t)
}

func TestGenerateTokenResponseForImplicit_IdTokenOnly(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	settings := &models.Settings{
		Issuer:                   "https://test-issuer.com",
		TokenExpirationInSeconds: 600,
	}

	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

	sub := uuid.New()
	sessionIdentifier := "test-session-idtoken"
	authenticatedAt := time.Now().UTC().Add(-5 * time.Minute)

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	client := &models.Client{
		Id:               1,
		ClientIdentifier: "idtoken-test-client",
	}
	user := &models.User{
		Id:            1,
		Subject:       sub,
		Email:         "idtoken@example.com",
		EmailVerified: true,
		Username:      "idtokenuser",
		GivenName:     "IdToken",
		FamilyName:    "User",
		UpdatedAt:     sql.NullTime{Time: time.Now().Add(-1 * time.Hour), Valid: true},
		Groups:        []models.Group{},
	}

	mockDB.On("GetCurrentSigningKey", mock.Anything).Return(&models.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: privateKeyBytes,
	}, nil)
	mockDB.On("UserLoadGroups", mock.Anything, user).Return(nil)
	mockDB.On("GroupsLoadAttributes", mock.Anything, user.Groups).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, user).Return(nil)
	mockDB.On("UserHasProfilePicture", mock.Anything, user.Id).Return(false, nil)

	input := &ImplicitGrantInput{
		Client:            client,
		User:              user,
		Scope:             "openid profile email",
		AcrLevel:          "urn:goiabada:pwd",
		AuthMethods:       "pwd",
		SessionIdentifier: sessionIdentifier,
		Nonce:             "nonce-for-idtoken",
		AuthenticatedAt:   authenticatedAt,
	}

	response, err := tokenIssuer.GenerateTokenResponseForImplicit(ctx, input, false, true)
	assert.NoError(t, err)
	assert.NotNil(t, response)

	// Verify NO access token is issued
	assert.Empty(t, response.AccessToken)
	// Verify id_token IS issued
	assert.NotEmpty(t, response.IdToken)
	// Verify scope
	assert.Equal(t, "openid profile email", response.Scope)

	// Decode and verify id_token claims
	idClaims := verifyAndDecodeToken(t, response.IdToken, publicKeyBytes)
	assert.Equal(t, settings.Issuer, idClaims["iss"])
	assert.Equal(t, sub.String(), idClaims["sub"])
	assert.Equal(t, client.ClientIdentifier, idClaims["aud"])
	assert.Equal(t, input.AcrLevel, idClaims["acr"])
	assert.Equal(t, input.AuthMethods, idClaims["amr"])
	assert.Equal(t, sessionIdentifier, idClaims["sid"])
	assert.Equal(t, "nonce-for-idtoken", idClaims["nonce"])

	// Verify NO at_hash (since no access token was issued)
	assert.Nil(t, idClaims["at_hash"])

	// Verify OIDC claims
	assert.Equal(t, "idtoken@example.com", idClaims["email"])
	assert.Equal(t, true, idClaims["email_verified"])
	assert.Equal(t, "IdToken User", idClaims["name"])
	assert.Equal(t, "IdToken", idClaims["given_name"])
	assert.Equal(t, "User", idClaims["family_name"])

	mockDB.AssertExpectations(t)
}

func TestGenerateTokenResponseForImplicit_BothTokens(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	settings := &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		IncludeOpenIDConnectClaimsInAccessToken: true,
	}

	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

	sub := uuid.New()
	sessionIdentifier := "test-session-both"
	authenticatedAt := time.Now().UTC().Add(-5 * time.Minute)

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	client := &models.Client{
		Id:               1,
		ClientIdentifier: "both-tokens-client",
	}
	user := &models.User{
		Id:            1,
		Subject:       sub,
		Email:         "both@example.com",
		EmailVerified: true,
		Username:      "bothuser",
		GivenName:     "Both",
		FamilyName:    "Tokens",
		UpdatedAt:     sql.NullTime{Time: time.Now().Add(-1 * time.Hour), Valid: true},
		Groups:        []models.Group{},
	}

	mockDB.On("GetCurrentSigningKey", mock.Anything).Return(&models.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: privateKeyBytes,
	}, nil)
	mockDB.On("UserLoadGroups", mock.Anything, user).Return(nil)
	mockDB.On("GroupsLoadAttributes", mock.Anything, user.Groups).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, user).Return(nil)
	mockDB.On("UserHasProfilePicture", mock.Anything, user.Id).Return(false, nil)

	input := &ImplicitGrantInput{
		Client:            client,
		User:              user,
		Scope:             "openid profile email",
		AcrLevel:          "urn:goiabada:pwd:otp_mandatory",
		AuthMethods:       "pwd otp",
		SessionIdentifier: sessionIdentifier,
		Nonce:             "nonce-for-both",
		AuthenticatedAt:   authenticatedAt,
	}

	response, err := tokenIssuer.GenerateTokenResponseForImplicit(ctx, input, true, true)
	assert.NoError(t, err)
	assert.NotNil(t, response)

	// Verify BOTH tokens are issued
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.IdToken)
	assert.Equal(t, "Bearer", response.TokenType)
	assert.Equal(t, int64(600), response.ExpiresIn)

	// Decode and verify access token
	accessClaims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)
	assert.Equal(t, settings.Issuer, accessClaims["iss"])
	assert.Equal(t, sub.String(), accessClaims["sub"])

	// Decode and verify id_token
	idClaims := verifyAndDecodeToken(t, response.IdToken, publicKeyBytes)
	assert.Equal(t, settings.Issuer, idClaims["iss"])
	assert.Equal(t, sub.String(), idClaims["sub"])
	assert.Equal(t, "nonce-for-both", idClaims["nonce"])

	// Verify at_hash IS present (since access token was also issued)
	assert.NotNil(t, idClaims["at_hash"])
	atHash := idClaims["at_hash"].(string)
	assert.NotEmpty(t, atHash)

	// Verify at_hash is correct
	expectedAtHash := tokenIssuer.calculateAtHash(response.AccessToken)
	assert.Equal(t, expectedAtHash, atHash)

	mockDB.AssertExpectations(t)
}

func TestGenerateTokenResponseForImplicit_NoRefreshToken(t *testing.T) {
	// This test verifies that implicit flow NEVER issues a refresh token
	// per RFC 6749 Section 4.2.2
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	settings := &models.Settings{
		Issuer:                   "https://test-issuer.com",
		TokenExpirationInSeconds: 600,
	}

	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

	sub := uuid.New()
	privateKeyBytes := getTestPrivateKey(t)

	client := &models.Client{
		Id:               1,
		ClientIdentifier: "no-refresh-client",
	}
	user := &models.User{
		Id:      1,
		Subject: sub,
		Groups:  []models.Group{},
	}

	mockDB.On("GetCurrentSigningKey", mock.Anything).Return(&models.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: privateKeyBytes,
	}, nil)
	mockDB.On("UserLoadGroups", mock.Anything, user).Return(nil)
	mockDB.On("GroupsLoadAttributes", mock.Anything, user.Groups).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, user).Return(nil)

	// Request with offline_access scope - should NOT result in refresh token for implicit flow
	input := &ImplicitGrantInput{
		Client:            client,
		User:              user,
		Scope:             "openid offline_access",
		AcrLevel:          "urn:goiabada:pwd",
		AuthMethods:       "pwd",
		SessionIdentifier: "session-123",
		Nonce:             "nonce-123",
		AuthenticatedAt:   time.Now().UTC(),
	}

	response, err := tokenIssuer.GenerateTokenResponseForImplicit(ctx, input, true, false)
	assert.NoError(t, err)
	assert.NotNil(t, response)

	// ImplicitGrantResponse struct does NOT have a RefreshToken field
	// This test documents that implicit flow cannot return refresh tokens by design
	assert.NotEmpty(t, response.AccessToken)
	// The response type itself prevents refresh tokens

	mockDB.AssertExpectations(t)
}

func TestGenerateTokenResponseForImplicit_ClientOverrideExpiration(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	settings := &models.Settings{
		Issuer:                   "https://test-issuer.com",
		TokenExpirationInSeconds: 600, // 10 minutes global
	}

	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

	sub := uuid.New()
	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	client := &models.Client{
		Id:                       1,
		ClientIdentifier:         "custom-expiry-client",
		TokenExpirationInSeconds: 1800, // 30 minutes client override
	}
	user := &models.User{
		Id:      1,
		Subject: sub,
		Groups:  []models.Group{},
	}

	mockDB.On("GetCurrentSigningKey", mock.Anything).Return(&models.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: privateKeyBytes,
	}, nil)
	mockDB.On("UserLoadGroups", mock.Anything, user).Return(nil)
	mockDB.On("GroupsLoadAttributes", mock.Anything, user.Groups).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, user).Return(nil)

	input := &ImplicitGrantInput{
		Client:            client,
		User:              user,
		Scope:             "openid",
		AcrLevel:          "urn:goiabada:pwd",
		AuthMethods:       "pwd",
		SessionIdentifier: "session-123",
		Nonce:             "nonce-123",
		AuthenticatedAt:   time.Now().UTC(),
	}

	response, err := tokenIssuer.GenerateTokenResponseForImplicit(ctx, input, true, false)
	assert.NoError(t, err)
	assert.NotNil(t, response)

	// Verify client override is used
	assert.Equal(t, int64(1800), response.ExpiresIn)

	// Verify token expiration claim
	accessClaims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)
	exp := accessClaims["exp"].(float64)
	iat := accessClaims["iat"].(float64)
	assert.Equal(t, float64(1800), exp-iat)

	mockDB.AssertExpectations(t)
}

func TestGenerateTokenResponseForImplicit_WithGroupsAndAttributes(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	settings := &models.Settings{
		Issuer:                   "https://test-issuer.com",
		TokenExpirationInSeconds: 600,
	}

	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

	sub := uuid.New()
	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	client := &models.Client{
		Id:               1,
		ClientIdentifier: "groups-attrs-client",
	}
	user := &models.User{
		Id:        1,
		Subject:   sub,
		UpdatedAt: sql.NullTime{Time: time.Now().Add(-1 * time.Hour), Valid: true},
		Groups: []models.Group{
			{GroupIdentifier: "admin", IncludeInIdToken: true, IncludeInAccessToken: true},
			{GroupIdentifier: "users", IncludeInIdToken: true, IncludeInAccessToken: false},
			{GroupIdentifier: "readonly", IncludeInIdToken: false, IncludeInAccessToken: true},
		},
		Attributes: []models.UserAttribute{
			{Key: "department", Value: "engineering", IncludeInIdToken: true, IncludeInAccessToken: true},
			{Key: "level", Value: "senior", IncludeInIdToken: true, IncludeInAccessToken: false},
			{Key: "team", Value: "platform", IncludeInIdToken: false, IncludeInAccessToken: true},
		},
	}

	mockDB.On("GetCurrentSigningKey", mock.Anything).Return(&models.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: privateKeyBytes,
	}, nil)
	mockDB.On("UserLoadGroups", mock.Anything, user).Return(nil)
	mockDB.On("GroupsLoadAttributes", mock.Anything, user.Groups).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, user).Return(nil)
	// Note: UserHasProfilePicture not called because we don't have "profile" scope

	input := &ImplicitGrantInput{
		Client:            client,
		User:              user,
		Scope:             "openid groups attributes",
		AcrLevel:          "urn:goiabada:pwd",
		AuthMethods:       "pwd",
		SessionIdentifier: "session-123",
		Nonce:             "nonce-123",
		AuthenticatedAt:   time.Now().UTC(),
	}

	response, err := tokenIssuer.GenerateTokenResponseForImplicit(ctx, input, true, true)
	assert.NoError(t, err)
	assert.NotNil(t, response)

	// Verify access token groups and attributes
	accessClaims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)

	accessGroups := accessClaims["groups"].([]interface{})
	assert.Len(t, accessGroups, 2) // admin and readonly
	assert.Contains(t, accessGroups, "admin")
	assert.Contains(t, accessGroups, "readonly")
	assert.NotContains(t, accessGroups, "users")

	accessAttrs := accessClaims["attributes"].(map[string]interface{})
	assert.Equal(t, "engineering", accessAttrs["department"])
	assert.Equal(t, "platform", accessAttrs["team"])
	assert.Nil(t, accessAttrs["level"])

	// Verify id_token groups and attributes
	idClaims := verifyAndDecodeToken(t, response.IdToken, publicKeyBytes)

	idGroups := idClaims["groups"].([]interface{})
	assert.Len(t, idGroups, 2) // admin and users
	assert.Contains(t, idGroups, "admin")
	assert.Contains(t, idGroups, "users")
	assert.NotContains(t, idGroups, "readonly")

	idAttrs := idClaims["attributes"].(map[string]interface{})
	assert.Equal(t, "engineering", idAttrs["department"])
	assert.Equal(t, "senior", idAttrs["level"])
	assert.Nil(t, idAttrs["team"])

	mockDB.AssertExpectations(t)
}

func TestCalculateAtHash(t *testing.T) {
	tokenIssuer := &TokenIssuer{}

	testCases := []struct {
		name        string
		accessToken string
	}{
		{
			name:        "Standard access token",
			accessToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
		},
		{
			name:        "Empty token",
			accessToken: "",
		},
		{
			name:        "Short token",
			accessToken: "abc",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			atHash := tokenIssuer.calculateAtHash(tc.accessToken)

			if tc.accessToken == "" {
				// Empty token should still produce a hash (of empty string)
				assert.NotEmpty(t, atHash)
			} else {
				assert.NotEmpty(t, atHash)
			}

			// Verify it's base64url encoded (no padding, no + or /)
			assert.NotContains(t, atHash, "=")
			assert.NotContains(t, atHash, "+")
			assert.NotContains(t, atHash, "/")

			// Verify consistency - same input produces same output
			atHash2 := tokenIssuer.calculateAtHash(tc.accessToken)
			assert.Equal(t, atHash, atHash2)
		})
	}
}

func TestCalculateAtHash_MatchesOIDCSpec(t *testing.T) {
	// This test verifies the at_hash calculation follows OIDC Core 3.2.2.10
	// at_hash = base64url(left_half(SHA256(access_token)))
	tokenIssuer := &TokenIssuer{}

	// Use a known access token to verify the calculation
	accessToken := "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y"

	atHash := tokenIssuer.calculateAtHash(accessToken)

	// The at_hash should be 16 bytes (128 bits) when decoded
	// SHA256 produces 32 bytes, left half is 16 bytes
	decoded, err := base64.RawURLEncoding.DecodeString(atHash)
	assert.NoError(t, err)
	assert.Len(t, decoded, 16, "at_hash should be 16 bytes (left half of SHA256)")
}
