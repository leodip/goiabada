package integration

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// phone_number off the real wire, after a phone saved the way an administrator saves one: through
// the admin API, which stores the country's calling code in its own column and the number as
// typed after it. The ID token and /userinfo then carry the number in strict E.164, the calling
// code followed by the digits, with no space or hyphen the user typed (#563 decision 4). A number
// the save accepts that would make more than E.164's 15 digits with its calling code is not sent in
// either token or at /userinfo, while phone_number_verified still is.
//
// The unit tier holds the rule at the mapper. This is here because a client reads the claim from a
// token issued off a stored row, and only this tier stores the row through the route that writes
// it. Both tokens' settings are turned on, so a missing claim is the mapper's doing and not the
// deployment's.
func TestToken_PhoneNumber_IsE164AfterAnAdminAPISave(t *testing.T) {
	changeSettings(t, func(settings *record.Settings) {
		settings.IncludeOpenIDConnectClaimsInIdToken = true
		settings.IncludeOpenIDConnectClaimsInAccessToken = true
	})

	tests := []struct {
		name   string
		number string
		want   string
	}{
		{name: "typed with spaces", number: "912 345 678", want: "+351912345678"},
		{name: "typed with hyphens", number: "912-345-678", want: "+351912345678"},
		{name: "fifteen digits with the calling code", number: "912 345 678 912", want: "+351912345678912"},
		{name: "sixteen digits with the calling code", number: "9123456789123", want: ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clientSecret := fake.LetterN(32)
			httpClient, code := createAuthCodeWithUserProfile(t, clientSecret, "openid phone")

			adminToken, _ := createAdminClientWithToken(t)
			phoneURL := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(code.UserId, 10) + "/phone"
			saveResp := makeAPIRequest(t, "PUT", phoneURL, adminToken, api.UpdateUserPhoneRequest{
				PhoneCountryUniqueId: "PRT_0",
				PhoneNumber:          test.number,
				PhoneNumberVerified:  true,
			})
			defer func() { _ = saveResp.Body.Close() }()
			require.Equal(t, http.StatusOK, saveResp.StatusCode)

			data := postToTokenEndpoint(t, httpClient, appConfig.AuthServer.BaseURL+"/auth/token/",
				url.Values{
					"grant_type":    {"authorization_code"},
					"client_id":     {code.Client.ClientIdentifier},
					"code":          {code.Code},
					"redirect_uri":  {code.RedirectURI},
					"code_verifier": {testCodeVerifier},
					"client_secret": {clientSecret},
				})

			assertPhoneClaims := func(where string, claims map[string]interface{}) {
				t.Helper()
				if test.want == "" {
					assert.NotContainsf(t, claims, "phone_number", "%s sends no number that is not E.164", where)
				} else {
					assert.Equalf(t, test.want, claims["phone_number"], "%s", where)
				}
				assert.Equalf(t, true, claims["phone_number_verified"], "%s", where)
			}

			idToken, ok := data["id_token"].(string)
			require.True(t, ok, "the grant carries openid, so an id_token is issued")
			assertPhoneClaims("the ID token", decodeJWTPayload(t, idToken))

			accessToken, ok := data["access_token"].(string)
			require.True(t, ok)
			assertPhoneClaims("the access token", decodeJWTPayload(t, accessToken))
			req, err := http.NewRequest("GET", appConfig.AuthServer.BaseURL+"/userinfo", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+accessToken)
			userinfoResp, err := httpClient.Do(req)
			require.NoError(t, err)
			defer func() { _ = userinfoResp.Body.Close() }()
			require.Equal(t, http.StatusOK, userinfoResp.StatusCode)

			var userinfo map[string]interface{}
			require.NoError(t, json.NewDecoder(userinfoResp.Body).Decode(&userinfo))
			assertPhoneClaims("/userinfo", userinfo)
		})
	}
}
