package integrationtests

import (
	"context"
	"net/url"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// updated_at is a profile-scope claim, at both token types, off the real wire.
//
// OIDC Core 5.4 lists it with name, family_name, birthdate and the rest of what the profile scope
// requests, and this repository's own documentation has always assigned it there
// (site/src/content/docs/concepts/openid-connect.mdx, integration/endpoints.mdx). Issuance
// disagreed with both until this test's two "openid email" rows: it emitted the claim for any
// scope beyond a lone openid, and in an access token for a lone openid too, because
// generateAccessTokenCore appends authserver:userinfo to the scope slice for the audience before
// the claim block reads it.
//
// The unit tier holds the same rule at the mapper and at the issuer. This one is here because the
// gate reads a slice that one caller mutates and the other does not, and only a token taken off
// the endpoint shows which slice each token type actually got. Both settings are turned on, so a
// claim that is absent is absent because of the scope and not because the deployment suppressed
// OIDC claims for that token type -- the access token's setting is seeded off, which is why this
// divergence could sit unnoticed.
func TestToken_UpdatedAt_RidesWithTheProfileScope(t *testing.T) {
	settings, err := database.GetSettingsById(context.Background(), nil, 1)
	require.NoError(t, err)

	originalIdToken := settings.IncludeOpenIDConnectClaimsInIdToken
	originalAccessToken := settings.IncludeOpenIDConnectClaimsInAccessToken
	settings.IncludeOpenIDConnectClaimsInIdToken = true
	settings.IncludeOpenIDConnectClaimsInAccessToken = true
	require.NoError(t, database.UpdateSettings(context.Background(), nil, settings))

	defer func() {
		settings.IncludeOpenIDConnectClaimsInIdToken = originalIdToken
		settings.IncludeOpenIDConnectClaimsInAccessToken = originalAccessToken
		_ = database.UpdateSettings(context.Background(), nil, settings)
	}()

	tests := []struct {
		name    string
		scope   string
		carries bool
	}{
		// Was absent from the ID token and present in the access token: the same grant, two
		// answers, because only one of the two slices had authserver:userinfo appended to it.
		{name: "openid alone", scope: "openid", carries: false},
		// Was present in both: a profile claim for a grant that was never given the profile
		// scope, and on the default path, since the ID token's setting is seeded on.
		{name: "openid email", scope: "openid email", carries: false},
		{name: "openid profile", scope: "openid profile", carries: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clientSecret := fake.LetterN(32)
			httpClient, code := createAuthCodeWithUserProfile(t, clientSecret, test.scope)

			data := postToTokenEndpoint(t, httpClient, config.GetAuthServer().BaseURL+"/auth/token/",
				url.Values{
					"grant_type":    {"authorization_code"},
					"client_id":     {code.Client.ClientIdentifier},
					"code":          {code.Code},
					"redirect_uri":  {code.RedirectURI},
					"code_verifier": {"code-verifier"},
					"client_secret": {clientSecret},
				})

			idToken, ok := data["id_token"].(string)
			require.True(t, ok, "the grant carries openid, so an id_token is issued")
			accessToken, ok := data["access_token"].(string)
			require.True(t, ok)

			idClaims := decodeJWTPayload(t, idToken)
			accessClaims := decodeJWTPayload(t, accessToken)

			if test.carries {
				assert.NotNil(t, idClaims["updated_at"], "the profile scope was granted")
				assert.NotNil(t, accessClaims["updated_at"], "the profile scope was granted")
			} else {
				assert.NotContains(t, idClaims, "updated_at",
					"updated_at is a profile-scope claim and no profile scope was granted")
				assert.NotContains(t, accessClaims, "updated_at",
					"the access token gates on the granted scope, not on the one the audience loop extended")
			}
		})
	}
}
