package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestHandleWellKnownOIDCConfigGet(t *testing.T) {
	t.Run("Returns correct OIDC configuration", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)

		handler := HandleWellKnownOIDCConfigGet(httpHelper)

		req, err := http.NewRequest("GET", "/.well-known/openid-configuration", nil)
		assert.NoError(t, err)

		settings := &models.Settings{
			Issuer: "https://example.com",
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		httpHelper.On("EncodeJson", rr, req, mock.AnythingOfType("oidc.WellKnownConfig")).Run(func(args mock.Arguments) {
			wellKnownConfig := args.Get(2).(oidc.WellKnownConfig)

			assert.Equal(t, "https://example.com", wellKnownConfig.Issuer)
			assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/authorize", wellKnownConfig.AuthorizationEndpoint)
			assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/token", wellKnownConfig.TokenEndpoint)
			assert.Equal(t, config.GetAuthServer().BaseURL+"/userinfo", wellKnownConfig.UserInfoEndpoint)
			assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/logout", wellKnownConfig.EndSessionEndpoint)
			assert.Equal(t, config.GetAuthServer().BaseURL+"/certs", wellKnownConfig.JWKsURI)
			assert.ElementsMatch(t, []string{"authorization_code", "refresh_token", "client_credentials"}, wellKnownConfig.GrantTypesSupported)
			assert.ElementsMatch(t, []string{"code"}, wellKnownConfig.ResponseTypesSupported)
			assert.ElementsMatch(t, []string{"urn:goiabada:level1", "urn:goiabada:level2_optional", "urn:goiabada:level2_mandatory"}, wellKnownConfig.ACRValuesSupported)
			assert.ElementsMatch(t, []string{"public"}, wellKnownConfig.SubjectTypesSupported)
			assert.ElementsMatch(t, []string{"RS256"}, wellKnownConfig.IdTokenSigningAlgValuesSupported)
			assert.ElementsMatch(t, []string{"openid", "profile", "email", "address", "phone", "groups", "attributes", "offline_access"}, wellKnownConfig.ScopesSupported)
			assert.ElementsMatch(t, []string{
				"iss", "iat", "auth_time", "jti", "acr", "amr", "sid", "aud", "typ", "exp", "nonce",
				"sub", "name", "given_name", "middle_name", "family_name", "nickname", "preferred_username",
				"profile", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at",
				"email", "email_verified", "address", "phone_number", "phone_number_verified",
				"groups", "attributes",
			}, wellKnownConfig.ClaimsSupported)
			assert.ElementsMatch(t, []string{"client_secret_post"}, wellKnownConfig.TokenEndpointAuthMethodsSupported)
			assert.ElementsMatch(t, []string{"S256"}, wellKnownConfig.CodeChallengeMethodsSupported)
		}).Return()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		httpHelper.AssertExpectations(t)
	})
}
