package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/authserver/internal/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestHandleWellKnownOIDCConfigGet(t *testing.T) {
	t.Run("Returns correct OIDC configuration", func(t *testing.T) {
		httpHelper := &mocks.HttpHelper{}

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
			assert.Equal(t, config.AuthServerBaseUrl+"/auth/authorize", wellKnownConfig.AuthorizationEndpoint)
			assert.Equal(t, config.AuthServerBaseUrl+"/auth/token", wellKnownConfig.TokenEndpoint)
			assert.Equal(t, config.AuthServerBaseUrl+"/userinfo", wellKnownConfig.UserInfoEndpoint)
			assert.Equal(t, config.AuthServerBaseUrl+"/auth/logout", wellKnownConfig.EndSessionEndpoint)
			assert.Equal(t, config.AuthServerBaseUrl+"/certs", wellKnownConfig.JWKsURI)
			assert.ElementsMatch(t, []string{"authorization_code", "refresh_token", "client_credentials"}, wellKnownConfig.GrantTypesSupported)
			assert.ElementsMatch(t, []string{"code"}, wellKnownConfig.ResponseTypesSupported)
			assert.ElementsMatch(t, []string{"urn:goiabada:pwd", "urn:goiabada:pwd:otp_ifpossible", "urn:goiabada:pwd:otp_mandatory"}, wellKnownConfig.ACRValuesSupported)
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
