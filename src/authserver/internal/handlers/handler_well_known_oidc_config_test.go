package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	mocks_handlers "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestHandleWellKnownOIDCConfigGet(t *testing.T) {
	t.Run("Returns correct OIDC configuration", func(t *testing.T) {
		jsonWriter := mocks_handlers.NewJSONWriter(t)

		handler := HandleWellKnownOIDCConfigGet(jsonWriter, testBaseURL)

		req, err := http.NewRequest("GET", "/.well-known/openid-configuration", nil)
		assert.NoError(t, err)

		settings := &models.Settings{
			Issuer: "https://example.com",
		}
		ctx := req.Context()
		ctx = reqctx.WithSettings(ctx, settings)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		jsonWriter.On("EncodeJson", rr, req, mock.AnythingOfType("oidc.WellKnownConfig")).Run(func(args mock.Arguments) {
			wellKnownConfig := args.Get(2).(oidc.WellKnownConfig)

			assert.Equal(t, "https://example.com", wellKnownConfig.Issuer)
			assert.Equal(t, testBaseURL+"/auth/authorize", wellKnownConfig.AuthorizationEndpoint)
			assert.Equal(t, testBaseURL+"/auth/token", wellKnownConfig.TokenEndpoint)
			assert.Equal(t, testBaseURL+"/userinfo", wellKnownConfig.UserInfoEndpoint)
			assert.Equal(t, testBaseURL+"/auth/logout", wellKnownConfig.EndSessionEndpoint)
			assert.Equal(t, testBaseURL+"/certs", wellKnownConfig.JWKsURI)
			// Equal, not ElementsMatch: the JSON array's order is observable. The list is oidc's
			// grant table, whose rows are pinned in grant_type_test.go (#437).
			assert.Equal(t, []string{"authorization_code", "refresh_token", "client_credentials"}, wellKnownConfig.GrantTypesSupported)
			assert.ElementsMatch(t, []string{"code"}, wellKnownConfig.ResponseTypesSupported)
			assert.ElementsMatch(t, []string{"urn:goiabada:level1", "urn:goiabada:level2_optional", "urn:goiabada:level2_mandatory"}, wellKnownConfig.ACRValuesSupported)
			assert.ElementsMatch(t, []string{"public"}, wellKnownConfig.SubjectTypesSupported)
			assert.ElementsMatch(t, []string{"RS256"}, wellKnownConfig.IdTokenSigningAlgValuesSupported)
			// The roster is pinned literally in oidc_test.go; this asserts discovery publishes that one list.
			assert.Equal(t, oidc.SupportedScopes(), wellKnownConfig.ScopesSupported)
			assert.ElementsMatch(t, []string{
				"iss", "iat", "nbf", "auth_time", "jti", "acr", "amr", "sid", "aud", "typ", "exp", "nonce",
				"sub", "name", "given_name", "middle_name", "family_name", "nickname", "preferred_username",
				"profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at",
				"email", "email_verified", "address", "phone_number", "phone_number_verified",
				"groups", "attributes",
			}, wellKnownConfig.ClaimsSupported)
			assert.ElementsMatch(t, []string{"client_secret_post", "client_secret_basic"}, wellKnownConfig.TokenEndpointAuthMethodsSupported)
			assert.ElementsMatch(t, []string{"S256"}, wellKnownConfig.CodeChallengeMethodsSupported)
		}).Return()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		jsonWriter.AssertExpectations(t)
	})

	// The implicit flow switched on globally adds implicit to the grant list and the three implicit
	// response types, each in order. password stays absent: discovery has never listed it (#437).
	t.Run("Implicit flow enabled adds implicit and its response types", func(t *testing.T) {
		jsonWriter := mocks_handlers.NewJSONWriter(t)

		handler := HandleWellKnownOIDCConfigGet(jsonWriter, testBaseURL)

		req, err := http.NewRequest("GET", "/.well-known/openid-configuration", nil)
		assert.NoError(t, err)

		settings := &models.Settings{
			Issuer:              "https://example.com",
			ImplicitFlowEnabled: true,
		}
		req = req.WithContext(reqctx.WithSettings(req.Context(), settings))

		rr := httptest.NewRecorder()

		var published oidc.WellKnownConfig
		jsonWriter.On("EncodeJson", rr, req, mock.AnythingOfType("oidc.WellKnownConfig")).Run(func(args mock.Arguments) {
			published = args.Get(2).(oidc.WellKnownConfig)
		}).Return()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, []string{"authorization_code", "refresh_token", "client_credentials", "implicit"}, published.GrantTypesSupported)
		assert.Equal(t, []string{"code", "token", "id_token", "id_token token"}, published.ResponseTypesSupported)
	})
}
