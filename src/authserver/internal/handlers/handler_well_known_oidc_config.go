package handlers

import (
	"net/http"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oidc"
)

func HandleWellKnownOIDCConfigGet(
	httpHelper HttpHelper,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

		// Build grant types - always include base types
		grantTypes := []string{"authorization_code", "refresh_token", "client_credentials"}
		if settings.ImplicitFlowEnabled {
			grantTypes = append(grantTypes, "implicit")
		}

		// Build response types - always include code
		responseTypes := []string{"code"}
		if settings.ImplicitFlowEnabled {
			// OIDC implicit flow response types per OIDC Core 1.0 Section 3.2
			responseTypes = append(responseTypes, "token", "id_token", "id_token token")
		}

		// Build response modes
		responseModes := []string{"query", "fragment", "form_post"}

		wellKnownConfig := oidc.WellKnownConfig{
			Issuer:                           settings.Issuer,
			AuthorizationEndpoint:            config.GetAuthServer().BaseURL + "/auth/authorize",
			TokenEndpoint:                    config.GetAuthServer().BaseURL + "/auth/token",
			UserInfoEndpoint:                 config.GetAuthServer().BaseURL + "/userinfo",
			EndSessionEndpoint:               config.GetAuthServer().BaseURL + "/auth/logout",
			JWKsURI:                          config.GetAuthServer().BaseURL + "/certs",
			GrantTypesSupported:              grantTypes,
			ResponseTypesSupported:           responseTypes,
			ResponseModesSupported:           responseModes,
			ACRValuesSupported:               []string{"urn:goiabada:level1", "urn:goiabada:level2_optional", "urn:goiabada:level2_mandatory"},
			SubjectTypesSupported:            []string{"public"},
			IdTokenSigningAlgValuesSupported: []string{"RS256"},
			ScopesSupported: []string{
				"openid", "profile", "email", "address", "phone", "groups", "attributes", oidc.OfflineAccessScope},
			ClaimsSupported: []string{
				"iss", "iat", "nbf", "auth_time", "jti", "acr", "amr", "sid", "aud", "typ", "exp", "nonce",
				"sub",                                                                                                                                                                 // openid
				"name", "given_name", "middle_name", "family_name", "nickname", "preferred_username", "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at", // profile
				"email", "email_verified", // email
				"address",                               // address
				"phone_number", "phone_number_verified", // phone
				"groups",     // groups
				"attributes", // attributes
			},
			TokenEndpointAuthMethodsSupported: []string{"client_secret_post", "client_secret_basic"},
			CodeChallengeMethodsSupported:     []string{"S256"},
		}

		// Include registration endpoint if DCR is enabled (RFC 7591 §4)
		if settings.DynamicClientRegistrationEnabled {
			wellKnownConfig.RegistrationEndpoint = config.GetAuthServer().BaseURL + "/connect/register"
		}

		httpHelper.EncodeJson(w, r, wellKnownConfig)
	}
}
