package handlers

import (
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
)

func HandleWellKnownOIDCConfigGet(
	jsonWriter JSONWriter,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			jsonWriter.JsonError(w, r, reqctx.ErrNoSettings)
			return
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
			AuthorizationEndpoint:            baseURL + "/auth/authorize",
			TokenEndpoint:                    baseURL + "/auth/token",
			UserInfoEndpoint:                 baseURL + "/userinfo",
			EndSessionEndpoint:               baseURL + "/auth/logout",
			JWKsURI:                          baseURL + "/certs",
			GrantTypesSupported:              oidc.GrantTypesSupported(settings.ImplicitFlowEnabled),
			ResponseTypesSupported:           responseTypes,
			ResponseModesSupported:           responseModes,
			PromptValuesSupported:            []string{"none", "login", "consent"},
			ACRValuesSupported:               []string{"urn:goiabada:level1", "urn:goiabada:level2_optional", "urn:goiabada:level2_mandatory"},
			SubjectTypesSupported:            []string{"public"},
			IdTokenSigningAlgValuesSupported: []string{"RS256"},
			ScopesSupported:                  oidc.SupportedScopes(),
			ClaimsSupported: []string{
				"iss", "iat", "nbf", "auth_time", "jti", "acr", "amr", "sid", "aud", "typ", "exp", "nonce",
				"sub",                                                                                                                                                                            // openid
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
			wellKnownConfig.RegistrationEndpoint = baseURL + "/connect/register"
		}

		jsonWriter.EncodeJson(w, r, wellKnownConfig)
	}
}
