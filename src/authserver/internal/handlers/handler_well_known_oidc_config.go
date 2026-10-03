package handlers

import (
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
)

// HandleWellKnownOIDCConfigGet serves the discovery document. It describes what the server
// implements, which no setting changes: every grant and response type is listed whether or not the
// implicit or password switch is on, because OIDC Discovery 1.0 section 3 and RFC 8414 section 2
// define both fields as what the server supports, and a client not allowed a flow is refused
// unauthorized_client at the endpoint. The two settings read here are the issuer and whether the
// registration endpoint exists at all (#437).
func HandleWellKnownOIDCConfigGet(
	jsonWriter JSONWriter,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			jsonWriter.JSONError(w, r, reqctx.ErrNoSettings)
			return
		}

		wellKnownConfig := oidc.WellKnownConfig{
			Issuer:                           settings.Issuer,
			AuthorizationEndpoint:            baseURL + "/auth/authorize",
			TokenEndpoint:                    baseURL + "/auth/token",
			UserInfoEndpoint:                 baseURL + "/userinfo",
			EndSessionEndpoint:               baseURL + "/auth/logout",
			JWKsURI:                          baseURL + "/certs",
			GrantTypesSupported:              oidc.GrantTypesSupported(),
			ResponseTypesSupported:           protocolvalidation.SupportedResponseTypes(),
			ResponseModesSupported:           protocolvalidation.SupportedResponseModes(),
			PromptValuesSupported:            []string{"none", "login", "consent"},
			ACRValuesSupported:               []string{"urn:goiabada:level1", "urn:goiabada:level2_optional", "urn:goiabada:level2_mandatory"},
			SubjectTypesSupported:            []string{"public"},
			IdTokenSigningAlgValuesSupported: []string{"RS256"},
			ScopesSupported:                  oidc.SupportedScopes(),
			ClaimsSupported: []string{
				"iss", "iat", "nbf", "auth_time", "jti", "acr", "amr", "sid", "aud", "typ", "exp", "nonce", "auth_state_generation",
				"sub",                                                                                                                                                                            // openid
				"name", "given_name", "middle_name", "family_name", "nickname", "preferred_username", "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at", // profile
				"email", "email_verified", // email
				"address",                               // address
				"phone_number", "phone_number_verified", // phone
				"groups",     // groups
				"attributes", // attributes
			},
			// none is a public client, which authenticates with its client_id alone (RFC 7591
			// section 2) and which DCR registers.
			TokenEndpointAuthMethodsSupported: []string{"client_secret_post", "client_secret_basic", "none"},
			CodeChallengeMethodsSupported:     []string{"S256"},
			RequestParameterSupported:         false,
			RequestURIParameterSupported:      false,
		}

		// Include registration endpoint if DCR is enabled (RFC 7591 §4)
		if settings.DynamicClientRegistrationEnabled {
			wellKnownConfig.RegistrationEndpoint = baseURL + "/connect/register"
		}

		jsonWriter.EncodeJSON(w, r, wellKnownConfig)
	}
}
