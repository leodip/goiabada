package server

import (
	"encoding/json"
	"net/http"

	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleWellKnownOIDCConfigGet() http.HandlerFunc {

	type oidcConfig struct {
		Issuer                            string   `json:"issuer"`
		AuthorizationEndpoint             string   `json:"authorization_endpoint"`
		TokenEndpoint                     string   `json:"token_endpoint"`
		UserInfoEndpoint                  string   `json:"userinfo_endpoint"`
		JWKsURI                           string   `json:"jwks_uri"`
		GrantTypesSupported               []string `json:"grant_types_supported"`
		ResponseTypesSupported            []string `json:"response_types_supported"`
		ACRValuesSupported                []string `json:"acr_values_supported"`
		SubjectTypesSupported             []string `json:"subject_types_supported"`
		IdTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
		ScopesSupported                   []string `json:"scopes_supported"`
		ClaimsSupported                   []string `json:"claims_supported"`
		TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
		CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	}

	return func(w http.ResponseWriter, r *http.Request) {

		settings := r.Context().Value(common.ContextKeySettings).(*entities.Settings)

		config := oidcConfig{
			Issuer:                           settings.Issuer,
			AuthorizationEndpoint:            lib.GetBaseUrl() + "/auth/authorize",
			TokenEndpoint:                    lib.GetBaseUrl() + "/auth/token",
			UserInfoEndpoint:                 lib.GetBaseUrl() + "/userinfo",
			JWKsURI:                          lib.GetBaseUrl() + "/certs",
			GrantTypesSupported:              []string{"authorization_code", "refresh_token", "client_credentials"},
			ResponseTypesSupported:           []string{"code"},
			ACRValuesSupported:               []string{"urn:goiabada:pwd", "urn:goiabada:pwd:otp_ifpossible", "urn:goiabada:pwd:otp_mandatory"},
			SubjectTypesSupported:            []string{"public"},
			IdTokenSigningAlgValuesSupported: []string{"RS256"},
			ScopesSupported: []string{
				"openid", "profile", "email", "address", "phone", "groups", "attributes", "offline_access"},
			ClaimsSupported: []string{
				"iss", "iat", "auth_time", "jti", "acr", "amr", "sid", "aud", "typ", "exp", "nonce",
				"sub",                                                                                                                                                                 // openid
				"name", "given_name", "middle_name", "family_name", "nickname", "preferred_username", "profile", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at", // profile
				"email", "email_verified", // email
				"address",                               // address
				"phone_number", "phone_number_verified", // phone
				"groups",     // groups
				"attributes", // attributes
			},
			TokenEndpointAuthMethodsSupported: []string{"client_secret_post"},
			CodeChallengeMethodsSupported:     []string{"S256"},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(config)
	}
}
