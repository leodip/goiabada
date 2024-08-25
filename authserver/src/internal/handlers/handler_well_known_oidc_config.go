package handlers

import (
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/oidc"
)

func HandleWellKnownOIDCConfigGet(
	httpHelper HttpHelper,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

		config := oidc.WellKnownConfig{
			Issuer:                           settings.Issuer,
			AuthorizationEndpoint:            config.AuthServerBaseUrl + "/auth/authorize",
			TokenEndpoint:                    config.AuthServerBaseUrl + "/auth/token",
			UserInfoEndpoint:                 config.AuthServerBaseUrl + "/userinfo",
			EndSessionEndpoint:               config.AuthServerBaseUrl + "/auth/logout",
			JWKsURI:                          config.AuthServerBaseUrl + "/certs",
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

		httpHelper.EncodeJson(w, r, config)
	}
}
