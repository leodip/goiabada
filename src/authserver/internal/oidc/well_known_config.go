package oidc

type WellKnownConfig struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserInfoEndpoint                  string   `json:"userinfo_endpoint"`
	EndSessionEndpoint                string   `json:"end_session_endpoint"`
	JWKsURI                           string   `json:"jwks_uri"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"` // RFC 7591 §4
	GrantTypesSupported               []string `json:"grant_types_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported,omitempty"` // OIDC Discovery 1.0 §3
	PromptValuesSupported             []string `json:"prompt_values_supported,omitempty"`  // OIDC Discovery 1.0 §3
	ACRValuesSupported                []string `json:"acr_values_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IdTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	// Written false, never omitted: OIDC Discovery 1.0 section 3 reads an absent
	// request_uri_parameter_supported as true, while the authorize endpoint refuses request_uri
	// (request_uri_not_supported). request_parameter_supported defaults to false and is written
	// beside it so the two refusals read alike. An omitempty tag here drops both, since the value
	// is always false (#231, #437).
	RequestParameterSupported    bool `json:"request_parameter_supported"`
	RequestURIParameterSupported bool `json:"request_uri_parameter_supported"`
}
