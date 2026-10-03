package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// expectedDiscoveryDocument is the whole document the handler publishes for the test issuer, with DCR
// off. Written out literally rather than read from the lists it is built from, so a change to any
// of them shows up here as a change to what relying parties are told (#437).
func expectedDiscoveryDocument() oidc.WellKnownConfig {
	return oidc.WellKnownConfig{
		Issuer:                "https://example.com",
		AuthorizationEndpoint: testBaseURL + "/auth/authorize",
		TokenEndpoint:         testBaseURL + "/auth/token",
		UserInfoEndpoint:      testBaseURL + "/userinfo",
		EndSessionEndpoint:    testBaseURL + "/auth/logout",
		JWKsURI:               testBaseURL + "/certs",
		// Every grant the server implements, in the grant table's order (#437).
		GrantTypesSupported:              []string{"authorization_code", "refresh_token", "client_credentials", "password", "implicit"},
		ResponseTypesSupported:           []string{"code", "token", "id_token", "id_token token"},
		ResponseModesSupported:           []string{"query", "fragment", "form_post"},
		PromptValuesSupported:            []string{"none", "login", "consent"},
		ACRValuesSupported:               []string{"urn:goiabada:level1", "urn:goiabada:level2_optional", "urn:goiabada:level2_mandatory"},
		SubjectTypesSupported:            []string{"public"},
		IdTokenSigningAlgValuesSupported: []string{"RS256"},
		// The roster is pinned literally in oidc_test.go; this asserts discovery publishes that one list.
		ScopesSupported: oidc.SupportedScopes(),
		ClaimsSupported: []string{
			"iss", "iat", "nbf", "auth_time", "jti", "acr", "amr", "sid", "aud", "typ", "exp", "nonce", "auth_state_generation",
			"sub", "name", "given_name", "middle_name", "family_name", "nickname", "preferred_username",
			"profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at",
			"email", "email_verified", "address", "phone_number", "phone_number_verified",
			"groups", "attributes",
		},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post", "client_secret_basic", "none"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		RequestParameterSupported:         false,
		RequestURIParameterSupported:      false,
	}
}

func serveDiscovery(t *testing.T, settings *record.Settings) oidc.WellKnownConfig {
	t.Helper()
	jsonWriter := handlersmocks.NewJSONWriter(t)
	handler := HandleWellKnownOIDCConfigGet(jsonWriter, testBaseURL)

	req, err := http.NewRequest("GET", "/.well-known/openid-configuration", nil)
	require.NoError(t, err)
	req = req.WithContext(reqctx.WithSettings(req.Context(), settings))
	rr := httptest.NewRecorder()

	var published oidc.WellKnownConfig
	jsonWriter.On("EncodeJSON", rr, req, mock.AnythingOfType("oidc.WellKnownConfig")).Run(func(args mock.Arguments) {
		published = args.Get(2).(oidc.WellKnownConfig)
	}).Return()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	return published
}

// TestHandleWellKnownOIDCConfigGet compares the whole document, so a field added, dropped or
// reordered fails here. Equal, not ElementsMatch: every JSON array's order is observable.
//
// The document reads no flow switch: grant_types_supported and response_types_supported are what
// the server implements (OIDC Discovery 1.0 section 3, RFC 8414 section 2), so the implicit and
// password switches, on or off, publish the same document (#437, decision 7).
func TestHandleWellKnownOIDCConfigGet(t *testing.T) {
	testCases := []struct {
		name     string
		settings *record.Settings
	}{
		{"every flow switch off", &record.Settings{Issuer: "https://example.com"}},
		{"implicit on", &record.Settings{Issuer: "https://example.com", ImplicitFlowEnabled: true}},
		{"password grant on", &record.Settings{Issuer: "https://example.com", ResourceOwnerPasswordCredentialsEnabled: true}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, expectedDiscoveryDocument(), serveDiscovery(t, tc.settings))
		})
	}

	// registration_endpoint is the one field a switch adds: the endpoint answers 404 while DCR is
	// off, so advertising it would point at nothing (RFC 7591 section 4).
	t.Run("DCR on adds the registration endpoint and nothing else", func(t *testing.T) {
		want := expectedDiscoveryDocument()
		want.RegistrationEndpoint = testBaseURL + "/connect/register"

		got := serveDiscovery(t, &record.Settings{Issuer: "https://example.com", DynamicClientRegistrationEnabled: true})

		assert.Equal(t, want, got)
	})
}

// TestWellKnownConfig_WritesFalseRequestParameters pins the wire form of the two request object
// fields. OIDC Discovery 1.0 section 3 reads an absent request_uri_parameter_supported as true, and
// the authorize endpoint refuses request_uri, so the key must be on the wire even though its value
// is the zero value. An omitempty tag drops it and this fails (#231, #437).
func TestWellKnownConfig_WritesFalseRequestParameters(t *testing.T) {
	encoded, err := json.Marshal(serveDiscovery(t, &record.Settings{Issuer: "https://example.com"}))
	require.NoError(t, err)

	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(encoded, &fields))

	for _, key := range []string{"request_uri_parameter_supported", "request_parameter_supported"} {
		value, present := fields[key]
		if assert.True(t, present, "%s must be written", key) {
			assert.Equal(t, "false", string(value), key)
		}
	}
	_, present := fields["registration_endpoint"]
	assert.False(t, present, "registration_endpoint stays omitted while DCR is off")
}
