package authflow

import (
	"context"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
)

// form_post against the redirect URI's scheme (#121): the mode answers through an HTML form whose
// action is the redirect URI, and html/template rewrites every scheme outside http, https and
// mailto to "#ZgotmplZ", so a private-use scheme (RFC 8252 section 7.1) can be answered in that
// mode neither with its code nor with an error. The request is refused on the page, as an
// unsupported mode is, before anything that answers by redirect.

// formPostParams is a request whose client and redirect URI the validator double accepts, varying
// the response type, the response mode and the redirect URI.
func formPostParams(responseType, responseMode, redirectURI string) url.Values {
	params := url.Values{
		"client_id":     {"test-client"},
		"redirect_uri":  {redirectURI},
		"response_type": {responseType},
		"scope":         {"openid"},
	}
	if responseMode != "" {
		params.Set("response_mode", responseMode)
	}
	return params
}

func acceptingAddressValidator(t *testing.T) *handlersmocks.AuthorizeValidator {
	validator := handlersmocks.NewAuthorizeValidator(t)
	validator.On("ValidateClientAndRedirectURI", mock.Anything, mock.Anything).Return(nil).Once()
	return validator
}

// Every response type a form cannot answer at a private-use scheme is refused, on the GET and on
// the POST alike, and the refusal says whether the request is implicit, which decides the modes
// the page names. The database doubles register nothing, so a request let through to the client
// load or the parking insert fails the case.
func TestAuthorization_FormPostToAPrivateUseSchemeIsRefusedOnThePage(t *testing.T) {
	testCases := []struct {
		responseType string
		redirectURI  string
		wantImplicit bool
	}{
		{responseType: "code", redirectURI: "myapp://callback"},
		{responseType: "code", redirectURI: "com.example.app:/oauth2redirect/example-provider"},
		{responseType: "token", redirectURI: "myapp://callback", wantImplicit: true},
		{responseType: "id_token", redirectURI: "myapp://callback", wantImplicit: true},
		{responseType: "id_token token", redirectURI: "com.example.app:/oauth2redirect/example-provider", wantImplicit: true},
	}

	for _, tc := range testCases {
		want := &AuthorizePageRefusal{Reason: AuthorizePageRefusalFormPostUnreachable, ImplicitFlow: tc.wantImplicit}
		params := formPostParams(tc.responseType, "form_post", tc.redirectURI)

		t.Run("GET "+tc.responseType+" "+tc.redirectURI, func(t *testing.T) {
			authorization := NewAuthorization(datamocks.NewDatabase(t), nil, acceptingAddressValidator(t), nil, nil, nil, nil)

			result, err := authorization.Run(context.Background(), nil, &record.Settings{}, params, AuthorizeArrival{})

			require.NoError(t, err)
			assert.Equal(t, want, result.PageRefusal)
			assert.Nil(t, result.AuthContext)
		})

		t.Run("POST "+tc.responseType+" "+tc.redirectURI, func(t *testing.T) {
			parking := NewAuthorizationParking(acceptingAddressValidator(t), datamocks.NewDatabase(t))

			result, err := parking.Run(context.Background(), params, "")

			require.NoError(t, err)
			assert.Equal(t, want, result.PageRefusal)
			assert.Empty(t, result.Handle)
		})
	}
}

// The rule is form_post's alone, and a scheme a form can post to passes it: the other modes answer
// with a Location, which a private-use scheme survives, and the parse lower-cases the scheme, so
// HTTPS names https.
func TestRefuseUnaddressableAuthorizeRequest_FormPostReachesHTTPAndOtherModesReachAnyScheme(t *testing.T) {
	testCases := []struct {
		responseType string
		responseMode string
		redirectURI  string
	}{
		{"code", "form_post", "http://127.0.0.1:9000/callback"},
		{"code", "form_post", "https://example.com/callback"},
		{"code", "form_post", "HTTPS://example.com/callback"},
		{"token", "form_post", "https://example.com/callback"},
		{"code", "", "myapp://callback"},
		{"code", "query", "myapp://callback"},
		{"code", "fragment", "myapp://callback"},
		{"token", "fragment", "myapp://callback"},
	}

	for _, tc := range testCases {
		t.Run(tc.responseType+" "+tc.responseMode+" "+tc.redirectURI, func(t *testing.T) {
			refusal, err := refuseUnaddressableAuthorizeRequest(context.Background(), acceptingAddressValidator(t), "",
				formPostParams(tc.responseType, tc.responseMode, tc.redirectURI))

			require.NoError(t, err)
			assert.Nil(t, refusal)
		})
	}
}
