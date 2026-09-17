package apiclient

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/api"
)

// Seam 2 for the logout request (#350 decision 2).
//
// CreateAccountLogoutRequest is the one method with two success shapes, and it tells them apart by
// what survived the unmarshal rather than by a discriminator the body carries. That makes it the
// place the whole of decision 2 can fail while the endpoint's own integration cases stay green: a
// form instruction read as "not a form" falls through to the redirect arm, the handler finds a nil
// redirect where it expected one, and the page that ends a session panics. The other direction is
// worse and quieter: a redirect body mistaken for a form renders a form with no action.
//
// The bodies are literal JSON text, not marshalled from the structs under test, so a renamed tag on
// either side is visible here. serves lives in user_client_test.go.

func TestAuthServerClient_CreateAccountLogoutRequestReadsTheFormInstruction(t *testing.T) {
	client, recorded := serves(t, `{
		"method": "POST",
		"endpoint": "https://auth.example.com/auth/logout",
		"params": {
			"id_token_hint": "the.id.token",
			"post_logout_redirect_uri": "https://console.example.com/",
			"state": "a-state"
		}
	}`)

	formResp, redirectResp, err := client.CreateAccountLogoutRequest("an-access-token",
		&api.AccountLogoutRequest{
			PostLogoutRedirectUri: "https://console.example.com/",
			ResponseMode:          api.AccountLogoutResponseModeFormPost,
		})
	require.NoError(t, err)

	gotPath, gotAuthorization := recorded()
	assert.Equal(t, "/api/v1/account/logout-request", gotPath)
	assert.Equal(t, "Bearer an-access-token", gotAuthorization)

	require.NotNil(t, formResp, "a form body must arrive as the form return")
	assert.Nil(t, redirectResp, "exactly one of the two returns is non-nil")

	assert.Equal(t, "POST", formResp.Method)
	assert.Equal(t, "https://auth.example.com/auth/logout", formResp.Endpoint)
	assert.Equal(t, map[string]string{
		"id_token_hint":            "the.id.token",
		"post_logout_redirect_uri": "https://console.example.com/",
		"state":                    "a-state",
	}, formResp.Params, "every parameter reaches the form, since the page renders this map and nothing else")
}

// The redirect arm stays reachable: an auth server older than this change answers it whatever
// responseMode asked for. Without this case the decoder could stop recognising it entirely and the
// case above would still pass.
func TestAuthServerClient_CreateAccountLogoutRequestReadsTheRedirect(t *testing.T) {
	client, _ := serves(t,
		`{"logoutUrl":"https://auth.example.com/auth/logout?id_token_hint=the.id.token"}`)

	formResp, redirectResp, err := client.CreateAccountLogoutRequest("an-access-token",
		&api.AccountLogoutRequest{
			PostLogoutRedirectUri: "https://console.example.com/",
			ResponseMode:          api.AccountLogoutResponseModeFormPost,
		})
	require.NoError(t, err)

	assert.Nil(t, formResp, "a redirect body must not be read as a form with empty fields")
	require.NotNil(t, redirectResp)
	assert.Equal(t, "https://auth.example.com/auth/logout?id_token_hint=the.id.token",
		redirectResp.LogoutUrl)
}

// A body that fills neither shape is an error rather than a nil pair, because the caller of a nil
// pair dereferences whichever return it expected.
func TestAuthServerClient_CreateAccountLogoutRequestRefusesABodyOfNeitherShape(t *testing.T) {
	client, _ := serves(t, `{"somethingElse":true}`)

	formResp, redirectResp, err := client.CreateAccountLogoutRequest("an-access-token",
		&api.AccountLogoutRequest{PostLogoutRedirectUri: "https://console.example.com/"})

	require.Error(t, err)
	assert.Nil(t, formResp)
	assert.Nil(t, redirectResp)
}
