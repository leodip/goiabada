package accounthandlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
	mocks_handler_helpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	"github.com/leodip/goiabada/core/oauth"
)

// Seam 3 for the logout page (#350 decision 2).
//
// Three things can go wrong here that the endpoint's own cases cannot see, and each of them is the
// leak decision 2 exists to close: the handler could keep asking for the redirect mode, it could
// receive the form instruction and redirect anyway, or it could render a page built from something
// other than the endpoint and parameters the API sent.

// logoutApiClient answers CreateAccountLogoutRequest from a script and records what it was asked
// for. The embedded interface means any other call panics naming its method.
type logoutApiClient struct {
	apiclient.ApiClient

	form     *api.AccountLogoutFormPostResponse
	redirect *api.AccountLogoutRedirectResponse

	got *api.AccountLogoutRequest
}

func (c *logoutApiClient) CreateAccountLogoutRequest(accessToken string, request *api.AccountLogoutRequest) (
	*api.AccountLogoutFormPostResponse, *api.AccountLogoutRedirectResponse, error) {
	c.got = request
	return c.form, c.redirect, nil
}

// logoutRequest is a visitor holding the parsed tokens this page reads. WithAccessToken alone leaves
// IdToken and AccessToken nil, which is the handler's unauthenticated arm.
func logoutRequest() *http.Request {
	return handlertest.Request(http.MethodGet, "/account/logout",
		handlertest.WithJwtInfo(oauth.JwtInfo{
			IdToken:     &oauth.JwtToken{TokenBase64: "the.id.token"},
			AccessToken: &oauth.JwtToken{TokenBase64: handlertest.AccessToken},
		}))
}

func TestHandleAccountLogoutGet_AsksForTheFormPostModeAndRendersTheForm(t *testing.T) {
	httpHelper := mocks_handler_helpers.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper,
		"/layouts/no_menu_layout.html", "/account_logout_form_post.html").Once()

	apiClient := &logoutApiClient{form: &api.AccountLogoutFormPostResponse{
		Method:   "POST",
		Endpoint: "https://auth.example.com/auth/logout",
		Params: map[string]string{
			"id_token_hint":            "the.id.token",
			"post_logout_redirect_uri": "https://console.example.com/",
			"state":                    "a-state",
		},
	}}

	rec := httptest.NewRecorder()
	HandleAccountLogoutGet(httpHelper, newFlashTestStore(), apiClient).ServeHTTP(rec, logoutRequest())

	require.NotNil(t, apiClient.got, "the handler must reach the API")
	assert.Equal(t, api.AccountLogoutResponseModeFormPost, apiClient.got.ResponseMode,
		"asking for the redirect mode is what puts the id_token_hint in a top-level URL")
	assert.NotEmpty(t, apiClient.got.State, "the console still sends a state")

	// The session cookie is cleared whichever arm is taken, so a 302 here would be a redirect the
	// handler wrote rather than the cookie write.
	assert.Equal(t, http.StatusOK, rec.Code, "the form page is rendered, not redirected to")
	assert.Empty(t, rec.Header().Get("Location"), "nothing may navigate the browser to the hint")

	bind := handlertest.Bind(t, httpHelper)
	assert.Equal(t, "https://auth.example.com/auth/logout", bind["endpoint"],
		"the form submits to the endpoint the API named")
	assert.Equal(t, apiClient.form.Params, bind["params"],
		"the page renders the API's own parameters, not a set rebuilt here")
}

// The other arm, and not a dead one: an auth server older than this change answers the redirect
// shape whatever the request asked for. Before decision 2 the handler dereferenced the redirect
// return unconditionally, so this is also the case that pins the nil check the form arm needed.
func TestHandleAccountLogoutGet_StillFollowsARedirectResponse(t *testing.T) {
	httpHelper := mocks_handler_helpers.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)

	apiClient := &logoutApiClient{redirect: &api.AccountLogoutRedirectResponse{
		LogoutUrl: "https://auth.example.com/auth/logout?id_token_hint=the.id.token",
	}}

	rec := httptest.NewRecorder()
	HandleAccountLogoutGet(httpHelper, newFlashTestStore(), apiClient).ServeHTTP(rec, logoutRequest())

	assert.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t, "https://auth.example.com/auth/logout?id_token_hint=the.id.token",
		rec.Header().Get("Location"))
}

// A visitor with no parsed tokens never reaches the API at all: the embedded interface would panic
// on the call, so this case would fail loudly rather than quietly.
func TestHandleAccountLogoutGet_WithoutTokensGoesHomeWithoutCallingTheAPI(t *testing.T) {
	httpHelper := mocks_handler_helpers.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)

	apiClient := &logoutApiClient{}
	rec := httptest.NewRecorder()
	req := handlertest.Request(http.MethodGet, "/account/logout", handlertest.WithAccessToken())

	HandleAccountLogoutGet(httpHelper, newFlashTestStore(), apiClient).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusFound, rec.Code)
	assert.Nil(t, apiClient.got, "there is no logout to prepare without an ID token")
}
