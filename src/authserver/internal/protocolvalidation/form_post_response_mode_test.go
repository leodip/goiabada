package protocolvalidation

import (
	"errors"
	"net/http"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// form_post against the redirect URI's scheme (#121): the mode answers through an HTML form whose
// action is the redirect URI, and html/template's URL filter — the one guard standing between a
// stored javascript: redirect URI and a live form action — rewrites every scheme outside http,
// https and mailto to "#ZgotmplZ" rather than let the form target it. A private-use scheme such as
// myapp:// (RFC 8252 section 7.1) therefore posts the response to this server and reaches nobody,
// and ValidateRequest used to accept the combination for any URI, so the flow completed and the
// code died on the form with no error anywhere. The rule is #121's Option A: refuse the
// combination up front, and leave the template's allowlist exactly as it is.

// formPostRequest is a request that names response_mode=form_post and passes every other
// validation, so the redirect URI is the one thing a case varies. The authorization code flow
// is on, which #587's gate asks of a response_type that names it.
func formPostRequest(redirectURI string) *ValidateRequestInput {
	return &ValidateRequestInput{
		ResponseType:             "code",
		CodeChallengeMethod:      "S256",
		CodeChallenge:            "a_valid_code_challenge_that_meets_length_requirements",
		ResponseMode:             "form_post",
		RedirectURI:              redirectURI,
		AuthorizationCodeEnabled: true,
	}
}

const formPostCustomSchemeRefusal = "response_mode=form_post posts the response to the redirect URI as a form, " +
	"which no scheme other than http or https can receive. " +
	"Use response_mode=query or response_mode=fragment instead."

// The URIs a form can be answered at: the two schemes a browser takes as a form action. Scheme case
// is the parse's to judge, and the parse lower-cases it, so HTTPS names the same scheme as https.
func TestValidateRequest_FormPost_HTTPRedirectURIAccepted(t *testing.T) {
	validator := NewAuthorizeValidator(datamocks.NewDatabase(t))

	for _, uri := range []string{
		"http://127.0.0.1:9000/callback",
		"https://example.com/callback",
		"HTTPS://example.com/callback",
	} {
		t.Run(uri, func(t *testing.T) {
			assert.NoError(t, validator.ValidateRequest(formPostRequest(uri)))
		})
	}
}

// The URIs a form cannot be answered at: the private-use schemes of RFC 8252 section 7.1, and the
// javascript: of #121's "why the obvious fix is wrong", which the template's URL filter exists to
// neutralise and which this rule now refuses before any form is built. The refusal is
// invalid_request, and the description names the two modes that reach a custom scheme.
func TestValidateRequest_FormPost_CustomSchemeRedirectURIRefused(t *testing.T) {
	validator := NewAuthorizeValidator(datamocks.NewDatabase(t))

	for _, uri := range []string{
		"myapp://callback",
		"com.example.app:/oauth2redirect/example-provider",
		"javascript:alert(1)",
	} {
		t.Run(uri, func(t *testing.T) {
			err := validator.ValidateRequest(formPostRequest(uri))

			require.Error(t, err)
			var detail *oauth.ErrorDetail
			ok := errors.As(err, &detail)
			require.True(t, ok, "the refusal is a protocol error, not a localized page")
			assert.Equal(t, "invalid_request", detail.Code())
			assert.Equal(t, formPostCustomSchemeRefusal, detail.Description())
			assert.Equal(t, http.StatusBadRequest, detail.HTTPStatus())
		})
	}
}

// The rule is the mode's, not the code flow's: the implicit flow may name form_post too —
// implicitResponseMode keeps its errors out of the query, and form_post is one of its three modes
// (#231) — and a token request through it is refused for the same URI.
func TestValidateRequest_FormPost_ImplicitFlowRefusedForTheSameURI(t *testing.T) {
	validator := NewAuthorizeValidator(datamocks.NewDatabase(t))

	request := implicitRequest("token", "form_post")
	request.RedirectURI = "myapp://callback"
	err := validator.ValidateRequest(request)

	require.Error(t, err)
	var detail *oauth.ErrorDetail
	ok := errors.As(err, &detail)
	require.True(t, ok)
	assert.Equal(t, "invalid_request", detail.Code())
	assert.Equal(t, formPostCustomSchemeRefusal, detail.Description())
}

// The other modes reach a custom scheme: they answer with a Location, which the scheme survives, so
// only form_post is refused. The empty row is the caller that has not resolved a URI — the
// authorization endpoint never is, because it registers the URI before validating the request — so
// the rule waits rather than judge a URI it was not given.
func TestValidateRequest_OtherModes_CustomSchemeAndUnresolvedURIAccepted(t *testing.T) {
	validator := NewAuthorizeValidator(datamocks.NewDatabase(t))

	for _, mode := range []string{"", "query", "fragment"} {
		t.Run("response_mode="+mode, func(t *testing.T) {
			request := formPostRequest("myapp://callback")
			request.ResponseMode = mode
			assert.NoError(t, validator.ValidateRequest(request))
		})
	}

	t.Run("form_post with no redirect URI yet", func(t *testing.T) {
		assert.NoError(t, validator.ValidateRequest(formPostRequest("")))
	})
}
