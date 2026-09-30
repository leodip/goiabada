package protocolvalidation

import (
	"net/http"
	"testing"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The implicit flow's response mode (#231, decision 15): the fragment, form_post or nothing, and
// never the query.
//
// OAuth 2.0 Multiple Response Type Encoding Practices section 3 says of id_token "the query encoding
// MUST NOT be used", section 5 says the same of id_token token, and RFC 6749 4.2.2 puts the implicit
// grant's token response in the fragment. OAuth 2.0 Form Post Response Mode section 4 says "it is
// safe to return Authorization Response parameters whose default Response Modes are the query
// encoding or the fragment encoding using the form_post Response Mode". ValidateRequest used to
// refuse form_post as well, so a request the specification allows was answered with an error while
// discovery advertised the mode.

// implicitRequest is a request for the response type that passes every other validation, so the
// mode is the one thing a case varies.
func implicitRequest(responseType string, responseMode string) *ValidateRequestInput {
	return &ValidateRequestInput{
		ResponseType:         responseType,
		ResponseMode:         responseMode,
		ImplicitGrantEnabled: true,
		Scope:                "openid",
		Nonce:                "test-nonce-123",
	}
}

var implicitResponseTypes = []string{"token", "id_token", "id_token token", "token id_token"}

const implicitQueryRefusal = "Implicit flow does not support response_mode=query. " +
	"Use response_mode=fragment (the default for implicit flow) or response_mode=form_post."

// The three modes an implicit request may name, for every response type that returns tokens. The
// form_post row is the leniency decision 15 chose on purpose: a request that used to be refused and
// is served now, so it fails if the refusal comes back.
func TestValidateRequest_ImplicitFlow_ResponseModeAccepted(t *testing.T) {
	validator := NewAuthorizeValidator(mocks_data.NewDatabase(t))

	for _, responseType := range implicitResponseTypes {
		for _, mode := range []string{"", "fragment", "form_post"} {
			t.Run(responseType+"/response_mode="+mode, func(t *testing.T) {
				assert.NoError(t, validator.ValidateRequest(implicitRequest(responseType, mode)))
			})
		}
	}
}

// The one mode an implicit request may not name. The refusal is invalid_request, delivered by the
// authorize handler in the fragment (its own table pins the emitter); the description names the
// parameter and the two modes that work, and the request differs from the accepted row above in the
// mode alone.
func TestValidateRequest_ImplicitFlow_ResponseModeQueryRefused(t *testing.T) {
	validator := NewAuthorizeValidator(mocks_data.NewDatabase(t))

	for _, responseType := range implicitResponseTypes {
		t.Run(responseType, func(t *testing.T) {
			err := validator.ValidateRequest(implicitRequest(responseType, "query"))

			require.Error(t, err)
			detail, ok := err.(*customerrors.ErrorDetail)
			require.True(t, ok, "the refusal is a protocol error, not a localized page")
			assert.Equal(t, "invalid_request", detail.GetCode())
			assert.Equal(t, implicitQueryRefusal, detail.GetDescription())
			assert.Equal(t, http.StatusBadRequest, detail.GetHttpStatusCode())
		})
	}
}

// The rule is the implicit flow's. The code flow keeps all three modes, its default query included,
// so the change moves nothing for a client that never asked for tokens.
func TestValidateRequest_CodeFlow_ResponseModeUnchanged(t *testing.T) {
	validator := NewAuthorizeValidator(mocks_data.NewDatabase(t))

	for _, mode := range []string{"", "query", "fragment", "form_post"} {
		t.Run("response_mode="+mode, func(t *testing.T) {
			err := validator.ValidateRequest(&ValidateRequestInput{
				ResponseType:        "code",
				ResponseMode:        mode,
				CodeChallengeMethod: "S256",
				CodeChallenge:       "a_valid_code_challenge_that_meets_length_requirements",
			})

			assert.NoError(t, err)
		})
	}
}

// A mode nothing implements is refused by the general rule, ahead of the implicit one: the answer for
// "jwt" is the same whatever the response type, and the implicit refusal is reserved for the query.
func TestValidateRequest_ImplicitFlow_UnsupportedResponseModeIsTheGeneralRefusal(t *testing.T) {
	validator := NewAuthorizeValidator(mocks_data.NewDatabase(t))

	for _, mode := range []string{"jwt", "Query", "FORM_POST"} {
		t.Run("response_mode="+mode, func(t *testing.T) {
			err := validator.ValidateRequest(implicitRequest("token", mode))

			require.Error(t, err)
			detail, ok := err.(*customerrors.ErrorDetail)
			require.True(t, ok)
			assert.Equal(t, "invalid_request", detail.GetCode())
			assert.Equal(t, "Invalid response_mode parameter. Supported values are: query, fragment, form_post.",
				detail.GetDescription())
		})
	}
}
