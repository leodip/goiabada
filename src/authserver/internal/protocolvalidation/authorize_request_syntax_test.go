package protocolvalidation

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/core/customerrors"
)

const unsupportedResponseTypeText = "The authorization server does not support this response_type. Supported values: code, token, id_token, id_token token."

// TestValidateRequest_ResponseTypeSpellings is #244's parser rule seen from the endpoint: a value the
// parser did not recognise, or a recognised one it saw twice, is unsupported_response_type, where
// each used to be collapsed into the request it resembled and accepted. Every refused row is an
// accepted spelling plus one token, or one separator that no longer separates, so the token is what
// is refused.
func TestValidateRequest_ResponseTypeSpellings(t *testing.T) {
	validator := NewAuthorizeValidator(mocks_data.NewDatabase(t))

	request := func(responseType string) *ValidateRequestInput {
		return &ValidateRequestInput{
			ResponseType:         responseType,
			ImplicitGrantEnabled: true,
			Scope:                "openid",
			Nonce:                "a-nonce",
		}
	}

	accepted := []string{
		"code", "token", "id_token", "id_token token", "token id_token",
		" code ", "id_token\ttoken", "id_token\ntoken", "id_token  token",
		// The edge trim is kept: padded with a no-break space, a value is still that value.
		"code ",
	}
	for _, responseType := range accepted {
		t.Run("accepts "+responseType, func(t *testing.T) {
			assert.NoError(t, validator.ValidateRequest(request(responseType)))
		})
	}

	refused := []string{
		// An unrecognised value beside a recognised one, both orders.
		"code foo", "foo code", "token unknown", "id_token token unknown",
		// A recognised value twice.
		"code code", "token token", "id_token id_token", "id_token token id_token", "code token code",
		// Unknown alone, and by case.
		"foo", "Code", "CODE", "codes",
		// Hybrid types, refused by the count and not by the two flags, still refused.
		"code token", "code id_token", "code id_token token",
		// A no-break space, a next-line character and a vertical tab are not separators: each joins
		// two types into one value nobody recognises.
		"code token", "id_token token", "code\u0085token", "code\vtoken",
	}
	for _, responseType := range refused {
		t.Run("refuses "+responseType, func(t *testing.T) {
			err := validator.ValidateRequest(request(responseType))

			var detail *customerrors.ErrorDetail
			require.ErrorAs(t, err, &detail)
			assert.Equal(t, "unsupported_response_type", detail.GetCode())
			assert.Equal(t, unsupportedResponseTypeText, detail.GetDescription())
			assert.Equal(t, http.StatusBadRequest, detail.GetHttpStatusCode())
		})
	}

	t.Run("a repeated type is refused as unsupported before the implicit switch is read", func(t *testing.T) {
		input := request("token token")
		input.ImplicitGrantEnabled = false

		err := validator.ValidateRequest(input)

		var detail *customerrors.ErrorDetail
		require.ErrorAs(t, err, &detail)
		assert.Equal(t, "unsupported_response_type", detail.GetCode())
	})

	// The same spelling with the switch off is the control: it is a real implicit request, refused
	// for the client's flag and for nothing about its spelling.
	t.Run("a well-formed implicit type with the switch off is unauthorized_client", func(t *testing.T) {
		input := request("token")
		input.ImplicitGrantEnabled = false

		err := validator.ValidateRequest(input)

		var detail *customerrors.ErrorDetail
		require.ErrorAs(t, err, &detail)
		assert.Equal(t, "unauthorized_client", detail.GetCode())
	})

	for _, missing := range []string{"", "   ", "\t\n", " ", "\v"} {
		t.Run("a response_type of nothing is missing, not unsupported", func(t *testing.T) {
			err := validator.ValidateRequest(request(missing))

			var detail *customerrors.ErrorDetail
			require.ErrorAs(t, err, &detail)
			assert.Equal(t, "invalid_request", detail.GetCode())
			assert.Equal(t, "The response_type parameter is missing.", detail.GetDescription())
		})
	}
}

// TestValidateRequest_OpenidScopeIsFoundThroughTheSharedSplitter: an id_token needs the openid
// scope, and the scope is read the way every other reader of it reads it, so a scope joined by a
// no-break space is one value that is not openid, exactly as SetScope stored it (#244).
func TestValidateRequest_OpenidScopeIsFoundThroughTheSharedSplitter(t *testing.T) {
	validator := NewAuthorizeValidator(mocks_data.NewDatabase(t))

	request := func(scope string) *ValidateRequestInput {
		return &ValidateRequestInput{ResponseType: "id_token", ImplicitGrantEnabled: true, Scope: scope, Nonce: "n"}
	}

	for _, scope := range []string{"openid", "openid profile", "profile openid", "profile\topenid", "profile\nopenid", "  openid  "} {
		t.Run("accepts "+scope, func(t *testing.T) {
			assert.NoError(t, validator.ValidateRequest(request(scope)))
		})
	}

	for _, scope := range []string{"profile", "openid_connect", "OPENID", "openid profile", "profile\u0085openid"} {
		t.Run("refuses "+scope, func(t *testing.T) {
			err := validator.ValidateRequest(request(scope))

			var detail *customerrors.ErrorDetail
			require.ErrorAs(t, err, &detail)
			assert.Equal(t, "invalid_request", detail.GetCode())
			assert.Equal(t, "The 'openid' scope is required when requesting an id_token.", detail.GetDescription())
		})
	}
}

// TestValidatePrompt_SelectAccountAndSeparators is decision 20's prompt rows: select_account is
// known, so it is refused for what it is and never as an unknown value, whatever it is combined with
// except the two refusals that come first; and prompt's separators are the shared set.
func TestValidatePrompt_SelectAccountAndSeparators(t *testing.T) {
	validator := NewAuthorizeValidator(mocks_data.NewDatabase(t))

	const selectAccountText = "prompt=select_account is not supported: the authorization server cannot ask the end user to select an account."

	testCases := []struct {
		name        string
		prompt      string
		want        string
		wantCode    string
		wantMessage string
	}{
		// select_account, alone and combined.
		{"alone", "select_account", "", "account_selection_required", selectAccountText},
		{"repeated is still one value", "select_account select_account", "", "account_selection_required", selectAccountText},
		{"with login", "select_account login", "", "account_selection_required", selectAccountText},
		{"after login", "login select_account", "", "account_selection_required", selectAccountText},
		{"with consent and login", "login consent select_account", "", "account_selection_required", selectAccountText},
		// The two refusals that come before it keep their own answers.
		{"with none is the combination error", "none select_account", "", "invalid_request", "prompt=none cannot be combined with other values"},
		{"after none is the combination error", "select_account none", "", "invalid_request", "prompt=none cannot be combined with other values"},
		{"beside an unknown value names the unknown one", "select_account foo", "", "invalid_request", "Invalid prompt value: foo"},
		// Case still matters: this is not select_account.
		{"upper case is unknown", "SELECT_ACCOUNT", "", "invalid_request", "Invalid prompt value: SELECT_ACCOUNT"},

		// The shared separators: a tab, a newline, a form feed and a carriage return still split.
		{"tab splits", "login\tconsent", "login consent", "", ""},
		{"newline splits", "login\nconsent", "login consent", "", ""},
		{"form feed splits", "login\fconsent", "login consent", "", ""},
		{"carriage return splits", "login\rconsent", "login consent", "", ""},
		// A no-break space, a next-line character and a vertical tab do not: two words are one
		// unknown value.
		{"no-break space does not split", "login consent", "", "invalid_request", "Invalid prompt value: login consent"},
		{"next-line character does not split", "login\u0085consent", "", "invalid_request", "Invalid prompt value: login\u0085consent"},
		{"vertical tab does not split", "login\vconsent", "", "invalid_request", "Invalid prompt value: login\vconsent"},
		// The edge trim is kept.
		{"a value padded with a no-break space is that value", "login ", "login", "", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := validator.ValidatePrompt(tc.prompt)

			if tc.wantCode == "" {
				require.NoError(t, err)
				assert.Equal(t, tc.want, result)
				return
			}

			var detail *customerrors.ErrorDetail
			require.ErrorAs(t, err, &detail)
			assert.Equal(t, tc.wantCode, detail.GetCode())
			assert.Equal(t, tc.wantMessage, detail.GetDescription())
			assert.Equal(t, http.StatusBadRequest, detail.GetHttpStatusCode())
			assert.Equal(t, "", result)
		})
	}
}
