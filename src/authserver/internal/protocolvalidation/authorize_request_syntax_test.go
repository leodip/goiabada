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

// malformedText is ValidateSpaceDelimited's description for parameter.
func malformedText(parameter string) string {
	return "The '" + parameter + "' parameter is malformed. Separate its values with a single space, with no space before the first value or after the last."
}

// TestValidateRequest_ResponseTypeSpellings is #244's parser rule seen from the endpoint: a value the
// parser did not recognise, or a recognised one it saw twice, is unsupported_response_type, where
// each used to be collapsed into the request it resembled and accepted; and a value whose spaces the
// grammar does not allow is invalid_request, where it used to be read as if the extra spaces were not
// there. Every refused row is an accepted spelling plus one token, one space, or one character that
// is not a separator, so that is what is refused.
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

	accepted := []string{"code", "token", "id_token", "id_token token", "token id_token"}
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
		// Only a space separates: each of these joins two types into one value nobody recognises. A
		// tab and a newline used to separate; the other three never did.
		"id_token\ttoken", "id_token\ntoken", "code\u00a0token", "code\u0085token", "code\vtoken",
		// Nothing is trimmed: a type padded with a no-break space, or a value of a tab and a newline,
		// is no type. The first used to be read as code and the second as missing.
		"code\u00a0", "\t\n", "\v",
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

	// RFC 6749 3.1.1: response-name *( SP response-name ). Each of these used to be accepted as the
	// type inside it, or, spaces alone, called missing (#244).
	malformed := []string{" code ", " code", "code ", "id_token  token", " ", "   "}
	for _, responseType := range malformed {
		t.Run("refuses as malformed "+responseType, func(t *testing.T) {
			err := validator.ValidateRequest(request(responseType))

			var detail *customerrors.ErrorDetail
			require.ErrorAs(t, err, &detail)
			assert.Equal(t, "invalid_request", detail.GetCode())
			assert.Equal(t, malformedText("response_type"), detail.GetDescription())
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

	t.Run("a malformed type is refused before the implicit switch is read", func(t *testing.T) {
		input := request("token ")
		input.ImplicitGrantEnabled = false

		err := validator.ValidateRequest(input)

		var detail *customerrors.ErrorDetail
		require.ErrorAs(t, err, &detail)
		assert.Equal(t, "invalid_request", detail.GetCode())
		assert.Equal(t, malformedText("response_type"), detail.GetDescription())
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

	t.Run("an empty response_type is missing, not unsupported", func(t *testing.T) {
		err := validator.ValidateRequest(request(""))

		var detail *customerrors.ErrorDetail
		require.ErrorAs(t, err, &detail)
		assert.Equal(t, "invalid_request", detail.GetCode())
		assert.Equal(t, "The response_type parameter is missing.", detail.GetDescription())
	})
}

// TestValidateRequest_OpenidScopeIsFoundThroughTheSharedSplitter: an id_token needs the openid
// scope, and the scope is read the way every other reader of it reads it, split on the space alone,
// so a scope joined by a tab, a newline or a no-break space is one value that is not openid, exactly
// as SetScope stored it (#244). Its grammar is ValidateScopes' question, which sees the raw value.
func TestValidateRequest_OpenidScopeIsFoundThroughTheSharedSplitter(t *testing.T) {
	validator := NewAuthorizeValidator(mocks_data.NewDatabase(t))

	request := func(scope string) *ValidateRequestInput {
		return &ValidateRequestInput{ResponseType: "id_token", ImplicitGrantEnabled: true, Scope: scope, Nonce: "n"}
	}

	for _, scope := range []string{"openid", "openid profile", "profile openid"} {
		t.Run("accepts "+scope, func(t *testing.T) {
			assert.NoError(t, validator.ValidateRequest(request(scope)))
		})
	}

	refused := []string{
		"profile", "openid_connect", "OPENID",
		// A tab and a newline used to separate, and found openid here (#244).
		"profile\topenid", "profile\nopenid",
		"openid\u00a0profile", "profile\u0085openid",
	}
	for _, scope := range refused {
		t.Run("refuses "+scope, func(t *testing.T) {
			err := validator.ValidateRequest(request(scope))

			var detail *customerrors.ErrorDetail
			require.ErrorAs(t, err, &detail)
			assert.Equal(t, "invalid_request", detail.GetCode())
			assert.Equal(t, "The 'openid' scope is required when requesting an id_token.", detail.GetDescription())
		})
	}
}

// TestValidatePrompt_SelectAccountAndSeparators is #244's prompt rows: select_account is known, so it
// is refused for what it is and never as an unknown value, whatever it is combined with except the
// two refusals that come first; and prompt is held to the space-delimited grammar, one space between
// each two values and none at either end, with no other character separating.
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

		// The control: one space separates two values.
		{"a space splits", "login consent", "login consent", "", ""},
		// No other character does, so two words joined by one are one unknown value. A tab, a
		// newline, a form feed and a carriage return used to split (#244).
		{"tab does not split", "login\tconsent", "", "invalid_request", "Invalid prompt value: login\tconsent"},
		{"newline does not split", "login\nconsent", "", "invalid_request", "Invalid prompt value: login\nconsent"},
		{"form feed does not split", "login\fconsent", "", "invalid_request", "Invalid prompt value: login\fconsent"},
		{"carriage return does not split", "login\rconsent", "", "invalid_request", "Invalid prompt value: login\rconsent"},
		{"no-break space does not split", "login\u00a0consent", "", "invalid_request", "Invalid prompt value: login\u00a0consent"},
		{"next-line character does not split", "login\u0085consent", "", "invalid_request", "Invalid prompt value: login\u0085consent"},
		{"vertical tab does not split", "login\vconsent", "", "invalid_request", "Invalid prompt value: login\vconsent"},
		// Nothing is trimmed: the edge trim used to read this as login.
		{"a value padded with a no-break space is not that value", "login\u00a0", "", "invalid_request", "Invalid prompt value: login\u00a0"},
		// The spaces the grammar does not allow (#244).
		{"a run of spaces is malformed", "login  consent", "", "invalid_request", malformedText("prompt")},
		{"a leading space is malformed", " login", "", "invalid_request", malformedText("prompt")},
		{"a trailing space is malformed", "login ", "", "invalid_request", malformedText("prompt")},
		{"spaces alone are malformed", "   ", "", "invalid_request", malformedText("prompt")},
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
