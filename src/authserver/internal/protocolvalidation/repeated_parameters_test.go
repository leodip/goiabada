package protocolvalidation

import (
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/oauth"
)

// Every row varies one thing from "one copy of each": the rule is RepeatedParameter's, and both
// endpoints consult it, so the whole table is here and the handlers carry one accept and the
// refusals per path (#228).
func TestRepeatedParameter(t *testing.T) {
	names := []string{"client_id", "state", "nonce"}

	tests := []struct {
		name   string
		values url.Values
		want   string
	}{
		{"nothing sent", url.Values{}, ""},
		{"one copy of each", url.Values{"client_id": {"a"}, "state": {"s"}, "nonce": {"n"}}, ""},
		{"one empty copy", url.Values{"state": {""}}, ""},
		{"two differing copies", url.Values{"client_id": {"a", "b"}}, "client_id"},
		// RFC 6749 3.1 and 3.2 make no exception for copies that agree, so neither does the rule.
		// Identical copies used to proceed (#228).
		{"two identical copies", url.Values{"client_id": {"a", "a"}}, "client_id"},
		{"three identical copies", url.Values{"state": {"s", "s", "s"}}, "state"},
		{"two empty copies", url.Values{"state": {"", ""}}, "state"},
		{"an empty copy beside a non-empty one", url.Values{"state": {"", "s"}}, "state"},
		{"a non-empty copy beside an empty one", url.Values{"state": {"s", ""}}, "state"},
		{"copies differing in case", url.Values{"nonce": {"n", "N"}}, "nonce"},
		// RFC 6749 3.1 and 3.2: an unrecognized parameter is ignored, so its copies are not read.
		{"a parameter the caller does not read is ignored", url.Values{"login_hint": {"a", "a"}}, ""},
		{"the first repeated name in names' order", url.Values{"nonce": {"1", "1"}, "client_id": {"a", "a"}}, "client_id"},
		{"a later name when the earlier ones arrive once", url.Values{"client_id": {"a"}, "nonce": {"1", "1"}}, "nonce"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, RepeatedParameter(tt.values, names))
		})
	}
}

func TestValidateNoRepeatedParameters(t *testing.T) {
	t.Run("one copy of each is accepted", func(t *testing.T) {
		assert.NoError(t, ValidateNoRepeatedParameters(url.Values{"scope": {"openid"}, "state": {"s"}}, []string{"scope", "state"}))
	})

	refusal := func(t *testing.T, err error) *oauth.ErrorDetail {
		t.Helper()
		var detail *oauth.ErrorDetail
		require.True(t, errors.As(err, &detail), "an ErrorDetail, which both endpoints answer as is")
		assert.Equal(t, "invalid_request", detail.Code())
		assert.Equal(t, http.StatusBadRequest, detail.HTTPStatus())
		return detail
	}

	t.Run("identical copies are invalid_request naming the parameter", func(t *testing.T) {
		detail := refusal(t, ValidateNoRepeatedParameters(url.Values{"scope": {"openid", "openid"}}, []string{"scope"}))
		assert.Equal(t, "The 'scope' parameter was included more than once.", detail.Description())
	})

	t.Run("differing copies are invalid_request naming the parameter and neither value", func(t *testing.T) {
		detail := refusal(t, ValidateNoRepeatedParameters(
			url.Values{"grant_type": {"client_credentials", "password"}}, []string{"code", "grant_type"}))
		assert.Equal(t, "The 'grant_type' parameter was included more than once.", detail.Description())
		assert.NotContains(t, detail.Description(), "client_credentials")
		assert.NotContains(t, detail.Description(), "password")
	})
}
