package protocolvalidation

import (
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/customerrors"
)

// Every row varies one thing from "one copy of each": the rule is ConflictingParameter's, and both
// endpoints consult it, so the whole table is here and the handlers carry one accept and one refusal
// per path (#437 decision 18).
func TestConflictingParameter(t *testing.T) {
	names := []string{"client_id", "state", "nonce"}

	tests := []struct {
		name   string
		values url.Values
		want   string
	}{
		{"nothing sent", url.Values{}, ""},
		{"one copy of each", url.Values{"client_id": {"a"}, "state": {"s"}, "nonce": {"n"}}, ""},
		// Decision 18's leniency: identical copies leave one unambiguous value and proceed.
		// Reversing it refuses a client that has always sent a harmless duplicate.
		{"identical copies proceed", url.Values{"client_id": {"a", "a"}, "state": {"s", "s", "s"}}, ""},
		{"two differing copies", url.Values{"client_id": {"a", "b"}}, "client_id"},
		{"an empty copy differs from a non-empty one", url.Values{"state": {"", "s"}}, "state"},
		{"a non-empty copy differs from an empty one", url.Values{"state": {"s", ""}}, "state"},
		{"only the third copy differs", url.Values{"nonce": {"n", "n", "m"}}, "nonce"},
		{"case is a difference", url.Values{"nonce": {"n", "N"}}, "nonce"},
		// RFC 6749 3.1 and 3.2: an unrecognized parameter is ignored, so its copies are not read.
		{"a parameter the caller does not read is ignored", url.Values{"login_hint": {"a", "b"}}, ""},
		{"the first conflicting name in names' order", url.Values{"nonce": {"1", "2"}, "client_id": {"a", "b"}}, "client_id"},
		{"a later name when the earlier ones agree", url.Values{"client_id": {"a", "a"}, "nonce": {"1", "2"}}, "nonce"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ConflictingParameter(tt.values, names))
		})
	}
}

func TestValidateNoConflictingParameters(t *testing.T) {
	t.Run("identical copies are accepted", func(t *testing.T) {
		assert.NoError(t, ValidateNoConflictingParameters(url.Values{"scope": {"openid", "openid"}}, []string{"scope"}))
	})

	t.Run("differing copies are invalid_request naming the parameter and neither value", func(t *testing.T) {
		err := ValidateNoConflictingParameters(
			url.Values{"grant_type": {"client_credentials", "password"}}, []string{"code", "grant_type"})

		var detail *customerrors.ErrorDetail
		require.True(t, errors.As(err, &detail), "an ErrorDetail, which both endpoints answer as is")
		assert.Equal(t, "invalid_request", detail.GetCode())
		assert.Equal(t, http.StatusBadRequest, detail.GetHttpStatusCode())
		assert.Equal(t, "The 'grant_type' parameter was included more than once with different values.", detail.GetDescription())
		assert.NotContains(t, detail.GetDescription(), "client_credentials")
		assert.NotContains(t, detail.GetDescription(), "password")
	})
}
