package customerrors

import (
	"errors"
	"fmt"
	"testing"
)

// Is is what the auth server's grant sentinels are matched by, and the method it replaced had no
// test at all. Every row here would have passed against IsError too, except the last two, which
// are the reason the signature changed: a target of another type, and a sentinel reached through a
// wrapper (#279 decision 6).
//
// The sentinels themselves are authserver/internal/protocolvalidation's and
// authserver/internal/handlerhelpers' since #385, and core cannot import either, so they are
// rebuilt here from the same constructor arguments. That costs nothing: the property under test is
// that an equal value built separately matches, so a fixture built separately is the subject
// rather than a stand-in for it.
func TestErrorDetail_Is(t *testing.T) {
	userDisabled := NewErrorDetailWithHttpStatusCode("invalid_grant", "The user account is disabled.", 400)
	noAuthContext := NewErrorDetail("no_auth_context", "no auth context in session")
	twoKeys := NewErrorDetail("invalid_grant", "The user account is disabled.")

	tests := []struct {
		name   string
		err    *ErrorDetail
		target error
		want   bool
	}{
		{
			name:   "an equal value built separately matches, which is the whole point",
			err:    NewErrorDetailWithHttpStatusCode("invalid_grant", "The user account is disabled.", 400),
			target: userDisabled,
			want:   true,
		},
		{
			name:   "the sentinel matches itself",
			err:    noAuthContext,
			target: noAuthContext,
			want:   true,
		},
		{
			name:   "a differing description does not match",
			err:    NewErrorDetailWithHttpStatusCode("invalid_grant", "Client is disabled.", 400),
			target: userDisabled,
			want:   false,
		},
		{
			name:   "a differing code does not match",
			err:    NewErrorDetailWithHttpStatusCode("invalid_request", "The user account is disabled.", 400),
			target: userDisabled,
			want:   false,
		},
		{
			// The two sentinels that share a code and a status and differ only in their text. The
			// token endpoint charges an account's failure budget on one and not the other, so this
			// row is the one keeping those two apart.
			name:   "the client-disabled sentinel is not the user-disabled one",
			err:    NewErrorDetailWithHttpStatusCode("invalid_grant", "Client is disabled.", 400),
			target: userDisabled,
			want:   false,
		},
		{
			name:   "a differing status code does not match, though code and description agree",
			err:    NewErrorDetailWithHttpStatusCode("invalid_grant", "The user account is disabled.", 401),
			target: userDisabled,
			want:   false,
		},
		{
			// Fewer keys, and every key it does have agrees. The length test is what refuses it, and
			// without that test a detail carrying no status would answer for one that carries 400.
			name:   "a shorter detail does not match a longer one",
			err:    twoKeys,
			target: userDisabled,
			want:   false,
		},
		{
			name:   "and not in the other direction either",
			err:    userDisabled,
			target: twoKeys,
			want:   false,
		},
		{
			name:   "a typed nil target is not this error",
			err:    userDisabled,
			target: (*ErrorDetail)(nil),
			want:   false,
		},
		{
			// IsError could not be handed this at all: its parameter was a *ErrorDetail, so the
			// caller had to have asserted the type first. errors.Is hands Is whatever the caller
			// named, and answering true for an unrelated type would make every sentinel match it.
			name:   "a target of another type is not this error",
			err:    userDisabled,
			target: errors.New("invalid_grant"),
			want:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.err.Is(tc.target); got != tc.want {
				t.Errorf("Is() = %v, want %v", got, tc.want)
			}
			// errors.Is is how every caller in the tree reaches this method, so each row is checked
			// through it as well. The two answers can only differ if Is stops being consulted.
			if got := errors.Is(tc.err, tc.target); got != tc.want {
				t.Errorf("errors.Is() = %v, want %v", got, tc.want)
			}
		})
	}
}

// The reason the method exists in this shape. A wrapped sentinel is unreachable from a bare type
// assertion, and every site that used to match one has been rewritten to errors.Is, so the sentinel
// has to survive an arbitrary number of layers above it.
func TestErrorDetail_Is_ThroughAWrapper(t *testing.T) {
	rebuilt := NewErrorDetailWithHttpStatusCode("invalid_grant", "The user account is disabled.", 400)
	wrapped := fmt.Errorf("unable to validate the token request: %w", rebuilt)

	userDisabled := NewErrorDetailWithHttpStatusCode("invalid_grant", "The user account is disabled.", 400)
	clientDisabled := NewErrorDetailWithHttpStatusCode("invalid_grant", "Client is disabled.", 400)

	if !errors.Is(wrapped, userDisabled) {
		t.Error("Expected a wrapped user-disabled detail to still match the sentinel")
	}
	if errors.Is(wrapped, clientDisabled) {
		t.Error("Expected a wrapped user-disabled detail not to match a different sentinel")
	}

	var detail *ErrorDetail
	if !errors.As(wrapped, &detail) {
		t.Fatal("Expected errors.As to reach the wrapped *ErrorDetail")
	}
	if detail.GetHttpStatusCode() != 400 {
		t.Errorf("Expected the wrapped detail to keep its status, got %d", detail.GetHttpStatusCode())
	}
}
