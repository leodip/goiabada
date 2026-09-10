package customerrors

import (
	"errors"
	"fmt"
	"testing"
)

// Is is what three of the four package-level sentinels are matched by, and the method it replaced
// had no test at all. Every row here would have passed against IsError too, except the last two,
// which are the reason the signature changed: a target of another type, and a sentinel reached
// through a wrapper (#279 decision 6).
func TestErrorDetail_Is(t *testing.T) {
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
			target: ErrUserDisabled,
			want:   true,
		},
		{
			name:   "the sentinel matches itself",
			err:    ErrNoAuthContext,
			target: ErrNoAuthContext,
			want:   true,
		},
		{
			name:   "a differing description does not match",
			err:    NewErrorDetailWithHttpStatusCode("invalid_grant", "Client is disabled.", 400),
			target: ErrUserDisabled,
			want:   false,
		},
		{
			name:   "a differing code does not match",
			err:    NewErrorDetailWithHttpStatusCode("invalid_request", "The user account is disabled.", 400),
			target: ErrUserDisabled,
			want:   false,
		},
		{
			// The two sentinels that share a code and a status and differ only in their text. The
			// token endpoint charges an account's failure budget on one and not the other, so this
			// row is the one keeping those two apart.
			name:   "ErrClientDisabled is not ErrUserDisabled",
			err:    NewErrorDetailWithHttpStatusCode("invalid_grant", "Client is disabled.", 400),
			target: ErrUserDisabled,
			want:   false,
		},
		{
			name:   "a differing status code does not match, though code and description agree",
			err:    NewErrorDetailWithHttpStatusCode("invalid_grant", "The user account is disabled.", 401),
			target: ErrUserDisabled,
			want:   false,
		},
		{
			// Fewer keys, and every key it does have agrees. The length test is what refuses it, and
			// without that test a detail carrying no status would answer for one that carries 400.
			name:   "a shorter detail does not match a longer one",
			err:    twoKeys,
			target: ErrUserDisabled,
			want:   false,
		},
		{
			name:   "and not in the other direction either",
			err:    ErrUserDisabled,
			target: twoKeys,
			want:   false,
		},
		{
			name:   "a typed nil target is not this error",
			err:    ErrUserDisabled,
			target: (*ErrorDetail)(nil),
			want:   false,
		},
		{
			// IsError could not be handed this at all: its parameter was a *ErrorDetail, so the
			// caller had to have asserted the type first. errors.Is hands Is whatever the caller
			// named, and answering true for an unrelated type would make every sentinel match it.
			name:   "a target of another type is not this error",
			err:    ErrUserDisabled,
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

	if !errors.Is(wrapped, ErrUserDisabled) {
		t.Error("Expected a wrapped ErrUserDisabled to still match the sentinel")
	}
	if errors.Is(wrapped, ErrClientDisabled) {
		t.Error("Expected a wrapped ErrUserDisabled not to match a different sentinel")
	}

	var detail *ErrorDetail
	if !errors.As(wrapped, &detail) {
		t.Fatal("Expected errors.As to reach the wrapped *ErrorDetail")
	}
	if detail.GetHttpStatusCode() != 400 {
		t.Errorf("Expected the wrapped detail to keep its status, got %d", detail.GetHttpStatusCode())
	}
}

// AuthCodeReusedError.Unwrap puts its Detail on the chain, so the writers and the sentinels reach
// it. Before Unwrap, handing this wrapper to JsonError answered 500 with the description in the log
// instead of 400 with it on the wire.
func TestAuthCodeReusedError_UnwrapsToItsDetail(t *testing.T) {
	detail := NewErrorDetailWithHttpStatusCode("invalid_grant", "Code is invalid.", 400)
	reuse := &AuthCodeReusedError{Detail: detail}

	var reached *ErrorDetail
	if !errors.As(reuse, &reached) {
		t.Fatal("Expected errors.As to reach the Detail")
	}
	if reached != detail {
		t.Error("Expected the Detail itself, not a copy")
	}
	if !errors.Is(reuse, NewErrorDetailWithHttpStatusCode("invalid_grant", "Code is invalid.", 400)) {
		t.Error("Expected errors.Is to match an equal detail through the wrapper")
	}
	if reuse.Error() != detail.Error() {
		t.Errorf("Expected Error() to stay the Detail's text, got %s", reuse.Error())
	}
}
