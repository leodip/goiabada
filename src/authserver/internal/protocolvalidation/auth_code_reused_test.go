package protocolvalidation

import (
	"errors"
	"testing"

	"github.com/leodip/goiabada/core/customerrors"
)

// AuthCodeReusedError.Unwrap puts its Detail on the chain, so the writers and the sentinels reach
// it. Before Unwrap, handing this wrapper to JsonError answered 500 with the description in the log
// instead of 400 with it on the wire.
func TestAuthCodeReusedError_UnwrapsToItsDetail(t *testing.T) {
	detail := customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant", "Code is invalid.", 400)
	reuse := &AuthCodeReusedError{Detail: detail}

	var reached *customerrors.ErrorDetail
	if !errors.As(reuse, &reached) {
		t.Fatal("Expected errors.As to reach the Detail")
	}
	if reached != detail {
		t.Error("Expected the Detail itself, not a copy")
	}
	if !errors.Is(reuse, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant", "Code is invalid.", 400)) {
		t.Error("Expected errors.Is to match an equal detail through the wrapper")
	}
	if reuse.Error() != detail.Error() {
		t.Errorf("Expected Error() to stay the Detail's text, got %s", reuse.Error())
	}
}
