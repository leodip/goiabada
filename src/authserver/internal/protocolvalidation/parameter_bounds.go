package protocolvalidation

import (
	"fmt"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/customerrors"
)

// parameterBound is the longest a free-form request parameter may be, in bytes, and the refusal
// that answers a longer one. The maximums are models' (the widths of the columns the values are
// stored in), so the rule and the schema cannot drift apart unnoticed: the data tier writes a
// value of exactly that many bytes to every engine (#437).
type parameterBound struct {
	// errorCode is invalid_request for state and nonce and invalid_scope for scope, the codes RFC
	// 6749 4.1.2.1 and 5.2 name for a malformed parameter and for a scope that is invalid.
	errorCode string
	name      string
	maxBytes  int
}

var (
	// stateBound and nonceBound bound what the authorization endpoint stores in codes.state and
	// codes.nonce, and carries in the ceremony whichever response type was asked for.
	stateBound = parameterBound{errorCode: "invalid_request", name: "state", maxBytes: models.StateMaxBytes}
	nonceBound = parameterBound{errorCode: "invalid_request", name: "nonce", maxBytes: models.NonceMaxBytes}

	// scopeBound bounds a scope where it enters: at the authorization endpoint and at the password
	// grant. It counts the normalized scope, duplicates dropped and whitespace collapsed, because
	// that is the value stored.
	scopeBound = parameterBound{errorCode: "invalid_scope", name: "scope", maxBytes: models.ScopeMaxBytes}
)

// check answers nil when value fits, and otherwise the refusal. It counts bytes, not characters,
// because models' bounds are widths that three engines count differently and a byte count is never
// below either. The description carries the parameter's name and the two counts and never the
// value: it becomes an error_description on a redirect, and the value is the client's to keep.
func (b parameterBound) check(value string) error {
	if len(value) <= b.maxBytes {
		return nil
	}
	return customerrors.NewErrorDetailWithHttpStatusCode(b.errorCode,
		fmt.Sprintf("The '%s' parameter is too long (%d bytes, the maximum is %d).", b.name, len(value), b.maxBytes),
		http.StatusBadRequest)
}
