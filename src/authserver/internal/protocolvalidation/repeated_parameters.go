package protocolvalidation

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/leodip/goiabada/core/customerrors"
)

// ConflictingParameter answers the first of names, in names' order, that values carries more than
// once with differing values, or "" when there is none.
//
// RFC 6749 sections 3.1 and 3.2 say of both endpoints: "Request and response parameters MUST NOT
// be included more than once." That binds the client; what it protects is that one request has one
// meaning. A parameter repeated with two values has none: this server would act on the first copy
// while a proxy, gateway or log in front of it may read another, and nothing downstream could see
// that a second value ever arrived. So two differing copies are refused, as invalid_request, which
// 4.1.2.1 and 5.2 name for a parameter "included more than once" (#228).
//
// Identical copies are tolerated on purpose: they leave one unambiguous value, so nothing in front
// of the server can read a different one, and a client that has always sent a harmless duplicate
// keeps working. Refusing them would break that client for no gain (#437 decision 18).
//
// Only the names the caller reads are checked. The same sections require the server to "ignore
// unrecognized request parameters", and refusing a request for an extension parameter it never reads
// would not be ignoring it.
func ConflictingParameter(values url.Values, names []string) string {
	for _, name := range names {
		copies := values[name]
		for _, value := range copies {
			if value != copies[0] {
				return name
			}
		}
	}
	return ""
}

// ValidateNoConflictingParameters refuses a request carrying one of names more than once with
// differing values, as invalid_request naming the parameter. The description names the parameter
// and never a value: the name is from the caller's fixed list, and either value could be anything.
func ValidateNoConflictingParameters(values url.Values, names []string) error {
	name := ConflictingParameter(values, names)
	if name == "" {
		return nil
	}
	return customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
		fmt.Sprintf("The '%v' parameter was included more than once with different values.", name),
		http.StatusBadRequest)
}
