package protocolvalidation

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/leodip/goiabada/core/customerrors"
)

// RepeatedParameter answers the first of names, in names' order, that values carries more than
// once, or "" when there is none.
//
// RFC 6749 sections 3.1 and 3.2 say of both endpoints: "Request and response parameters MUST NOT
// be included more than once", with no exception for copies that agree, and 4.1.2.1 and 5.2 name
// invalid_request for a request that "includes a parameter more than once". A parameter repeated
// with two values has no one meaning: this server would act on the first copy while a proxy, gateway
// or log in front of it may read another, and nothing downstream could see that a second value ever
// arrived. Identical copies are refused too, since the sections make no exception for them: the
// check is how many copies arrived, never what they hold, so an empty copy beside a filled one is a
// repeat like any other. Identical copies used to proceed, and a client sending a harmless duplicate
// now gets invalid_request (#228, #437).
//
// Only the names the caller reads are checked. The same sections require the server to "ignore
// unrecognized request parameters", and refusing a request for an extension parameter it never reads
// would not be ignoring it.
func RepeatedParameter(values url.Values, names []string) string {
	for _, name := range names {
		if len(values[name]) > 1 {
			return name
		}
	}
	return ""
}

// ValidateNoRepeatedParameters refuses a request carrying one of names more than once, as
// invalid_request naming the parameter. The description names the parameter and never a value: the
// name is from the caller's fixed list, and a value could be anything.
func ValidateNoRepeatedParameters(values url.Values, names []string) error {
	name := RepeatedParameter(values, names)
	if name == "" {
		return nil
	}
	return customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
		fmt.Sprintf("The '%v' parameter was included more than once.", name),
		http.StatusBadRequest)
}
