package handlertest

import (
	"encoding/json"
	"fmt"

	"github.com/stretchr/testify/mock"

	mocks_handlerhelpers "github.com/leodip/goiabada/adminconsole/internal/handlerhelpers/mocks"
	"github.com/leodip/goiabada/core/testutil"
)

// ExpectEncodeJson admits EncodeJson and hands the call back so the caller can bound it. It is the
// AJAX half of ExpectRender and chooses neither Maybe() nor Once() for the same reason: a handler
// that may or may not answer says so itself.
func ExpectEncodeJson(httpHelper *mocks_handlerhelpers.HttpHelper) *mock.Call {
	return httpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.Anything).Return()
}

// Encoded is the answer an AJAX handler wrote, read back off the mock's call log as the browser
// reads it: marshalled, and then decoded into a map. EncodeJson is mocked, so the call log is the
// only place the value exists.
//
// It goes through encoding/json rather than returning the value the handler passed, because these
// handlers answer anonymous structs with no tags. The field names the console's own scripts read
// -- Success, IsCurrentSession -- are therefore the Go names, and a case reading the struct back
// through a type assertion would pin the shape the handler happened to build while saying nothing
// about the names on the wire. Absence is part of the answer too: a handler that answers Success
// alone leaves IsCurrentSession out of the object rather than sending it false.
//
// It is the last EncodeJson call, for the reason Bind takes the last render.
//
// context is an optional printf-style clause appended to the failure, for the table helpers whose
// rows a bare message could not tell apart.
func Encoded(reporter testutil.Reporter, httpHelper *mocks_handlerhelpers.HttpHelper,
	context ...any) map[string]any {
	reporter.Helper()

	var answered bool
	var value any
	for _, call := range httpHelper.Calls {
		if call.Method == "EncodeJson" {
			answered = true
			value = call.Arguments.Get(2)
		}
	}
	if !answered {
		reporter.Fatalf("%s", withContext("the handler encoded nothing", context))
		return nil
	}

	encoded, err := json.Marshal(value)
	if err != nil {
		reporter.Fatalf("%s", withContext(fmt.Sprintf("the answer does not marshal: %v", err), context))
		return nil
	}

	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		reporter.Fatalf("%s", withContext(fmt.Sprintf("the answer is not a JSON object: %v", err), context))
		return nil
	}
	// A JSON null unmarshals into a map without an error and leaves it nil, so it reaches here as
	// an object with no keys rather than as the absence it is. Left alone, a case asserting only
	// that a field is absent would pass against a handler that answered nothing at all.
	if decoded == nil {
		reporter.Fatalf("%s", withContext("the answer is JSON null rather than an object", context))
		return nil
	}
	return decoded
}

func withContext(message string, context []any) string {
	if len(context) > 0 {
		message += " " + fmt.Sprintf(context[0].(string), context[1:]...)
	}
	return message
}
